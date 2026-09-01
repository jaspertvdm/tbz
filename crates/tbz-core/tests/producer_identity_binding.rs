//! Producer identity binding — the negative vector, written BEFORE the binding exists.
//!
//! Codex mapped the seal family on 31 Aug and the conclusion reorders the work: do NOT make
//! `tbz-core` identity-bound in isolation, because the shape already exists elsewhere in the stack.
//!
//!     tibet-drop     proves the identity-binding SHAPE   (manifest_sig over canonical CBOR
//!                    carrying sender_aint, sender_pubkey, receiver_aint, receiver_pubkey, tpid,
//!                    payload_type, transfer_out_token_id)
//!     /root/tbz v2   proves the carrier CRYPTO           (real X25519-ECDH + HKDF + AES-GCM,
//!                    Ed25519 authorship)
//!
//! Two halves that do not know each other. The canonical TBZ converges them; it does not pick one
//! and reinvent the other.
//!
//! ## Why this file is RED on purpose, and why that is not the same as broken
//!
//! Codex's order says "negative vector first", and the instinct is right — but a vector that flips
//! `producer_identity` while no such field exists fails at FIELD NOT FOUND, never at SIGNATURE
//! REFUSED. That is a passing-shaped failure, and it is exactly the clause every probe in this
//! stack now carries: KNOWN BAD MUST FAIL AT THE CONSUMER FOR THE RIGHT REASON.
//!
//! So this vector is written in two halves that must go green IN ORDER:
//!
//!     A. the signed commitment CONTAINS the producer identity      <- red today
//!     B. flipping one field of it makes verification fail          <- cannot be measured until A
//!
//! B is deliberately gated on A rather than asserted independently. A vector that could pass while
//! A is red would be measuring the absence of a field and calling it security.
//!
//! ## What the commitment must become
//!
//! Per Codex's map, and following the domain-separator style already in the stack
//! (`tibet-genesis:v1:<candidate_hash>`, `cmail.message.sealed.v1`, `tbz-unseal.v1`):
//!
//!     tbz-producer-archive:v1:<archive_root>
//!
//! over a canonical root carrying at least format_version, producer_identity, producer_key_id,
//! identity_epoch, producer_pubkey, parent_receipt_root, task_root/transition_ref,
//! policy_envelope_hash, payload_class and the ordered file merkle root.
//!
//! ## Deliberately NOT in this vector
//!
//! KEY CURRENTNESS. Codex's sharpest finding is that identity-bound bytes are necessary and not
//! sufficient: a consumer also needs to know whether the producer key was current / reseeded /
//! revoked / unknown at the claimed causal point, or an identity-bound archive replays cleanly
//! across a revoke. That is a SECOND axis and it gets its own vector. Folding it in here would mean
//! that when this file goes green, nobody could say which of the two bindings did it.
//!
//! MANIFEST/BLOCK TRANSPLANT is the other one he named — blocks signed by the same key wandering
//! between manifests unless the block commitment derives from the archive root. Also its own
//! vector, for the same reason.

use tibet_zip_core::envelope::TibetEnvelope;
use tibet_zip_core::manifest::Manifest;
use tibet_zip_core::signature;
use tibet_zip_core::stream::{TbzReader, TbzWriter};

/// The fields the canonical producer commitment must carry. Named here so the target is a written
/// contract rather than a memory of a conversation.
const REQUIRED_IN_COMMITMENT: &[&str] = &["producer_identity", "producer_key_id", "identity_epoch"];

const PAYLOAD: &[u8] = b"an archive that should name its maker";

/// Everything the current block signature actually covers: header || envelope || payload.
fn signed_commitment() -> Vec<u8> {
    let (signing_key, _) = signature::generate_keypair();
    let verifying_key = signing_key.verifying_key();

    let mut buf = Vec::new();
    {
        let mut manifest = Manifest::new();
        manifest.set_signing_key(&verifying_key);
        let mut writer = TbzWriter::new(&mut buf, signing_key);
        writer.write_manifest(&manifest).unwrap();
        let envelope = TibetEnvelope::new(
            signature::sha256_hash(PAYLOAD),
            "data",
            "application/octet-stream",
            "producer-identity-vector",
            "identity binding",
            vec!["block:0".to_string()],
        );
        writer.write_data_block(PAYLOAD, 0, &envelope).unwrap();
    }

    let mut reader = TbzReader::new(buf.as_slice());
    let blocks = reader.read_all_blocks().unwrap();

    let mut commitment = Vec::new();
    commitment.extend_from_slice(&blocks[1].header_raw);
    commitment.extend_from_slice(&blocks[1].envelope_raw);
    commitment.extend_from_slice(&blocks[1].payload);
    commitment
}

/// A — THE COMMITMENT MUST NAME ITS PRODUCER.
///
/// RED TODAY, and this is the whole point of writing it now: the failure message states what is
/// missing, so the red is a specification rather than a defect report.
// VISIBLE, NOT FAILING. This is a public repo: a permanently red `cargo test` reads as "this
// project is broken" rather than "this binding is pending", and that is its own kind of dishonesty.
// `#[ignore = "..."]` keeps the gap ANNOUNCED on every single run -- the reason prints in the test
// list -- without claiming the crate is defective. Remove both ignores when the binding lands; that
// removal is the commit that earns the green.
#[test]
#[ignore = "RED BY DESIGN: producer identity is not yet in the signed commitment (see module docs)"]
fn a_signed_commitment_carries_the_producer_identity() {
    let commitment = String::from_utf8_lossy(&signed_commitment()).to_lowercase();

    let missing: Vec<&str> = REQUIRED_IN_COMMITMENT
        .iter()
        .copied()
        .filter(|f| !commitment.contains(f))
        .collect();

    assert!(
        missing.is_empty(),
        "the signed commitment carries none of {missing:?}.\n\
         \n\
         This is the EXPECTED red until the canonical producer root lands. It is written as a test \
         rather than a note so the gap is measured and dated, and so it turns green by being fixed \
         rather than by being remembered.\n\
         \n\
         Today the commitment is header || envelope || payload. That binds the header to the data \
         (see cve_2026_0866.rs, which proves it) and says nothing about WHO produced the archive: \
         swap the identity claimed in the manifest and the artefact is byte-identical with a \
         different name on it.\n\
         \n\
         Target: tbz-producer-archive:v1:<archive_root>, taking tibet-drop's manifest shape --\n\
         identity-bound root first, block commitments under that root second."
    );
}

/// B — FLIPPING ONE FIELD MUST BREAK VERIFICATION.
///
/// Gated on A rather than asserted on its own. Until the field exists, "flip producer_identity and
/// watch verify fail" would fail at FIELD NOT FOUND — a refusal for the wrong reason, which this
/// stack has now been bitten by often enough to guard against by construction.
#[test]
#[ignore = "GATED ON TEST A: cannot flip a field that does not exist yet"]
fn b_flipping_the_producer_identity_breaks_verification() {
    let commitment = String::from_utf8_lossy(&signed_commitment()).to_lowercase();
    let bound = REQUIRED_IN_COMMITMENT.iter().all(|f| commitment.contains(f));

    if !bound {
        // Not a silent skip. A skipped vector reads as a passing one at a glance, and that is the
        // failure mode this whole file exists to avoid.
        panic!(
            "GATED ON TEST A. The producer identity is not yet inside the signed commitment, so \
             flipping it could only fail at 'field not found' -- never at 'signature refused'. \
             Measuring that would be measuring the absence of a field and calling it security.\n\
             \n\
             When A goes green, replace this body with the real mutation:\n\
               1. build a valid archive and confirm it verifies       (positive control)\n\
               2. change ONLY producer_identity in the canonical root\n\
               3. require verification to fail\n\
               4. require the failure to NAME the identity binding, not a parse error\n\
             \n\
             And retire producer_identity_is_not_yet_bound in cve_2026_0866.rs at the same moment: \
             that test asserts the absence this one asserts the presence of, and leaving both would \
             leave the suite contradicting itself."
        );
    }

    unreachable!("A is green — implement the real mutation here (see the panic text above)");
}
