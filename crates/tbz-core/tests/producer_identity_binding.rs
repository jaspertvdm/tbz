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

/// Build an archive WITH a producer binding, and hand back its manifest.
///
/// The manifest is where an archive declares what it IS -- block 0, always JIS level 0. So it is
/// also where it declares WHO MADE IT. Data blocks binding to that root is the manifest/block
/// transplant axis and has its own vector; see the module note.
fn bound_manifest() -> (Manifest, tibet_zip_core::VerifyingKey) {
    let (signing_key, _) = signature::generate_keypair();
    let verifying_key = signing_key.verifying_key();

    let mut manifest = Manifest::new();
    manifest.set_signing_key(&verifying_key);
    manifest.sign_producer("alice.aint", "key-7f3a", 4, &signing_key);
    (manifest, verifying_key)
}

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
fn a_signed_commitment_carries_the_producer_identity() {
    let (manifest, _) = bound_manifest();
    let commitment = String::from_utf8_lossy(&manifest.producer_commitment()).to_lowercase();

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
/// The vector Jasper asked for: change ONLY the producer identity and require that the artefact
/// stops verifying. A different identity must yield a different ARTEFACT, not a different label.
#[test]
fn b_flipping_the_producer_identity_breaks_verification() {
    // 1. POSITIVE CONTROL. Without this, every refusal below could be a verifier that refuses
    //    everything -- which would pass this test while proving nothing.
    let (manifest, _) = bound_manifest();
    assert_eq!(
        manifest.verify_producer(),
        Ok(()),
        "an untouched producer binding did not verify; nothing below means anything"
    );
    let root_before = manifest.archive_root();

    // 2. CHANGE ONLY THE IDENTITY. One field, nothing else -- not the key, not the epoch, not a
    //    block. If the artefact is identity-bound this alone must be enough.
    let mut tampered = manifest.clone();
    tampered.producer_identity = Some("mallory.aint".to_string());

    assert_ne!(
        tampered.archive_root(), root_before,
        "the archive root did not move when the producer identity changed. Then identity is still \
         METADATA beside the bytes rather than part of them, and the whole binding is cosmetic."
    );

    // 3. AND VERIFICATION MUST REFUSE IT.
    let verdict = tampered.verify_producer();
    assert!(
        verdict.is_err(),
        "a swapped producer identity still verified -- the archive does not bind its maker"
    );

    // 4. FOR THE RIGHT REASON. Unsigned and Incomplete are also Err, and both would mean the
    //    refusal came from a missing field rather than from a signature that no longer holds. That
    //    distinction is the whole clause: known bad must fail at the consumer for the RIGHT reason.
    assert_eq!(
        verdict, Err(tibet_zip_core::manifest::ProducerError::Invalid),
        "refused, but not as Invalid ({verdict:?}) -- a refusal for another reason proves the \
         field-checker works and says nothing about the binding"
    );
}

/// The epoch is bound too — otherwise an identity-bound archive replays across a reseed.
///
/// Codex named this as the axis BEYOND identity: binding who is necessary and not sufficient, since
/// a consumer must also know whether the key was current at the claimed causal point. Full
/// key-currentness (current/reseeded/revoked/unknown) is a consumer-side question and still open;
/// this only proves the epoch cannot be edited after the fact.
#[test]
fn the_identity_epoch_is_inside_the_commitment_too() {
    let (manifest, _) = bound_manifest();
    let mut rolled = manifest.clone();
    rolled.identity_epoch = Some(manifest.identity_epoch.unwrap() + 1);

    assert_ne!(rolled.archive_root(), manifest.archive_root(),
               "the epoch is not part of the commitment — an archive could be re-dated silently");
    assert_eq!(rolled.verify_producer(),
               Err(tibet_zip_core::manifest::ProducerError::Invalid));
}

/// An archive with NO binding is unsigned, not invalid — and the difference is a different repair.
#[test]
fn a_legacy_archive_reads_unsigned_rather_than_broken() {
    let (signing_key, _) = signature::generate_keypair();
    let mut manifest = Manifest::new();
    manifest.set_signing_key(&signing_key.verifying_key());

    assert_eq!(
        manifest.verify_producer(),
        Err(tibet_zip_core::manifest::ProducerError::Unsigned),
        "a legacy archive must read as UNSIGNED. Collapsing that into `invalid` is how 'no proof' \
         starts reading like 'failed proof', and the two are repaired completely differently."
    );
}

/// A binding that is declared and incomplete is neither of the above, and says which field is gone.
#[test]
fn a_half_declared_binding_names_what_is_missing() {
    let (mut manifest, _) = bound_manifest();
    manifest.producer_key_id = None;

    match manifest.verify_producer() {
        Err(tibet_zip_core::manifest::ProducerError::Incomplete(missing)) => {
            assert!(missing.contains(&"producer_key_id"), "missing list did not name the field: {missing:?}");
        }
        other => panic!("a half-declared binding read as {other:?} — a named binding without its \
                         fields is a label, and the reader must say WHICH field is absent"),
    }
}
