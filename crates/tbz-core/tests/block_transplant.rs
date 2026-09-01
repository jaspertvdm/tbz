//! Manifest/block transplant — the property, written before the mechanism exists.
//!
//! Codex named this as the second edge beyond producer identity, and it is the one that decides
//! whether a sealed archive means anything as a WHOLE:
//!
//!     If block signatures sit under a manifest identity, the block commitment should include or
//!     derive from the manifest/archive root. Otherwise a block signed by the same key may be
//!     transplanted into another valid manifest unless the reader proves the block list and root
//!     composition.
//!
//! ## The property, in one sentence
//!
//! A block that is valid under manifest A must not verify under manifest B, **even when both
//! manifests are signed by the same key.** Same key is not the same archive.
//!
//! ## Why this is not a detail
//!
//! It is the precondition for a sealed state to mean anything. A frozen system state — Jasper's
//! snapshot-lock — IS a manifest with blocks under it: SBOM, AI-BOM, MUX-BOM, route map, vector
//! results, receipts. If blocks can wander, someone can hang state A's SBOM under state B and every
//! signature still checks out. You would then be holding, in his words, "een nette doos met oude
//! lucht erin" — a tidy box with old air in it.
//!
//! It is also the same shape as `carrier_change` in IAB, one layer down: an edge that is perfectly
//! valid and describes a different transfer. Valid, and about something else.
//!
//! ## What this file does NOT do
//!
//! It does not choose the mechanism. Two are plausible and each costs something:
//!
//!     (a) blocks sign over `archive_root || header || envelope || payload`
//!         No circularity — archive_root derives from block CONTENT hashes, not block signatures.
//!         But it breaks STREAMING: every block must be known before any is signed.
//!
//!     (b) an `archive_id` chosen up front, bound by both the blocks and the manifest
//!         Stays streamable. Transplant fails because the id differs. The cost is that the id must
//!         itself be unforgeably tied to the manifest, or the problem simply moves one layer.
//!
//! The vector states the property so a mechanism can be MEASURED against it rather than assumed to
//! satisfy it. That division is deliberate: Codex holds the tbz family map, so the mechanism is his
//! call, and this test is what his choice has to pass.
//!
//! RED BY DESIGN, via `#[ignore]` with the reason printed on every run — a permanently failing
//! `cargo test` in a public repo reads as "this project is broken" rather than "this binding is
//! pending", which is its own kind of dishonesty. Removing the ignore is the commit that earns the
//! green.

use tibet_zip_core::block::Block;
use tibet_zip_core::envelope::TibetEnvelope;
use tibet_zip_core::manifest::Manifest;
use tibet_zip_core::signature;
use tibet_zip_core::stream::{TbzReader, TbzWriter};

/// Two archives from ONE key. The shared key is the whole point: if the key were different, any
/// verifier would already refuse, and the test would pass while proving nothing.
fn archive_with(payload: &[u8], identity: &str, sk: &ed25519_dalek::SigningKey) -> Vec<Block> {
    let mut buf = Vec::new();
    {
        let mut manifest = Manifest::new();
        manifest.set_signing_key(&sk.verifying_key());
        manifest.sign_producer(identity, "key-7f3a", 4, sk);
        let mut writer = TbzWriter::new(&mut buf, sk.clone());
        writer.write_manifest(&manifest).unwrap();
        let envelope = TibetEnvelope::new(
            signature::sha256_hash(payload),
            "data",
            "application/octet-stream",
            "transplant-vector",
            "block that should not travel",
            vec!["block:0".to_string()],
        );
        writer.write_data_block(payload, 0, &envelope).unwrap();
    }
    TbzReader::new(buf.as_slice()).read_all_blocks().unwrap()
}

#[test]
#[ignore = "RED BY DESIGN: block commitments do not yet derive from the archive root (see module docs)"]
fn a_block_from_one_archive_must_not_verify_under_another() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let vk = sk.verifying_key();

    let archive_a = archive_with(b"contents of archive A", "alice.aint", &sk);
    let archive_b = archive_with(b"contents of archive B", "alice.aint", &sk);

    // POSITIVE CONTROL FIRST. Each block must verify in its own archive, or the refusal below could
    // just be a verifier that refuses everything.
    assert!(archive_a[1].verify_signature(&vk).is_ok(), "block A did not verify in archive A");
    assert!(archive_b[1].verify_signature(&vk).is_ok(), "block B did not verify in archive B");

    // THE TRANSPLANT. Archive A's data block, lifted whole, presented as archive B's. Nothing about
    // the block is altered — that is what makes this different from tampering: the bytes are
    // genuine, they are simply somewhere they were never authorised to be.
    let transplanted = archive_a[1].clone();

    // Today this passes, because sign_data = header_raw || envelope_raw || payload carries nothing
    // that names the archive it belongs to.
    assert!(
        transplanted.verify_signature(&vk).is_err(),
        "a block from archive A verified while presented as part of archive B.\n\
         \n\
         The signature is genuine and the block is unaltered -- so this is not tampering, it is a \
         block that is valid and belongs somewhere else. Nothing in the commitment names its \
         archive, so the reader cannot tell.\n\
         \n\
         SAME KEY IS NOT THE SAME ARCHIVE. Until the block commitment derives from the archive \
         root (or from an unforgeable archive id), a sealed state's SBOM can be swapped for another \
         validly signed one and every check still passes."
    );
}

/// The manifests genuinely differ, so the transplant above is a real relocation rather than two
/// copies of one thing. Asserted rather than assumed — the vector would be meaningless if the two
/// archives happened to share a root.
#[test]
fn the_two_archives_have_different_roots() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    let mut a = Manifest::new();
    a.set_signing_key(&sk.verifying_key());
    a.sign_producer("alice.aint", "key-7f3a", 4, &sk);

    let mut b = Manifest::new();
    b.set_signing_key(&sk.verifying_key());
    b.sign_producer("alice.aint", "key-7f3a", 5, &sk); // different epoch

    assert_ne!(
        a.archive_root(), b.archive_root(),
        "two archives that differ produced the same root — then the root does not identify an \
         archive and the transplant vector has nothing to bind against"
    );
}

/// And the one that is already true, kept as the floor: the PRODUCER binding does hold. This is
/// what landed in 5c75f26, and it is what makes the gap above legible — identity is bound at the
/// manifest, and not yet carried down to the blocks.
#[test]
fn the_producer_binding_itself_still_holds() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let mut m = Manifest::new();
    m.set_signing_key(&sk.verifying_key());
    m.sign_producer("alice.aint", "key-7f3a", 4, &sk);

    assert_eq!(m.verify_producer(), Ok(()));

    let mut swapped = m.clone();
    swapped.producer_identity = Some("mallory.aint".into());
    assert!(swapped.verify_producer().is_err(), "the producer binding regressed");
}
