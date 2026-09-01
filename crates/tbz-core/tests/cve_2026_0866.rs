//! CVE-2026-0866 (Zombie ZIP) — the claim in the README, as an executable vector.
//!
//! The README says: *"Classic archive formats have no cryptographic binding between headers and
//! data. CVE-2026-0866 proves this: flip one byte in a ZIP header, and 50 out of 51 antivirus
//! engines see noise instead of malware."*
//!
//! That claim lived only in prose. `README.md` and `ARCHITECTURE.md` name the CVE; nothing under
//! `crates/` did. The existing tamper tests (`test_tampered_data_fails`,
//! `test_tampered_block_fails_signature`) corrupt the PAYLOAD, which proves the underlying
//! principle and is not this attack.
//!
//! ## What makes it the CVE rather than "tampering breaks signatures"
//!
//! The Zombie ZIP class is PARSER CONFUSION: declared header metadata contradicts actual payload
//! behaviour, so a scanner reading the header decodes something different from what an extractor
//! produces. The archive still opens. That is why 50 of 51 engines pass it: they are not broken,
//! they are lied to by the header, and nothing in the format binds the header to the bytes.
//!
//! So a vector that only asserts "verify fails" would be too weak. It must show BOTH halves:
//!
//!   1. the attack's premise HOLDS — the tampered archive is still structurally readable, and its
//!      payload still decompresses to the original content. A naive reader is fooled exactly as it
//!      is with ZIP.
//!   2. and TBZ REFUSES IT ANYWAY — because the header is inside the signed commitment.
//!
//! Without (1) we would be proving that a broken file is broken. Without (2) there is no claim.
//! Assert one and not the other and the vector is worthless, which is the same clause the
//! load-bearing probes in IAB carry: **known bad must fail at the consumer for the right reason.**
//!
//! ## Which fields
//!
//! TBZ has no ZIP-style "compression method" field — zstd is fixed. The equivalent surface is the
//! declared metadata a reader uses to decide HOW to consume the payload: `uncompressed_size`,
//! `compressed_size`, `block_type` and `jis_level`. Each is tampered separately, so a regression
//! names WHICH field stopped being covered rather than reporting that something, somewhere, broke.

use tibet_zip_core::block::Block;
use tibet_zip_core::envelope::TibetEnvelope;
use tibet_zip_core::manifest::Manifest;
use tibet_zip_core::signature;
use tibet_zip_core::stream::{TbzReader, TbzWriter};

const ORIGINAL: &[u8] = b"payload the scanner is supposed to see";

/// Build a one-data-block archive and read it back. Returns (blocks, verifying key).
fn built_archive() -> (Vec<Block>, tibet_zip_core::VerifyingKey) {
    let (signing_key, _) = signature::generate_keypair();
    let verifying_key = signing_key.verifying_key();

    let mut buf = Vec::new();
    {
        let mut manifest = Manifest::new();
        manifest.set_signing_key(&verifying_key);
        let mut writer = TbzWriter::new(&mut buf, signing_key);
        writer.write_manifest(&manifest).unwrap();

        let envelope = TibetEnvelope::new(
            signature::sha256_hash(ORIGINAL),
            "data",
            "application/octet-stream",
            "cve-2026-0866",
            "Zombie ZIP vector",
            vec!["block:0".to_string()],
        );
        writer.write_data_block(ORIGINAL, 0, &envelope).unwrap();
    }

    let mut reader = TbzReader::new(buf.as_slice());
    let blocks = reader.read_all_blocks().unwrap();
    (blocks, verifying_key)
}

/// Rewrite one numeric field inside the raw header JSON, leaving the archive well-formed.
///
/// Deliberately edits `header_raw` rather than the parsed struct: `verify_signature` reconstructs
/// the signing payload from the RAW bytes, so this is what an attacker actually touches on the
/// wire. Re-serialising from the struct would test a path no attacker uses.
fn tamper_header_field(block: &mut Block, field: &str, new_value: serde_json::Value) {
    let mut header: serde_json::Value = serde_json::from_slice(&block.header_raw)
        .expect("header_raw must be JSON — if this fails the format changed, not the test");
    assert!(
        header.get(field).is_some(),
        "header has no field {field:?} — the vector is aimed at a field that no longer exists, \
         which is a stale test, not a passing one"
    );
    header[field] = new_value;
    block.header_raw = serde_json::to_vec(&header).unwrap();
}

#[test]
fn positive_control_untampered_archive_verifies() {
    // Without this, every refusal below could be a resolver that refuses everything.
    let (blocks, vk) = built_archive();
    for (i, b) in blocks.iter().enumerate() {
        assert!(
            b.verify_signature(&vk).is_ok(),
            "block {i} of an untouched archive did not verify — nothing below means anything"
        );
    }
    assert_eq!(blocks[1].decompress().unwrap(), ORIGINAL);
}

#[test]
fn cve_2026_0866_header_metadata_manipulation_is_refused() {
    // The four declared fields a Zombie-ZIP-class attacker would target, each on its own so a
    // regression names the field rather than the file.
    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("uncompressed_size", serde_json::json!(1u64)),
        ("compressed_size", serde_json::json!(u64::MAX)),
        ("block_type", serde_json::json!("Nested")),
        ("jis_level", serde_json::json!(0u8)),
    ];

    for (field, value) in cases {
        let (mut blocks, vk) = built_archive();

        // sanity: it verified before we touched it
        assert!(blocks[1].verify_signature(&vk).is_ok(), "{field}: pre-tamper block did not verify");

        tamper_header_field(&mut blocks[1], field, value);

        // ── 1. THE ATTACK'S PREMISE HOLDS ────────────────────────────────────────────────────
        // The archive is still well-formed and the payload still decompresses to the original
        // bytes. This is what fools a scanner: nothing is corrupt, the header simply lies.
        let out = blocks[1]
            .decompress()
            .expect("tampered archive stopped decompressing — then this is not the Zombie ZIP \
                     class at all, and the vector is testing a different thing");
        assert_eq!(
            out, ORIGINAL,
            "{field}: payload changed. The attack requires the CONTENT to survive intact while the \
             header lies about it"
        );

        // ── 2. AND TBZ REFUSES IT ANYWAY ─────────────────────────────────────────────────────
        // Because header_raw is inside the signed commitment, a header that lies is a header that
        // was not signed. This is the README's claim, executed.
        let verdict = blocks[1].verify_signature(&vk);
        assert!(
            verdict.is_err(),
            "{field}: a tampered header still verified — the header is NOT bound to the data, and \
             TBZ has the same hole as ZIP for this field"
        );

        // ── 3. FOR THE RIGHT REASON ──────────────────────────────────────────────────────────
        // A parse error would also be an Err. The refusal must come from the signature.
        assert!(
            matches!(verdict, Err(tibet_zip_core::block::BlockError::SignatureInvalid)),
            "{field}: refused, but not as SignatureInvalid ({verdict:?}). A refusal for another \
             reason proves the parser works and says nothing about binding"
        );
    }
}

#[test]
fn the_manifest_block_is_covered_too() {
    // Block 0 carries the archive's own description and the verifying key. If only data blocks were
    // covered, an attacker could rewrite what the archive CLAIMS TO BE while every data block still
    // verified — the same confusion one level up.
    let (mut blocks, vk) = built_archive();
    assert!(blocks[0].verify_signature(&vk).is_ok());

    tamper_header_field(&mut blocks[0], "uncompressed_size", serde_json::json!(7u64));

    assert!(
        blocks[0].decompress().is_ok(),
        "the manifest stopped decompressing — not the parser-confusion class"
    );
    assert!(
        matches!(
            blocks[0].verify_signature(&vk),
            Err(tibet_zip_core::block::BlockError::SignatureInvalid)
        ),
        "the manifest header is not bound to the manifest bytes"
    );
}

/// WHAT THIS VECTOR DOES NOT PROVE — and the name of this test changed once it stopped being true.
///
/// It proves the header is bound to the data. As of the producer binding (see
/// producer_identity_binding.rs) the MANIFEST now names and signs its maker — but BLOCK
/// commitments still do not derive from that root. `sign_data = header_raw || envelope_raw ||
/// payload` carries no producer identity, so a block signed by the same key could be transplanted
/// into another valid manifest unless a reader proves the block list and root composition.
///
/// That is Codex's manifest/block transplant axis, and this test is now its precursor: it measures
/// the gap that vector will close. Renamed rather than deleted, because it was never wrong — only
/// its name stopped describing what it measures.
#[test]
fn block_commitments_do_not_yet_derive_from_the_archive_root() {
    let (blocks, vk) = built_archive();

    let mut commitment = Vec::new();
    commitment.extend_from_slice(&blocks[1].header_raw);
    commitment.extend_from_slice(&blocks[1].envelope_raw);
    commitment.extend_from_slice(&blocks[1].payload);

    let signed_over = String::from_utf8_lossy(&commitment).to_lowercase();
    for absent in ["producer_identity", "archive_root"] {
        assert!(
            !signed_over.contains(absent),
            "{absent} now appears in the BLOCK commitment. If that is deliberate, this test is the \
             stale one and the transplant vector should replace it."
        );
    }

    assert!(blocks[1].verify_signature(&vk).is_ok());
}
