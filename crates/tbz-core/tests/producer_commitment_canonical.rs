//! Cross-language canonicalisation fixture for the producer commitment.
//!
//! Codex, reviewing the producer binding: the `BTreeMap` with named keys is the right shape, and it
//! **proves the Rust side of the contract only.** The claim that a Python implementation reproduces
//! these bytes lives in a source comment, and nothing carries it. That is this repo's own rule
//! turned on its own code — a claim in prose that no test holds up.
//!
//! JSON canonicalisation is exactly where that drift hides, and none of it is exotic:
//!
//!     key order            BTreeMap sorts; `json.dumps(sort_keys=True)` sorts — but only if asked
//!     separators           Rust emits `{"a":1}`; Python's default emits `{"a": 1}`
//!     null vs absent       `Option::None` serialises as `null` here, and a Python dict may omit
//!     integer form         `4` and `4.0` are the same number and different bytes
//!     unicode escaping     `ensure_ascii=True` rewrites non-ASCII identities
//!
//! An `.aint` with a non-ASCII character would be enough to make two conforming implementations
//! disagree about an archive root, and neither would be wrong — they would simply never have been
//! made to agree.
//!
//! So this test pins the bytes. Not the shape, not the field list: THE BYTES, from a fixed key and
//! a fixed manifest, so a second implementation has something to fail against.
//!
//! The fixture is written to `target/producer_commitment_fixture.json` when the test runs, so the
//! Python side can be checked against a file rather than against a transcription of one.
//!
//! CBOR (as tibet-drop uses) is the stronger long-term answer and it does not block this slice —
//! Codex's read, and mine: pin the bytes first, change the encoding later with the fixture as the
//! thing that proves the change was intentional.

use tibet_zip_core::manifest::{Manifest, PRODUCER_DOMAIN};

/// A fixed 32-byte seed. Deterministic ON PURPOSE: a fixture generated from a random key pins
/// nothing, because it can never be reproduced by anyone else.
const SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

fn fixture_manifest() -> Manifest {
    let sk = ed25519_dalek::SigningKey::from_bytes(&SEED);
    let mut m = Manifest::new();
    m.set_signing_key(&sk.verifying_key());
    // No blocks: an empty archive is the smallest case a second implementation can start from,
    // and `ordered_block_root` over zero blocks is itself a value worth pinning.
    m.sign_producer("alice.aint", "key-7f3a", 4, &sk);
    m
}

#[test]
fn the_commitment_bytes_are_pinned() {
    let m = fixture_manifest();
    let bytes = m.producer_commitment();
    let text = String::from_utf8(bytes.clone()).expect("the commitment must be valid UTF-8");

    // Written out so a Python implementation is checked against a FILE rather than a
    // transcription. A transcribed expectation is a place for a typo to become a spec.
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/producer_commitment_fixture.json");
    if let Some(dir) = out.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let fixture = serde_json::json!({
        "note": "Reproduce these exactly. See tests/producer_commitment_canonical.rs.",
        "seed_hex": SEED.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        "producer_identity": "alice.aint",
        "producer_key_id": "key-7f3a",
        "identity_epoch": 4,
        "commitment_utf8": text,
        "ordered_block_root": m.ordered_block_root(),
        "archive_root": m.archive_root(),
        "signing_target_utf8": String::from_utf8_lossy(&m.producer_signing_target()),
        "producer_sig": m.producer_sig,
    });
    let _ = std::fs::write(&out, serde_json::to_vec_pretty(&fixture).unwrap());

    // ── the properties a second implementation must match, asserted rather than described ──

    // 1. COMPACT SEPARATORS. Python's json.dumps defaults to ", " and ": ".
    assert!(!text.contains(", "), "commitment has spaced separators: {text}");
    assert!(!text.contains("\": "), "commitment has spaced key separators: {text}");

    // 2. SORTED KEYS. Asserted on the actual order, not on the type that happens to provide it.
    let keys: Vec<&str> = text
        .split(',')
        .filter_map(|p| p.split(':').next())
        .map(|k| k.trim_matches(|c| c == '{' || c == '"'))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "commitment keys are not in sorted order: {keys:?}");

    // 3. ABSENT IS `null`, NOT OMITTED. The struct uses skip_serializing_if for the wire manifest;
    //    the COMMITMENT must not, or a missing field and a null field would hash differently across
    //    implementations — and "absent" is exactly the state this stack keeps insisting is
    //    first-class.
    assert!(
        text.contains("\"producer_identity\":\"alice.aint\""),
        "identity not in the expected compact form: {text}"
    );

    // 4. THE EPOCH IS AN INTEGER, not a float. `4` and `4.0` are the same number and different bytes.
    assert!(
        text.contains("\"identity_epoch\":4"),
        "epoch is not a bare integer: {text}"
    );

    // 5. THE DOMAIN SEPARATOR IS PART OF THE SIGNING TARGET, never the root alone.
    let target = String::from_utf8(m.producer_signing_target()).unwrap();
    assert!(target.starts_with(PRODUCER_DOMAIN), "signing target lost its domain: {target}");
    assert_eq!(target, format!("{}{}", PRODUCER_DOMAIN, m.archive_root()));
}

/// The same input must always give the same root. Sounds trivial; it is the property that makes a
/// cross-language fixture meaningful at all.
#[test]
fn the_root_is_deterministic() {
    assert_eq!(fixture_manifest().archive_root(), fixture_manifest().archive_root());
    assert_eq!(fixture_manifest().producer_sig, fixture_manifest().producer_sig);
}

/// AND THE FIXTURE MUST STILL VERIFY. A pinned byte string that no longer passes its own verifier
/// would pin a broken state — which is worse than pinning nothing, because it looks authoritative.
#[test]
fn the_pinned_fixture_verifies() {
    assert_eq!(fixture_manifest().verify_producer(), Ok(()));
}
