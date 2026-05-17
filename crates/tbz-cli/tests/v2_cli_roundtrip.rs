//! Integration test: full v2 CLI roundtrip
//!
//! keygen → pack --seal → unpack --as → sha256 verify
//! Plus wrong-receiver rejection + missing-arg rejection.

use std::process::Command;

fn bin() -> String {
    env!("CARGO_BIN_EXE_tibet-zip").to_string()
}

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin()).args(args).output().expect("run cli");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn sha256_hex(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path).expect("read");
    let mut h = Sha256::new();
    h.update(&data);
    format!("{:x}", h.finalize())
}

fn unique_tmp(label: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("tbz-v2-it-{}-{}-{}", label, pid, nanos))
}

#[test]
fn v2_full_roundtrip_with_correct_receiver() {
    let workdir = unique_tmp("roundtrip");
    std::fs::create_dir_all(&workdir).expect("mkdir");
    let fixture = workdir.join("fixture");
    std::fs::create_dir_all(&fixture).expect("mkdir fixture");

    // Two test files
    std::fs::write(fixture.join("hello.txt"), b"hello v2 sealed CLI").unwrap();
    std::fs::write(fixture.join("secret.md"), b"# secret\nbody content").unwrap();
    let orig_hello = sha256_hex(&fixture.join("hello.txt"));
    let orig_secret = sha256_hex(&fixture.join("secret.md"));

    // 1. Keygen for receiver (Bob)
    let bob_key = workdir.join("bob");
    let (ok, _, err) = run(&[
        "keygen",
        "-o",
        bob_key.to_str().unwrap(),
    ]);
    assert!(ok, "keygen failed: {}", err);
    let bob_pub = std::fs::read_to_string(workdir.join("bob.pub")).unwrap();
    let bob_pub = bob_pub.trim();
    assert_eq!(bob_pub.len(), 64, "pubkey should be 64 hex chars");

    // 2. Keygen for sender (Alice)
    let alice_key = workdir.join("alice");
    let (ok, _, _) = run(&["keygen", "-o", alice_key.to_str().unwrap()]);
    assert!(ok);

    // 3. Pack --seal --to bob_pub --from alice.priv
    let sealed = workdir.join("sealed.tza");
    let alice_priv = workdir.join("alice.priv");
    let (ok, _, err) = run(&[
        "pack",
        fixture.to_str().unwrap(),
        "-o",
        sealed.to_str().unwrap(),
        "--seal",
        "--to",
        bob_pub,
        "--from",
        alice_priv.to_str().unwrap(),
    ]);
    assert!(ok, "pack --seal failed: {}", err);
    assert!(sealed.exists());

    // 4. Verify the archive is detected as v2 (= bytes 3-4 must be 0x02, 0x00)
    let sealed_bytes = std::fs::read(&sealed).unwrap();
    assert_eq!(&sealed_bytes[0..3], b"TBZ");
    assert_eq!(sealed_bytes[3], 0x02, "byte 3 should be v2 major");
    assert_eq!(sealed_bytes[4], 0x00, "byte 4 should be v2 minor");

    // 5. Unpack --as bob.priv (correct receiver)
    let out_dir = workdir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let bob_priv = workdir.join("bob.priv");
    let (ok, _, err) = run(&[
        "unpack",
        sealed.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--as",
        bob_priv.to_str().unwrap(),
    ]);
    assert!(ok, "unpack failed: {}", err);

    // 6. Verify sha256 roundtrip
    assert!(out_dir.join("hello.txt").exists());
    assert!(out_dir.join("secret.md").exists());
    assert_eq!(sha256_hex(&out_dir.join("hello.txt")), orig_hello);
    assert_eq!(sha256_hex(&out_dir.join("secret.md")), orig_secret);

    // Cleanup
    std::fs::remove_dir_all(&workdir).ok();
}

#[test]
fn v2_wrong_receiver_is_rejected() {
    let workdir = unique_tmp("wrongreceiver");
    std::fs::create_dir_all(&workdir).unwrap();
    let fixture = workdir.join("fixture");
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::write(fixture.join("data.txt"), b"top secret bytes").unwrap();

    let bob_key = workdir.join("bob");
    let _ = run(&["keygen", "-o", bob_key.to_str().unwrap()]);
    let eve_key = workdir.join("eve");
    let _ = run(&["keygen", "-o", eve_key.to_str().unwrap()]);

    let bob_pub = std::fs::read_to_string(workdir.join("bob.pub")).unwrap();
    let bob_pub = bob_pub.trim();

    let sealed = workdir.join("sealed.tza");
    let (ok, _, _) = run(&[
        "pack",
        fixture.to_str().unwrap(),
        "-o",
        sealed.to_str().unwrap(),
        "--seal",
        "--to",
        bob_pub,
    ]);
    assert!(ok);

    // Eve tries with HER private key — should fail
    let out_dir = workdir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let eve_priv = workdir.join("eve.priv");
    let (ok, _, err) = run(&[
        "unpack",
        sealed.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--as",
        eve_priv.to_str().unwrap(),
    ]);
    assert!(!ok, "Eve should NOT be able to unseal Bob's archive");
    assert!(
        err.contains("AEAD")
            || err.contains("wrong receiver")
            || err.contains("DecryptFailed")
            || err.contains("unseal failed"),
        "expected decryption error, got: {}",
        err
    );

    std::fs::remove_dir_all(&workdir).ok();
}

#[test]
fn v2_missing_as_key_is_rejected() {
    let workdir = unique_tmp("missingas");
    std::fs::create_dir_all(&workdir).unwrap();
    let fixture = workdir.join("fixture");
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::write(fixture.join("a.txt"), b"x").unwrap();

    let bob_key = workdir.join("bob");
    let _ = run(&["keygen", "-o", bob_key.to_str().unwrap()]);
    let bob_pub = std::fs::read_to_string(workdir.join("bob.pub")).unwrap();
    let bob_pub = bob_pub.trim();

    let sealed = workdir.join("sealed.tza");
    let (ok, _, _) = run(&[
        "pack",
        fixture.to_str().unwrap(),
        "-o",
        sealed.to_str().unwrap(),
        "--seal",
        "--to",
        bob_pub,
    ]);
    assert!(ok);

    // Unpack without --as — should fail with helpful error
    let out_dir = workdir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let (ok, _, err) = run(&[
        "unpack",
        sealed.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
    ]);
    assert!(!ok, "should require --as");
    assert!(
        err.contains("--as") || err.contains("privkey"),
        "expected helpful error, got: {}",
        err
    );

    std::fs::remove_dir_all(&workdir).ok();
}

#[test]
fn v2_seal_requires_to_flag() {
    let workdir = unique_tmp("missingto");
    std::fs::create_dir_all(&workdir).unwrap();
    let fixture = workdir.join("fixture");
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::write(fixture.join("a.txt"), b"x").unwrap();

    let sealed = workdir.join("sealed.tza");
    let (ok, _, err) = run(&[
        "pack",
        fixture.to_str().unwrap(),
        "-o",
        sealed.to_str().unwrap(),
        "--seal",
        // --to omitted
    ]);
    assert!(!ok, "--seal without --to should fail");
    assert!(err.contains("--to") || err.contains("pubkey"));

    std::fs::remove_dir_all(&workdir).ok();
}

#[test]
fn v1_unaffected_by_v2_dispatch() {
    let workdir = unique_tmp("v1unchanged");
    std::fs::create_dir_all(&workdir).unwrap();
    let fixture = workdir.join("fixture");
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::write(fixture.join("test.txt"), b"v1 plain transparent").unwrap();
    let orig = sha256_hex(&fixture.join("test.txt"));

    // Plain v1 pack (no --seal)
    let archive = workdir.join("v1.tza");
    let (ok, _, err) = run(&[
        "pack",
        fixture.to_str().unwrap(),
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert!(ok, "v1 pack failed: {}", err);

    // V1 archive: byte 3 should be 0x00 (manifest length high byte), NOT 0x02
    let bytes = std::fs::read(&archive).unwrap();
    assert_eq!(&bytes[0..3], b"TBZ");
    assert_ne!(bytes[3], 0x02, "v1 byte 3 must not be 0x02");

    // Unpack without --as (= v1 path)
    let out_dir = workdir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let (ok, _, err) = run(&[
        "unpack",
        archive.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
    ]);
    assert!(ok, "v1 unpack should not require --as: {}", err);
    assert_eq!(sha256_hex(&out_dir.join("test.txt")), orig);

    std::fs::remove_dir_all(&workdir).ok();
}
