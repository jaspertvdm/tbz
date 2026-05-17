//! TBZ v2 wire-format — confidential block encryption + SSM routing header.
//!
//! Implements the spec from `python/tbz/SPEC-V2.md`:
//!
//! ```text
//! +-------+-------+--------+----------+--------+--------+
//! | MAGIC | SSM   | v2 hdr | manifest | blocks |  ...   |
//! | "TBZ" | 1 B   | 4 B    | Ed25519  | optional        |
//! +-------+-------+--------+----------+--------+--------+
//!         (opt)
//!         cap-flag
//!         bit 0
//! ```
//!
//! Three-layer hash truth:
//! - SHA256 says the file moved
//! - Ed25519 says the sender sealed it (= v1 + v2)
//! - AES-256-GCM says only the receiver can read it (= v2 add-on)
//!
//! Byte-for-byte compatible with the Python reference implementation
//! at `tbz/v2.py` and validated against
//! `tibet-conformance-vectors v0.2.0`.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key as AesKey, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// TBZ v2 major version byte (= 0x02).
pub const V2_VERSION_MAJOR: u8 = 0x02;

/// TBZ v2 minor version byte (= 0x00 for initial v2).
pub const V2_VERSION_MINOR: u8 = 0x00;

/// Length of the v2 header in bytes (= 4).
pub const V2_HEADER_LEN: usize = 4;

// Capability flags (byte 2 of v2 header).
pub const FLAG_HAS_SSM_HEADER: u8 = 0x01;
pub const FLAG_HAS_ENCRYPTED_BLOCKS: u8 = 0x02;
pub const FLAG_HAS_RECEIVER_IDENTITY: u8 = 0x04;
pub const FLAG_HAS_BLOCK_COMPRESSION: u8 = 0x08;

/// Declared payload class (byte 3 of v2 header, was reserved in v2.1).
///
/// First-class semantic typing of what kind of payload an envelope carries,
/// so unpack tooling can warn on extension/class mismatches and so the
/// iddrop protocol layer can refuse to materialise the wrong kind of claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadClass {
    /// Unspecified / legacy v2.1 archives (byte was always 0).
    Unspecified = 0,
    /// Identity claim — birth bundle, AINS credential, JIS-DID assertion.
    Identity = 1,
    /// Executable code — script, binary, agent capsule.
    Code = 2,
    /// Human-readable document — text, markdown, PDF.
    Document = 3,
    /// Command / request — orchestration intent for the receiver.
    Command = 4,
    /// Receipt / acknowledgement — proof of prior action.
    Receipt = 5,
}

impl PayloadClass {
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => PayloadClass::Identity,
            2 => PayloadClass::Code,
            3 => PayloadClass::Document,
            4 => PayloadClass::Command,
            5 => PayloadClass::Receipt,
            _ => PayloadClass::Unspecified,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn label(self) -> &'static str {
        match self {
            PayloadClass::Unspecified => "unspecified",
            PayloadClass::Identity => "identity",
            PayloadClass::Code => "code",
            PayloadClass::Document => "document",
            PayloadClass::Command => "command",
            PayloadClass::Receipt => "receipt",
        }
    }

    /// Parse a CLI-friendly name.
    pub fn from_label(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "unspecified" | "unspec" | "none" => Some(PayloadClass::Unspecified),
            "identity" | "id" => Some(PayloadClass::Identity),
            "code" | "exec" | "binary" => Some(PayloadClass::Code),
            "document" | "doc" => Some(PayloadClass::Document),
            "command" | "cmd" | "request" => Some(PayloadClass::Command),
            "receipt" | "ack" => Some(PayloadClass::Receipt),
            _ => None,
        }
    }
}

/// Errors specific to the v2 wire format.
#[derive(Error, Debug)]
pub enum Tbzv2Error {
    #[error("Ed25519 pubkey must be 32 bytes")]
    InvalidKeyLength,
    #[error("too short for v2 header")]
    TooShort,
    #[error("does not match v2 header layout")]
    VersionMismatch,
    #[error("flag claims SSM header but layout-A has no SSM byte slot")]
    SsmFlagMismatchA,
    #[error("SSM byte present but FLAG_HAS_SSM_HEADER not set")]
    SsmFlagMismatchB,
    #[error("envelope does not have FLAG_HAS_ENCRYPTED_BLOCKS")]
    EncryptionDisabled,
    #[error("AEAD authentication failed — wrong identity or tampered ciphertext")]
    AeadAuthFailed,
}

/// Result type for v2 operations.
pub type Result<T> = std::result::Result<T, Tbzv2Error>;

/// Encode the v2 wire-format prefix that follows MAGIC.
///
/// Returns: `[SSM (1B, optional)] [v2_hdr (4B)]`.
/// If `ssm_byte` is `Some`, `FLAG_HAS_SSM_HEADER` is auto-set.
///
/// Byte 3 of the v2 header carries the declared `PayloadClass`. In v2.1
/// archives this byte was always 0 (`Unspecified`), which the v2.2 decoder
/// reads back identically, so existing v2.1 envelopes remain readable.
pub fn encode_v2_header(flags: u8, ssm_byte: Option<u8>) -> Vec<u8> {
    encode_v2_header_with_class(flags, ssm_byte, PayloadClass::Unspecified)
}

/// Encode v2 header with an explicit payload class declaration.
pub fn encode_v2_header_with_class(
    flags: u8,
    ssm_byte: Option<u8>,
    payload_class: PayloadClass,
) -> Vec<u8> {
    let final_flags = if ssm_byte.is_some() {
        flags | FLAG_HAS_SSM_HEADER
    } else {
        flags
    };
    let mut out: Vec<u8> = Vec::with_capacity(if ssm_byte.is_some() { 5 } else { 4 });
    if let Some(b) = ssm_byte {
        out.push(b);
    }
    out.extend_from_slice(&[
        V2_VERSION_MAJOR,
        V2_VERSION_MINOR,
        final_flags,
        payload_class.as_byte(),
    ]);
    out
}

/// Decode the v2 wire-format prefix immediately following MAGIC.
///
/// Returns `(version_major, flags, ssm_byte_or_None)`.
///
/// Kept for backward compatibility; use [`decode_v2_header_full`] to also
/// retrieve the declared `PayloadClass`.
pub fn decode_v2_header(data: &[u8]) -> Result<(u8, u8, Option<u8>)> {
    let (v, f, s, _c) = decode_v2_header_full(data)?;
    Ok((v, f, s))
}

/// Decode v2 header including the declared payload class.
pub fn decode_v2_header_full(data: &[u8]) -> Result<(u8, u8, Option<u8>, PayloadClass)> {
    if data.len() < V2_HEADER_LEN {
        return Err(Tbzv2Error::TooShort);
    }

    // Layout A: [v2_hdr(4)] — ssm absent.
    if data[0] == V2_VERSION_MAJOR && data[1] == V2_VERSION_MINOR {
        let flags = data[2];
        if flags & FLAG_HAS_SSM_HEADER != 0 {
            return Err(Tbzv2Error::SsmFlagMismatchA);
        }
        let class = PayloadClass::from_byte(data[3]);
        return Ok((V2_VERSION_MAJOR, flags, None, class));
    }

    // Layout B: [ssm(1)][v2_hdr(4)].
    if data.len() >= 1 + V2_HEADER_LEN
        && data[1] == V2_VERSION_MAJOR
        && data[2] == V2_VERSION_MINOR
    {
        let ssm = data[0];
        let flags = data[3];
        if flags & FLAG_HAS_SSM_HEADER == 0 {
            return Err(Tbzv2Error::SsmFlagMismatchB);
        }
        let class = PayloadClass::from_byte(data[4]);
        return Ok((V2_VERSION_MAJOR, flags, Some(ssm), class));
    }

    Err(Tbzv2Error::VersionMismatch)
}

/// Detect TBZ version from the first bytes.
///
/// Returns:
/// - `0` — not a TBZ file (magic mismatch)
/// - `1` — TBZ v1 (transparent, signed only)
/// - `2` — TBZ v2 (with v2 header)
pub fn detect_version(data: &[u8]) -> u8 {
    if data.len() < 4 || data[0..3] != crate::MAGIC {
        return 0;
    }
    let after_magic = &data[3..];
    if decode_v2_header(after_magic).is_ok() {
        2
    } else {
        1
    }
}

/// Derive a 32-byte AES-256 key for a specific receiver in this archive
/// (HKDF-SHA256, RFC 5869).
pub fn derive_aes_key(
    receiver_pubkey: &[u8],
    sender_pubkey: &[u8],
    archive_uuid: &[u8],
) -> Result<[u8; 32]> {
    if receiver_pubkey.len() != 32 || sender_pubkey.len() != 32 {
        return Err(Tbzv2Error::InvalidKeyLength);
    }

    // salt = sender_pubkey || archive_uuid
    let mut salt = Vec::with_capacity(sender_pubkey.len() + archive_uuid.len());
    salt.extend_from_slice(sender_pubkey);
    salt.extend_from_slice(archive_uuid);

    let hk = Hkdf::<Sha256>::new(Some(&salt), receiver_pubkey);
    let mut okm = [0u8; 32];
    hk.expand(b"tbz.v2.aes256gcm.aead", &mut okm)
        .expect("HKDF expand cannot fail for 32-byte output");
    Ok(okm)
}

/// Derive a 12-byte AEAD nonce for the given block index in this archive.
///
/// Deterministic per-block so the same vault snapshot has stable nonces.
pub fn block_nonce(archive_uuid: &[u8], block_index: u32) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(archive_uuid);
    h.update(block_index.to_be_bytes());
    let result = h.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&result[..12]);
    nonce
}

/// A v2 sealed envelope ready to encode or decode blocks.
///
/// Default flags = `FLAG_HAS_ENCRYPTED_BLOCKS | FLAG_HAS_RECEIVER_IDENTITY
/// | FLAG_HAS_BLOCK_COMPRESSION`.
pub struct SealedEnvelope {
    pub sender_pubkey: [u8; 32],
    pub receiver_pubkey: [u8; 32],
    pub archive_uuid: [u8; 16],
    pub ssm_byte: Option<u8>,
    pub flags: u8,
}

impl SealedEnvelope {
    /// Build a sealed envelope with a random archive_uuid and default flags.
    pub fn new(sender_pubkey: [u8; 32], receiver_pubkey: [u8; 32]) -> Self {
        let flags =
            FLAG_HAS_ENCRYPTED_BLOCKS | FLAG_HAS_RECEIVER_IDENTITY | FLAG_HAS_BLOCK_COMPRESSION;
        let mut archive_uuid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut archive_uuid);
        Self {
            sender_pubkey,
            receiver_pubkey,
            archive_uuid,
            ssm_byte: None,
            flags,
        }
    }

    /// Override the archive UUID (= deterministic envelopes for tests).
    pub fn with_archive_uuid(mut self, uuid: [u8; 16]) -> Self {
        self.archive_uuid = uuid;
        self
    }

    /// Attach an SSM magic-bytes routing header byte.
    pub fn with_ssm_byte(mut self, ssm: u8) -> Self {
        self.ssm_byte = Some(ssm);
        self.flags |= FLAG_HAS_SSM_HEADER;
        self
    }

    fn aes_key(&self) -> Result<[u8; 32]> {
        derive_aes_key(&self.receiver_pubkey, &self.sender_pubkey, &self.archive_uuid)
    }

    /// Return the wire-format prefix that follows MAGIC.
    pub fn encode_header(&self) -> Vec<u8> {
        encode_v2_header(self.flags, self.ssm_byte)
    }

    /// Encrypt one block with AES-256-GCM bound to this envelope.
    pub fn encrypt_block(&self, plain: &[u8], block_index: u32) -> Result<Vec<u8>> {
        if self.flags & FLAG_HAS_ENCRYPTED_BLOCKS == 0 {
            return Err(Tbzv2Error::EncryptionDisabled);
        }
        let key = self.aes_key()?;
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key));
        let nonce_bytes = block_nonce(&self.archive_uuid, block_index);
        let nonce = Nonce::from_slice(&nonce_bytes);
        cipher
            .encrypt(nonce, plain)
            .map_err(|_| Tbzv2Error::AeadAuthFailed)
    }

    /// Decrypt one block. Returns `Tbzv2Error::AeadAuthFailed` on wrong identity.
    pub fn decrypt_block(&self, cipher_bytes: &[u8], block_index: u32) -> Result<Vec<u8>> {
        let key = self.aes_key()?;
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key));
        let nonce_bytes = block_nonce(&self.archive_uuid, block_index);
        let nonce = Nonce::from_slice(&nonce_bytes);
        cipher
            .decrypt(nonce, cipher_bytes)
            .map_err(|_| Tbzv2Error::AeadAuthFailed)
    }
}

// =============================================================================
// V2 SEALED CONTAINER (single-block wrap-of-payload)
// =============================================================================
//
// On-disk layout (= "envelope-around-payload" simplest possible v2 archive):
//
//   [MAGIC "TBZ"            3 bytes]
//   [V2_HEADER              4 bytes]   major(0x02) minor(0x00) flags reserved(0)
//   [sender_pubkey         32 bytes]
//   [receiver_pubkey       32 bytes]
//   [archive_uuid          16 bytes]
//   [ciphertext_len  u32 BE 4 bytes]
//   [ciphertext       N bytes      ]   AES-256-GCM(payload, block_index=0)
//   [sender_signature      64 bytes]   Ed25519 over ciphertext
//
// Fixed overhead = 155 bytes. Payload = arbitrary bytes (typically a v1
// archive, allowing v2 to wrap-and-seal an existing v1 archive end-to-end).
//
// Future v2.x can extend with multi-block, but this single-block form is
// sufficient for "seal a folder to a recipient" semantics in v2.1.0.

/// Length of the v2 sealed container header BEFORE ciphertext (without sig).
/// = MAGIC(3) + V2_HDR(4) + sender_pk(32) + receiver_pk(32) + uuid(16) + cipher_len(4)
pub const V2_CONTAINER_PREFIX_LEN: usize = 3 + 4 + 32 + 32 + 16 + 4;

/// Length of the Ed25519 signature trailer.
pub const V2_CONTAINER_SIG_LEN: usize = 64;

/// Errors for v2 container parsing.
#[derive(Error, Debug)]
pub enum V2ContainerError {
    #[error("too short to be a v2 container")]
    TooShort,
    #[error("magic bytes mismatch (not a TBZ archive)")]
    BadMagic,
    #[error("not a v2 archive (header missing v2 marker)")]
    NotV2,
    #[error("inconsistent length: declared ciphertext does not fit")]
    LengthMismatch,
    #[error("Ed25519 sender signature does not verify")]
    BadSignature,
    #[error("AEAD decryption failed (wrong receiver or tampered)")]
    DecryptFailed,
    #[error("envelope error: {0}")]
    Envelope(#[from] Tbzv2Error),
}

/// Build a v2 sealed container around `payload`.
///
/// `payload` is typically a v1 archive's bytes; the v2 layer adds AES-256-GCM
/// confidentiality for the named receiver and an Ed25519 signature from the
/// sender over the ciphertext.
///
/// Uses `PayloadClass::Unspecified`; for v2.2 callers that want to declare
/// a payload class, use [`write_sealed_container_with_class`].
pub fn write_sealed_container(
    sender_signing_key: &ed25519_dalek::SigningKey,
    receiver_pubkey: &[u8; 32],
    payload: &[u8],
) -> std::result::Result<Vec<u8>, V2ContainerError> {
    write_sealed_container_with_class(
        sender_signing_key,
        receiver_pubkey,
        payload,
        PayloadClass::Unspecified,
    )
}

/// Build a v2 sealed container with an explicit declared payload class.
///
/// The declared class is carried in byte 3 of the V2 header. Unpack tooling
/// can warn on extension/class mismatches and the iddrop layer can refuse
/// to materialise the wrong kind of claim.
pub fn write_sealed_container_with_class(
    sender_signing_key: &ed25519_dalek::SigningKey,
    receiver_pubkey: &[u8; 32],
    payload: &[u8],
    payload_class: PayloadClass,
) -> std::result::Result<Vec<u8>, V2ContainerError> {
    use ed25519_dalek::Signer;

    let sender_pubkey: [u8; 32] = sender_signing_key.verifying_key().to_bytes();

    // Generate archive UUID
    let mut archive_uuid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut archive_uuid);

    // Build envelope and encrypt payload as block 0
    let envelope = SealedEnvelope {
        sender_pubkey,
        receiver_pubkey: *receiver_pubkey,
        archive_uuid,
        ssm_byte: None,
        flags: FLAG_HAS_ENCRYPTED_BLOCKS | FLAG_HAS_RECEIVER_IDENTITY,
    };

    let ciphertext = envelope.encrypt_block(payload, 0)?;
    let cipher_len_u32: u32 = ciphertext
        .len()
        .try_into()
        .map_err(|_| V2ContainerError::LengthMismatch)?;

    // Sign the ciphertext for sender authentication
    let signature = sender_signing_key.sign(&ciphertext);
    let sig_bytes: [u8; 64] = signature.to_bytes();

    // Assemble: MAGIC + V2_HDR (with payload_class) + sender_pk + receiver_pk
    //         + uuid + len + cipher + sig
    let mut out: Vec<u8> = Vec::with_capacity(
        V2_CONTAINER_PREFIX_LEN + ciphertext.len() + V2_CONTAINER_SIG_LEN,
    );
    out.extend_from_slice(&crate::MAGIC);
    out.extend_from_slice(&encode_v2_header_with_class(envelope.flags, None, payload_class));
    out.extend_from_slice(&sender_pubkey);
    out.extend_from_slice(receiver_pubkey);
    out.extend_from_slice(&archive_uuid);
    out.extend_from_slice(&cipher_len_u32.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&sig_bytes);
    Ok(out)
}

/// Parse and decrypt a v2 sealed container. Returns the inner payload.
///
/// Verifies the sender signature first; on failure returns `BadSignature`
/// without attempting decryption.
///
/// Use [`read_sealed_container_full`] to also retrieve the declared
/// `PayloadClass`.
pub fn read_sealed_container(
    container: &[u8],
    receiver_signing_key: &ed25519_dalek::SigningKey,
) -> std::result::Result<(SealedEnvelope, Vec<u8>), V2ContainerError> {
    let (env, plain, _class) = read_sealed_container_full(container, receiver_signing_key)?;
    Ok((env, plain))
}

/// Parse and decrypt a v2 sealed container, returning the declared
/// payload class as well as the inner payload.
pub fn read_sealed_container_full(
    container: &[u8],
    receiver_signing_key: &ed25519_dalek::SigningKey,
) -> std::result::Result<(SealedEnvelope, Vec<u8>, PayloadClass), V2ContainerError> {
    use ed25519_dalek::{Verifier, VerifyingKey};

    if container.len() < V2_CONTAINER_PREFIX_LEN + V2_CONTAINER_SIG_LEN {
        return Err(V2ContainerError::TooShort);
    }
    if container[0..3] != crate::MAGIC {
        return Err(V2ContainerError::BadMagic);
    }

    // V2 header (including declared payload class in byte 3)
    let v2_hdr = &container[3..3 + V2_HEADER_LEN];
    let (version, flags, _ssm, payload_class) =
        decode_v2_header_full(v2_hdr).map_err(V2ContainerError::Envelope)?;
    if version != V2_VERSION_MAJOR {
        return Err(V2ContainerError::NotV2);
    }

    let mut off = 3 + V2_HEADER_LEN;
    let sender_pubkey: [u8; 32] = container[off..off + 32]
        .try_into()
        .map_err(|_| V2ContainerError::TooShort)?;
    off += 32;
    let receiver_pubkey: [u8; 32] = container[off..off + 32]
        .try_into()
        .map_err(|_| V2ContainerError::TooShort)?;
    off += 32;
    let archive_uuid: [u8; 16] = container[off..off + 16]
        .try_into()
        .map_err(|_| V2ContainerError::TooShort)?;
    off += 16;

    let cipher_len_bytes: [u8; 4] = container[off..off + 4]
        .try_into()
        .map_err(|_| V2ContainerError::TooShort)?;
    let cipher_len = u32::from_be_bytes(cipher_len_bytes) as usize;
    off += 4;

    if container.len() < off + cipher_len + V2_CONTAINER_SIG_LEN {
        return Err(V2ContainerError::LengthMismatch);
    }
    let ciphertext = &container[off..off + cipher_len];
    let sig_bytes: [u8; 64] = container[off + cipher_len..off + cipher_len + V2_CONTAINER_SIG_LEN]
        .try_into()
        .map_err(|_| V2ContainerError::TooShort)?;

    // Verify sender signature on ciphertext
    let sender_vk = VerifyingKey::from_bytes(&sender_pubkey)
        .map_err(|_| V2ContainerError::BadSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    sender_vk
        .verify(ciphertext, &signature)
        .map_err(|_| V2ContainerError::BadSignature)?;

    // Confirm we're the receiver
    let our_pubkey: [u8; 32] = receiver_signing_key.verifying_key().to_bytes();
    let envelope = SealedEnvelope {
        sender_pubkey,
        receiver_pubkey,
        archive_uuid,
        ssm_byte: None,
        flags,
    };

    if our_pubkey != receiver_pubkey {
        // Try decryption anyway — it will fail with the wrong key, but the
        // sealed envelope still carries the addressed recipient. Returning
        // BadSignature would be incorrect; the right error is DecryptFailed.
        return Err(V2ContainerError::DecryptFailed);
    }

    let plain = envelope
        .decrypt_block(ciphertext, 0)
        .map_err(|_| V2ContainerError::DecryptFailed)?;

    Ok((envelope, plain, payload_class))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [0x11; 32];
    const BOB: [u8; 32] = [0x22; 32];
    const EVE: [u8; 32] = [0x33; 32];

    #[test]
    fn header_encode_no_ssm_no_flags() {
        let hdr = encode_v2_header(0, None);
        assert_eq!(hdr.len(), V2_HEADER_LEN);
        assert_eq!(hdr, vec![V2_VERSION_MAJOR, V2_VERSION_MINOR, 0, 0]);
    }

    #[test]
    fn header_encode_decode_roundtrip_no_ssm() {
        let hdr = encode_v2_header(FLAG_HAS_ENCRYPTED_BLOCKS, None);
        let (ver, flags, ssm) = decode_v2_header(&hdr).unwrap();
        assert_eq!(ver, V2_VERSION_MAJOR);
        assert_eq!(flags, FLAG_HAS_ENCRYPTED_BLOCKS);
        assert_eq!(ssm, None);
    }

    #[test]
    fn header_encode_decode_roundtrip_with_ssm() {
        let hdr = encode_v2_header(0, Some(0x19));
        assert_eq!(hdr.len(), 1 + V2_HEADER_LEN);
        let (ver, flags, ssm) = decode_v2_header(&hdr).unwrap();
        assert_eq!(ver, V2_VERSION_MAJOR);
        assert!(flags & FLAG_HAS_SSM_HEADER != 0);
        assert_eq!(ssm, Some(0x19));
    }

    #[test]
    fn detect_v1() {
        // Simulated v1: MAGIC + manifest length prefix.
        let data = [&crate::MAGIC[..], &[0x00, 0x40, 0x00, 0x00], b"manifest..."[..].as_ref()]
            .concat();
        assert_eq!(detect_version(&data), 1);
    }

    #[test]
    fn detect_v2_no_ssm() {
        let data = [
            &crate::MAGIC[..],
            &encode_v2_header(FLAG_HAS_ENCRYPTED_BLOCKS, None)[..],
        ]
        .concat();
        assert_eq!(detect_version(&data), 2);
    }

    #[test]
    fn detect_v2_with_ssm() {
        let data = [
            &crate::MAGIC[..],
            &encode_v2_header(FLAG_HAS_ENCRYPTED_BLOCKS, Some(0x19))[..],
        ]
        .concat();
        assert_eq!(detect_version(&data), 2);
    }

    #[test]
    fn detect_not_tbz() {
        assert_eq!(detect_version(b"NOT_TBZ_AT_ALL"), 0);
        assert_eq!(detect_version(b""), 0);
    }

    #[test]
    fn keys_deterministic() {
        let uuid = [0xAAu8; 16];
        let k1 = derive_aes_key(&BOB, &ALICE, &uuid).unwrap();
        let k2 = derive_aes_key(&BOB, &ALICE, &uuid).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn keys_differ_per_receiver() {
        let uuid = [0xAAu8; 16];
        let k_bob = derive_aes_key(&BOB, &ALICE, &uuid).unwrap();
        let k_eve = derive_aes_key(&EVE, &ALICE, &uuid).unwrap();
        assert_ne!(k_bob, k_eve);
    }

    #[test]
    fn nonces_deterministic_per_index() {
        let uuid = [0xAAu8; 16];
        assert_eq!(block_nonce(&uuid, 0), block_nonce(&uuid, 0));
        assert_ne!(block_nonce(&uuid, 0), block_nonce(&uuid, 1));
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let env = SealedEnvelope::new(ALICE, BOB).with_archive_uuid([0u8; 16]);
        let plain = b"Bob's secret block content";
        let cipher = env.encrypt_block(plain, 0).unwrap();
        assert_ne!(cipher.as_slice(), plain);
        // Bob (same envelope params)
        let bob_env = SealedEnvelope::new(ALICE, BOB).with_archive_uuid([0u8; 16]);
        let recovered = bob_env.decrypt_block(&cipher, 0).unwrap();
        assert_eq!(recovered.as_slice(), plain);
    }

    #[test]
    fn wrong_receiver_fails() {
        let alice_to_bob = SealedEnvelope::new(ALICE, BOB).with_archive_uuid([1u8; 16]);
        let cipher = alice_to_bob.encrypt_block(b"for Bob only", 0).unwrap();
        let eve = SealedEnvelope::new(ALICE, EVE).with_archive_uuid([1u8; 16]);
        assert!(matches!(
            eve.decrypt_block(&cipher, 0),
            Err(Tbzv2Error::AeadAuthFailed)
        ));
    }

    #[test]
    fn tampered_cipher_fails() {
        let env = SealedEnvelope::new(ALICE, BOB).with_archive_uuid([2u8; 16]);
        let mut cipher = env.encrypt_block(b"original content", 0).unwrap();
        cipher[5] ^= 0xFF;
        assert!(matches!(
            env.decrypt_block(&cipher, 0),
            Err(Tbzv2Error::AeadAuthFailed)
        ));
    }

    #[test]
    fn multi_block_archive() {
        let env = SealedEnvelope::new(ALICE, BOB).with_archive_uuid([7u8; 16]);
        let blocks: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("Block #{} content payload", i).into_bytes())
            .collect();
        let ciphers: Vec<Vec<u8>> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| env.encrypt_block(b, i as u32).unwrap())
            .collect();
        let bob = SealedEnvelope::new(ALICE, BOB).with_archive_uuid([7u8; 16]);
        let recovered: Vec<Vec<u8>> = ciphers
            .iter()
            .enumerate()
            .map(|(i, c)| bob.decrypt_block(c, i as u32).unwrap())
            .collect();
        assert_eq!(recovered, blocks);
    }

    /// Byte-for-byte agreement with Python POC: tests/test_v2.py
    /// `TestSealedEnvelope::test_encrypt_decrypt_roundtrip` shape.
    #[test]
    fn python_python_compat_envelope_header_layout() {
        let env = SealedEnvelope::new(ALICE, BOB).with_ssm_byte(0x19);
        let hdr = env.encode_header();
        assert_eq!(hdr.len(), 1 + V2_HEADER_LEN);
        assert_eq!(hdr[0], 0x19);
        assert_eq!(hdr[1], V2_VERSION_MAJOR);
        assert_eq!(hdr[2], V2_VERSION_MINOR);
        // hdr[3] = flags with FLAG_HAS_SSM_HEADER + ENCRYPTED + RECEIVER_IDENTITY + COMPRESSION
        assert!(hdr[3] & FLAG_HAS_SSM_HEADER != 0);
        assert!(hdr[3] & FLAG_HAS_ENCRYPTED_BLOCKS != 0);
        assert_eq!(hdr[4], 0x00); // reserved
    }

    // -------------------------------------------------------------------------
    // V2 SEALED CONTAINER tests (= the on-disk wire format)
    // -------------------------------------------------------------------------

    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn container_roundtrip_smallpayload() {
        let sender = make_signing_key();
        let receiver = make_signing_key();
        let payload = b"hello v2 sealed container, this is the inner payload bytes";

        let container = write_sealed_container(
            &sender,
            &receiver.verifying_key().to_bytes(),
            payload,
        )
        .expect("write_sealed_container should succeed");

        // Magic + V2 header should be detectable
        assert_eq!(detect_version(&container), 2);
        assert_eq!(&container[0..3], &crate::MAGIC);

        let (env, recovered) =
            read_sealed_container(&container, &receiver).expect("read should succeed");
        assert_eq!(recovered, payload);
        assert_eq!(env.sender_pubkey, sender.verifying_key().to_bytes());
        assert_eq!(env.receiver_pubkey, receiver.verifying_key().to_bytes());
    }

    #[test]
    fn container_roundtrip_largepayload() {
        let sender = make_signing_key();
        let receiver = make_signing_key();
        let payload: Vec<u8> = (0..100_000).map(|i| (i & 0xff) as u8).collect();

        let container =
            write_sealed_container(&sender, &receiver.verifying_key().to_bytes(), &payload)
                .unwrap();
        let (_, recovered) = read_sealed_container(&container, &receiver).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn container_wrong_receiver_fails() {
        let sender = make_signing_key();
        let bob = make_signing_key();
        let eve = make_signing_key();
        let payload = b"top secret";

        let container =
            write_sealed_container(&sender, &bob.verifying_key().to_bytes(), payload).unwrap();
        // Eve tries with her key — must fail
        let result = read_sealed_container(&container, &eve);
        assert!(matches!(result, Err(V2ContainerError::DecryptFailed)));
    }

    #[test]
    fn container_tampered_ciphertext_fails() {
        let sender = make_signing_key();
        let receiver = make_signing_key();
        let payload = b"original payload bytes";

        let mut container =
            write_sealed_container(&sender, &receiver.verifying_key().to_bytes(), payload).unwrap();
        // Flip a bit deep in the ciphertext region
        let mid = V2_CONTAINER_PREFIX_LEN + 5;
        container[mid] ^= 0xFF;
        let result = read_sealed_container(&container, &receiver);
        // BadSignature OR DecryptFailed both acceptable — tampering detected.
        assert!(matches!(
            result,
            Err(V2ContainerError::BadSignature) | Err(V2ContainerError::DecryptFailed)
        ));
    }

    #[test]
    fn container_tampered_signature_fails() {
        let sender = make_signing_key();
        let receiver = make_signing_key();
        let payload = b"original payload bytes";

        let mut container =
            write_sealed_container(&sender, &receiver.verifying_key().to_bytes(), payload).unwrap();
        // Flip the last byte (= signature trailer)
        let last = container.len() - 1;
        container[last] ^= 0xFF;
        let result = read_sealed_container(&container, &receiver);
        assert!(matches!(result, Err(V2ContainerError::BadSignature)));
    }

    #[test]
    fn container_truncated_fails() {
        let sender = make_signing_key();
        let receiver = make_signing_key();
        let payload = b"some payload";

        let container =
            write_sealed_container(&sender, &receiver.verifying_key().to_bytes(), payload).unwrap();
        // Truncate
        let truncated = &container[..container.len() / 2];
        let result = read_sealed_container(truncated, &receiver);
        assert!(matches!(
            result,
            Err(V2ContainerError::TooShort) | Err(V2ContainerError::LengthMismatch)
        ));
    }

    #[test]
    fn container_overhead_matches_constants() {
        let sender = make_signing_key();
        let receiver = make_signing_key();
        let payload = vec![0u8; 1000];

        let container =
            write_sealed_container(&sender, &receiver.verifying_key().to_bytes(), &payload)
                .unwrap();
        // AES-GCM adds 16 byte tag → ciphertext = payload.len() + 16
        // Total = V2_CONTAINER_PREFIX_LEN + (payload + 16) + V2_CONTAINER_SIG_LEN
        let expected = V2_CONTAINER_PREFIX_LEN + payload.len() + 16 + V2_CONTAINER_SIG_LEN;
        assert_eq!(container.len(), expected);
    }

    // -------------------------------------------------------------------------
    // V2.2 PAYLOAD CLASS tests
    // -------------------------------------------------------------------------

    #[test]
    fn payload_class_roundtrip_via_container() {
        for &cls in &[
            PayloadClass::Unspecified,
            PayloadClass::Identity,
            PayloadClass::Code,
            PayloadClass::Document,
            PayloadClass::Command,
            PayloadClass::Receipt,
        ] {
            let sender = make_signing_key();
            let receiver = make_signing_key();
            let payload = b"payload-class-test";

            let container = write_sealed_container_with_class(
                &sender,
                &receiver.verifying_key().to_bytes(),
                payload,
                cls,
            )
            .unwrap();

            let (_env, recovered, decoded_cls) =
                read_sealed_container_full(&container, &receiver).unwrap();
            assert_eq!(recovered, payload, "payload roundtrip failed for {:?}", cls);
            assert_eq!(decoded_cls, cls, "class roundtrip failed for {:?}", cls);
        }
    }

    #[test]
    fn payload_class_backward_compat_v21_archives() {
        // A v2.1 archive (= class byte was always 0 / Unspecified) must
        // still decode under v2.2 readers.
        let sender = make_signing_key();
        let receiver = make_signing_key();
        let container = write_sealed_container(
            &sender,
            &receiver.verifying_key().to_bytes(),
            b"legacy v2.1",
        )
        .unwrap();
        // Reserved byte (= byte 3 of v2 header = byte 6 of container) must be 0
        assert_eq!(container[6], 0);
        let (_env, recovered, cls) =
            read_sealed_container_full(&container, &receiver).unwrap();
        assert_eq!(recovered, b"legacy v2.1");
        assert_eq!(cls, PayloadClass::Unspecified);
    }

    #[test]
    fn payload_class_label_parse_roundtrip() {
        for &cls in &[
            PayloadClass::Identity,
            PayloadClass::Code,
            PayloadClass::Document,
            PayloadClass::Command,
            PayloadClass::Receipt,
        ] {
            assert_eq!(PayloadClass::from_label(cls.label()), Some(cls));
        }
        // Aliases
        assert_eq!(PayloadClass::from_label("id"), Some(PayloadClass::Identity));
        assert_eq!(PayloadClass::from_label("DOC"), Some(PayloadClass::Document));
        assert_eq!(PayloadClass::from_label("cmd"), Some(PayloadClass::Command));
        // Unknown
        assert_eq!(PayloadClass::from_label("hugotron"), None);
    }
}
