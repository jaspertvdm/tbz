"""Tests for tbz.v2 — confidential block encryption + SSM routing header."""

import pytest

from tbz.v2 import (
    MAGIC,
    V2_HEADER_LEN,
    V2_VERSION_MAJOR,
    FLAG_HAS_SSM_HEADER,
    FLAG_HAS_ENCRYPTED_BLOCKS,
    FLAG_HAS_RECEIVER_IDENTITY,
    SealedEnvelope,
    TBZv2DecryptError,
    TBZVersionMismatch,
    TBZv2Error,
    decode_v2_header,
    derive_aes_key,
    detect_version,
    encode_v2_header,
    block_nonce,
)


ALICE = bytes.fromhex("11" * 32)  # sender
BOB = bytes.fromhex("22" * 32)    # receiver
EVE = bytes.fromhex("33" * 32)    # attacker


class TestHeaderEncodeDecodeRoundtrip:

    def test_no_ssm_no_flags(self):
        hdr = encode_v2_header(flags=0)
        assert len(hdr) == V2_HEADER_LEN
        ver, flags, ssm = decode_v2_header(hdr)
        assert ver == V2_VERSION_MAJOR
        assert flags == 0
        assert ssm is None

    def test_ssm_only(self):
        hdr = encode_v2_header(flags=0, ssm_byte=0x19)
        assert len(hdr) == 1 + V2_HEADER_LEN
        ver, flags, ssm = decode_v2_header(hdr)
        assert ver == V2_VERSION_MAJOR
        assert flags & FLAG_HAS_SSM_HEADER
        assert ssm == 0x19

    def test_encrypted_blocks_flag(self):
        hdr = encode_v2_header(flags=FLAG_HAS_ENCRYPTED_BLOCKS)
        ver, flags, ssm = decode_v2_header(hdr)
        assert flags & FLAG_HAS_ENCRYPTED_BLOCKS
        assert ssm is None

    def test_full_sealed_envelope(self):
        flags = (
            FLAG_HAS_ENCRYPTED_BLOCKS
            | FLAG_HAS_RECEIVER_IDENTITY
        )
        hdr = encode_v2_header(flags=flags, ssm_byte=0x61)
        ver, flags_out, ssm = decode_v2_header(hdr)
        assert ssm == 0x61
        assert flags_out & FLAG_HAS_SSM_HEADER
        assert flags_out & FLAG_HAS_ENCRYPTED_BLOCKS
        assert flags_out & FLAG_HAS_RECEIVER_IDENTITY

    def test_invalid_ssm_byte_raises(self):
        with pytest.raises(TBZv2Error):
            encode_v2_header(flags=0, ssm_byte=300)

    def test_short_buffer_raises(self):
        with pytest.raises(TBZVersionMismatch):
            decode_v2_header(b"\x01\x02")


class TestVersionDetection:

    def test_detect_v1_transparent(self):
        # v1 layout: MAGIC + manifest bytes (= no v2 header pattern)
        data = MAGIC + bytes([0x00, 0x40, 0x00, 0x00]) + b"manifest..."
        assert detect_version(data) == 1

    def test_detect_v2_no_ssm(self):
        data = MAGIC + encode_v2_header(flags=FLAG_HAS_ENCRYPTED_BLOCKS)
        assert detect_version(data) == 2

    def test_detect_v2_with_ssm(self):
        data = MAGIC + encode_v2_header(flags=FLAG_HAS_ENCRYPTED_BLOCKS, ssm_byte=0x19)
        assert detect_version(data) == 2

    def test_detect_not_tbz(self):
        assert detect_version(b"\x50\x4b\x03\x04zip header") == 0
        assert detect_version(b"") == 0
        assert detect_version(b"XYZ") == 0


class TestKeyDerivation:

    def test_keys_are_deterministic(self):
        uuid_bytes = b"a" * 16
        k1 = derive_aes_key(BOB, ALICE, uuid_bytes)
        k2 = derive_aes_key(BOB, ALICE, uuid_bytes)
        assert k1 == k2
        assert len(k1) == 32

    def test_different_receiver_different_key(self):
        uuid_bytes = b"a" * 16
        k_bob = derive_aes_key(BOB, ALICE, uuid_bytes)
        k_eve = derive_aes_key(EVE, ALICE, uuid_bytes)
        assert k_bob != k_eve

    def test_different_archive_different_key(self):
        k1 = derive_aes_key(BOB, ALICE, b"a" * 16)
        k2 = derive_aes_key(BOB, ALICE, b"b" * 16)
        assert k1 != k2

    def test_invalid_key_length_raises(self):
        with pytest.raises(TBZv2Error):
            derive_aes_key(BOB[:16], ALICE, b"a" * 16)
        with pytest.raises(TBZv2Error):
            derive_aes_key(BOB, b"short", b"a" * 16)

    def test_block_nonce_deterministic(self):
        nonce_0 = block_nonce(b"a" * 16, 0)
        nonce_1 = block_nonce(b"a" * 16, 1)
        assert nonce_0 != nonce_1
        assert nonce_0 == block_nonce(b"a" * 16, 0)
        assert len(nonce_0) == 12


class TestSealedEnvelope:
    """End-to-end seal/unseal roundtrip."""

    def test_encrypt_decrypt_roundtrip(self):
        env = SealedEnvelope(
            sender_pubkey=ALICE,
            receiver_pubkey=BOB,
        )
        plain = b"Bob's secret block content here. " * 10
        cipher = env.encrypt_block(plain, 0)
        assert cipher != plain  # encrypted
        # Bob decrypts (same envelope params)
        bob_env = SealedEnvelope(
            sender_pubkey=ALICE,
            receiver_pubkey=BOB,
            archive_uuid=env.archive_uuid,
        )
        recovered = bob_env.decrypt_block(cipher, 0)
        assert recovered == plain

    def test_wrong_receiver_raises(self):
        alice_to_bob = SealedEnvelope(
            sender_pubkey=ALICE,
            receiver_pubkey=BOB,
        )
        cipher = alice_to_bob.encrypt_block(b"for Bob's eyes only", 0)
        # Eve tries to decrypt
        eve_env = SealedEnvelope(
            sender_pubkey=ALICE,
            receiver_pubkey=EVE,
            archive_uuid=alice_to_bob.archive_uuid,
        )
        with pytest.raises(TBZv2DecryptError):
            eve_env.decrypt_block(cipher, 0)

    def test_wrong_block_index_raises(self):
        env = SealedEnvelope(sender_pubkey=ALICE, receiver_pubkey=BOB)
        cipher = env.encrypt_block(b"block zero data", 0)
        # Try decrypting at index 1 → nonce mismatch → auth fail
        with pytest.raises(TBZv2DecryptError):
            env.decrypt_block(cipher, 1)

    def test_tampered_cipher_raises(self):
        env = SealedEnvelope(sender_pubkey=ALICE, receiver_pubkey=BOB)
        cipher = bytearray(env.encrypt_block(b"original content", 0))
        cipher[5] ^= 0xFF  # flip one byte
        with pytest.raises(TBZv2DecryptError):
            env.decrypt_block(bytes(cipher), 0)

    def test_envelope_header_encodes(self):
        env = SealedEnvelope(
            sender_pubkey=ALICE,
            receiver_pubkey=BOB,
            ssm_byte=0x19,
        )
        hdr = env.encode_header()
        assert len(hdr) == 1 + V2_HEADER_LEN
        ver, flags, ssm = decode_v2_header(hdr)
        assert ssm == 0x19
        assert flags & FLAG_HAS_ENCRYPTED_BLOCKS
        assert flags & FLAG_HAS_RECEIVER_IDENTITY
        assert flags & FLAG_HAS_SSM_HEADER

    def test_multi_block_archive(self):
        """Encrypt several blocks, all with same envelope, different indices."""
        env = SealedEnvelope(sender_pubkey=ALICE, receiver_pubkey=BOB)
        plain_blocks = [f"Block #{i} content payload here".encode() for i in range(5)]
        ciphers = [env.encrypt_block(p, i) for i, p in enumerate(plain_blocks)]
        # All distinct
        assert len(set(ciphers)) == 5
        # Bob decrypts
        bob_env = SealedEnvelope(
            sender_pubkey=ALICE,
            receiver_pubkey=BOB,
            archive_uuid=env.archive_uuid,
        )
        recovered = [bob_env.decrypt_block(c, i) for i, c in enumerate(ciphers)]
        assert recovered == plain_blocks


class TestBackwardCompat:

    def test_v1_data_detected_correctly(self):
        # Simulated v1 file: MAGIC + manifest length prefix
        v1_data = MAGIC + bytes([0xAB, 0x00, 0x00, 0x10]) + b"...manifest..."
        assert detect_version(v1_data) == 1

    def test_v2_data_detected_correctly(self):
        v2_data = MAGIC + encode_v2_header(flags=FLAG_HAS_ENCRYPTED_BLOCKS)
        assert detect_version(v2_data) == 2

    def test_corrupt_magic_not_tbz(self):
        assert detect_version(b"NOT_TBZ_AT_ALL_NO") == 0
