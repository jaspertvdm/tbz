"""Tests for tbz.v2 — v2 header reader + retired-seal fail-closed guards."""

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


class TestBlockNonce:

    def test_block_nonce_deterministic(self):
        nonce_0 = block_nonce(b"a" * 16, 0)
        nonce_1 = block_nonce(b"a" * 16, 1)
        assert nonce_0 != nonce_1
        assert nonce_0 == block_nonce(b"a" * 16, 0)
        assert len(nonce_0) == 12


class TestRetiredSeal:
    """The v2 'confidential' seal is retired (public-input key = no confidentiality).
    Every seal op must fail closed; the real recipient-only seal lives in
    tibet_drop.crypto / handshake_seal.py / the Rust tbz-cli."""

    def test_derive_aes_key_is_retired(self):
        with pytest.raises(TBZv2Error):
            derive_aes_key(BOB, ALICE, b"a" * 16)


    def test_encrypt_block_is_retired(self):
        env = SealedEnvelope(sender_pubkey=ALICE, receiver_pubkey=BOB)
        with pytest.raises(TBZv2Error):
            env.encrypt_block(b"whatever", 0)

    def test_decrypt_block_is_retired(self):
        env = SealedEnvelope(sender_pubkey=ALICE, receiver_pubkey=BOB)
        with pytest.raises(TBZv2Error):
            env.decrypt_block(b"x" * 48, 0)

    def test_header_still_encodes(self):
        # Reading/writing the v2 header is fine — only the seal is retired.
        env = SealedEnvelope(sender_pubkey=ALICE, receiver_pubkey=BOB, ssm_byte=0x19)
        hdr = env.encode_header()
        assert len(hdr) == 1 + V2_HEADER_LEN
        ver, flags, ssm = decode_v2_header(hdr)
        assert ssm == 0x19
        assert flags & FLAG_HAS_ENCRYPTED_BLOCKS
        assert flags & FLAG_HAS_RECEIVER_IDENTITY
        assert flags & FLAG_HAS_SSM_HEADER


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
