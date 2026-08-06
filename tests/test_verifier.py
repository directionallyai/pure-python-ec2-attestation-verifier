"""Tests for the NitroTPM attestation verifier, using a real captured document."""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from verifier import verify_nitrotpm_attestation
from payload import NitroTPMPayload

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "aws_nitrotpm_doc.bin"

# The fixture's leaf certificate is valid 2026-06-18 05:10:46 to 08:10:49 UTC.
VALID_TIME = datetime(2026, 6, 18, 6, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def document() -> bytes:
    return FIXTURE_PATH.read_bytes()


@pytest.fixture(scope="module")
def real_nonce(document: bytes) -> bytes:
    from cose import CoseSign1

    payload = NitroTPMPayload.from_cbor(CoseSign1.parse(document).get_payload())
    assert payload.nonce is not None
    return payload.nonce


def test_valid_document_verifies_successfully(document):
    result = verify_nitrotpm_attestation(document, now=VALID_TIME)

    assert result.payload_valid is True
    assert result.certificate_chain_valid is True
    assert result.cose_signature_valid is True
    assert result.errors == []
    assert result.is_valid is True


def test_expired_verification_time_fails_chain_validation(document):
    result = verify_nitrotpm_attestation(
        document, now=VALID_TIME + timedelta(days=365)
    )

    assert result.payload_valid is True
    assert result.certificate_chain_valid is False
    assert any("not valid at" in e for e in result.errors)


def test_tampered_payload_fails_signature_verification(document):
    tampered = bytearray(document)
    tampered[300] ^= 0xFF  # flip a byte inside the CBOR payload

    result = verify_nitrotpm_attestation(bytes(tampered), now=VALID_TIME)

    assert result.cose_signature_valid is False
    assert any("Signature verification failed" in e for e in result.errors)
    assert result.is_valid is False

    # Verification must stop once the signature is known-bad: policy checks
    # against an unauthenticated payload would be meaningless.
    assert result.nonce_match is None
    assert result.pcr_matches == {}
    assert result.timestamp_fresh is None


def test_signature_failure_short_circuits_even_with_matching_policy(document, real_nonce):
    """A tampered document must not report matching nonce/PCRs even if the
    attacker-controlled payload happens to carry the real nonce/PCR bytes."""
    tampered = bytearray(document)
    tampered[300] ^= 0xFF

    result = verify_nitrotpm_attestation(
        bytes(tampered),
        expected_nonce=real_nonce,
        expected_pcrs={0: b"\x00" * 48},
        now=VALID_TIME,
    )

    assert result.cose_signature_valid is False
    assert result.nonce_match is None
    assert result.pcr_matches == {}
    assert result.is_valid is False


def test_correct_nonce_matches(document, real_nonce):
    result = verify_nitrotpm_attestation(
        document, expected_nonce=real_nonce, now=VALID_TIME
    )

    assert result.nonce_match is True
    assert result.is_valid is True


def test_wrong_nonce_does_not_match(document, real_nonce):
    wrong_nonce = bytes((b ^ 0xFF) for b in real_nonce)

    result = verify_nitrotpm_attestation(
        document, expected_nonce=wrong_nonce, now=VALID_TIME
    )

    assert result.nonce_match is False
    assert "Nonce mismatch" in result.errors
    assert result.is_valid is False


def test_max_age_rejects_stale_document(document):
    result = verify_nitrotpm_attestation(
        document,
        now=VALID_TIME + timedelta(hours=2),
        max_age=timedelta(hours=1),
    )

    assert result.timestamp_fresh is False
    assert any("too old" in e for e in result.errors)
    assert result.is_valid is False


def test_wrong_pcr_value_is_reported(document):
    result = verify_nitrotpm_attestation(
        document, expected_pcrs={0: b"\x00" * 48}, now=VALID_TIME
    )

    assert result.pcr_matches[0] is False
    assert result.is_valid is False


class TestPayloadPcrIndexBounds:
    """AWS's NitroTPM CDDL defines PCR index as 0..31 (32 registers)."""

    @staticmethod
    def _payload_with_pcr(idx: int) -> NitroTPMPayload:
        p = NitroTPMPayload()
        p.module_id = "i-test"
        p.timestamp = 1
        p.digest = "SHA384"
        p.nitrotpm_pcrs = {idx: b"\x00" * 48}
        p.certificate = b"\x00"
        p.cabundle = [b"\x00"]
        return p

    def test_pcr_index_31_is_accepted(self):
        self._payload_with_pcr(31).validate()

    def test_pcr_index_23_is_accepted(self):
        self._payload_with_pcr(23).validate()

    def test_pcr_index_32_is_rejected(self):
        with pytest.raises(ValueError, match="Invalid PCR index"):
            self._payload_with_pcr(32).validate()

    def test_pcr_index_negative_is_rejected(self):
        with pytest.raises(ValueError, match="Invalid PCR index"):
            self._payload_with_pcr(-1).validate()
