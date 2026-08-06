"""Main NitroTPM attestation verifier."""

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from dataclasses import dataclass, field

try:
    from .cose import CoseSign1
    from .payload import NitroTPMPayload
    from .certificates import CertificateChain
    from .signature import SignatureVerifier
except ImportError:
    from cose import CoseSign1
    from payload import NitroTPMPayload
    from certificates import CertificateChain
    from signature import SignatureVerifier


@dataclass
class VerificationResult:
    """Result of attestation verification."""

    payload_valid: bool = False
    certificate_chain_valid: bool = False
    cose_signature_valid: bool = False
    nonce_match: Optional[bool] = None
    pcr_matches: Dict[int, bool] = field(default_factory=dict)
    timestamp_fresh: Optional[bool] = None
    errors: list = field(default_factory=list)


class NitroTPMVerifier:
    """NitroTPM attestation document verifier."""

    def __init__(self):
        self.expected_nonce: Optional[bytes] = None
        self.expected_pcrs: Dict[int, bytes] = {}
        self.current_time: datetime = datetime.now(timezone.utc)
        self.max_age: Optional[timedelta] = None

    def set_expected_nonce(self, nonce: bytes) -> None:
        """Set expected nonce for verification."""
        self.expected_nonce = nonce

    def set_expected_pcrs(self, pcrs: Dict[int, bytes]) -> None:
        """Set expected PCRs for verification."""
        self.expected_pcrs = pcrs

    def set_current_time(self, now: datetime) -> None:
        """Set current time for timestamp validation."""
        self.current_time = now

    def set_max_age(self, age: timedelta) -> None:
        """Set maximum allowed document age."""
        self.max_age = age

    def verify(self, document: bytes) -> VerificationResult:
        """Verify a NitroTPM attestation document.

        Args:
            document: Raw attestation document bytes

        Returns:
            VerificationResult with detailed status
        """
        result = VerificationResult()

        # Step 1: Parse COSE envelope
        try:
            cose = CoseSign1.parse(document)
            result.payload_valid = True
        except Exception as e:
            result.errors.append(f"COSE parsing failed: {e}")
            return result

        # Step 2: Validate COSE headers
        try:
            cose.validate_headers()
        except Exception as e:
            result.errors.append(f"COSE header validation failed: {e}")
            return result

        # Step 3: Parse attestation payload
        try:
            payload = NitroTPMPayload.from_cbor(cose.get_payload())
            payload.validate()
        except Exception as e:
            result.errors.append(f"Payload parsing failed: {e}")
            return result

        # Step 4: Validate certificate chain
        cert_chain = None
        try:
            cert_chain = CertificateChain(
                payload.certificate, payload.cabundle
            )
            cert_chain.validate(self.current_time)
            result.certificate_chain_valid = True
        except Exception as e:
            result.errors.append(f"Certificate validation failed: {e}")
            return result  # STOP if certificate chain validation fails

        # Step 5: Verify COSE signature (only if chain is valid)
        try:
            sig_structure = cose.get_sig_structure()
            SignatureVerifier.verify_cose_signature(
                sig_structure,
                cose.get_signature(),
                cert_chain.get_leaf_certificate(),
            )
            result.cose_signature_valid = True
        except Exception as e:
            result.errors.append(f"Signature verification failed: {e}")

        # Step 6: Check nonce
        if self.expected_nonce:
            if payload.nonce == self.expected_nonce:
                result.nonce_match = True
            else:
                result.nonce_match = False
                result.errors.append("Nonce mismatch")

        # Step 7: Check PCRs
        for idx, expected in self.expected_pcrs.items():
            actual = payload.nitrotpm_pcrs.get(idx)
            if actual == expected:
                result.pcr_matches[idx] = True
            else:
                result.pcr_matches[idx] = False
                if actual is None:
                    result.errors.append(f"PCR {idx} not found in payload")
                else:
                    result.errors.append(f"PCR {idx} mismatch")

        # Step 8: Check timestamp freshness
        if self.max_age:
            doc_time = datetime.fromtimestamp(
                payload.timestamp / 1000,
                tz=timezone.utc
            )
            age = self.current_time - doc_time
            if age <= self.max_age:
                result.timestamp_fresh = True
            else:
                result.timestamp_fresh = False
                result.errors.append(
                    f"Document too old: {age} > {self.max_age}"
                )

        return result


def verify_nitrotpm_attestation(
    document: bytes,
    expected_nonce: Optional[bytes] = None,
    expected_pcrs: Optional[Dict[int, bytes]] = None,
    now: Optional[datetime] = None,
    max_age: Optional[timedelta] = None,
) -> VerificationResult:
    """Convenience function to verify NitroTPM attestation.

    Args:
        document: Raw attestation document
        expected_nonce: Optional nonce to verify
        expected_pcrs: Optional PCR map to verify
        now: Current time for validation (defaults to now)
        max_age: Maximum allowed document age

    Returns:
        VerificationResult with verification status
    """
    verifier = NitroTPMVerifier()

    if expected_nonce:
        verifier.set_expected_nonce(expected_nonce)
    if expected_pcrs:
        verifier.set_expected_pcrs(expected_pcrs)
    if now:
        verifier.set_current_time(now)
    if max_age:
        verifier.set_max_age(max_age)

    return verifier.verify(document)
