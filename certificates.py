"""Certificate chain validation for NitroTPM attestation using certvalidator."""

import hashlib
from datetime import datetime, timezone
from typing import Optional, List

try:
    from certvalidator import CertificateValidator
    from certvalidator.context import ValidationContext
except ImportError:
    raise ImportError("certvalidator is required. Install with: pip install certvalidator")

try:
    from tlslite.x509 import X509
except ImportError:
    raise ImportError("tlslite-ng is required. Install with: pip install tlslite-ng")


# AWS Nitro root certificate SHA-256 fingerprint (pinned out-of-band)
AWS_NITRO_ROOT_FINGERPRINT = "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"


class CertificateChain:
    """X.509 certificate chain validator using certvalidator."""

    def __init__(self, leaf_der: bytes, cabundle_der: List[bytes]):
        """Initialize certificate chain.

        Args:
            leaf_der: DER-encoded leaf certificate
            cabundle_der: List of DER-encoded certificates (root to leaf intermediates)

        Raises:
            ValueError: If certificates are invalid
        """
        if not leaf_der:
            raise ValueError("Leaf certificate cannot be empty")
        if not cabundle_der:
            raise ValueError("CA bundle cannot be empty")

        self.leaf_der = leaf_der
        self.cabundle_der = cabundle_der
        self.root_der = cabundle_der[0] if cabundle_der else None

        # Parse certificates using tlslite-ng
        try:
            self.leaf_cert = self._parse_cert(leaf_der, "leaf")
            self.root_cert = self._parse_cert(self.root_der, "root") if self.root_der else None
            self.intermediates = [
                self._parse_cert(cert_der, f"intermediate[{i}]")
                for i, cert_der in enumerate(cabundle_der[1:])
            ]
        except Exception as e:
            raise ValueError(f"Failed to parse certificates: {e}")

    @staticmethod
    def _parse_cert(cert_der: bytes, label: str) -> X509:
        """Parse DER-encoded certificate using tlslite-ng."""
        try:
            cert = X509()
            cert.parseBinary(cert_der)
            return cert
        except Exception as e:
            raise ValueError(f"Failed to parse {label} certificate: {e}")

    def validate(self, now: Optional[datetime] = None) -> None:
        """Validate certificate chain.

        Args:
            now: Current time for validation (defaults to now)

        Raises:
            ValueError: If validation fails
        """
        if now is None:
            now = datetime.now(timezone.utc)

        # Verify pinned root
        self._verify_root_pinning()

        # Verify certificate chain using certvalidator
        self._verify_chain_with_certvalidator(now)

    def _verify_root_pinning(self) -> None:
        """Verify root certificate fingerprint.

        Raises:
            ValueError: If root fingerprint doesn't match
        """
        if not self.root_der:
            raise ValueError("Root certificate missing")

        fingerprint = hashlib.sha256(self.root_der).hexdigest().upper()

        if fingerprint != AWS_NITRO_ROOT_FINGERPRINT:
            raise ValueError(
                f"Root certificate fingerprint mismatch. "
                f"Expected {AWS_NITRO_ROOT_FINGERPRINT}, got {fingerprint}"
            )

    def _verify_chain_with_certvalidator(self, now: datetime) -> None:
        """Verify certificate chain using certvalidator.

        Args:
            now: Current time (UTC)

        Raises:
            ValueError: If chain validation fails
        """
        try:
            # Create validation context with trust roots and intermediates
            context = ValidationContext(
                trust_roots=[self.root_der],
                other_certs=self.intermediates_der if self.intermediates else [],
                moment=now,
                allow_fetching=False
            )

            # Create validator with leaf certificate and validate
            validator = CertificateValidator(
                end_entity_cert=self.leaf_der,
                intermediate_certs=None,
                validation_context=context
            )

            # Validate the chain (this will check dates, signatures, and build path)
            # Use validate_usage with empty set to validate chain without specific key usage requirements
            path = validator.validate_usage(
                key_usage=set(),
                extended_optional=True
            )

            if not path:
                raise ValueError("Certificate chain validation returned empty path")

        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Certificate chain validation failed: {e}")

    @property
    def intermediates_der(self) -> List[bytes]:
        """Get intermediate certificates as DER bytes."""
        return self.cabundle_der[1:] if len(self.cabundle_der) > 1 else []

    def get_leaf_certificate(self):
        """Get parsed leaf certificate (tlslite-ng X509 object)."""
        return self.leaf_cert

    def get_leaf_certificate_der(self) -> bytes:
        """Get DER-encoded leaf certificate."""
        return self.leaf_der
