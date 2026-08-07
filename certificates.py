"""X.509 certificate chain validation for NitroTPM attestation.

Pure Python implementation using asn1crypto (structure parsing only, no
crypto operations) and tlslite-ng/ecdsa (signature verification). This
avoids certvalidator/oscrypto, which shell out to the system OpenSSL
(libcrypto) via ctypes and are not actually pure Python.

Per AWS's NitroTPM attestation document validation guide, revocation
(CRL/OCSP) checking must be disabled for this chain - the certificates
are short-lived and there is no revocation infrastructure for them. Key
usage enforcement (keyCertSign on CAs, digitalSignature on the leaf) is
not mandated by that guide, but is applied here anyway as a standard
X.509 hygiene check, borrowed from AWS's sibling Nitro Enclaves
attestation process documentation.
"""

import hashlib
from datetime import datetime, timezone
from typing import List, Optional

try:
    from asn1crypto import x509 as asn1_x509
except ImportError:
    raise ImportError("asn1crypto is required. Install with: pip install asn1crypto")

try:
    from tlslite.x509 import X509
    from tlslite.utils.ecdsakey import ECDSAKey
except ImportError:
    raise ImportError("tlslite-ng is required. Install with: pip install tlslite-ng")


# AWS Nitro root certificate SHA-256 fingerprint (pinned out-of-band)
AWS_NITRO_ROOT_FINGERPRINT = "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"


class CertificateChain:
    """X.509 certificate chain validator (pure Python, no OpenSSL)."""

    def __init__(self, leaf_der: bytes, cabundle_der: List[bytes]):
        """Initialize certificate chain.

        Args:
            leaf_der: DER-encoded leaf certificate
            cabundle_der: DER-encoded certs, ordered [ROOT, INTERM_1, ..., INTERM_N]
                          per the AWS attestation document CA bundle convention

        Raises:
            ValueError: If certificates are invalid
        """
        if not leaf_der:
            raise ValueError("Leaf certificate cannot be empty")
        if not cabundle_der:
            raise ValueError("CA bundle cannot be empty")

        self.leaf_der = leaf_der
        self.cabundle_der = cabundle_der
        self.root_der = cabundle_der[0]

        # Chain, in signing order, closest to trust anchor last:
        # [leaf, INTERM_N, ..., INTERM_1, ROOT]
        self.chain_der = [leaf_der] + list(reversed(cabundle_der[1:])) + [self.root_der]

        try:
            self.chain = [
                asn1_x509.Certificate.load(der) for der in self.chain_der
            ]
        except Exception as e:
            raise ValueError(f"Failed to parse certificates: {e}")

    def validate(self, now: Optional[datetime] = None) -> None:
        """Validate certificate chain.

        Args:
            now: Current time for validation (defaults to now)

        Raises:
            ValueError: If validation fails
        """
        if now is None:
            now = datetime.now(timezone.utc)

        self._verify_root_pinning()
        self._verify_validity_periods(now)
        self._verify_issuer_subject_linkage()
        self._verify_basic_constraints_and_path_len()
        self._verify_key_usage()
        self._verify_signature_chain()

    def _verify_root_pinning(self) -> None:
        """Verify root certificate fingerprint.

        Raises:
            ValueError: If root fingerprint doesn't match
        """
        fingerprint = hashlib.sha256(self.root_der).hexdigest().upper()

        if fingerprint != AWS_NITRO_ROOT_FINGERPRINT:
            raise ValueError(
                f"Root certificate fingerprint mismatch. "
                f"Expected {AWS_NITRO_ROOT_FINGERPRINT}, got {fingerprint}"
            )

    def _verify_validity_periods(self, now: datetime) -> None:
        """Ensure every certificate in the chain is within its validity period."""
        for label, cert in zip(self._labels(), self.chain):
            validity = cert["tbs_certificate"]["validity"]
            not_before = validity["not_before"].native
            not_after = validity["not_after"].native
            if now < not_before or now > not_after:
                raise ValueError(
                    f"{label} certificate not valid at {now}: "
                    f"validity window {not_before} to {not_after}"
                )

    def _verify_issuer_subject_linkage(self) -> None:
        """Ensure each cert's issuer matches the next cert's subject."""
        for i in range(len(self.chain) - 1):
            child = self.chain[i]
            parent = self.chain[i + 1]
            child_issuer = child["tbs_certificate"]["issuer"].dump()
            parent_subject = parent["tbs_certificate"]["subject"].dump()
            if child_issuer != parent_subject:
                raise ValueError(
                    f"{self._labels()[i]} issuer does not match "
                    f"{self._labels()[i + 1]} subject"
                )

        # Root must be self-signed
        root = self.chain[-1]
        root_issuer = root["tbs_certificate"]["issuer"].dump()
        root_subject = root["tbs_certificate"]["subject"].dump()
        if root_issuer != root_subject:
            raise ValueError("Root certificate is not self-signed")

    def _verify_basic_constraints_and_path_len(self) -> None:
        """Ensure CA flags and pathLenConstraint are respected."""
        leaf = self.chain[0]
        leaf_bc = leaf.basic_constraints_value
        if leaf_bc is not None and leaf_bc.native.get("ca"):
            raise ValueError("Leaf certificate must not be a CA")

        # CAs, ordered from closest-to-leaf to root; subordinate_cas is the
        # count of CA certs between (exclusive) this cert and the leaf.
        cas = self.chain[1:]
        for depth, cert in enumerate(cas):
            bc = cert.basic_constraints_value
            if bc is None or not bc.native.get("ca"):
                raise ValueError(
                    f"{self._labels()[1 + depth]} certificate is not a valid CA "
                    f"(missing or false BasicConstraints CA flag)"
                )
            path_len = bc.native.get("path_len_constraint")
            if path_len is not None and depth > path_len:
                raise ValueError(
                    f"{self._labels()[1 + depth]} certificate violates its "
                    f"pathLenConstraint of {path_len}"
                )

    def _verify_key_usage(self) -> None:
        """Ensure key usage bits are appropriate for each cert's role."""
        leaf = self.chain[0]
        leaf_ku = leaf.key_usage_value
        if leaf_ku is None or "digital_signature" not in leaf_ku.native:
            raise ValueError("Leaf certificate missing digitalSignature key usage")

        for label, cert in zip(self._labels()[1:], self.chain[1:]):
            ku = cert.key_usage_value
            if ku is None or "key_cert_sign" not in ku.native:
                raise ValueError(f"{label} certificate missing keyCertSign key usage")

    def _verify_signature_chain(self) -> None:
        """Verify each certificate's signature against its issuer's public key.

        The root's self-signature is not verified (trust in the root comes
        from the pinned fingerprint, not from its own signature).
        """
        for i in range(len(self.chain) - 1):
            child = self.chain[i]
            parent_der = self.chain_der[i + 1]
            label = self._labels()[i]

            if child.hash_algo != "sha384" or child.signature_algo != "ecdsa":
                raise ValueError(
                    f"{label} certificate uses unsupported signature algorithm: "
                    f"{child.signature_algo}/{child.hash_algo}"
                )

            parent_x509 = X509()
            try:
                parent_x509.parseBinary(parent_der)
            except Exception as e:
                raise ValueError(f"Failed to parse issuer of {label}: {e}")

            public_key = parent_x509.publicKey
            if not isinstance(public_key, ECDSAKey):
                raise ValueError(f"Issuer of {label} has non-ECDSA public key")

            tbs_bytes = child["tbs_certificate"].dump()
            signature_der = child.signature  # already DER-encoded for ECDSA certs

            try:
                valid = public_key.hashAndVerify(signature_der, tbs_bytes, hAlg="sha384")
            except Exception as e:
                raise ValueError(f"Signature verification failed for {label}: {e}")

            if not valid:
                raise ValueError(f"Invalid signature on {label} certificate")

    def _labels(self) -> List[str]:
        n_intermediates = len(self.chain) - 2
        return (
            ["leaf"]
            + [f"intermediate[{n_intermediates - 1 - i}]" for i in range(n_intermediates)]
            + ["root"]
        )

    def get_leaf_certificate(self):
        """Get parsed leaf certificate (tlslite-ng X509 object) for signature verification."""
        x509_leaf = X509()
        x509_leaf.parseBinary(self.leaf_der)
        return x509_leaf

    def get_leaf_certificate_der(self) -> bytes:
        """Get DER-encoded leaf certificate."""
        return self.leaf_der
