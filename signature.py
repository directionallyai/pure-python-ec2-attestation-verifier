"""COSE signature verification using tlslite-ng."""

from typing import Any

try:
    from tlslite.utils.ecdsakey import ECDSAKey
except ImportError:
    raise ImportError("tlslite-ng is required. Install with: pip install tlslite-ng")

try:
    from ecdsa.der import encode_integer, encode_sequence
except ImportError:
    raise ImportError("ecdsa is required. Install with: pip install ecdsa")


class SignatureVerifier:
    """ECDSA signature verification using tlslite-ng."""

    @staticmethod
    def _raw_to_der_signature(r: int, s: int) -> bytes:
        """Convert raw ECDSA signature (r, s integers) to DER format.

        Args:
            r: R component as integer
            s: S component as integer

        Returns:
            DER-encoded ECDSA signature

        Raises:
            ValueError: If conversion fails
        """
        if r < 0 or s < 0:
            raise ValueError("r and s must be non-negative")

        return encode_sequence(
            encode_integer(r),
            encode_integer(s),
        )

    @staticmethod
    def verify_cose_signature(
        sig_structure: bytes,
        signature_bytes: bytes,
        leaf_certificate: Any,
    ) -> None:
        """Verify COSE_Sign1 signature using ES384 (ECDSA with P-384).

        Args:
            sig_structure: The Sig_structure to verify (CBOR serialized)
            signature_bytes: Raw signature bytes (r||s format, 96 bytes for P-384)
            leaf_certificate: tlslite-ng X509 certificate with public key

        Raises:
            ValueError: If signature verification fails
        """
        if not leaf_certificate:
            raise ValueError("No leaf certificate provided")

        # Extract public key from tlslite-ng certificate
        public_key = leaf_certificate.publicKey
        if not public_key:
            raise ValueError("Certificate has no public key")

        # Verify it's an ECDSA key with P-384
        if not isinstance(public_key, ECDSAKey):
            raise ValueError(f"Expected ECDSA key, got {type(public_key)}")

        curve_name = getattr(public_key, "curve_name", None)
        if not curve_name:
            curve_name = getattr(public_key, "curve", None)

        p384_curves = {"secp384r1", "P-384", "NIST384p", "prime384v1"}
        if curve_name not in p384_curves:
            raise ValueError(f"Expected P-384 curve, got {curve_name}")

        if len(signature_bytes) != 96:
            raise ValueError(
                f"Invalid signature length: expected 96 bytes, got {len(signature_bytes)}"
            )

        r_bytes = signature_bytes[:48]
        s_bytes = signature_bytes[48:]
        r = int.from_bytes(r_bytes, byteorder="big")
        s = int.from_bytes(s_bytes, byteorder="big")

        try:
            der_signature = SignatureVerifier._raw_to_der_signature(r, s)
        except Exception as e:
            raise ValueError(f"Failed to convert signature to DER: {e}")

        try:
            valid = public_key.hashAndVerify(
                der_signature,
                sig_structure,
                hAlg="sha384"
            )
            if not valid:
                raise ValueError("ECDSA signature verification failed")
        except Exception as e:
            raise ValueError(f"Failed to verify signature: {e}")
