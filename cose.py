"""COSE_Sign1 envelope parsing and validation."""

import cbor2
from io import BytesIO
from typing import Dict

COSE_ALG_ES384 = -35


class CoseSign1:
    """COSE_Sign1 structure parser."""

    def __init__(self):
        self.protected: bytes = b""
        self.unprotected: Dict = {}
        self.payload: bytes = b""
        self.signature: bytes = b""

    @staticmethod
    def parse(data: bytes) -> "CoseSign1":
        """Parse COSE_Sign1 from raw bytes.

        Args:
            data: Raw CBOR-encoded COSE_Sign1 structure

        Returns:
            CoseSign1 instance

        Raises:
            ValueError: If parsing fails
        """
        try:
            # Decode CBOR array
            decoder = cbor2.CBORDecoder(BytesIO(data))
            value = decoder.decode()
        except Exception as e:
            raise ValueError(f"CBOR parsing failed: {e}")

        if not isinstance(value, list) or len(value) != 4:
            raise ValueError(
                f"Expected COSE_Sign1 array of 4 elements, got {type(value)}"
            )

        cose = CoseSign1()

        # Element 0: protected headers (byte string)
        if not isinstance(value[0], bytes):
            raise ValueError("Protected headers must be bytes")
        cose.protected = value[0]

        # Element 1: unprotected headers (map)
        if not isinstance(value[1], dict):
            raise ValueError("Unprotected headers must be map")
        cose.unprotected = value[1]

        # Element 2: payload (byte string)
        if not isinstance(value[2], bytes):
            raise ValueError("Payload must be bytes")
        cose.payload = value[2]

        # Element 3: signature (byte string, must be 96 bytes for ES384/P-384)
        if not isinstance(value[3], bytes):
            raise ValueError("Signature must be bytes")
        if len(value[3]) != 96:
            raise ValueError(
                f"Signature must be 96 bytes for P-384, got {len(value[3])}"
            )
        cose.signature = value[3]

        return cose

    def validate_headers(self) -> None:
        """Validate COSE headers.

        Raises:
            ValueError: If algorithm is not ES384
        """
        # Decode protected headers
        try:
            decoder = cbor2.CBORDecoder(BytesIO(self.protected))
            protected_map = decoder.decode()
        except Exception as e:
            raise ValueError(f"Failed to parse protected headers: {e}")

        if not isinstance(protected_map, dict):
            raise ValueError("Protected headers must be a map")

        # Check algorithm (key 1 in COSE)
        alg = protected_map.get(1)
        if alg != COSE_ALG_ES384:
            raise ValueError(
                f"Expected algorithm ES384 (-35), got {alg}"
            )

    def get_payload(self) -> bytes:
        """Get the raw payload bytes."""
        return self.payload

    def get_signature(self) -> bytes:
        """Get the raw signature bytes (r || s, 96 bytes for P-384)."""
        return self.signature

    def get_protected_headers(self) -> Dict:
        """Get parsed protected headers."""
        try:
            decoder = cbor2.CBORDecoder(BytesIO(self.protected))
            return decoder.decode()
        except Exception as e:
            raise ValueError(f"Failed to parse protected headers: {e}")

    def get_sig_structure(self) -> bytes:
        """Get the signature structure for verification.

        Constructs: ["Signature1", body_protected, external_aad, payload]

        Returns:
            CBOR-encoded Sig_structure
        """

        sig_structure = [
            "Signature1",
            self.protected,
            b"",  # empty external AAD
            self.payload,
        ]

        # Encode as CBOR
        output = BytesIO()
        encoder = cbor2.CBOREncoder(output)
        encoder.encode(sig_structure)
        return output.getvalue()
