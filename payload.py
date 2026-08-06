"""NitroTPM attestation payload parsing."""

import cbor2
from io import BytesIO
from typing import Dict, List, Optional


class NitroTPMPayload:
    """NitroTPM attestation payload."""

    def __init__(self):
        self.module_id: str = ""
        self.timestamp: int = 0  # Unix milliseconds
        self.digest: str = ""
        self.nitrotpm_pcrs: Dict[int, bytes] = {}
        self.certificate: bytes = b""
        self.cabundle: List[bytes] = []
        self.public_key: Optional[bytes] = None
        self.user_data: Optional[bytes] = None
        self.nonce: Optional[bytes] = None

    @staticmethod
    def from_cbor(data: bytes) -> "NitroTPMPayload":
        """Parse NitroTPM payload from CBOR data.

        Args:
            data: Raw CBOR-encoded payload

        Returns:
            NitroTPMPayload instance

        Raises:
            ValueError: If parsing or validation fails
        """
        try:
            decoder = cbor2.CBORDecoder(BytesIO(data))
            payload_dict = decoder.decode()
        except Exception as e:
            raise ValueError(f"CBOR parsing failed: {e}")

        if not isinstance(payload_dict, dict):
            raise ValueError(f"Expected payload to be a map, got {type(payload_dict)}")

        payload = NitroTPMPayload()

        # Extract required fields
        try:
            payload.module_id = str(payload_dict.get("module_id", ""))
            if not payload.module_id:
                raise ValueError("module_id missing or empty")

            payload.timestamp = int(payload_dict.get("timestamp", 0))
            if payload.timestamp == 0:
                raise ValueError("timestamp missing or zero")

            payload.digest = str(payload_dict.get("digest", ""))
            if payload.digest != "SHA384":
                raise ValueError(f"Unsupported digest: {payload.digest}")

            # Parse PCRs
            pcrs_data = payload_dict.get("nitrotpm_pcrs", {})
            if isinstance(pcrs_data, dict):
                for idx, value in pcrs_data.items():
                    if not isinstance(value, bytes):
                        raise ValueError(f"PCR {idx} value must be bytes")
                    if len(value) != 48:  # SHA384 = 48 bytes
                        raise ValueError(
                            f"PCR {idx} has invalid size {len(value)}, expected 48"
                        )
                    payload.nitrotpm_pcrs[int(idx)] = value

            # Parse certificate
            cert = payload_dict.get("certificate")
            if not isinstance(cert, bytes) or len(cert) == 0:
                raise ValueError("certificate missing or invalid")
            payload.certificate = cert

            # Parse CA bundle
            cabundle = payload_dict.get("cabundle", [])
            if not isinstance(cabundle, list):
                raise ValueError("cabundle must be a list")
            for idx, cert_bytes in enumerate(cabundle):
                if not isinstance(cert_bytes, bytes):
                    raise ValueError(f"cabundle[{idx}] must be bytes")
                payload.cabundle.append(cert_bytes)

            if not payload.cabundle:
                raise ValueError("cabundle is empty")

            # Parse optional fields
            public_key = payload_dict.get("public_key")
            if public_key is not None:
                if not isinstance(public_key, bytes):
                    raise ValueError("public_key must be bytes")
                payload.public_key = public_key

            user_data = payload_dict.get("user_data")
            if user_data is not None:
                if not isinstance(user_data, bytes):
                    raise ValueError("user_data must be bytes")
                payload.user_data = user_data

            nonce = payload_dict.get("nonce")
            if nonce is not None:
                if not isinstance(nonce, bytes):
                    raise ValueError("nonce must be bytes")
                payload.nonce = nonce

        except (KeyError, ValueError, TypeError) as e:
            raise ValueError(f"Field parsing error: {e}")

        return payload

    def validate(self) -> None:
        """Validate payload fields.

        Raises:
            ValueError: If validation fails
        """
        if not self.module_id:
            raise ValueError("module_id cannot be empty")

        if self.timestamp <= 0:
            raise ValueError("timestamp must be positive")

        if self.digest != "SHA384":
            raise ValueError(f"Unsupported digest: {self.digest}")

        # Validate PCRs
        for idx, value in self.nitrotpm_pcrs.items():
            if idx > 23:
                raise ValueError(f"Invalid PCR index: {idx}")
            if len(value) != 48:
                raise ValueError(
                    f"PCR {idx} invalid size: {len(value)}, expected 48"
                )

        if not self.certificate:
            raise ValueError("certificate cannot be empty")

        if not self.cabundle:
            raise ValueError("cabundle cannot be empty")

        # Validate optional field sizes (AWS documented limits)
        if self.nonce and len(self.nonce) > 64:
            raise ValueError(f"nonce size {len(self.nonce)} exceeds limit of 64")

        if self.user_data and len(self.user_data) > 512:
            raise ValueError(
                f"user_data size {len(self.user_data)} exceeds limit of 512"
            )
