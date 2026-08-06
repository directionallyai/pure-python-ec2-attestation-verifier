# NitroTPM Attestation Verifier

Pure Python verifier for AWS EC2 **NitroTPM Attestation Documents** using pure Python crypto (tlslite-ng). Validates that attestation documents are authentic, unmodified, and match expected state.

## What is NitroTPM?

**NitroTPM** is AWS's Trusted Platform Module that proves:
- The instance boot chain (firmware, bootloader, kernel) hasn't been tampered with
- Platform state (secure boot, measurements) is as configured
- The running system is authentic

## Features

- ✅ COSE_Sign1 envelope parsing (CBOR)
- ✅ X.509 certificate chain validation with root pinning
- ✅ ECDSA P-384 signature verification (ES384)
- ✅ Attestation payload parsing (PCRs, timestamps, nonce)
- ✅ Optional policy enforcement (PCR, nonce, freshness checks)
- ✅ Pure Python crypto - no OpenSSL or C extensions

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install .
```

## Usage

### Basic Verification

```python
from verifier import verify_nitrotpm_attestation
from datetime import datetime, timezone

# Load and verify
with open("document.bin", "rb") as f:
    document = f.read()

result = verify_nitrotpm_attestation(
    document,
    now=datetime.now(timezone.utc),
)

# Check results
if result.cose_signature_valid and result.certificate_chain_valid:
    print("✓ Attestation is authentic!")
else:
    print("✗ Verification failed:")
    for error in result.errors:
        print(f"  - {error}")
```

### With Policy Checks

```python
from verifier import verify_nitrotpm_attestation
from datetime import datetime, timezone, timedelta

result = verify_nitrotpm_attestation(
    document,
    expected_nonce=b"\x12\x34...",
    expected_pcrs={
        0: b"\x00...",  # Firmware measurement
        7: b"\xff...",  # Secure Boot state
    },
    now=datetime.now(timezone.utc),
    max_age=timedelta(hours=1),
)

print(f"Signature: {result.cose_signature_valid}")
print(f"Certs: {result.certificate_chain_valid}")
print(f"Nonce: {result.nonce_match}")
print(f"PCRs: {result.pcr_matches}")
print(f"Fresh: {result.timestamp_fresh}")
```

## Architecture

```
nitrotpm-verifier/
├── cose.py           # COSE_Sign1 envelope parsing
├── payload.py        # Attestation payload extraction
├── certificates.py   # X.509 certificate validation
├── signature.py      # ECDSA signature verification
├── verifier.py       # Main orchestrator
├── errors.py         # Exception types
├── example.py        # Usage example
└── pyproject.toml    # Dependencies
```

## Verification Flow

1. **Parse COSE envelope** - Deserialize CBOR to extract payload and signature
2. **Validate COSE headers** - Verify ES384 algorithm
3. **Parse payload** - Extract PCRs, module ID, timestamp, certificates
4. **Validate certificate chain** - Check dates, verify pinned AWS root
5. **Verify signature** - ECDSA P-384 verification with SHA-384
6. **Check nonce** (optional) - Verify challenge matches
7. **Check PCRs** (optional) - Verify platform measurements match
8. **Check timestamp** (optional) - Ensure document is fresh
