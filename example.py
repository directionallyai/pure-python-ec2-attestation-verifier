#!/usr/bin/env python3
"""Simple example of using NitroTPM verifier."""

from pathlib import Path
from datetime import datetime, timezone
from verifier import verify_nitrotpm_attestation

# Load AWS NitroTPM attestation document
doc_path = Path(__file__).parent / "tests" / "fixtures" / "aws_nitrotpm_doc.bin"
with open(doc_path, "rb") as f:
    document = f.read()

print(f"Document size: {len(document)} bytes")

# Verify with a timestamp in the certificate's validity period
verification_time = datetime(2026, 6, 18, 6, 0, 0, tzinfo=timezone.utc)

result = verify_nitrotpm_attestation(
    document,
    now=verification_time,
)

# Print results
print("\n" + "="*60)
print("VERIFICATION RESULTS")
print("="*60)
print(f"✓ Payload valid: {result.payload_valid}")
print(f"✓ Certificate chain valid: {result.certificate_chain_valid}")
print(f"✓ COSE signature valid: {result.cose_signature_valid}")
print(f"✓ Overall valid: {result.is_valid}")

if result.errors:
    print(f"\n✗ Errors ({len(result.errors)}):")
    for error in result.errors:
        print(f"  - {error}")
else:
    print("\n✓ No errors - Attestation verified successfully!")
