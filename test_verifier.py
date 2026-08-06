#!/usr/bin/env python3
"""Test NitroTPM verifier with real AWS document."""

import sys
from pathlib import Path
from datetime import datetime, timezone

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from verifier import verify_nitrotpm_attestation


def test_real_document():
    """Test with real AWS NitroTPM attestation document."""

    # Load test document from Reclaim Protocol
    doc_path = Path(__file__).parent.parent / "attestation-verifier" / "tests" / "fixtures" / "aws_nitrotpm_doc.bin"

    if not doc_path.exists():
        print(f"Test document not found at {doc_path}")
        print("Trying alternative path...")
        doc_path = Path("/home/dymchenko/compiler/attestation-verifier/tests/fixtures/aws_nitrotpm_doc.bin")

    if not doc_path.exists():
        print(f"Test document not found. Please ensure the fixture exists at {doc_path}")
        return False

    print(f"Loading document from: {doc_path}")
    with open(doc_path, "rb") as f:
        document = f.read()

    print(f"Document size: {len(document)} bytes")
    print(f"First 32 bytes (hex): {document[:32].hex()}")

    # Use a time within the certificate's validity period
    # Certificate valid from 2026-06-18 05:10:46 to 2026-06-18 08:10:49
    # Use 2026-06-18 06:00:00 UTC (middle of validity period)
    expected_time = datetime(2026, 6, 18, 6, 0, 0, tzinfo=timezone.utc)

    print(f"\nUsing verification time: {expected_time} (within cert validity period)")

    # Verify document
    print("\n" + "=" * 60)
    print("VERIFYING ATTESTATION DOCUMENT")
    print("=" * 60)

    result = verify_nitrotpm_attestation(
        document,
        expected_nonce=None,
        expected_pcrs=None,
        now=expected_time,
        max_age=None,
    )

    # Print results
    print(f"\nPayload valid: {result.payload_valid}")
    print(f"Certificate chain valid: {result.certificate_chain_valid}")
    print(f"COSE signature valid: {result.cose_signature_valid}")
    print(f"Nonce match: {result.nonce_match}")
    print(f"PCR matches: {result.pcr_matches}")
    print(f"Timestamp fresh: {result.timestamp_fresh}")

    if result.errors:
        print(f"\nErrors ({len(result.errors)}):")
        for i, error in enumerate(result.errors, 1):
            print(f"  {i}. {error}")
    else:
        print("\n✓ No errors!")

    # Return success if basic parsing worked
    return result.payload_valid


if __name__ == "__main__":
    success = test_real_document()
    sys.exit(0 if success else 1)
