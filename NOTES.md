# Implementation Notes

Design choices made while building this verifier, and the sources they're
based on. Written so a future reader (or auditor) doesn't have to re-derive
"why" from the code alone.

## Primary sources

- [Validate a NitroTPM Attestation Document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-validate.html) —
  attestation document structure, COSE_Sign1 layout, CA bundle ordering,
  root certificate fingerprint, "CRL must be disabled" note.
- [NitroTPM Attestation Document contents](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-content.html) —
  CDDL schema (field names, types, size bounds), PCR semantics.
- AWS Nitro Enclaves attestation documentation (sibling spec, same COSE/CBOR
  shape) — used only where the NitroTPM guide is silent (see "Key usage
  enforcement" below).
- `tests/fixtures/aws_nitrotpm_doc.bin` — one real, captured attestation
  document, used to validate the full parse → chain → signature path against
  actual bytes rather than only hand-built fixtures.

## Why pure Python (no OpenSSL)

`certvalidator`/`oscrypto`, the usual choice for X.509 path validation in
Python, shell out to the system's `libcrypto` via `ctypes`. That's not
actually pure Python and pulls in a runtime dependency on whatever OpenSSL
happens to be installed. Instead:

- `asn1crypto` for certificate *structure* parsing only (no crypto
  operations performed by that library).
- `tlslite-ng` / `ecdsa` for the actual ECDSA math (signature verification,
  DER signature encoding).

## Root pinning

The AWS Nitro root cert is pinned by SHA-256 fingerprint
(`641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B`),
copied verbatim from the AWS validation guide, rather than trusted via a
downloaded/bundled root cert file. This avoids taking a dependency on any
CA bundle or trust store and matches AWS's own suggested pinning value
exactly (confirmed byte-for-byte against the doc — see
`certificates.py:34`).

## CA bundle chain reconstruction

AWS documents the `cabundle` field as ordered `[ROOT, INTERM_1, ..., INTERM_N]`
and says the verifier must reassemble it as
`[TARGET_CERT, INTERM_N, ..., INTERM_1, ROOT_CERT]` before path validation.
`CertificateChain.__init__` (`certificates.py:62`) does exactly this
reversal. This ordering is unusual (most CA bundles go leaf-to-root or are
unordered) so it's called out explicitly rather than assumed obvious.

## Revocation checking is deliberately disabled

The AWS guide states plainly: "CRL must be disabled when doing the
validation." No CRL/OCSP checking is implemented. This isn't an oversight —
it's the documented, intended behavior, since Nitro attestation certs are
short-lived and there's no revocation infrastructure for them.

## Key usage / BasicConstraints enforcement

The NitroTPM validation guide describes X.509 path validation in general
terms ("basic constraints and policy constraint extensions allow the
certification path processing logic to automate the decision making
process") but doesn't spell out explicit KeyUsage bit requirements.
BasicConstraints (CA flag, pathLenConstraint) enforcement is standard PKIX
behavior and is implemented directly from that description. KeyUsage
enforcement (`keyCertSign` on CAs, `digitalSignature` on the leaf) goes
beyond what the NitroTPM guide states explicitly — it's borrowed from AWS's
sibling Nitro Enclaves attestation documentation, which does spell this out
for the same COSE/CBOR/cert-chain shape. Flagged in code comments
(`certificates.py:8-14`) as inference, not a guaranteed requirement, so a
future maintainer knows to re-check if AWS updates the NitroTPM-specific
guide.

## Signature verification order (short-circuit on failure)

Verification proceeds: parse COSE envelope → validate COSE headers → parse
payload → validate cert chain → verify COSE signature → *only then* run
optional policy checks (nonce/PCR/freshness). If the signature check fails,
`verifier.py` stops immediately (`verifier.py:132`) rather than continuing
to report nonce/PCR matches. This isn't required by the AWS guide's
four-step outline, but is a deliberate hardening choice: nonce and PCR
bytes read from an unauthenticated payload are attacker-controlled, so
reporting "PCR matched" against forged bytes would be actively misleading.
Covered by
`test_tampered_payload_fails_signature_verification` and
`test_signature_failure_short_circuits_even_with_matching_policy` in
`tests/test_verifier.py`.

## Field size limits

The CDDL in the "contents" doc defines:

```
cert = bytes .size (1..1024)
user_data = bytes .size (0..1024)
pcr = bytes .size (32/48/64)
index = 0..31
digest = "SHA384"
```

`public_key`, `user_data`, and `nonce` are all typed as `user_data` in the
CDDL — i.e. they share one 0..1024-byte bound. An earlier version of this
code enforced invented, stricter limits (nonce ≤ 64 bytes, user_data ≤ 512
bytes, no limit on `public_key`/`certificate`/`cabundle` entries at all).
That was a real bug: a legitimate AWS-issued document with, say, a 200-byte
nonce would have been wrongly rejected. Fixed in `payload.py` to the
spec-correct 1024-byte bound on all five fields (`certificate`, each
`cabundle` entry, `public_key`, `user_data`, `nonce`). PCR values are
required to be exactly 48 bytes rather than accepting the full 32/48/64
CDDL range, because `digest` is pinned to `"SHA384"` (48-byte output) and no
other digest value is currently defined for NitroTPM documents — if AWS
ever adds another digest option this constraint would need loosening
alongside the `digest` check.

## Document size cap

Not something the AWS guide mentions, and not part of the CDDL. Added as a
defensive measure: `CoseSign1.parse` rejects any input over 64 KiB
(`cose.py`) before handing it to the CBOR decoder, so a malicious or
corrupted blob can't force large allocations/CPU time. Real captured
documents are on the order of a few KB (the test fixture is ~4.9 KB), so 64
KiB leaves generous headroom without accepting arbitrary-sized input.

## Known gaps / things not done

- Only one real fixture document is exercised in tests. Chain-validation
  failure branches (bad path length, wrong issuer/subject linkage, etc.)
  are tested via hand-built `CertificateChain`/cert objects, not real
  captured bytes, so coverage of those branches against actual AWS-issued
  DER is thinner than the happy path.
- No `kid` (COSE key id) cross-check against the leaf certificate — checked
  against the real fixture and AWS's own COSE_Sign1 example in the guide,
  where the unprotected header is always `{}`; there's no `kid` field to
  check for this document type, so this isn't a gap in practice.
- Certificates are parsed by two different libraries (`asn1crypto` for
  structure, `tlslite-ng` for the signature math). Not a bug, but the trust
  decision depends on both agreeing on what a given DER blob means.
