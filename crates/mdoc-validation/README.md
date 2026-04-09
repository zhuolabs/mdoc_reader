# mdoc-validation Crate

## Purpose

`mdoc-validation` provides validation logic for:

1. **Reader authentication certificate validation** aligned with ISO/IEC 18013-5 section 12.8.3.
2. **MSO revocation checks** aligned with ISO/IEC 18013-5 section 12.3.6 (planned, not implemented yet).

This document keeps both:
- the **current implementation status**, and
- the **future plan** for remaining specification coverage.

## Standards Reference

Primary reference:
- ISO working draft: https://github.com/ISOWG10/ISO-18013/blob/main/Working%20Documents/Working%20Draft%20ISO_IEC_18013-5_second-edition_CD_ballot_resolution_v4.pdf

Important sections:
- 12.8.3: inspection procedure for mdoc reader authentication certificate validation
- 12.3.6: MSO revocation
- 12.3.6.2: certificate source rules for status checks
- Annex B.3.2: CRL validation example

---

## #1 `certificate_validation`

### Goal
Validate an mdoc reader authentication certificate chain (`x5chain`) against an IACA root certificate (`iacacert`) provided as DER.

### Inputs
- `iacacert_der: &[u8]`
- `x5chain: &[Vec<u8>]` (leaf first)
- `now: SystemTime`

### Current implementation status

Implemented in this repository:

- `download_iacacert_der(iacacert_url: Url) -> Result<Vec<u8>, ValidationError>`
  - HTTPS-only download.
  - `reqwest` + `rustls` + native roots.
  - timeout and status checks.
- `validate_reader_auth_certificate(iacacert_der, x5chain, now)`
  - DER parse for IACA + chain certificates.
  - validity period checks (`notBefore` / `notAfter`).
  - chain linkage checks via issuer/subject matching.
  - basic constraints checks (CA/non-CA consistency).
  - leaf keyUsage check (`digitalSignature`) when extension exists.
  - CRL Distribution Point extraction from IACA.
  - CRL download + parse + leaf serial revocation match check.

### Not implemented yet (deferred)

To keep first implementation manageable, the following are intentionally deferred:

- cryptographic signature verification for each chain hop.
- full ISO profile checks for EKU/OID requirements specific to mdoc reader auth.
- strict CRL issuer/signature/validity-time validation as described in Annex B.3.2.
- multiple CRL endpoint processing and advanced fallback policy.
- OCSP support.

### Output

Current output types:
- `CertificateValidationOutcome::Valid { crl_checked: bool }`
- `ValidationError::{CertificateParse, CrlParse, InvalidChain, Expired, Revoked, CrlUnavailable, Network, Unsupported}`

---

## #2 `mso_revocation_check`

### Goal (planned)
Implement MSO revocation logic based on section 12.3.6 using `VerifiedMso` and `iacacert`.

### Planned inputs
- `verified_mso: VerifiedMso`
- `iacacert_der: &[u8]`

### Planned behavior (12.3.6.2)
1. Extract status endpoint URL from `Status` in MSO.
2. Access status endpoint.
3. Select certificate source for status verification:
   - certificate in MSO status info if present,
   - otherwise fallback to IACA certificate.

### Planned formats
- `identifier_list`
- `status_list`

### Current status
- Not implemented yet.

---

## Dependency notes

Current dependencies:
- `reqwest` (`blocking`, `rustls-tls`, `rustls-tls-native-roots`)
- `x509-parser`
- `thiserror`
- `url`
- `time`

Future candidates (if needed):
- dedicated certificate-path validation backend
- stricter CRL verification helpers
- optional tracing/metrics integration

---

## Additional concerns (future plan)

- HTTP caching / freshness policy for CRL/status responses.
- Clock skew policy for cert/CRL checks.
- Configurable fail-open vs fail-closed policy.
- Max-size limits for downloaded payloads.
- Content-type and encoding validation.
- Stable and deterministic error taxonomy for integrators.

---

## Security and robustness considerations

- Keep HTTPS requirement for remote certificate/CRL/status endpoints unless spec requires otherwise.
- Keep network timeout and add explicit payload size limits.
- Handle malformed ASN.1/DER defensively.
- Make offline/network-failure behavior explicit via typed errors.

---

## Test plan (remaining)

- Unit tests
  - valid / invalid / expired chain
  - CRL present: revoked / not revoked
  - CRL endpoint unavailable
- Integration tests
  - mocked HTTP for iacacert/CRL/status endpoints
  - certificate-source selection behavior for status responses
- Cross-platform checks
  - HTTPS native root behavior on Windows

