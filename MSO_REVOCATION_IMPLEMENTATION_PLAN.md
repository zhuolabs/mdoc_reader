# MSO Revocation Implementation Plan

## Scope

This plan covers implementation of ISO/IEC 18013-5 second-edition working draft section `12.3.6 MSO revocation`.

Implementation split:

- Data model additions and CBOR/CWT decoding types: `mdoc-core`
- Network access, certificate selection, signature/path validation, and revocation decision logic: `mdoc-security`

## Specification Baseline

Relevant sections in the working draft:

- `12.3.6.1` Introduction
- `12.3.6.2` Status structure in the MSO
- `12.3.6.3` MSO revocation list
- `12.3.6.4` Identifier list details
- `12.3.6.5` Status list details

Key requirements to implement:

- MSO revocation is optional for the reader, but if performed it shall follow the Token Status List verification requirements plus the ISO-specific rules.
- The MSO `status` element may carry either `identifier_list` or `status_list`.
- `identifier_list.certificate` or `status_list.certificate`, if present, is the trust point for the revocation-list `x5chain`.
- If that certificate is absent, the top-level certificate in the revocation-list `x5chain` shall chain to the certificate that signed the MSO signer certificate. In mDL deployments, this is the IACA certificate.
- The revocation list itself is a `COSE_Sign1` CWT and must contain:
  - `exp`
  - protected-header `x5chain`
  - one of the allowed signature algorithms already used elsewhere in the project
- Identifier-list specific rules:
  - content type / type is `application/identifierlist+cwt`
  - claim key `65530` contains `IdentifierList`
  - presence of the identifier means the MSO is revoked
- Status-list specific rules:
  - `StatusListInfo` follows the Token Status List structure
  - `bits` must be `1`
  - only revoked / not revoked semantics are needed for mDL

## Current Codebase Status

Already present in `mdoc-core`:

- `MobileSecurityObject.status`
- `Status`
- `IdentifierListInfo`
- `StatusListInfo`

Already present in `mdoc-security`:

- `VerifiedMso`
- MSO signature verification
- issuer certificate extraction from `issuerAuth`
- certificate-chain validation helpers and download utilities

This means the missing work is not in the MSO itself. The missing work is the externally hosted revocation-list model and the validation flow around it.

## `b02c` Compatibility Check

The saved `b02c` file appears to be a real identifier-list example and is structurally compatible with the ISO model:

- top level is `COSE_Sign1`
- protected header includes:
  - `alg`
  - content type set to `identifierlist+cwt`
  - `x5chain`
- payload is a CWT-like claims map
- claims include:
  - `2` => URI
  - `4` => expiration time
  - `6` => issued-at time
  - `65530` => identifier-list claim
  - `65534` => TTL
- the `65530` claim contains an `identifiers` map whose keys are binary identifiers

Observed interoperability note:

- The ISO text says `application/identifierlist+cwt`, while the captured `b02c` protected content type is `identifierlist+cwt`.
- The implementation should therefore normalize and accept both representations when parsing, while keeping the ISO value as the canonical target in our own validation rules and documentation.

## Proposed `mdoc-core` Additions

Add a new module, for example `mso_revocation.rs`, that contains only decoding-friendly data structures.

This plan assumes implementation through Phase 2:

- Phase 1: identifier-list support
- Phase 2: status-list support

### Planned structures for `mdoc-core`

The following structures are expected to be added on the `mdoc-core` side.

#### Shared token wrapper

- `MsoRevocationToken`
  - decoded payload of the downloaded revocation-list CWT
  - common claims only
  - proposed fields:
    - `iss: Option<String>`
    - `sub: Option<String>`
    - `uri: Option<String>` from claim `2`
    - `exp: u64` from claim `4`
    - `iat: Option<u64>` from claim `6`
    - `ttl: Option<u64>` from claim `65534`
    - `kind: MsoRevocationTokenKind`

- `MsoRevocationTokenKind`
  - `IdentifierList(IdentifierList)`
  - `StatusList(StatusList)`

This wrapper is intentionally limited to claims that are needed for Phase 1 and Phase 2 validation. It does not need to model the full Token Status List specification up front.

#### Phase 1: identifier-list structures

- `IdentifierList`
  - corresponds to ISO `12.3.6.4`
  - proposed fields:
    - `identifiers: BTreeMap<Identifier, IdentifierInfo>`
    - `aggregation_uri: Option<String>`

- `IdentifierInfo`
  - empty struct
  - this project does not need RFU handling for Phase 1

The current `Identifier` alias in `mobile_security_object.rs` can be reused for identifier-list keys.

#### Phase 2: status-list structures

- `StatusList`
  - wrapper for the Token Status List claim content needed by this project
  - proposed fields:
    - `bits: u64`
    - `lst: ByteVec` or equivalent raw bytes field for the compressed status-list payload
    - `aggregation_uri: Option<String>`

- `StatusValue`
  - optional helper enum used after decoding a single entry:
    - `Valid`
    - `Invalid`

- `StatusListView` or equivalent helper type
  - small decoding helper that can read the status bit for a given `idx`
  - this can stay in `mdoc-core` if implemented as pure parsing logic, or move to `mdoc-security` if we want to keep `mdoc-core` strictly as wire-format types

For Phase 2, the implementation target is intentionally narrow:

- support the subset needed by ISO `12.3.6.5`
- require `bits == 1`
- support only revoked / not revoked semantics for mDL

### Compression handling for `StatusList`

The `lst` field should be treated as compressed data and must be decompressed before bit lookup.

Planned crate:

- `flate2`

Planned dependency form in `mdoc-security`:

```toml
flate2 = { version = "1", default-features = false, features = ["rust_backend"] }
```

Reason for choosing `flate2`:

- it supports the zlib format directly
- it provides streaming decompression APIs, which fit security-sensitive input handling better than unbounded one-shot decompression
- with `rust_backend`, it stays pure Rust and does not require a C toolchain
- this matches the current project style, which already prefers portable Rust-native dependencies such as `reqwest` with `rustls`

Planned usage:

- decode `StatusList.lst` with `flate2::read::ZlibDecoder`
- stream into a bounded buffer
- reject payloads that exceed an explicit decompressed-size limit
- after decompression, read the bit at `StatusListInfo.idx`

Not selected:

- `miniz_oxide` direct one-shot helpers
  - they can decompress zlib-wrapped data
  - however, their own documentation warns that `decompress_to_vec_zlib` is unbounded and suggests using functions with limits or preferably streaming decompression via `flate2`

### Why these belong in `mdoc-core`

- They are pure data definitions.
- They can be CBOR-decoded without network or PKI logic.
- They keep the revocation wire format reusable for tests and future tooling.
- They let `mdoc-security` focus on validation flow instead of CBOR schema details.

### Simplicity rule

For this implementation plan, RFU fields and unknown extension fields are ignored.

- `IdentifierInfo` is treated as an empty structure
- only the claims and fields required for Phase 1 and Phase 2 are modeled
- forward-compatible preservation of unknown fields is out of scope

## Proposed `mdoc-security` API

Add a new module, for example `mso_revocation.rs`.

Suggested public entry point:

```rust
pub async fn check_mso_revocation(
    verified_mso: &VerifiedMso,
    iaca_cert: &x509_cert::Certificate,
    now: DateTime<Utc>,
) -> Result<MsoRevocationCheck, MsoRevocationError>
```

Suggested result model:

```rust
pub enum MsoRevocationState {
    NotChecked,
    NotRevoked,
    Revoked,
}

pub struct MsoRevocationCheck {
    pub state: MsoRevocationState,
    pub source_uri: Option<url::Url>,
    pub mechanism: Option<MsoRevocationMechanism>,
}
```

Suggested mechanism enum:

```rust
pub enum MsoRevocationMechanism {
    IdentifierList,
    StatusList,
}
```

Suggested error categories:

- missing `status`
- both `identifier_list` and `status_list` present
- unsupported or malformed URI
- download failure
- invalid COSE structure
- missing required claims
- unsupported content type
- missing `x5chain`
- invalid revocation-list certificate chain
- invalid signature
- expired revocation list
- malformed identifier list
- malformed status list

## Validation Flow

### 1. Select mechanism from MSO

- Read `verified_mso.mso.status`.
- Require exactly one of:
  - `identifier_list`
  - `status_list`

### 2. Download the revocation list

- Parse the URI from the selected status info.
- Reuse the existing `reqwest`/`rustls` approach already used for certificate and CRL download.
- Keep the first implementation HTTPS-only.
- Add response size limits and explicit timeouts.

### 3. Decode and verify `COSE_Sign1`

- Decode the downloaded bytes as `CoseSign1`.
- Read protected header:
  - `alg`
  - content type
  - `x5chain`
- Decode the payload into the new `mdoc-core` revocation claims model.

### 4. Choose trust point according to `12.3.6.2`

- If `status_info.certificate` is present:
  - decode it as X.509
  - use it as the trust point for validating the revocation-list `x5chain`
- Otherwise:
  - use the provided `iaca_cert`
  - require the revocation-list signer chain to anchor there

### 5. Validate certificate chain and signature

- Validate the revocation-list `x5chain` against the selected trust point.
- Verify the `COSE_Sign1` signature using the leaf certificate in that `x5chain`.

### Reuse of `certificate_validation.rs`

The existing `certificate_validation.rs` implementation is reusable as a base, but not as a complete drop-in solution.

What can be reused directly:

- parsing and loading X.509 certificates
- date validity checks
- issuer/subject chain linkage checks
- basic CA / non-CA checks
- the general async validation flow already used by `validate_x5chain`

What needs adaptation for MSO revocation lists:

- `validate_document_x5chain()` is not directly usable because it is tied to `issuerAuth`
- revocation-list validation needs a new entry point that accepts:
  - the revocation-list `x5chain`
  - the trust point selected from `status_info.certificate` or fallback `iaca_cert`
- the trust anchor semantics are slightly different from document-signer validation:
  - the revocation-list signer chain anchors at the status certificate if present
  - otherwise it anchors at the certificate above the MSO signer chain, which in mDL is the IACA certificate
- the revocation-list certificate profile may later need extra checks specific to Token Status List signing certificates

Recommended approach:

- reuse `validate_x5chain()` for the actual chain validation logic
- add a new helper in `mdoc-security` for revocation-list validation, for example:

```rust
pub async fn validate_revocation_list_x5chain(
    trust_point: &x509_cert::Certificate,
    x5chain: &[x509_cert::Certificate],
    now: SystemTime,
) -> Result<CertificateValidationOutcome, ValidationError>
```

- keep the first implementation aligned with the current `certificate_validation.rs` strictness
- document that stricter Token Status List profile checks can be added later if needed

### 6. Validate common claims

- `exp` must exist and must be in the future relative to `now`
- `ttl` may exist and should be exposed for later caching policy
- `aggregation_uri` may exist but can be ignored in the first implementation

### 7. Apply mechanism-specific decision

Identifier list:

- Look up `IdentifierListInfo.id` in `IdentifierList.identifiers`
- present => `Revoked`
- absent => `NotRevoked`

Status list:

- Read `StatusListInfo.idx`
- Decode the status-list bit representation
- Require `bits == 1`
- read the single-bit status at `idx`
- `1` => `Revoked`
- `0` => `NotRevoked`

## Recommended Delivery Order

### Phase 1: Identifier list only

This should be implemented first because:

- the project already has a real captured example in `b02c`
- the MSO already exposes `IdentifierListInfo`
- the revocation decision is simple membership lookup

Deliverables:

- `mdoc-core` identifier-list token model
- parser for downloaded identifier list
- signature and certificate validation path
- membership-based revocation decision
- tests using `b02c` as a fixture

### Phase 2: Status list support

Deliverables:

- `mdoc-core` status-list token model
- decoding of the Token Status List payload
- zlib decompression of `lst` using `flate2`
- `bits == 1` enforcement
- index lookup logic

### Phase 3: Operational hardening

Deliverables:

- caching based on `ttl`
- optional aggregation support
- configurable fail-open / fail-closed behavior
- tighter media-type and claim validation
- metrics / tracing hooks

## Test Plan

### `mdoc-core`

- round-trip decode/encode for `IdentifierList`
- decode test from captured `b02c`
- malformed payload coverage:
  - missing `65530`
  - missing `identifiers`
  - wrong identifier key type

### `mdoc-security`

- identifier list present and identifier found => revoked
- identifier list present and identifier absent => not revoked
- certificate source from `IdentifierListInfo.certificate`
- fallback certificate source from IACA certificate
- expired revocation list rejected
- invalid `x5chain` rejected
- invalid signature rejected
- missing status info returns explicit not-checked / unsupported outcome

### Fixtures

- keep `b02c` as a fixture for a real identifier-list example
- add synthetic fixtures for:
  - identifier absent
  - broken signature
  - alternate trust-point source

## Open Design Decisions

- Whether absence of `status` should return `NotChecked` or an error
- Whether download failure should be fail-open or fail-closed
- Whether strict ISO media-type checking should reject `identifierlist+cwt` without the `application/` prefix
- How much of the Token Status List aggregation mechanism should be implemented in the first release

## Recommendation

Implement identifier-list support first and make it production-quality before adding status-list support.

The captured `b02c` sample is sufficient to drive the first milestone. It already confirms that the current MSO-side `IdentifierListInfo { id, uri, certificate }` shape is aligned with the ISO structure, and that the missing work is the downloaded revocation-list token model plus the verification pipeline in `mdoc-security`.
