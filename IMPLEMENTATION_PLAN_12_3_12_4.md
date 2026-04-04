# DeviceResponse Verification Implementation Plan (ISO/IEC 18013-5, Clause 12)

Target crate: `crates/mdoc-core`

## 0. Assumptions and review outcome

- We assume the MSO-related data structures are already in place in the current codebase.
- This document focuses on the **next implementation steps** for:
  - **12.3 Issuer Data Authentication**
  - **12.4 mdoc authentication**

Key mandatory points to keep spec alignment:

- COSE `Sig_structure` verification behavior must be explicit
- Strict `tdate`/UTC timestamp validation is required
- Digest input must be tagged `IssuerSignedItemBytes` (CBOR tag 24)
- `DeviceAuth` must enforce XOR (`deviceSignature` xor `deviceMac`)
- `KeyAuthorizations` checks are required for `DeviceSigned`

---

## 1. Implementation scope for upcoming work

### 1.1 Clause 12.3 Issuer Data Authentication

- Verify `issuerSigned.issuerAuth` (`COSE_Sign1`)
- Decode payload into `MobileSecurityObject`
- Validate `validityInfo`:
  - `validFrom <= validUntil`
  - `validFrom <= now <= validUntil`
- Validate `mso.docType == document.docType`
- Validate `valueDigests` against returned `IssuerSignedItemBytes`
- Root CA trust anchor validation: deferred as TODO (as requested)

### 1.2 Clause 12.4 mdoc authentication

- Verify `DeviceSigned`
- Enforce `deviceSignature` vs `deviceMac` XOR mode
- Implement `deviceSignature` (`COSE_Sign1`) verification first
- Validate `KeyAuthorizations` for all returned `DeviceSigned` elements
- Add staged `deviceMac` verification interface; keep explicit TODO behavior where key-material integration is missing

---

## 2. Module update plan by phase (when each module is touched)

This section answers "when" each module is updated, split by 12.3 and 12.4.

### 2.1 Phase A — 12.3 implementation

**Primary modules to update in this phase**

1. `crates/mdoc-core/src/issuer_data_auth.rs` (new)
   - Add 12.3 entrypoint, context type, error type, verification flow
2. `crates/mdoc-core/src/cose_sign.rs`
   - Add/reuse COSE signature verification utilities for `IssuerAuth`
3. `crates/mdoc-core/src/lib.rs`
   - Export `issuer_data_auth`

**Optional support updates in Phase A (only if needed)**

- `crates/mdoc-core/src/mobile_security_object.rs`
  - Timestamp parsing helpers

### 2.2 Phase B — 12.4 implementation

**Primary modules to update in this phase**

1. `crates/mdoc-core/src/mdoc_auth.rs` (new)
   - Add 12.4 entrypoint, context type, error type, verification flow
2. `crates/mdoc-core/src/cose_sign.rs`
   - Reuse/extend signature verification utilities for `deviceSignature`
3. `crates/mdoc-core/src/device_response.rs`
   - Add `DeviceAuth` mode validation helpers (XOR checks)
4. `crates/mdoc-core/src/lib.rs`
   - Export `mdoc_auth`

**Follow-up in Phase B**

- Add `deviceMac` API + explicit unimplemented path until session key handoff is finalized

---

## 3. Detailed implementation plan for 12.3

### 3.1 APIs

In `issuer_data_auth.rs`:

- `pub struct IssuerDataAuthContext { pub now: DateTime<Utc>, pub expected_doc_type: Option<String> }`
- `pub fn verify_issuer_data_auth(doc: &MdocDocument, ctx: &IssuerDataAuthContext) -> Result<VerifiedMso, IssuerDataAuthError>`
- `pub struct VerifiedMso { pub mso: MobileSecurityObject, pub issuer_cert: Option<x509_cert::Certificate> }`

### 3.2 Verification steps

1. Decode `issuerAuth.payload` to `MobileSecurityObject`
2. Validate `alg` consistency in protected/unprotected headers
3. Extract document signer certificate from `x5chain` (minimum one cert)
4. Verify `COSE_Sign1` using `Sig_structure`
   - `context = "Signature1"`
   - `external_aad = b""`
   - `payload = MobileSecurityObjectBytes`
5. Keep Root CA validation as explicit TODO for this phase

### 3.3 Semantic checks

- `docType` consistency: `mso.docType == document.docType`
- Strict timestamp parse (`tdate` / RFC3339)
- Check:
  - `validFrom <= validUntil`
  - `validFrom <= now <= validUntil`

### 3.4 Digest checks

1. Treat missing `issuer_signed.name_spaces` as empty
2. For each returned `IssuerSignedItem`, hash exact tagged bytes (`IssuerSignedItemBytes`)
3. Lookup digest by `(namespace, digestID)`
4. Compare against `mso.valueDigests`
5. Policy:
   - returned item without matching digest -> error
   - digest without returned item -> allowed (selective disclosure)

### 3.5 Digest algorithms

- Implement `SHA-256` first
- Return `UnsupportedDigestAlgorithm` for unsupported algorithms

---

## 4. Detailed implementation plan for 12.4

### 4.1 APIs

In `mdoc_auth.rs`:

- `pub struct MdocAuthContext { pub session_transcript: SessionTranscript, pub verified_mso: VerifiedMso, pub reader_ephemeral_pubkey: Option<CoseKeyPublic>, pub allow_mac: bool }`
- `pub fn verify_mdoc_auth(doc: &MdocDocument, ctx: &MdocAuthContext) -> Result<(), MdocAuthError>`

### 4.2 DeviceAuth mode checks

- Reject if both `deviceSignature` and `deviceMac` are present
- Reject if neither is present

### 4.3 Build `DeviceAuthentication`

- `DeviceAuthentication = [ "DeviceAuthentication", SessionTranscript, docType, deviceNameSpacesBytes ]`
- Signature/MAC input is CBOR bytes of this structure
- `deviceNameSpacesBytes` from encoded `TaggedCborBytes<DeviceNameSpaces>`

### 4.4 `deviceSignature` verification

1. Verification key: `verified_mso.mso.device_key_info.device_key`
2. Validate payload equality: `COSE_Sign1.payload == DeviceAuthenticationBytes`
3. Verify signature with COSE `Sig_structure`
4. Check algorithm/key-type compatibility

### 4.5 `deviceMac` staged delivery

- Add type/interface in this phase
- Add explicit `UnimplementedDeviceMac` path until key-material integration is complete

### 4.6 `KeyAuthorizations` checks

- Read `mso.device_key_info.key_authorizations`
- Verify every returned `DeviceSigned` namespace/element is authorized
- Return error for unauthorized elements

---

## 5. Error model

`IssuerDataAuthError`:

- `MissingIssuerAuthPayload`
- `IssuerSignatureInvalid`
- `MissingX5Chain`
- `MsoDocTypeMismatch`
- `ValidityTimeParseError`
- `MsoNotYetValid`
- `MsoExpired`
- `DigestMismatch { namespace, digest_id }`
- `UnsupportedDigestAlgorithm(String)`

`MdocAuthError`:

- `DeviceAuthModeInvalid`
- `DeviceSignatureInvalid`
- `DeviceAuthPayloadMismatch`
- `UnauthorizedDeviceSignedElement { namespace, element_identifier }`
- `UnimplementedDeviceMac`

---

## 6. Ordered delivery plan (milestones)

1. **Milestone A (12.3)**
   - `issuer_data_auth.rs` skeleton + API + errors
   - `IssuerAuth` signature verification + MSO semantic checks + digest checks
2. **Milestone B (12.4 signature path)**
   - `mdoc_auth.rs` skeleton + API + errors
   - `DeviceAuth` XOR + `deviceSignature` verification + `KeyAuthorizations` checks
3. **Milestone C (12.4 MAC path)**
   - `deviceMac` interface hardening + key handoff integration

---

## 7. Test plan

### 7.1 For 12.3

- Success: signature valid + validity window valid + digest match
- Failures:
  - signature mismatch
  - invalid validity window (`now < validFrom`, `now > validUntil`, `validFrom > validUntil`)
  - digest mismatch
  - `docType` mismatch

### 7.2 For 12.4

- Success: valid `deviceSignature`
- Failures:
  - XOR violation (`deviceSignature` / `deviceMac`)
  - payload mismatch
  - unauthorized element (`KeyAuthorizations`)

Test locations:
- `crates/mdoc-core/src/issuer_data_auth.rs` (`#[cfg(test)]`)
- `crates/mdoc-core/src/mdoc_auth.rs` (`#[cfg(test)]`)
- Reuse Annex D vectors when possible

---

## 8. Final note

This plan intentionally starts **after MSO struct definition**, and is now split clearly into:

- work to do in **12.3**,
- work to do in **12.4**,
- and **when** each module is updated in each phase.
