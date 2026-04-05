use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::{MdocDocument, MobileSecurityObject};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerDataAuthContext {
    pub now: DateTime<Utc>,
    pub expected_doc_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMso {
    pub mso: MobileSecurityObject,
    pub issuer_cert: Option<x509_cert::Certificate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerDataAuthError {
    MissingIssuerCertificate,
    InvalidIssuerAuth(String),
    InvalidMobileSecurityObject(String),
    DocTypeMismatch {
        expected: String,
        actual: String,
    },
    InvalidTimestamp {
        field: &'static str,
        value: String,
    },
    InvalidValidityRange,
    DocumentNotYetValid {
        now: DateTime<Utc>,
        valid_from: DateTime<Utc>,
    },
    DocumentExpired {
        now: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    UnsupportedDigestAlgorithm(String),
    MissingDigest {
        namespace: String,
        digest_id: u64,
    },
    DigestMismatch {
        namespace: String,
        element_identifier: String,
        digest_id: u64,
    },
}

impl fmt::Display for IssuerDataAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingIssuerCertificate => {
                write!(f, "issuerAuth did not contain a document signer certificate")
            }
            Self::InvalidIssuerAuth(message) => write!(f, "invalid issuerAuth: {message}"),
            Self::InvalidMobileSecurityObject(message) => {
                write!(f, "invalid MobileSecurityObject: {message}")
            }
            Self::DocTypeMismatch { expected, actual } => {
                write!(f, "docType mismatch: expected {expected}, got {actual}")
            }
            Self::InvalidTimestamp { field, value } => {
                write!(f, "invalid RFC3339 timestamp for {field}: {value}")
            }
            Self::InvalidValidityRange => write!(f, "MSO validity range is inverted"),
            Self::DocumentNotYetValid { now, valid_from } => {
                write!(f, "document is not yet valid at {now}; valid_from={valid_from}")
            }
            Self::DocumentExpired { now, valid_until } => {
                write!(f, "document expired at {valid_until}; now={now}")
            }
            Self::UnsupportedDigestAlgorithm(algorithm) => {
                write!(f, "unsupported digest algorithm: {algorithm}")
            }
            Self::MissingDigest {
                namespace,
                digest_id,
            } => write!(f, "missing digest for namespace {namespace} and digestID {digest_id}"),
            Self::DigestMismatch {
                namespace,
                element_identifier,
                digest_id,
            } => write!(
                f,
                "digest mismatch for namespace {namespace}, element {element_identifier}, digestID {digest_id}"
            ),
        }
    }
}

impl std::error::Error for IssuerDataAuthError {}

pub fn verify_issuer_data_auth(
    doc: &MdocDocument,
    ctx: &IssuerDataAuthContext,
) -> Result<VerifiedMso, IssuerDataAuthError> {
    let issuer_auth = &doc.issuer_signed.issuer_auth;
    let mso_bytes = issuer_auth
        .decode_payload_cbor()
        .map_err(|err| IssuerDataAuthError::InvalidIssuerAuth(err.to_string()))?;
    let mso = mso_bytes
        .decode()
        .map_err(|err| IssuerDataAuthError::InvalidMobileSecurityObject(err.to_string()))?;

    let issuer_cert = issuer_auth
        .resolved_document_signer_cert()
        .map_err(|err| IssuerDataAuthError::InvalidIssuerAuth(err.to_string()))?
        .cloned()
        .ok_or(IssuerDataAuthError::MissingIssuerCertificate)?;

    issuer_auth
        .verify_with_certificate(&issuer_cert, b"")
        .map_err(|err| IssuerDataAuthError::InvalidIssuerAuth(err.to_string()))?;

    verify_doc_type(&mso.doc_type, &doc.doc_type)?;
    if let Some(expected_doc_type) = &ctx.expected_doc_type {
        verify_doc_type(&mso.doc_type, expected_doc_type)?;
    }

    verify_validity_info(&mso, ctx.now)?;
    verify_name_space_digests(doc, &mso)?;

    Ok(VerifiedMso {
        mso,
        issuer_cert: Some(issuer_cert),
    })
}

fn verify_doc_type(actual: &str, expected: &str) -> Result<(), IssuerDataAuthError> {
    if actual == expected {
        return Ok(());
    }

    Err(IssuerDataAuthError::DocTypeMismatch {
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

fn verify_validity_info(
    mso: &MobileSecurityObject,
    now: DateTime<Utc>,
) -> Result<(), IssuerDataAuthError> {
    let valid_from = parse_rfc3339("validFrom", mso.validity_info.valid_from.value())?;
    let valid_until = parse_rfc3339("validUntil", mso.validity_info.valid_until.value())?;
    parse_rfc3339("signed", mso.validity_info.signed.value())?;
    if let Some(expected_update) = &mso.validity_info.expected_update {
        parse_rfc3339("expectedUpdate", expected_update.value())?;
    }

    if valid_from > valid_until {
        return Err(IssuerDataAuthError::InvalidValidityRange);
    }

    if now < valid_from {
        return Err(IssuerDataAuthError::DocumentNotYetValid { now, valid_from });
    }

    if now > valid_until {
        return Err(IssuerDataAuthError::DocumentExpired { now, valid_until });
    }

    Ok(())
}

fn parse_rfc3339(field: &'static str, value: &str) -> Result<DateTime<Utc>, IssuerDataAuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| IssuerDataAuthError::InvalidTimestamp {
            field,
            value: value.to_string(),
        })
}

fn verify_name_space_digests(
    doc: &MdocDocument,
    mso: &MobileSecurityObject,
) -> Result<(), IssuerDataAuthError> {
    let digest_lookup = match mso.digest_algorithm.as_str() {
        "SHA-256" => DigestLookup::Sha256,
        other => {
            return Err(IssuerDataAuthError::UnsupportedDigestAlgorithm(
                other.to_string(),
            ))
        }
    };

    let name_spaces = doc
        .issuer_signed
        .name_spaces
        .as_ref()
        .cloned()
        .unwrap_or_else(BTreeMap::new);

    for (namespace, items) in name_spaces {
        for tagged_item in items {
            let encoded = minicbor::to_vec(&tagged_item).map_err(|err| {
                IssuerDataAuthError::InvalidIssuerAuth(format!(
                    "failed to encode IssuerSignedItemBytes: {err}"
                ))
            })?;
            let item = tagged_item.decode().map_err(|err| {
                IssuerDataAuthError::InvalidIssuerAuth(format!(
                    "failed to decode IssuerSignedItemBytes: {err}"
                ))
            })?;
            let expected_digest = mso
                .value_digests
                .get(&namespace)
                .and_then(|digest_ids| digest_ids.get(&item.digest_id))
                .ok_or_else(|| IssuerDataAuthError::MissingDigest {
                    namespace: namespace.clone(),
                    digest_id: item.digest_id,
                })?;

            let actual_digest = digest_lookup.digest(&encoded);
            if actual_digest.as_slice() != expected_digest.as_slice() {
                return Err(IssuerDataAuthError::DigestMismatch {
                    namespace,
                    element_identifier: item.element_identifier,
                    digest_id: item.digest_id,
                });
            }
        }
    }

    Ok(())
}

enum DigestLookup {
    Sha256,
}

impl DigestLookup {
    fn digest(&self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::bytes::ByteVec;
    use minicbor::{Decode, Encode};
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use x509_cert::der::Decode as DerDecode;

    use crate::device_response::{DeviceAuth, DeviceSigned, IssuerSigned};
    use crate::{
        CborBytes, CoseAlg, CoseSign1, HeaderMap, IssuerSignedItem, MobileSecurityObject,
        ProtectedHeaderMap, TDate, TaggedCborBytes, ValidityInfo, X5Chain,
    };

    #[test]
    fn verify_issuer_data_auth_accepts_valid_signed_document() {
        let fixture = signed_document_fixture();
        let verified = verify_issuer_data_auth(
            &fixture.document,
            &IssuerDataAuthContext {
                now: DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                expected_doc_type: Some(fixture.document.doc_type.clone()),
            },
        )
        .unwrap();

        assert_eq!(verified.mso.doc_type, fixture.document.doc_type);
        assert!(verified.issuer_cert.is_some());
    }

    #[test]
    fn verify_issuer_data_auth_rejects_missing_digest_entry() {
        let mut fixture = signed_document_fixture();
        fixture.document.issuer_signed.name_spaces = Some(BTreeMap::from([(
            "org.iso.18013.5.1".to_string(),
            vec![issuer_signed_item(7, "family_name", "Mustermann")],
        )]));

        let err = verify_issuer_data_auth(
            &fixture.document,
            &IssuerDataAuthContext {
                now: DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                expected_doc_type: None,
            },
        )
        .unwrap_err();

        assert!(matches!(err, IssuerDataAuthError::MissingDigest { .. }));
    }

    #[test]
    fn verify_issuer_data_auth_rejects_invalid_validity_window() {
        let mut fixture = signed_document_fixture();
        fixture.mso.validity_info.valid_until = TDate::from("2026-05-01T00:00:00Z".to_string());
        fixture.document.issuer_signed.issuer_auth =
            issuer_auth_for_mso(&fixture.mso, &fixture.cert_der, &fixture.signing_key);

        let err = verify_issuer_data_auth(
            &fixture.document,
            &IssuerDataAuthContext {
                now: DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                expected_doc_type: None,
            },
        )
        .unwrap_err();

        assert!(matches!(err, IssuerDataAuthError::DocumentExpired { .. }));
    }

    struct SignedDocumentFixture {
        document: MdocDocument,
        mso: MobileSecurityObject,
        cert_der: Vec<u8>,
        signing_key: p256::ecdsa::SigningKey,
    }

    fn signed_document_fixture() -> SignedDocumentFixture {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert_der = CertificateParams::new(Vec::new())
            .unwrap()
            .self_signed(&key_pair)
            .unwrap()
            .der()
            .to_vec();
        let secret_key = p256::SecretKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let signing_key = p256::ecdsa::SigningKey::from(secret_key);
        let item = issuer_signed_item(0, "family_name", "Mustermann");
        let item_digest = Sha256::digest(&minicbor::to_vec(&item).unwrap()).to_vec();
        let namespace = "org.iso.18013.5.1".to_string();
        let doc_type = "org.iso.18013.5.1.mDL".to_string();
        let mso = MobileSecurityObject {
            version: "1.0".to_string(),
            digest_algorithm: "SHA-256".to_string(),
            value_digests: BTreeMap::from([(
                namespace.clone(),
                BTreeMap::from([(0_u64, ByteVec::from(item_digest))]),
            )]),
            device_key_info: crate::DeviceKeyInfo {
                device_key: crate::CoseKeyPrivate::new().unwrap().to_public(),
                key_authorizations: None,
                key_info: None,
            },
            doc_type: doc_type.clone(),
            validity_info: ValidityInfo {
                signed: TDate::from("2026-01-01T00:00:00Z".to_string()),
                valid_from: TDate::from("2026-01-01T00:00:00Z".to_string()),
                valid_until: TDate::from("2027-01-01T00:00:00Z".to_string()),
                expected_update: None,
            },
            status: None,
        };
        let issuer_auth = issuer_auth_for_mso(&mso, &cert_der, &signing_key);
        let document = MdocDocument {
            doc_type,
            issuer_signed: IssuerSigned {
                issuer_auth,
                name_spaces: Some(BTreeMap::from([(namespace, vec![item])])),
            },
            device_signed: DeviceSigned {
                name_spaces: TaggedCborBytes::from(&BTreeMap::new()),
                device_auth: DeviceAuth {
                    device_signature: None,
                    device_mac: None,
                },
            },
            errors: None,
        };

        SignedDocumentFixture {
            document,
            mso,
            cert_der,
            signing_key,
        }
    }

    fn issuer_auth_for_mso(
        mso: &MobileSecurityObject,
        cert_der: &[u8],
        signing_key: &p256::ecdsa::SigningKey,
    ) -> CoseSign1<TaggedCborBytes<MobileSecurityObject>> {
        let payload = TaggedCborBytes::from(mso);
        let cert = x509_cert::Certificate::from_der(cert_der).unwrap();
        let protected = ProtectedHeaderMap::from(&HeaderMap {
            alg: Some(CoseAlg::ES256),
            x5chain: None,
        });
        let unprotected = HeaderMap {
            alg: None,
            x5chain: Some(X5Chain::from_certificates(vec![cert]).unwrap()),
        };
        let payload_bytes = CborBytes::from(&payload);
        let sig_structure =
            build_sig_structure_for_test(&protected, payload_bytes.raw_cbor_bytes());
        let signature: p256::ecdsa::Signature = signing_key.sign(&sig_structure);

        CoseSign1 {
            protected,
            unprotected,
            payload: Some(payload_bytes),
            signature: ByteVec::from(signature.to_bytes().to_vec()),
        }
    }

    fn issuer_signed_item(
        digest_id: u64,
        element_identifier: &str,
        value: &str,
    ) -> TaggedCborBytes<IssuerSignedItem> {
        TaggedCborBytes::from(&IssuerSignedItem {
            digest_id,
            random: ByteVec::from(vec![0xAA; 16]),
            element_identifier: element_identifier.to_string(),
            element_value: crate::ElementValue::new(minicbor::to_vec(value).unwrap()),
        })
    }

    fn build_sig_structure_for_test(protected: &ProtectedHeaderMap, payload: &[u8]) -> Vec<u8> {
        minicbor::to_vec(TestSigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(protected.raw_cbor_bytes().to_vec()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(payload.to_vec()),
        })
        .unwrap()
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
    #[cbor(array)]
    struct TestSigStructureSignature1 {
        #[n(0)]
        context: String,
        #[n(1)]
        body_protected: ByteVec,
        #[n(2)]
        external_aad: ByteVec,
        #[n(3)]
        payload: ByteVec,
    }
}
