use std::collections::BTreeSet;
use std::fmt;

use minicbor::{Decode, Encode};
use p256::ecdsa::VerifyingKey;

use crate::device_response::DeviceNameSpaces;
use crate::{MdocDocument, SessionTranscript, TaggedCborBytes, VerifiedMso};

#[derive(Debug, Clone)]
pub struct MdocDeviceAuthContext {
    pub session_transcript: TaggedCborBytes<SessionTranscript>,
    pub verified_mso: VerifiedMso,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdocDeviceAuthError {
    DeviceAuthModeInvalid,
    DeviceMacUnsupported,
    DeviceAuthenticationEncodingFailed(String),
    DeviceAuthPayloadMismatch,
    DeviceSignatureInvalid(String),
    UnauthorizedDeviceNamespace {
        namespace: String,
    },
    UnauthorizedDeviceSignedElement {
        namespace: String,
        element_identifier: String,
    },
}

impl fmt::Display for MdocDeviceAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceAuthModeInvalid => {
                write!(f, "deviceAuth must contain exactly one of deviceSignature or deviceMac")
            }
            Self::DeviceMacUnsupported => write!(f, "deviceMac is not supported"),
            Self::DeviceAuthenticationEncodingFailed(message) => {
                write!(f, "failed to encode DeviceAuthentication: {message}")
            }
            Self::DeviceAuthPayloadMismatch => {
                write!(f, "deviceSignature payload does not match DeviceAuthentication bytes")
            }
            Self::DeviceSignatureInvalid(message) => write!(f, "invalid deviceSignature: {message}"),
            Self::UnauthorizedDeviceNamespace { namespace } => {
                write!(f, "unauthorized DeviceSigned namespace: {namespace}")
            }
            Self::UnauthorizedDeviceSignedElement {
                namespace,
                element_identifier,
            } => write!(
                f,
                "unauthorized DeviceSigned element: namespace={namespace}, elementIdentifier={element_identifier}"
            ),
        }
    }
}

impl std::error::Error for MdocDeviceAuthError {}

pub fn verify_mdoc_device_auth(
    doc: &MdocDocument,
    ctx: &MdocDeviceAuthContext,
) -> Result<(), MdocDeviceAuthError> {
    let device_auth = &doc.device_signed.device_auth;
    match (
        device_auth.device_signature.as_ref(),
        device_auth.device_mac.as_ref(),
    ) {
        (Some(_), Some(_)) | (None, None) => return Err(MdocDeviceAuthError::DeviceAuthModeInvalid),
        (None, Some(_)) => return Err(MdocDeviceAuthError::DeviceMacUnsupported),
        (Some(device_signature), None) => {
            let expected_payload = build_device_authentication_bytes(
                &ctx.session_transcript,
                &doc.doc_type,
                &doc.device_signed.name_spaces,
            )?;
            if let Some(actual_payload) = device_signature.payload.as_ref() {
                if actual_payload.raw_cbor_bytes() != expected_payload.as_slice() {
                    return Err(MdocDeviceAuthError::DeviceAuthPayloadMismatch);
                }
            }
            let verifying_key: VerifyingKey = (&ctx.verified_mso.mso.device_key_info.device_key).try_into().map_err(|err| {
                MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(format!(
                    "failed to convert device key to verifying key: {err}"
                ))
            })?;
            device_signature
                .verify_detached_payload(
                    &verifying_key,
                    b"",
                    &expected_payload,
                )
                .map_err(|err| MdocDeviceAuthError::DeviceSignatureInvalid(err.to_string()))?;

            verify_key_authorizations(doc, &ctx.verified_mso)
        }
    }
}

fn build_device_authentication_bytes(
    session_transcript: &TaggedCborBytes<SessionTranscript>,
    doc_type: &str,
    device_name_spaces: &TaggedCborBytes<DeviceNameSpaces>,
) -> Result<Vec<u8>, MdocDeviceAuthError> {
    let decoded_session_transcript: SessionTranscript = session_transcript
        .decode()
        .map_err(|err| MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(err.to_string()))?;
    let device_authentication = DeviceAuthentication {
        context: DEVICE_AUTHENTICATION_CONTEXT.to_string(),
        session_transcript: decoded_session_transcript,
        doc_type: doc_type.to_string(),
        device_name_spaces: device_name_spaces.clone(),
    };
    let tagged = TaggedCborBytes::from(&device_authentication);
    minicbor::to_vec(&tagged)
        .map_err(|err| MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(err.to_string()))
}

fn verify_key_authorizations(
    doc: &MdocDocument,
    verified_mso: &VerifiedMso,
) -> Result<(), MdocDeviceAuthError> {
    let Some(key_authorizations) = verified_mso.mso.device_key_info.key_authorizations.as_ref() else {
        return Ok(());
    };

    let allowed_namespaces = key_authorizations
        .name_spaces
        .as_ref()
        .map(|namespaces| namespaces.iter().cloned().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let allowed_data_elements = key_authorizations
        .data_elements
        .as_ref()
        .cloned()
        .unwrap_or_default();
    let device_name_spaces = doc
        .device_signed
        .name_spaces
        .decode()
        .map_err(|err| MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(err.to_string()))?;

    for (namespace, items) in device_name_spaces {
        let namespace_allowed = allowed_namespaces.contains(&namespace);
        let allowed_elements = allowed_data_elements.get(&namespace);

        if !namespace_allowed && allowed_elements.is_none() {
            return Err(MdocDeviceAuthError::UnauthorizedDeviceNamespace { namespace });
        }

        for element_identifier in items.keys() {
            let element_allowed = allowed_elements
                .map(|elements| elements.iter().any(|allowed| allowed == element_identifier))
                .unwrap_or(false);
            if !namespace_allowed && !element_allowed {
                return Err(MdocDeviceAuthError::UnauthorizedDeviceSignedElement {
                    namespace: namespace.clone(),
                    element_identifier: element_identifier.clone(),
                });
            }
        }
    }

    Ok(())
}

const DEVICE_AUTHENTICATION_CONTEXT: &str = "DeviceAuthentication";

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
struct DeviceAuthentication {
    #[n(0)]
    context: String,
    #[n(1)]
    session_transcript: SessionTranscript,
    #[n(2)]
    doc_type: String,
    #[n(3)]
    device_name_spaces: TaggedCborBytes<DeviceNameSpaces>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use minicbor::bytes::ByteVec;
    use minicbor::Decode;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    use super::*;
    use crate::device_response::{DeviceAuth, DeviceSigned, IssuerSigned};
    use crate::mobile_security_object::{DeviceKeyInfo, KeyAuthorizations};
    use crate::{
        CborBytes, CoseAlg, CoseKeyPrivate, CoseSign1, HeaderMap, MdocDocument, MobileSecurityObject,
        ProtectedHeaderMap, TDate, TaggedCborBytes, ValidityInfo,
    };

    #[test]
    fn verify_mdoc_device_auth_accepts_valid_device_signature() {
        let fixture = signed_document_fixture();

        verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap();
    }

    #[test]
    fn verify_mdoc_device_auth_rejects_xor_violation() {
        let mut fixture = signed_document_fixture();
        fixture.document.device_signed.device_auth.device_mac =
            Some(crate::ElementValue::new(vec![0x01]));

        let err = verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap_err();
        assert_eq!(err, MdocDeviceAuthError::DeviceAuthModeInvalid);
    }

    #[test]
    fn verify_mdoc_device_auth_rejects_when_both_modes_missing() {
        let mut fixture = signed_document_fixture();
        fixture.document.device_signed.device_auth.device_signature = None;

        let err = verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap_err();
        assert_eq!(err, MdocDeviceAuthError::DeviceAuthModeInvalid);
    }

    #[test]
    fn verify_mdoc_device_auth_rejects_device_mac() {
        let mut fixture = signed_document_fixture();
        fixture.document.device_signed.device_auth.device_signature = None;
        fixture.document.device_signed.device_auth.device_mac =
            Some(crate::ElementValue::new(vec![0x01]));

        let err = verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap_err();
        assert_eq!(err, MdocDeviceAuthError::DeviceMacUnsupported);
    }

    #[test]
    fn verify_mdoc_device_auth_accepts_detached_payload() {
        let mut fixture = signed_document_fixture();
        fixture.document.device_signed.device_auth.device_signature.as_mut().unwrap().payload = None;

        verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap();
    }

    #[test]
    fn verify_mdoc_device_auth_rejects_payload_mismatch() {
        let mut fixture = signed_document_fixture();
        fixture.document.device_signed.device_auth.device_signature.as_mut().unwrap().payload =
            Some(CborBytes::from_raw_bytes(vec![0x01]));

        let err = verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap_err();
        assert_eq!(err, MdocDeviceAuthError::DeviceAuthPayloadMismatch);
    }

    #[test]
    fn verify_mdoc_device_auth_rejects_invalid_signature() {
        let mut fixture = signed_document_fixture();
        fixture.document.device_signed.device_auth.device_signature.as_mut().unwrap().signature =
            ByteVec::from(vec![0u8; 64]);

        let err = verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap_err();
        assert!(matches!(err, MdocDeviceAuthError::DeviceSignatureInvalid(_)));
    }

    #[test]
    fn verify_mdoc_device_auth_rejects_unauthorized_namespace() {
        let mut fixture = signed_document_fixture();
        fixture.document.device_signed.name_spaces = TaggedCborBytes::from(&BTreeMap::from([(
            "org.iso.18013.5.1.aamva".to_string(),
            BTreeMap::from([(
                "age_over_18".to_string(),
                crate::ElementValue::new(minicbor::to_vec(true).unwrap()),
            )]),
        )]));
        resign_device_auth(&mut fixture);

        let err = verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap_err();
        assert_eq!(
            err,
            MdocDeviceAuthError::UnauthorizedDeviceNamespace {
                namespace: "org.iso.18013.5.1.aamva".to_string(),
            }
        );
    }

    #[test]
    fn verify_mdoc_device_auth_rejects_unauthorized_element() {
        let mut fixture = signed_document_fixture();
        fixture.document.device_signed.name_spaces = TaggedCborBytes::from(&BTreeMap::from([(
            "org.iso.18013.5.1".to_string(),
            BTreeMap::from([(
                "given_name".to_string(),
                crate::ElementValue::new(minicbor::to_vec("Erika").unwrap()),
            )]),
        )]));
        resign_device_auth(&mut fixture);

        let err = verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap_err();
        assert_eq!(
            err,
            MdocDeviceAuthError::UnauthorizedDeviceSignedElement {
                namespace: "org.iso.18013.5.1".to_string(),
                element_identifier: "given_name".to_string(),
            }
        );
    }

    #[test]
    fn verify_mdoc_device_auth_uses_tagged_session_transcript_bytes() {
        let mut fixture = signed_document_fixture();
        let different_session_transcript = TaggedCborBytes::from(&SessionTranscript(
            None,
            fixture.reader_key.clone(),
            crate::NFCHandover(make_handover_select_bytes(&[0x02]), None),
        ));
        fixture.context.session_transcript = different_session_transcript;

        let err = verify_mdoc_device_auth(&fixture.document, &fixture.context).unwrap_err();
        assert_eq!(err, MdocDeviceAuthError::DeviceAuthPayloadMismatch);
    }

    struct SignedDocumentFixture {
        document: MdocDocument,
        context: MdocDeviceAuthContext,
        signing_key: SigningKey,
        reader_key: TaggedCborBytes<crate::CoseKeyPublic>,
    }

    fn signed_document_fixture() -> SignedDocumentFixture {
        let device_key_private = CoseKeyPrivate::new().unwrap();
        let device_key_public = device_key_private.to_public();
        let signing_key =
            SigningKey::from_bytes(device_key_private.d.as_slice().into()).unwrap();
        let reader_key = TaggedCborBytes::from(&CoseKeyPrivate::new().unwrap().to_public());
        let session_transcript = TaggedCborBytes::from(&SessionTranscript(
            None,
            reader_key.clone(),
            crate::NFCHandover(make_handover_select_bytes(&[0x01]), None),
        ));
        let device_name_spaces = TaggedCborBytes::from(&BTreeMap::from([(
            "org.iso.18013.5.1".to_string(),
            BTreeMap::from([(
                "family_name".to_string(),
                crate::ElementValue::new(minicbor::to_vec("Mustermann").unwrap()),
            )]),
        )]));
        let doc_type = "org.iso.18013.5.1.mDL".to_string();
        let payload = build_device_authentication_bytes(
            &session_transcript,
            &doc_type,
            &device_name_spaces,
        )
        .unwrap();
        let protected = ProtectedHeaderMap::from(&HeaderMap {
            alg: Some(CoseAlg::ES256),
            x5chain: None,
        });
        let sig_structure = build_sig_structure_for_test(&protected, &payload);
        let signature: p256::ecdsa::Signature = signing_key.sign(&sig_structure);
        let document = MdocDocument {
            doc_type: doc_type.clone(),
            issuer_signed: IssuerSigned {
                issuer_auth: CoseSign1 {
                    protected: ProtectedHeaderMap::from(&HeaderMap::default()),
                    unprotected: HeaderMap::default(),
                    payload: None,
                    signature: ByteVec::from(vec![0u8; 64]),
                },
                name_spaces: None,
            },
            device_signed: DeviceSigned {
                name_spaces: device_name_spaces,
                device_auth: DeviceAuth {
                    device_signature: Some(CoseSign1 {
                        protected,
                        unprotected: HeaderMap::default(),
                        payload: Some(CborBytes::from_raw_bytes(payload)),
                        signature: ByteVec::from(signature.to_bytes().to_vec()),
                    }),
                    device_mac: None,
                },
            },
            errors: None,
        };
        let verified_mso = VerifiedMso {
            mso: MobileSecurityObject {
                version: "1.0".to_string(),
                digest_algorithm: "SHA-256".to_string(),
                value_digests: BTreeMap::new(),
                device_key_info: DeviceKeyInfo {
                    device_key: device_key_public,
                    key_authorizations: Some(KeyAuthorizations {
                        name_spaces: None,
                        data_elements: Some(BTreeMap::from([(
                            "org.iso.18013.5.1".to_string(),
                            vec!["family_name".to_string()],
                        )])),
                    }),
                    key_info: None,
                },
                doc_type,
                validity_info: ValidityInfo {
                    signed: TDate::from("2026-01-01T00:00:00Z".to_string()),
                    valid_from: TDate::from("2026-01-01T00:00:00Z".to_string()),
                    valid_until: TDate::from("2027-01-01T00:00:00Z".to_string()),
                    expected_update: None,
                },
                status: None,
            },
            issuer_cert: None,
        };
        let context = MdocDeviceAuthContext {
            session_transcript,
            verified_mso,
        };

        SignedDocumentFixture {
            document,
            context,
            signing_key,
            reader_key,
        }
    }

    fn resign_device_auth(fixture: &mut SignedDocumentFixture) {
        let payload = build_device_authentication_bytes(
            &fixture.context.session_transcript,
            &fixture.document.doc_type,
            &fixture.document.device_signed.name_spaces,
        )
        .unwrap();
        let sign1 = fixture
            .document
            .device_signed
            .device_auth
            .device_signature
            .as_mut()
            .unwrap();
        let protected = sign1.protected.clone();
        let sig_structure = build_sig_structure_for_test(&protected, &payload);
        let signature: p256::ecdsa::Signature = fixture.signing_key.sign(&sig_structure);
        sign1.payload = Some(CborBytes::from_raw_bytes(payload));
        sign1.signature = ByteVec::from(signature.to_bytes().to_vec());
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

    fn make_handover_select_bytes(bytes: &[u8]) -> crate::session_transcript::HandoverSelectBytes {
        minicbor::decode(&minicbor::to_vec(ByteVec::from(bytes.to_vec())).unwrap()).unwrap()
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
