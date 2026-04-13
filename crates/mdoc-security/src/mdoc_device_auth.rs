use std::collections::BTreeSet;
use std::fmt;

use hmac::{Hmac, Mac};
use mdoc_core::{
    derive_emac_key, derive_shared_secret, CoseAlg, CoseKeyPrivate, CoseMac0, ElementValue,
    MacStructure, MdocDocument, SessionTranscript, TaggedCborBytes, MAC0_CONTEXT,
};
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use p256::ecdsa::VerifyingKey;
use sha2::Sha256;

use crate::VerifiedMso;

type DeviceNameSpaces =
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, ElementValue>>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct MdocDeviceAuthContext {
    pub session_transcript: TaggedCborBytes<SessionTranscript>,
    pub verified_mso: VerifiedMso,
}

#[derive(Debug, Clone)]
pub struct MdocMacAuthContext {
    pub session_transcript: TaggedCborBytes<SessionTranscript>,
    pub verified_mso: VerifiedMso,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdocDeviceAuthError {
    DeviceAuthModeInvalid,
    DeviceAuthenticationEncodingFailed(String),
    DeviceAuthPayloadMismatch,
    DeviceSignatureInvalid(String),
    DeviceMacInvalid(String),
    UnauthorizedDeviceNamespace {
        namespace: String,
    },
    UnauthorizedDeviceSignedElement {
        namespace: String,
        element_identifier: String,
    },
}

pub type MdocMacAuthError = MdocDeviceAuthError;

impl fmt::Display for MdocDeviceAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceAuthModeInvalid => {
                write!(f, "deviceAuth must contain exactly one of deviceSignature or deviceMac")
            }
            Self::DeviceAuthenticationEncodingFailed(message) => {
                write!(f, "failed to encode DeviceAuthentication: {message}")
            }
            Self::DeviceAuthPayloadMismatch => {
                write!(f, "device authentication payload does not match DeviceAuthentication bytes")
            }
            Self::DeviceSignatureInvalid(message) => write!(f, "invalid deviceSignature: {message}"),
            Self::DeviceMacInvalid(message) => write!(f, "invalid deviceMac: {message}"),
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

enum DeviceAuthVerifier<'a> {
    Signature,
    Mac { e_reader_key_private: &'a CoseKeyPrivate },
}

pub fn verify_mdoc_device_auth(
    doc: &MdocDocument,
    ctx: &MdocDeviceAuthContext,
) -> Result<(), MdocDeviceAuthError> {
    verify_mdoc_device_auth_internal(doc, ctx, DeviceAuthVerifier::Signature)
}

pub fn verify_mdoc_mac_auth(
    doc: &MdocDocument,
    e_reader_key_private: &CoseKeyPrivate,
    ctx: &MdocMacAuthContext,
) -> Result<(), MdocMacAuthError> {
    let device_ctx = MdocDeviceAuthContext {
        session_transcript: ctx.session_transcript.clone(),
        verified_mso: ctx.verified_mso.clone(),
    };
    verify_mdoc_device_auth_internal(
        doc,
        &device_ctx,
        DeviceAuthVerifier::Mac {
            e_reader_key_private,
        },
    )
}

fn verify_mdoc_device_auth_internal(
    doc: &MdocDocument,
    ctx: &MdocDeviceAuthContext,
    verifier: DeviceAuthVerifier<'_>,
) -> Result<(), MdocDeviceAuthError> {
    let expected_payload = build_device_authentication_bytes(
        &ctx.session_transcript,
        &doc.doc_type,
        &doc.device_signed.name_spaces,
    )?;

    match verifier {
        DeviceAuthVerifier::Signature => verify_device_signature(doc, ctx, &expected_payload)?,
        DeviceAuthVerifier::Mac {
            e_reader_key_private,
        } => verify_device_mac_auth(doc, ctx, e_reader_key_private, &expected_payload)?,
    }

    verify_key_authorizations(doc, &ctx.verified_mso)
}

fn verify_device_signature(
    doc: &MdocDocument,
    ctx: &MdocDeviceAuthContext,
    expected_payload: &[u8],
) -> Result<(), MdocDeviceAuthError> {
    let device_auth = &doc.device_signed.device_auth;
    let Some(device_signature) = device_auth.device_signature.as_ref() else {
        return Err(MdocDeviceAuthError::DeviceAuthModeInvalid);
    };
    if device_auth.device_mac.is_some() {
        return Err(MdocDeviceAuthError::DeviceAuthModeInvalid);
    }

    if let Some(actual_payload) = device_signature.payload.as_ref() {
        if actual_payload.raw_cbor_bytes() != expected_payload {
            return Err(MdocDeviceAuthError::DeviceAuthPayloadMismatch);
        }
    }

    let verifying_key: VerifyingKey = (&ctx.verified_mso.mso.device_key_info.device_key)
        .try_into()
        .map_err(|err| {
            MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(format!(
                "failed to convert device key to verifying key: {err}"
            ))
        })?;

    device_signature
        .verify_detached_payload(&verifying_key, b"", expected_payload)
        .map_err(|err| MdocDeviceAuthError::DeviceSignatureInvalid(err.to_string()))
}

fn verify_device_mac_auth(
    doc: &MdocDocument,
    ctx: &MdocDeviceAuthContext,
    e_reader_key_private: &CoseKeyPrivate,
    expected_payload: &[u8],
) -> Result<(), MdocDeviceAuthError> {
    let device_auth = &doc.device_signed.device_auth;
    let Some(device_mac) = device_auth.device_mac.as_ref() else {
        return Err(MdocDeviceAuthError::DeviceAuthModeInvalid);
    };
    if device_auth.device_signature.is_some() {
        return Err(MdocDeviceAuthError::DeviceAuthModeInvalid);
    }

    let shared_secret = derive_shared_secret(
        e_reader_key_private,
        &ctx.verified_mso.mso.device_key_info.device_key,
    )
    .map_err(|err| MdocDeviceAuthError::DeviceMacInvalid(err.to_string()))?;

    let emac_key = derive_emac_key(&shared_secret, &ctx.session_transcript)
        .map_err(|err| MdocDeviceAuthError::DeviceMacInvalid(err.to_string()))?;

    verify_device_mac(device_mac, &emac_key, expected_payload)
}

fn verify_device_mac(
    device_mac: &ElementValue,
    emac_key: &[u8; 32],
    expected_payload: &[u8],
) -> Result<(), MdocDeviceAuthError> {
    let mac0: CoseMac0 = device_mac
        .decode()
        .map_err(|err| MdocDeviceAuthError::DeviceMacInvalid(err.to_string()))?;
    let protected = mac0
        .protected
        .decode()
        .map_err(|err| MdocDeviceAuthError::DeviceMacInvalid(err.to_string()))?;

    match protected.alg {
        Some(CoseAlg::HMAC256256) => {}
        Some(alg) => {
            return Err(MdocDeviceAuthError::DeviceMacInvalid(format!(
                "unsupported COSE_Mac0 algorithm: {alg:?}"
            )))
        }
        None => {
            return Err(MdocDeviceAuthError::DeviceMacInvalid(
                "COSE_Mac0 algorithm is missing from protected header".to_string(),
            ))
        }
    }

    if let Some(payload) = mac0.payload.as_ref() {
        if payload.raw_cbor_bytes() != expected_payload {
            return Err(MdocDeviceAuthError::DeviceAuthPayloadMismatch);
        }
    }

    let mac_structure = build_mac_structure_bytes(&mac0, expected_payload, &[])?;
    let mut hmac = HmacSha256::new_from_slice(emac_key)
        .map_err(|err| MdocDeviceAuthError::DeviceMacInvalid(err.to_string()))?;
    hmac.update(&mac_structure);
    if hmac.verify_slice(mac0.tag.as_slice()).is_ok() {
        return Ok(());
    }

    Err(MdocDeviceAuthError::DeviceMacInvalid(
        "COSE_Mac0 tag verification failed".to_string(),
    ))
}

fn build_mac_structure_bytes(
    mac0: &CoseMac0,
    payload: &[u8],
    external_aad: &[u8],
) -> Result<Vec<u8>, MdocDeviceAuthError> {
    minicbor::to_vec(MacStructure {
        context: MAC0_CONTEXT.to_string(),
        body_protected: ByteVec::from(mac0.protected.raw_cbor_bytes().to_vec()),
        external_aad: ByteVec::from(external_aad.to_vec()),
        payload: ByteVec::from(payload.to_vec()),
    })
    .map_err(|err| MdocDeviceAuthError::DeviceMacInvalid(err.to_string()))
}

pub(crate) fn build_device_authentication_bytes(
    session_transcript: &TaggedCborBytes<SessionTranscript>,
    doc_type: &str,
    device_name_spaces: &TaggedCborBytes<DeviceNameSpaces>,
) -> Result<Vec<u8>, MdocDeviceAuthError> {
    let device_authentication =
        build_device_authentication(session_transcript, doc_type, device_name_spaces)?;
    let tagged = TaggedCborBytes::from(&device_authentication);
    minicbor::to_vec(&tagged)
        .map_err(|err| MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(err.to_string()))
}

fn build_device_authentication(
    session_transcript: &TaggedCborBytes<SessionTranscript>,
    doc_type: &str,
    device_name_spaces: &TaggedCborBytes<DeviceNameSpaces>,
) -> Result<DeviceAuthentication, MdocDeviceAuthError> {
    let decoded_session_transcript: SessionTranscript = session_transcript
        .decode()
        .map_err(|err| MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(err.to_string()))?;
    Ok(DeviceAuthentication {
        context: DEVICE_AUTHENTICATION_CONTEXT.to_string(),
        session_transcript: decoded_session_transcript,
        doc_type: doc_type.to_string(),
        device_name_spaces: device_name_spaces.clone(),
    })
}

pub(crate) fn verify_key_authorizations(
    doc: &MdocDocument,
    verified_mso: &VerifiedMso,
) -> Result<(), MdocDeviceAuthError> {
    let Some(key_authorizations) = verified_mso.mso.device_key_info.key_authorizations.as_ref()
    else {
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
    let device_name_spaces =
        doc.device_signed.name_spaces.decode().map_err(|err| {
            MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(err.to_string())
        })?;

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
