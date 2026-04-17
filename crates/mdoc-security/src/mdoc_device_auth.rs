use std::collections::BTreeSet;
use std::fmt;

use mdoc_core::{
    CoseKeyPrivate, CoseKeyPublic, CoseVerifyDedicatedPayload, DeviceKeyInfo, DeviceNameSpaces,
    DeviceSigned, GetCosePayload, KeyAuthorizations, SessionTranscript, TaggedCborBytes,
};
use minicbor::{Decode, Encode};
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::{derive_shared_key, derive_shared_secret};

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

pub fn verify_mdoc_device_auth(
    device_signed: &DeviceSigned,
    device_key_info: &DeviceKeyInfo,
    e_reader_key_private: &CoseKeyPrivate,
    session_transcript: &SessionTranscript,
    doc_type: &str,
) -> Result<(), MdocDeviceAuthError> {
    if let Some(key_authorizations) = &device_key_info.key_authorizations {
        verify_key_authorizations(&device_signed, key_authorizations)?;
    }

    let expected_payload = build_device_authentication_bytes(
        session_transcript,
        doc_type,
        &device_signed.name_spaces,
    )?;

    match (
        &device_signed.device_auth.device_signature,
        &device_signed.device_auth.device_mac,
    ) {
        (Some(device_signature), None) => {
            let verifying_key: VerifyingKey =
                (&device_key_info.device_key).try_into().map_err(|err| {
                    MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(format!(
                        "failed to convert device key to verifying key: {err}"
                    ))
                })?;
            verify_device(device_signature, &verifying_key, &expected_payload)
        }
        (None, Some(device_mac)) => {
            let emac_key = derive_emac_key(
                e_reader_key_private,
                session_transcript,
                &device_key_info.device_key,
            )
            .map_err(|err| MdocDeviceAuthError::DeviceMacInvalid(err.to_string()))?;
            verify_device(device_mac, &emac_key, &expected_payload)
        }
        _ => Err(MdocDeviceAuthError::DeviceAuthModeInvalid),
    }
}

fn verify_device<K, T: GetCosePayload + CoseVerifyDedicatedPayload<K>>(
    cose_verify: &T,
    key: &K,
    expected_payload: &[u8],
) -> Result<(), MdocDeviceAuthError> {
    // If the device signature contains a payload, verify that it matches the expected DeviceAuthentication bytes.
    if let Some(actual_payload) = cose_verify
        .payload()
        .map(|payload| payload.raw_cbor_bytes())
    {
        if actual_payload != expected_payload {
            return Err(MdocDeviceAuthError::DeviceAuthPayloadMismatch);
        }
    }

    cose_verify
        .verify_with(&key, b"", expected_payload)
        .map_err(|err| {
            MdocDeviceAuthError::DeviceMacInvalid(format!(
                "COSE_Mac0/COSE_Sign1 verification failed: {err}"
            ))
        })
}

fn derive_emac_key(
    e_reader_key_private: &CoseKeyPrivate,
    session_transcript: &SessionTranscript,
    device_key: &CoseKeyPublic,
) -> Result<[u8; 32], MdocDeviceAuthError> {
    let shared_secret = derive_shared_secret(e_reader_key_private, device_key)
        .map_err(|err| MdocDeviceAuthError::DeviceMacInvalid(err.to_string()))?;

    let tagged = TaggedCborBytes::from(session_transcript);
    let data = minicbor::to_vec(&tagged)
        .map_err(|err| MdocDeviceAuthError::DeviceAuthenticationEncodingFailed(err.to_string()))?;

    let salt = Sha256::digest(data);

    derive_shared_key(&shared_secret, &salt, b"EMacKey")
        .map_err(|err| MdocDeviceAuthError::DeviceMacInvalid(err.to_string()))
}

fn build_device_authentication_bytes(
    session_transcript: &SessionTranscript,
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
    session_transcript: &SessionTranscript,
    doc_type: &str,
    device_name_spaces: &TaggedCborBytes<DeviceNameSpaces>,
) -> Result<DeviceAuthentication, MdocDeviceAuthError> {
    Ok(DeviceAuthentication {
        context: DEVICE_AUTHENTICATION_CONTEXT.to_string(),
        session_transcript: session_transcript.clone(),
        doc_type: doc_type.to_string(),
        device_name_spaces: device_name_spaces.clone(),
    })
}

fn verify_key_authorizations(
    device_signed: &DeviceSigned,
    key_authorizations: &KeyAuthorizations,
) -> Result<(), MdocDeviceAuthError> {
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
    let device_name_spaces = device_signed
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
