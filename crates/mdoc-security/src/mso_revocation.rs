use std::time::SystemTime;

use chrono::{DateTime, Utc};
use log::{debug, info};
use mdoc_core::{CborWebToken, CoseSign1, CoseVerify, GetCosePayload, IdentifierListInfo};
use minicbor::data::Tagged;
use reqwest::Client;
use thiserror::Error;
use url::Url;
use x509_cert::der::Decode as _;

use crate::{ValidationError, VerifiedMso, validate_x5chain};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsoRevocationState {
    NotChecked,
    NotRevoked,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsoRevocationMechanism {
    IdentifierList,
    StatusList,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsoRevocationCheck {
    pub state: MsoRevocationState,
    pub source_uri: Option<Url>,
    pub mechanism: Option<MsoRevocationMechanism>,
}

#[derive(Debug, Error)]
pub enum MsoRevocationError {
    #[error("invalid MSO status selection: {0}")]
    InvalidStatus(&'static str),
    #[error("status_list revocation is not implemented yet")]
    UnsupportedStatusList,
    #[error("invalid revocation-list URI: {0}")]
    InvalidUri(String),
    #[error("revocation-list download failed: {0}")]
    DownloadFailed(String),
    #[error("invalid revocation list: {0}")]
    InvalidRevocationList(String),
    #[error("revocation-list certificate validation failed: {0}")]
    ValidationFailed(#[from] ValidationError),
}

pub async fn check_mso_revocation(
    verified_mso: &VerifiedMso,
    iaca_cert: Option<&x509_cert::Certificate>,
    now: DateTime<Utc>,
) -> Result<MsoRevocationCheck, MsoRevocationError> {
    let Some(status) = &verified_mso.mso.status else {
        return Ok(MsoRevocationCheck {
            state: MsoRevocationState::NotChecked,
            source_uri: None,
            mechanism: None,
        });
    };

    match (&status.identifier_list, &status.status_list) {
        (Some(info), None) => check_identifier_list(info, iaca_cert, now).await,
        (None, Some(_)) => Err(MsoRevocationError::UnsupportedStatusList),
        (Some(_), Some(_)) => Err(MsoRevocationError::InvalidStatus(
            "both identifier_list and status_list are present",
        )),
        (None, None) => Err(MsoRevocationError::InvalidStatus(
            "status is present but empty",
        )),
    }
}

async fn check_identifier_list(
    info: &IdentifierListInfo,
    iaca_cert: Option<&x509_cert::Certificate>,
    now: DateTime<Utc>,
) -> Result<MsoRevocationCheck, MsoRevocationError> {
    let source_uri =
        Url::parse(&info.uri).map_err(|err| MsoRevocationError::InvalidUri(err.to_string()))?;
    if source_uri.scheme() != "https" {
        return Err(MsoRevocationError::InvalidUri(
            "only https revocation-list URLs are supported".to_string(),
        ));
    }

    let bytes = download_revocation_list(&source_uri).await?;
    evaluate_identifier_list_bytes(&bytes, info, iaca_cert, now, source_uri).await
}

async fn evaluate_identifier_list_bytes(
    bytes: &[u8],
    info: &IdentifierListInfo,
    iaca_cert: Option<&x509_cert::Certificate>,
    now: DateTime<Utc>,
    source_uri: Url,
) -> Result<MsoRevocationCheck, MsoRevocationError> {
    let token = validate_identifier_list_token(&bytes, info, iaca_cert, now).await?;
    debug!(
        "mso_revocation: identifier_list own_identifier={}",
        hex_string(info.id.as_slice()),
    );
    let state = if token.identifier_list.identifiers.contains_key(&info.id) {
        MsoRevocationState::Revoked
    } else {
        MsoRevocationState::NotRevoked
    };

    Ok(MsoRevocationCheck {
        state,
        source_uri: Some(source_uri),
        mechanism: Some(MsoRevocationMechanism::IdentifierList),
    })
}

async fn download_revocation_list(url: &Url) -> Result<Vec<u8>, MsoRevocationError> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|err| MsoRevocationError::DownloadFailed(format!("client build failed: {err}")))?;

    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|err| MsoRevocationError::DownloadFailed(err.to_string()))?
        .error_for_status()
        .map_err(|err| MsoRevocationError::DownloadFailed(err.to_string()))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|err| MsoRevocationError::DownloadFailed(err.to_string()))?;

    let bytes = bytes.to_vec();
    debug!(
        "mso_revocation: downloaded revocation list url={} bytes={} prefix={:02X?}",
        url,
        bytes.len(),
        &bytes[..bytes.len().min(16)]
    );
    Ok(normalize_downloaded_revocation_list(&bytes))
}

async fn validate_identifier_list_token(
    bytes: &[u8],
    info: &IdentifierListInfo,
    iaca_cert: Option<&x509_cert::Certificate>,
    now: DateTime<Utc>,
) -> Result<CborWebToken, MsoRevocationError> {
    let sign1 = decode_cose_sign1(bytes)?;
    let protected = sign1
        .protected
        .decode()
        .map_err(|err| MsoRevocationError::InvalidRevocationList(err.to_string()))?;
    let typ = protected.typ.as_deref().ok_or_else(|| {
        MsoRevocationError::InvalidRevocationList("protected typ is missing".to_string())
    })?;
    if !is_identifier_list_content_type(typ) {
        return Err(MsoRevocationError::InvalidRevocationList(format!(
            "unexpected typ: {typ}"
        )));
    }

    let x5chain = protected.x5chain.as_deref().ok_or_else(|| {
        MsoRevocationError::InvalidRevocationList("protected x5chain is missing".to_string())
    })?;
    let trust_point = select_trust_point(info, iaca_cert)?;
    let validation =
        validate_x5chain(&trust_point, x5chain, false, system_time_from_datetime(now)).await?;
    info!("mso_revocation: x5chain validation result={validation:?}");

    sign1.verify(&x5chain[0], b"").map_err(|err| {
        MsoRevocationError::InvalidRevocationList(format!("signature verification failed: {err}"))
    })?;

    let token: CborWebToken = sign1
        .payload()
        .ok_or_else(|| {
            MsoRevocationError::InvalidRevocationList("revocation-list payload is missing".to_string())
        })?
        .decode()
        .map_err(|err| MsoRevocationError::InvalidRevocationList(err.to_string()))?;

    if token.exp <= now.timestamp() as u64 {
        return Err(MsoRevocationError::InvalidRevocationList(
            "revocation list is expired".to_string(),
        ));
    }

    Ok(token)
}

fn decode_cose_sign1(bytes: &[u8]) -> Result<CoseSign1<CborWebToken>, MsoRevocationError> {
    minicbor::decode::<Tagged<18, CoseSign1<CborWebToken>>>(bytes)
        .map(Tagged::into_value)
        .map_err(|err| MsoRevocationError::InvalidRevocationList(err.to_string()))
}

fn normalize_downloaded_revocation_list(bytes: &[u8]) -> Vec<u8> {
    decode_hex_ascii(bytes).unwrap_or_else(|| bytes.to_vec())
}

fn decode_hex_ascii(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.len() < 2 || text.len() % 2 != 0 {
        return None;
    }
    hex::decode(text).ok()
}

fn hex_string(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn select_trust_point(
    info: &IdentifierListInfo,
    iaca_cert: Option<&x509_cert::Certificate>,
) -> Result<x509_cert::Certificate, MsoRevocationError> {
    if let Some(certificate_der) = &info.certificate {
        return x509_cert::Certificate::from_der(certificate_der.as_slice()).map_err(|err| {
            MsoRevocationError::InvalidRevocationList(format!(
                "status certificate is not valid DER X.509: {err}"
            ))
        });
    }

    iaca_cert.cloned().ok_or_else(|| {
        MsoRevocationError::InvalidRevocationList(
            "IACA certificate is required when status.certificate is absent".to_string(),
        )
    })
}

fn is_identifier_list_content_type(value: &str) -> bool {
    matches!(
        value,
        "application/identifierlist+cwt" | "identifierlist+cwt"
    )
}

fn system_time_from_datetime(now: DateTime<Utc>) -> SystemTime {
    let seconds = now.timestamp();
    let nanos = now.timestamp_subsec_nanos();
    if seconds >= 0 {
        SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(seconds as u64)
            + std::time::Duration::from_nanos(nanos as u64)
    } else {
        SystemTime::UNIX_EPOCH
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use mdoc_core::{
        CborBytes, CoseAlg, CoseKeyPrivate, HeaderMap, IdentifierInfo, IdentifierList,
        MobileSecurityObject, ProtectedHeaderMap, Status, TDate, ValidityInfo, X5Chain,
    };
    use minicbor::bytes::ByteVec;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
    use x509_cert::der::Encode as _;

    #[tokio::test]
    async fn identifier_list_marks_document_revoked_when_identifier_is_present() {
        let fixture = revocation_fixture(true, false);
        let check = validate_identifier_list_token(
            &fixture.token_bytes,
            fixture
                .verified
                .mso
                .status
                .as_ref()
                .unwrap()
                .identifier_list
                .as_ref()
                .unwrap(),
            Some(&fixture.root_cert),
            fixture.now,
        )
        .await
        .unwrap();

        assert!(
            check
                .identifier_list
                .identifiers
                .contains_key(&fixture.expected_identifier)
        );
    }

    #[tokio::test]
    async fn check_mso_revocation_reports_not_revoked_when_identifier_is_absent() {
        let fixture = revocation_fixture(false, false);
        let info = fixture
            .verified
            .mso
            .status
            .as_ref()
            .unwrap()
            .identifier_list
            .as_ref()
            .unwrap();
        let result = evaluate_identifier_list_bytes(
            &fixture.token_bytes,
            info,
            Some(&fixture.root_cert),
            fixture.now,
            Url::parse(&info.uri).unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(result.state, MsoRevocationState::NotRevoked);
        assert_eq!(
            result.mechanism,
            Some(MsoRevocationMechanism::IdentifierList)
        );
    }

    #[tokio::test]
    async fn check_mso_revocation_uses_status_certificate_when_present() {
        let fixture = revocation_fixture(true, true);
        let info = fixture
            .verified
            .mso
            .status
            .as_ref()
            .unwrap()
            .identifier_list
            .as_ref()
            .unwrap();
        let result = evaluate_identifier_list_bytes(
            &fixture.token_bytes,
            info,
            None,
            fixture.now,
            Url::parse(&info.uri).unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(result.state, MsoRevocationState::Revoked);
    }

    #[test]
    fn normalize_downloaded_revocation_list_decodes_hex_ascii_payload() {
        let normalized = normalize_downloaded_revocation_list(b"4432");
        assert_eq!(normalized, vec![0x44, 0x32]);
    }

    struct RevocationFixture {
        verified: VerifiedMso,
        root_cert: x509_cert::Certificate,
        token_bytes: Vec<u8>,
        expected_identifier: ByteVec,
        now: DateTime<Utc>,
    }

    fn revocation_fixture(include_identifier: bool, embed_status_cert: bool) -> RevocationFixture {
        let now = DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_cert = CertificateParams::new(vec!["revocation.example".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap();

        let root_cert = x509_cert::Certificate::from_der(ca_cert.der()).unwrap();
        let leaf_cert_der = x509_cert::Certificate::from_der(leaf_cert.der()).unwrap();
        let leaf_secret = p256::SecretKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
        let leaf_signing_key = p256::ecdsa::SigningKey::from(leaf_secret);

        let expected_identifier = ByteVec::from(vec![0xAB; 16]);
        let identifiers = if include_identifier {
            BTreeMap::from([(expected_identifier.clone(), IdentifierInfo {})])
        } else {
            BTreeMap::new()
        };

        let token = CborWebToken {
            uri: Some("https://example.com/identifier-list".to_string()),
            exp: (now.timestamp() as u64) + 3600,
            iat: Some(now.timestamp() as u64),
            ttl: Some(60),
            identifier_list: IdentifierList {
                identifiers,
                aggregation_uri: None,
            },
        };
        let token_bytes = sign_identifier_list_token(&token, &leaf_cert_der, &leaf_signing_key);

        let status_certificate =
            embed_status_cert.then(|| ByteVec::from(root_cert.to_der().unwrap()));
        let verified = VerifiedMso {
            mso: MobileSecurityObject {
                version: "1.0".to_string(),
                digest_algorithm: "SHA-256".to_string(),
                value_digests: BTreeMap::new(),
                device_key_info: mdoc_core::DeviceKeyInfo {
                    device_key: CoseKeyPrivate::new().unwrap().to_public(),
                    key_authorizations: None,
                    key_info: None,
                },
                doc_type: "org.iso.18013.5.1.mDL".to_string(),
                validity_info: ValidityInfo {
                    signed: TDate::from("2026-01-01T00:00:00Z".to_string()),
                    valid_from: TDate::from("2026-01-01T00:00:00Z".to_string()),
                    valid_until: TDate::from("2027-01-01T00:00:00Z".to_string()),
                    expected_update: None,
                },
                status: Some(Status {
                    identifier_list: Some(mdoc_core::IdentifierListInfo {
                        id: expected_identifier.clone(),
                        uri: "https://example.com/identifier-list".to_string(),
                        certificate: status_certificate,
                    }),
                    status_list: None,
                }),
            },
            issuer_cert: None,
        };

        RevocationFixture {
            verified,
            root_cert,
            token_bytes,
            expected_identifier,
            now,
        }
    }

    fn sign_identifier_list_token(
        token: &CborWebToken,
        leaf_cert: &x509_cert::Certificate,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> Vec<u8> {
        let protected = ProtectedHeaderMap::from(&HeaderMap {
            alg: Some(CoseAlg::ES256),
            typ: Some("identifierlist+cwt".to_string()),
            x5chain: Some(X5Chain::from_certificates(vec![leaf_cert.clone()]).unwrap()),
        });
        let payload = CborBytes::from(token);
        let sig_structure = minicbor::to_vec((
            "Signature1",
            ByteVec::from(protected.raw_cbor_bytes().to_vec()),
            ByteVec::from(Vec::<u8>::new()),
            ByteVec::from(payload.raw_cbor_bytes().to_vec()),
        ))
        .unwrap();
        let signature: p256::ecdsa::Signature = signing_key.sign(&sig_structure);

        minicbor::to_vec(Tagged::<18, _>::from(CoseSign1::new(
            protected,
            HeaderMap::default(),
            Some(payload),
            ByteVec::from(signature.to_bytes().to_vec()),
        )))
        .unwrap()
    }
}
