use std::{fs, path::Path, time::SystemTime};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use log::{info, warn};
use reqwest::Client;
use rustls_pki_types::{CertificateDer, UnixTime};
use url::Url;
use webpki::{
    CertRevocationList, EndEntityCert, Error as WebPkiError, ExpirationPolicy,
    ExtendedKeyUsageValidator, KeyPurposeIdIter, OwnedCertRevocationList, RevocationCheckDepth,
    RevocationOptionsBuilder, UnknownStatusPolicy, anchor_from_trusted_cert,
};
use x509_cert::der::{Decode as _, Encode as _};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::ValidationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateValidationOutcome {
    Valid { crl_checked: bool },
}

#[derive(Debug, Clone, Copy)]
enum RemoteDerKind {
    Certificate,
    Crl,
}

pub fn load_x509_certificate_from_file(
    path: impl AsRef<Path>,
) -> Result<x509_cert::Certificate, ValidationError> {
    let path = path.as_ref();
    let certificate_bytes = fs::read(path)
        .map_err(|err| ValidationError::Unavailable(format!("{}: {err}", path.display())))?;
    parse_x509_certificate(&certificate_bytes)
}

fn parse_x509_certificate(
    certificate_bytes: &[u8],
) -> Result<x509_cert::Certificate, ValidationError> {
    let certificate_der = decode_pem_or_der(certificate_bytes, RemoteDerKind::Certificate)?;
    x509_cert::Certificate::from_der(certificate_der.as_slice())
        .map_err(|err| ValidationError::Parse(err.to_string()))
}

pub async fn download_x509_certificate(
    certificate_url: &Url,
) -> Result<x509_cert::Certificate, ValidationError> {
    let certificate_bytes =
        download_remote_bytes(certificate_url, RemoteDerKind::Certificate).await?;
    parse_x509_certificate(&certificate_bytes)
}

pub async fn validate_x5chain(
    root_certificate: &x509_cert::Certificate,
    x5chain: &[x509_cert::Certificate],
    skip_crl: bool,
    now: SystemTime,
) -> Result<CertificateValidationOutcome, ValidationError> {
    let root_certificate_der = root_certificate
        .to_der()
        .map_err(|err| ValidationError::Parse(err.to_string()))?;

    info!(
        "certificate_validation: start root_bytes={} chain_len={} skip_crl={skip_crl}",
        root_certificate_der.len(),
        x5chain.len()
    );

    let root_der = CertificateDer::from(root_certificate_der.as_slice());
    let root_anchor =
        anchor_from_trusted_cert(&root_der).map_err(map_webpki_error_to_validation_error)?;

    let encoded_chain = x5chain
        .iter()
        .map(|cert| {
            cert.to_der()
                .map_err(|err| ValidationError::Parse(err.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut parsed_chain = Vec::with_capacity(encoded_chain.len());
    let mut chain_der = Vec::with_capacity(encoded_chain.len());
    for der in &encoded_chain {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|e| ValidationError::Parse(e.to_string()))?;
        parsed_chain.push(cert);
        chain_der.push(CertificateDer::from(der.as_slice()));
    }

    validate_key_usage(&parsed_chain[0])?;

    let end_entity =
        EndEntityCert::try_from(&chain_der[0]).map_err(map_webpki_error_to_validation_error)?;
    let intermediates = &chain_der[1..];
    let trust_anchors = [root_anchor];
    let now = UnixTime::since_unix_epoch(
        now.duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ValidationError::Expired)?,
    );

    let downloaded_crls =
        download_crls_for_chain_if_enabled(root_certificate, x5chain, skip_crl).await?;
    let crl_refs = downloaded_crls.iter().collect::<Vec<_>>();
    let revocation = if crl_refs.is_empty() {
        None
    } else {
        Some(
            RevocationOptionsBuilder::new(&crl_refs)
                .map_err(|_| ValidationError::Parse("no CRLs provided".to_string()))?
                .with_depth(RevocationCheckDepth::Chain)
                .with_status_policy(UnknownStatusPolicy::Deny)
                .with_expiration_policy(ExpirationPolicy::Ignore)
                .build(),
        )
    };
    let crl_checked = !skip_crl && !crl_refs.is_empty();

    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            intermediates,
            now,
            AllowAnyExtendedKeyUsage,
            revocation,
            None,
        )
        .map_err(map_webpki_error_to_validation_error)?;

    info!("certificate_validation: completed crl_checked={crl_checked}");
    Ok(CertificateValidationOutcome::Valid { crl_checked })
}

async fn download_crls_for_chain_if_enabled(
    root_certificate: &x509_cert::Certificate,
    x5chain: &[x509_cert::Certificate],
    skip_crl: bool,
) -> Result<Vec<CertRevocationList<'static>>, ValidationError> {
    if skip_crl {
        info!("certificate_validation: CRL check skipped");
        return Ok(Vec::new());
    }

    download_crls_for_certificate_chain(root_certificate, x5chain).await
}

fn validate_key_usage(
    leaf: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(), ValidationError> {
    if let Ok(Some(ku)) = leaf.key_usage() {
        if !ku.value.digital_signature() {
            return Err(ValidationError::InvalidChain);
        }
    }
    Ok(())
}

fn extract_crl_uris(cert: &x509_parser::certificate::X509Certificate<'_>) -> Vec<Url> {
    let mut urls = Vec::new();

    for ext in cert.extensions() {
        let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() else {
            continue;
        };

        for point in &points.points {
            let Some(name) = &point.distribution_point else {
                continue;
            };
            let x509_parser::extensions::DistributionPointName::FullName(names) = name else {
                continue;
            };

            for general_name in names {
                let GeneralName::URI(uri) = general_name else {
                    continue;
                };
                if let Ok(url) = Url::parse(uri) {
                    urls.push(url);
                }
            }
        }
    }

    urls
}

fn parse_crl(crl_bytes: &[u8]) -> Result<CertRevocationList<'static>, ValidationError> {
    let crl_der = decode_pem_or_der(crl_bytes, RemoteDerKind::Crl)?;
    let crl = OwnedCertRevocationList::from_der(crl_der.as_slice())
        .map_err(|err| ValidationError::Parse(err.to_string()))?;
    Ok(CertRevocationList::from(crl))
}

async fn download_crl(crl_url: &Url) -> Result<CertRevocationList<'static>, ValidationError> {
    let crl_bytes = download_remote_bytes(crl_url, RemoteDerKind::Crl).await?;
    parse_crl(&crl_bytes)
}

async fn download_crls_for_certificate(
    certificate: &x509_cert::Certificate,
) -> Result<Option<Vec<CertRevocationList<'static>>>, ValidationError> {
    let certificate_der = certificate
        .to_der()
        .map_err(|err| ValidationError::Parse(err.to_string()))?;
    let (_, parsed_certificate) =
        x509_parser::certificate::X509Certificate::from_der(&certificate_der)
            .map_err(|err| ValidationError::Parse(err.to_string()))?;
    let crl_urls = extract_crl_uris(&parsed_certificate);
    if crl_urls.is_empty() {
        return Ok(None);
    }

    let mut crls = Vec::new();
    let mut last_error = None;
    for crl_url in crl_urls {
        info!("certificate_validation: CRL distribution point found url={crl_url}");
        match download_crl(&crl_url).await {
            Ok(crl) => crls.push(crl),
            Err(err) => {
                warn!(
                    "certificate_validation: CRL download skipped url={} error={err}",
                    crl_url
                );
                last_error = Some(err);
            }
        }
    }

    if crls.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            ValidationError::Unavailable("all CRL downloads failed".to_string())
        }));
    }

    Ok(Some(crls))
}

async fn download_crls_for_certificate_chain(
    root_certificate: &x509_cert::Certificate,
    x5chain: &[x509_cert::Certificate],
) -> Result<Vec<CertRevocationList<'static>>, ValidationError> {
    let mut all_crls = Vec::new();
    let mut saw_distribution_point = false;

    for certificate in std::iter::once(root_certificate).chain(x5chain.iter()) {
        match download_crls_for_certificate(certificate).await? {
            Some(mut crls) => {
                saw_distribution_point = true;
                all_crls.append(&mut crls);
            }
            None => {
                // This certificate does not advertise CRL distribution points.
            }
        }
    }

    if !saw_distribution_point {
        info!(
            "certificate_validation: no CRL distribution point found in root or chain certificates"
        );
    }

    Ok(all_crls)
}

#[derive(Debug, Clone, Copy)]
struct AllowAnyExtendedKeyUsage;

impl ExtendedKeyUsageValidator for AllowAnyExtendedKeyUsage {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), WebPkiError> {
        for eku in iter {
            eku?;
        }
        Ok(())
    }
}

fn map_webpki_error_to_validation_error(err: WebPkiError) -> ValidationError {
    match err {
        WebPkiError::CertRevoked => {
            warn!("certificate_validation: revocation check failed error={err}");
            ValidationError::Revoked
        }
        WebPkiError::CertExpired { .. }
        | WebPkiError::CertNotValidYet { .. }
        | WebPkiError::InvalidCertValidity => ValidationError::Expired,
        WebPkiError::UnknownRevocationStatus => {
            ValidationError::Unavailable("CRL status unknown".to_string())
        }
        WebPkiError::BadDer
        | WebPkiError::BadDerTime
        | WebPkiError::TrailingData(_)
        | WebPkiError::InvalidSerialNumber
        | WebPkiError::MalformedExtensions
        | WebPkiError::ExtensionValueInvalid => ValidationError::Parse(err.to_string()),
        _ => ValidationError::InvalidChain,
    }
}

async fn download_remote_bytes(url: &Url, kind: RemoteDerKind) -> Result<Vec<u8>, ValidationError> {
    ensure_https_url(url, kind)?;

    info!(
        "certificate_validation: downloading {} url={url}",
        kind.label()
    );

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|err| {
            ValidationError::Unavailable(format!("{} client build failed: {err}", kind.label()))
        })?;

    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|err| {
            warn!(
                "certificate_validation: {} download failed url={} error={err}",
                kind.label(),
                url
            );
            ValidationError::Unavailable(format!("{} download failed: {err}", kind.label()))
        })?
        .error_for_status()
        .map_err(|err| {
            warn!(
                "certificate_validation: {} download failed url={} error={err}",
                kind.label(),
                url
            );
            ValidationError::Unavailable(format!("{} download failed: {err}", kind.label()))
        })?;

    let bytes = response.bytes().await.map_err(|err| {
        warn!(
            "certificate_validation: {} response body read failed url={} error={err}",
            kind.label(),
            url
        );
        ValidationError::Unavailable(format!("{} response body read failed: {err}", kind.label()))
    })?;

    info!(
        "certificate_validation: downloaded {} url={} bytes={}",
        kind.label(),
        url,
        bytes.len()
    );

    Ok(bytes.to_vec())
}

fn decode_pem_or_der(bytes: &[u8], kind: RemoteDerKind) -> Result<Vec<u8>, ValidationError> {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return Ok(bytes.to_vec()),
    };

    let (begin_marker, end_marker) = match kind {
        RemoteDerKind::Certificate => ("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"),
        RemoteDerKind::Crl => ("-----BEGIN X509 CRL-----", "-----END X509 CRL-----"),
    };

    let Some(begin) = text.find(begin_marker) else {
        return Ok(bytes.to_vec());
    };
    let rest = &text[begin + begin_marker.len()..];
    let end = rest
        .find(end_marker)
        .ok_or_else(|| ValidationError::Parse(format!("{} PEM footer not found", kind.label())))?;
    let base64_body: String = rest[..end].lines().map(str::trim).collect();

    STANDARD.decode(base64_body).map_err(|err| {
        ValidationError::Parse(format!(
            "{} PEM body is not valid base64: {err}",
            kind.label()
        ))
    })
}

fn ensure_https_url(url: &Url, kind: RemoteDerKind) -> Result<(), ValidationError> {
    if url.scheme() == "https" {
        return Ok(());
    }

    Err(ValidationError::Unavailable(format!(
        "only https {} URLs are supported",
        kind.label()
    )))
}

impl RemoteDerKind {
    fn label(self) -> &'static str {
        match self {
            RemoteDerKind::Certificate => "certificate",
            RemoteDerKind::Crl => "CRL",
        }
    }
}
