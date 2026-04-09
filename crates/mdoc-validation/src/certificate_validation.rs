use std::time::SystemTime;

use log::{info, warn};
use reqwest::blocking::Client;
use rustls_pki_types::{CertificateDer, UnixTime};
use url::Url;
use webpki::{
    anchor_from_trusted_cert, BorrowedCertRevocationList, CertRevocationList, EndEntityCert,
    Error as WebPkiError, ExpirationPolicy, ExtendedKeyUsageValidator, KeyPurposeIdIter,
    RevocationCheckDepth, RevocationOptionsBuilder, UnknownStatusPolicy,
};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::ValidationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateValidationOutcome {
    Valid { crl_checked: bool },
}

pub fn download_iacacert_der(iacacert_url: Url) -> Result<Vec<u8>, ValidationError> {
    if iacacert_url.scheme() != "https" {
        return Err(ValidationError::Unsupported(
            "only https iacacert URLs are allowed".to_string(),
        ));
    }

    info!("certificate_validation: downloading IACA certificate url={iacacert_url}");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ValidationError::Network(e.to_string()))?;

    let response = client
        .get(iacacert_url.clone())
        .send()
        .and_then(|resp| resp.error_for_status())
        .map_err(|e| ValidationError::Network(e.to_string()))?;

    let bytes = response
        .bytes()
        .map_err(|e| ValidationError::Network(e.to_string()))?;

    info!(
        "certificate_validation: downloaded IACA certificate url={} bytes={}",
        iacacert_url,
        bytes.len()
    );

    Ok(bytes.to_vec())
}

pub fn validate_reader_auth_certificate(
    iacacert_der: &[u8],
    x5chain: &[Vec<u8>],
    now: SystemTime,
) -> Result<CertificateValidationOutcome, ValidationError> {
    if x5chain.is_empty() {
        return Err(ValidationError::InvalidChain);
    }

    info!(
        "certificate_validation: start iaca_bytes={} chain_len={}",
        iacacert_der.len(),
        x5chain.len()
    );

    let iaca_der = CertificateDer::from(iacacert_der);
    let iaca_anchor =
        anchor_from_trusted_cert(&iaca_der).map_err(map_webpki_error_to_validation_error)?;
    let (_, iaca) = x509_parser::certificate::X509Certificate::from_der(iacacert_der)
        .map_err(|e| ValidationError::CertificateParse(e.to_string()))?;

    let mut parsed_chain = Vec::with_capacity(x5chain.len());
    let mut chain_der = Vec::with_capacity(x5chain.len());
    for der in x5chain {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|e| ValidationError::CertificateParse(e.to_string()))?;
        parsed_chain.push(cert);
        chain_der.push(CertificateDer::from(der.as_slice()));
    }

    validate_key_usage(&parsed_chain[0])?;

    let end_entity =
        EndEntityCert::try_from(&chain_der[0]).map_err(map_webpki_error_to_validation_error)?;
    let intermediates = &chain_der[1..];
    let trust_anchors = [iaca_anchor];
    let now = UnixTime::since_unix_epoch(
        now.duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ValidationError::Expired)?,
    );

    let mut crl_checked = false;
    let mut crls = Vec::new();
    if let Some(crl_url) = extract_first_crl_uri(&iaca) {
        info!("certificate_validation: CRL distribution point found url={crl_url}");
        let crl_der = download_crl_der(&crl_url)?;
        let crl = BorrowedCertRevocationList::from_der(&crl_der)
            .map_err(|e| ValidationError::CrlParse(e.to_string()))?;
        let crl = CertRevocationList::from(
            crl.to_owned()
                .map_err(|e| ValidationError::CrlParse(e.to_string()))?,
        );
        crls.push(crl);
        crl_checked = true;
        info!(
            "certificate_validation: CRL parsed url={} bytes={}",
            crl_url,
            crl_der.len(),
        );
    } else {
        info!("certificate_validation: no CRL distribution point found in IACA certificate");
    }

    let crl_refs = crls.iter().collect::<Vec<_>>();
    let revocation = if crl_refs.is_empty() {
        None
    } else {
        Some(
            RevocationOptionsBuilder::new(&crl_refs)
                .map_err(|_| ValidationError::CrlParse("no CRLs provided".to_string()))?
                .with_depth(RevocationCheckDepth::EndEntity)
                .with_status_policy(UnknownStatusPolicy::Deny)
                .with_expiration_policy(ExpirationPolicy::Ignore)
                .build(),
        )
    };

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

fn extract_first_crl_uri(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<Url> {
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
            for point in &points.points {
                if let Some(name) = &point.distribution_point {
                    if let x509_parser::extensions::DistributionPointName::FullName(names) = name {
                        for general_name in names {
                            if let GeneralName::URI(uri) = general_name {
                                if let Ok(url) = Url::parse(uri) {
                                    return Some(url);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn download_crl_der(crl_url: &Url) -> Result<Vec<u8>, ValidationError> {
    if crl_url.scheme() != "https" {
        return Err(ValidationError::Unsupported(
            "only https crl URLs are supported".to_string(),
        ));
    }

    info!("certificate_validation: downloading CRL url={crl_url}");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ValidationError::Network(e.to_string()))?;

    let response = client
        .get(crl_url.clone())
        .send()
        .and_then(|resp| resp.error_for_status())
        .map_err(|err| {
            warn!(
                "certificate_validation: CRL download failed url={} error={err}",
                crl_url
            );
            ValidationError::CrlUnavailable
        })?;

    let bytes = response.bytes().map_err(|err| {
        warn!(
            "certificate_validation: CRL response body read failed url={} error={err}",
            crl_url
        );
        ValidationError::CrlUnavailable
    })?;

    info!(
        "certificate_validation: downloaded CRL url={} bytes={}",
        crl_url,
        bytes.len()
    );

    Ok(bytes.to_vec())
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
        WebPkiError::UnknownRevocationStatus => ValidationError::CrlUnavailable,
        WebPkiError::BadDer
        | WebPkiError::BadDerTime
        | WebPkiError::TrailingData(_)
        | WebPkiError::InvalidSerialNumber
        | WebPkiError::MalformedExtensions
        | WebPkiError::ExtensionValueInvalid => ValidationError::CertificateParse(err.to_string()),
        _ => ValidationError::InvalidChain,
    }
}
