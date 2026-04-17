use std::time::SystemTime;

use mdoc_core::{CoseSign1, MobileSecurityObject, TaggedCborBytes};

use crate::certificate_validation::{validate_x5chain, CertificateValidationOutcome};

pub async fn validate_document_x5chain(
    issuer_auth: &CoseSign1<TaggedCborBytes<MobileSecurityObject>>,
    root_certificate: &x509_cert::Certificate,
    skip_crl: bool,
    now: SystemTime,
) -> Result<CertificateValidationOutcome, crate::ValidationError> {
    let x5chain = issuer_auth
        .x5chain()
        .ok_or(crate::ValidationError::InvalidChain)?;

    validate_x5chain(root_certificate, x5chain, skip_crl, now).await
}
