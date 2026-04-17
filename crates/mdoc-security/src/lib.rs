mod certificate_validation;
mod error;
mod issuer_data_auth;
mod mdoc_device_auth;
mod session_encryption;

pub use certificate_validation::{
    download_crl_der, download_iacacert_der, extract_crl_distribution_point,
    validate_reader_auth_certificate, CertificateValidationOutcome,
};
pub use error::ValidationError;
pub use issuer_data_auth::{
    verify_issuer_data_auth, IssuerDataAuthContext, IssuerDataAuthError, VerifiedMso,
};
pub use mdoc_device_auth::{verify_mdoc_device_auth, MdocDeviceAuthError, MdocMacAuthError};
pub use session_encryption::{
    derive_session_key, derive_session_keys, derive_shared_secret, MdocRole, SessionEncryption,
};
