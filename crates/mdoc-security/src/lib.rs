mod certificate_validation;
mod error;
mod issuer_validation;
mod issuer_data_auth;
mod mdoc_device_auth;
mod session_encryption;

pub use certificate_validation::{
    download_x509_certificate, load_x509_certificate_from_file, validate_x5chain,
    CertificateValidationOutcome,
};
pub use error::ValidationError;
pub use issuer_data_auth::{
    verify_issuer_data_auth, IssuerDataAuthContext, IssuerDataAuthError, VerifiedMso,
};
pub use issuer_validation::validate_document_x5chain;
pub use mdoc_device_auth::{verify_mdoc_device_auth, MdocDeviceAuthError, MdocMacAuthError};
pub use session_encryption::{
    derive_shared_key, derive_shared_secret, MdocRole, SessionEncryption,
};
