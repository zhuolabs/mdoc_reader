use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("failed to parse certificate: {0}")]
    CertificateParse(String),
    #[error("failed to parse crl: {0}")]
    CrlParse(String),
    #[error("invalid certificate chain")]
    InvalidChain,
    #[error("certificate expired or not yet valid")]
    Expired,
    #[error("certificate revoked")]
    Revoked,
    #[error("crl distribution point exists but crl could not be downloaded")]
    CrlUnavailable,
    #[error("network error: {0}")]
    Network(String),
    #[error("unsupported feature: {0}")]
    Unsupported(String),
}
