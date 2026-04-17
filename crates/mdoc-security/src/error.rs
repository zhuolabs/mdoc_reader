use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("failed to parse data: {0}")]
    Parse(String),
    #[error("invalid certificate chain")]
    InvalidChain,
    #[error("certificate expired or not yet valid")]
    Expired,
    #[error("certificate revoked")]
    Revoked,
}
