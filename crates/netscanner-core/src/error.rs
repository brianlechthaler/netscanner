use thiserror::Error;

pub type ScanResult<T> = Result<T, ScanError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScanError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("no local network interfaces found")]
    NoLocalNetwork,
    #[error("internal error: {0}")]
    Internal(String),
}

impl ScanError {
    pub fn invalid_target(message: impl Into<String>) -> Self {
        Self::InvalidTarget(message.into())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_invalid_target() {
        let err = ScanError::invalid_target("bad cidr");
        assert_eq!(err.to_string(), "invalid target: bad cidr");
    }

    #[test]
    fn error_display_no_local_network() {
        assert_eq!(
            ScanError::NoLocalNetwork.to_string(),
            "no local network interfaces found"
        );
    }

    #[test]
    fn error_display_internal() {
        let err = ScanError::internal("boom");
        assert_eq!(err.to_string(), "internal error: boom");
    }

    #[test]
    fn error_constructors() {
        let internal = ScanError::internal("boom");
        let invalid = ScanError::invalid_target("bad");
        assert_eq!(internal.to_string(), "internal error: boom");
        assert_eq!(invalid.to_string(), "invalid target: bad");
    }

    #[test]
    fn error_equality() {
        assert_eq!(
            ScanError::InvalidTarget("x".into()),
            ScanError::InvalidTarget("x".into())
        );
        assert_ne!(
            ScanError::InvalidTarget("x".into()),
            ScanError::InvalidTarget("y".into())
        );
    }
}
