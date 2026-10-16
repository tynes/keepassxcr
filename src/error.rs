use std::io;

/// Error type for keepassxcr operations.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// IO-related failures.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Cryptography failures.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Invalid or unsupported file format.
    #[error("format error: {0}")]
    Format(String),

    /// XML parsing or serialization failures.
    #[error("xml error: {0}")]
    Xml(String),

    /// Invalid user input or arguments.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Clipboard interaction failures.
    #[error("clipboard error: {0}")]
    Clipboard(String),

    /// The database's agent unlock expired; the command refuses to prompt.
    #[error("{0}")]
    Locked(String),
}

/// Result alias for keepassxcr operations.
pub type AppResult<T> = Result<T, AppError>;
