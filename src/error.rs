use std::io;

/// Error type for keepassxcr operations.
///
/// New variants may be added in minor releases, so a `match` needs a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

    /// The password, key file or other credentials do not open the database.
    #[error("invalid credentials: wrong password or key file")]
    InvalidCredentials,

    /// XML parsing or serialization failures.
    #[error("xml error: {0}")]
    Xml(String),

    /// Invalid user input or arguments.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Clipboard interaction failures.
    #[error("clipboard error: {0}")]
    Clipboard(String),

    /// YubiKey challenge-response failures.
    #[error("YubiKey: {0}")]
    YubiKey(String),

    /// FIDO2 security key failures.
    #[error("security key: {0}")]
    Fido2(String),

    /// A FIDO2 security key answered with a CTAP2 error status.
    #[error("security key: {1}")]
    Fido2Status(u8, String),

    /// The database's agent unlock expired; the command refuses to prompt.
    #[error("{0}")]
    Locked(String),

    /// The command already printed its errors; exit with status 1 and print nothing more.
    #[error("errors were reported above")]
    Reported,
}

/// Result alias for keepassxcr operations.
pub type AppResult<T> = Result<T, AppError>;
