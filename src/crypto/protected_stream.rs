use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};
use salsa20::Salsa20;

use crate::crypto::constants::INNER_STREAM_SALSA20_IV;
use crate::crypto::hash::{sha256, sha512};
use crate::error::{AppError, AppResult};

/// Protected field stream algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedStreamAlgo {
    /// ArcFour variant (not implemented).
    ArcFourVariant,
    /// Salsa20 stream.
    Salsa20,
    /// ChaCha20 stream.
    ChaCha20,
}

impl ProtectedStreamAlgo {
    /// Convert from numeric ID.
    pub fn from_id(id: u32) -> Option<Self> {
        match id {
            1 => Some(Self::ArcFourVariant),
            2 => Some(Self::Salsa20),
            3 => Some(Self::ChaCha20),
            _ => None,
        }
    }

    /// Numeric ID for serialization.
    pub fn id(self) -> u32 {
        match self {
            Self::ArcFourVariant => 1,
            Self::Salsa20 => 2,
            Self::ChaCha20 => 3,
        }
    }
}

/// Protected stream cipher wrapper.
pub struct ProtectedStream {
    algo: ProtectedStreamAlgo,
    salsa20: Option<Salsa20>,
    chacha20: Option<ChaCha20>,
}

impl std::fmt::Debug for ProtectedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedStream")
            .field("algo", &self.algo)
            .finish()
    }
}

impl ProtectedStream {
    /// Initialize a protected stream cipher.
    pub fn new(algo: ProtectedStreamAlgo, key: &[u8]) -> AppResult<Self> {
        match algo {
            ProtectedStreamAlgo::ArcFourVariant => Err(AppError::Crypto(
                "ArcFour protected stream is not supported".to_string(),
            )),
            ProtectedStreamAlgo::Salsa20 => {
                let key_hash = sha256(key);
                let cipher = Salsa20::new_from_slices(&key_hash, &INNER_STREAM_SALSA20_IV)
                    .map_err(|_| AppError::Crypto("invalid Salsa20 key".to_string()))?;
                Ok(Self {
                    algo,
                    salsa20: Some(cipher),
                    chacha20: None,
                })
            }
            ProtectedStreamAlgo::ChaCha20 => {
                let key_iv = sha512(key);
                let key_bytes = &key_iv[..32];
                let iv_bytes = &key_iv[32..44];
                let cipher = ChaCha20::new_from_slices(key_bytes, iv_bytes)
                    .map_err(|_| AppError::Crypto("invalid ChaCha20 key".to_string()))?;
                Ok(Self {
                    algo,
                    salsa20: None,
                    chacha20: Some(cipher),
                })
            }
        }
    }

    /// Apply the protected stream to the provided buffer.
    pub fn apply(&mut self, data: &mut [u8]) -> AppResult<()> {
        match self.algo {
            ProtectedStreamAlgo::ArcFourVariant => Err(AppError::Crypto(
                "ArcFour protected stream is not supported".to_string(),
            )),
            ProtectedStreamAlgo::Salsa20 => {
                if let Some(cipher) = &mut self.salsa20 {
                    cipher.apply_keystream(data);
                    Ok(())
                } else {
                    Err(AppError::Crypto("Salsa20 not initialized".to_string()))
                }
            }
            ProtectedStreamAlgo::ChaCha20 => {
                if let Some(cipher) = &mut self.chacha20 {
                    cipher.apply_keystream(data);
                    Ok(())
                } else {
                    Err(AppError::Crypto("ChaCha20 not initialized".to_string()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salsa20_roundtrip() {
        let mut stream = ProtectedStream::new(ProtectedStreamAlgo::Salsa20, b"key")
            .expect("stream should initialize");
        let mut data = b"secret".to_vec();
        stream.apply(&mut data).expect("encrypt");

        let mut stream = ProtectedStream::new(ProtectedStreamAlgo::Salsa20, b"key")
            .expect("stream should initialize");
        stream.apply(&mut data).expect("decrypt");
        assert_eq!(data, b"secret");
    }

    #[test]
    fn chacha20_roundtrip() {
        let mut stream = ProtectedStream::new(ProtectedStreamAlgo::ChaCha20, b"key")
            .expect("stream should initialize");
        let mut data = b"secret".to_vec();
        stream.apply(&mut data).expect("encrypt");

        let mut stream = ProtectedStream::new(ProtectedStreamAlgo::ChaCha20, b"key")
            .expect("stream should initialize");
        stream.apply(&mut data).expect("decrypt");
        assert_eq!(data, b"secret");
    }
}
