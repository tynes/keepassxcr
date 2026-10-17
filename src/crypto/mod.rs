//! Cryptographic primitives and key derivation.

mod cipher;
mod composite_key;
mod constants;
mod hash;
mod kdf;
mod keyfile;
mod protected_stream;

pub use cipher::{CipherId, decrypt, encrypt};
pub use composite_key::CompositeKey;
pub use constants::{
    CIPHER_AES128, CIPHER_AES256, CIPHER_CHACHA20, CIPHER_TWOFISH, INNER_STREAM_SALSA20_IV,
    KDF_AES_KDBX3, KDF_AES_KDBX4, KDF_ARGON2D, KDF_ARGON2ID,
};
pub use hash::{hmac_sha256, kdbx_hmac_key, sha256, sha512};
pub use kdf::{KdfConfig, KdfProgressHook, KdfType, set_kdf_progress_hook};
pub use keyfile::KeyFile;
pub use protected_stream::{ProtectedStream, ProtectedStreamAlgo};
