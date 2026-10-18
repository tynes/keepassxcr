//! PIN/UV auth protocols one and two (CTAP 2.1, section 6.5): the ECDH key
//! agreement and the shared-secret encryption that protect the PIN and the
//! hmac-secret salt and output on their way to and from the key.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::AppResult;
use crate::fido2::cbor::Value;
use crate::fido2::fido2_error;

/// Which PIN/UV auth protocol a shared secret belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    One = 1,
    Two = 2,
}

impl Protocol {
    pub fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            _ => None,
        }
    }

    pub fn number(self) -> i64 {
        self as i64
    }
}

/// A secret shared with the authenticator for one session.
pub struct SharedSecret {
    pub protocol: Protocol,
    /// Protocol one: 32 bytes. Protocol two: HMAC key then AES key.
    key: Zeroizing<Vec<u8>>,
}

/// An ephemeral P-256 key pair for one key agreement.
pub struct KeyAgreement {
    secret: EphemeralSecret,
}

impl KeyAgreement {
    pub fn new() -> Self {
        Self {
            secret: EphemeralSecret::random(&mut OsRng),
        }
    }

    /// Our public key as a COSE_Key, as CTAP sends it.
    pub fn cose_public_key(&self) -> Value {
        cose_key(&self.secret.public_key())
    }

    /// Derive the shared secret with the peer's COSE_Key.
    ///
    /// # Errors
    ///
    /// Fails when the peer key is not a valid P-256 point.
    pub fn agree(&self, protocol: Protocol, peer: &Value) -> AppResult<SharedSecret> {
        let peer = parse_cose_key(peer)?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SharedSecret::derive(
            protocol,
            shared.raw_secret_bytes().as_slice(),
        ))
    }
}

impl Default for KeyAgreement {
    fn default() -> Self {
        Self::new()
    }
}

/// A P-256 public key as a COSE_Key for ECDH-ES+HKDF-256.
pub fn cose_key(key: &PublicKey) -> Value {
    let point = key.to_encoded_point(false);
    Value::int_map(vec![
        (1, Value::Int(2)),
        (3, Value::Int(-25)),
        (-1, Value::Int(1)),
        (
            -2,
            Value::Bytes(point.x().map(|x| x.to_vec()).unwrap_or_default()),
        ),
        (
            -3,
            Value::Bytes(point.y().map(|y| y.to_vec()).unwrap_or_default()),
        ),
    ])
}

/// Read a P-256 COSE_Key.
///
/// # Errors
///
/// Fails when it is not a valid P-256 point.
pub fn parse_cose_key(value: &Value) -> AppResult<PublicKey> {
    let coordinate = |label| {
        value
            .get_int(label)
            .and_then(Value::as_bytes)
            .filter(|bytes| bytes.len() == 32)
            .ok_or_else(|| fido2_error("the security key sent a malformed public key"))
    };
    if value.get_int(-1).and_then(Value::as_int) != Some(1) {
        return Err(fido2_error("the security key's public key is not on P-256"));
    }
    let point = EncodedPoint::from_affine_coordinates(
        coordinate(-2)?.into(),
        coordinate(-3)?.into(),
        false,
    );
    Option::from(PublicKey::from_encoded_point(&point))
        .ok_or_else(|| fido2_error("the security key's public key is not a valid point"))
}

impl SharedSecret {
    /// The shared secret from the ECDH x coordinate `z`.
    pub fn derive(protocol: Protocol, z: &[u8]) -> Self {
        let key = match protocol {
            Protocol::One => Zeroizing::new(Sha256::digest(z).to_vec()),
            Protocol::Two => {
                let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z);
                let mut key = Zeroizing::new(vec![0u8; 64]);
                // Both lengths are well under HKDF's limit.
                let _ = hkdf.expand(b"CTAP2 HMAC key", &mut key[..32]);
                let _ = hkdf.expand(b"CTAP2 AES key", &mut key[32..]);
                key
            }
        };
        Self { protocol, key }
    }

    fn aes_key(&self) -> &[u8] {
        match self.protocol {
            Protocol::One => &self.key,
            Protocol::Two => &self.key[32..],
        }
    }

    /// Encrypt a multiple of 16 bytes.
    ///
    /// # Errors
    ///
    /// Fails when `data` is not a whole number of blocks.
    pub fn encrypt(&self, data: &[u8]) -> AppResult<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(fido2_error("data to encrypt is not whole AES blocks"));
        }
        let mut iv = [0u8; 16];
        if self.protocol == Protocol::Two {
            OsRng.fill_bytes(&mut iv);
        }
        let encryptor = Encryptor::<Aes256>::new_from_slices(self.aes_key(), &iv)
            .map_err(|_| fido2_error("bad AES key"))?;
        let mut ciphertext = data.to_vec();
        encryptor
            .encrypt_padded_mut::<NoPadding>(&mut ciphertext, data.len())
            .map_err(|_| fido2_error("AES encryption failed"))?;
        Ok(match self.protocol {
            Protocol::One => ciphertext,
            Protocol::Two => [iv.as_slice(), &ciphertext].concat(),
        })
    }

    /// Decrypt what [`Self::encrypt`] produced on the other side.
    ///
    /// # Errors
    ///
    /// Fails on a malformed ciphertext.
    pub fn decrypt(&self, data: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
        let (iv, body) = match self.protocol {
            Protocol::One => ([0u8; 16], data),
            Protocol::Two => {
                if data.len() < 16 {
                    return Err(fido2_error(
                        "encrypted data from the security key is too short",
                    ));
                }
                let mut iv = [0u8; 16];
                iv.copy_from_slice(&data[..16]);
                (iv, &data[16..])
            }
        };
        let decryptor = Decryptor::<Aes256>::new_from_slices(self.aes_key(), &iv)
            .map_err(|_| fido2_error("bad AES key"))?;
        let mut plain = Zeroizing::new(body.to_vec());
        let len = decryptor
            .decrypt_padded_mut::<NoPadding>(&mut plain)
            .map_err(|_| fido2_error("encrypted data from the security key is malformed"))?
            .len();
        plain.truncate(len);
        Ok(plain)
    }

    /// Authenticate `message` with the shared secret.
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        authenticate(self.protocol, &self.key, message)
    }
}

/// `authenticate(key, message)` of the given protocol. With protocol two
/// only the first 32 bytes of `key` are used (the HMAC half of a shared
/// secret, or a whole PIN token).
pub fn authenticate(protocol: Protocol, key: &[u8], message: &[u8]) -> Vec<u8> {
    let key = match protocol {
        Protocol::One => key,
        Protocol::Two => &key[..key.len().min(32)],
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    let tag = mac.finalize().into_bytes().to_vec();
    match protocol {
        Protocol::One => tag[..16].to_vec(),
        Protocol::Two => tag,
    }
}

/// `LEFT(SHA-256(pin), 16)`, what CTAP sends in place of the PIN.
pub fn pin_hash(pin: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Sha256::digest(pin.as_bytes())[..16].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_secret() {
        for protocol in [Protocol::One, Protocol::Two] {
            let platform = KeyAgreement::new();
            let authenticator = KeyAgreement::new();
            let a = platform
                .agree(protocol, &authenticator.cose_public_key())
                .unwrap();
            let b = authenticator
                .agree(protocol, &platform.cose_public_key())
                .unwrap();
            let data = [7u8; 32];
            let encrypted = a.encrypt(&data).unwrap();
            assert_eq!(&b.decrypt(&encrypted).unwrap()[..], &data);
            assert_eq!(a.authenticate(b"m"), b.authenticate(b"m"));
        }
    }

    #[test]
    fn protocol_two_matches_the_spec_derivation() {
        // HKDF-SHA-256 with a zero salt and the spec's two info strings.
        let z = [0x11u8; 32];
        let secret = SharedSecret::derive(Protocol::Two, &z);
        let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &z);
        let mut hmac_key = [0u8; 32];
        hkdf.expand(b"CTAP2 HMAC key", &mut hmac_key).unwrap();
        assert_eq!(&secret.key[..32], &hmac_key);
        let encrypted = secret.encrypt(&[0u8; 16]).unwrap();
        assert_eq!(encrypted.len(), 32);
        // Protocol one has no IV, so the same input always encrypts the same.
        let one = SharedSecret::derive(Protocol::One, &z);
        assert_eq!(
            one.encrypt(&[0u8; 16]).unwrap(),
            one.encrypt(&[0u8; 16]).unwrap()
        );
        assert_eq!(one.authenticate(b"m").len(), 16);
    }
}
