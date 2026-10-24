//! The CTAP2 commands keepassxcr needs, and PIN/UV protocol 1 for hmac-secret.
//!
//! Requests are CBOR maps whose keys must be in canonical order (integers
//! ascending, then text keys by length), which is the order they are built in
//! here. Ledger's Security Key app only speaks PIN/UV protocol 1, so that is
//! the one used: the salt goes to the device encrypted under SHA-256 of a
//! P-256 ECDH secret, and the answer comes back the same way.

use std::io::Cursor;
use std::sync::atomic::AtomicBool;

use aes::Aes256;
use ciborium::Value;
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::crypto::{hmac_sha256, sha256};
use crate::fido2::ctaphid::{Device, QUICK_TIMEOUT, USER_TIMEOUT};
use crate::fido2::{Failure, SALT_LEN, Secret, fido2_error};

pub(super) const MAKE_CREDENTIAL: u8 = 0x01;
pub(super) const GET_ASSERTION: u8 = 0x02;
pub(super) const GET_INFO: u8 = 0x04;
pub(super) const CLIENT_PIN: u8 = 0x06;
/// clientPIN subcommand: get the device's ECDH public key.
pub(super) const GET_KEY_AGREEMENT: i64 = 2;
pub(super) const HMAC_SECRET: &str = "hmac-secret";

/// authData flag: attested credential data follows the header.
pub(super) const FLAG_AT: u8 = 0x40;
/// authData flag: extension outputs follow.
pub(super) const FLAG_ED: u8 = 0x80;
/// rpIdHash (32), flags (1) and signature counter (4).
pub(super) const AUTH_DATA_HEADER: usize = 37;

/// A CBOR map in canonical key order.
pub(super) type Map = Vec<(Value, Value)>;

/// A CBOR integer.
pub(super) fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

/// A CBOR text string.
pub(super) fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

/// Encode `command` followed by `map`.
pub(super) fn encode(command: u8, map: Map) -> Result<Vec<u8>, Failure> {
    let mut request = vec![command];
    ciborium::into_writer(&Value::Map(map), &mut request)
        .map_err(|err| fido2_error(format!("encoding a request failed: {err}")))?;
    Ok(request)
}

/// Decode a response, or request, that must be a CBOR map.
pub(super) fn decode_map(bytes: &[u8]) -> Result<Map, Failure> {
    match ciborium::from_reader(bytes) {
        Ok(Value::Map(map)) => Ok(map),
        _ => Err(fido2_error("the device sent malformed CBOR")),
    }
}

/// The value under integer `key`.
pub(super) fn get(map: &Map, key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| k.as_integer() == Some(key.into()))
        .map(|(_, v)| v)
}

/// The value under text `key`.
pub(super) fn get_text<'a>(map: &'a Map, key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

/// The byte string under integer `key`.
pub(super) fn get_bytes(map: &Map, key: i64) -> Result<&[u8], Failure> {
    get(map, key)
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
        .ok_or_else(|| fido2_error(format!("the device's answer lacks field {key}")))
}

/// Whether the device supports hmac-secret with PIN/UV protocol 1.
pub(super) fn supports_hmac_secret(device: &mut Device) -> Result<bool, Failure> {
    let info =
        decode_map(&device.cbor(&[GET_INFO], QUICK_TIMEOUT, &AtomicBool::new(false), &|| {})?)?;
    let has_extension = get(&info, 2)
        .and_then(Value::as_array)
        .is_some_and(|list| list.iter().any(|v| v.as_text() == Some(HMAC_SECRET)));
    // CTAP 2.0 devices without a PIN may leave the list out; protocol 1 is the default.
    let has_protocol_1 = get(&info, 6)
        .and_then(Value::as_array)
        .is_none_or(|list| list.iter().any(|v| v.as_integer() == Some(1.into())));
    Ok(has_extension && has_protocol_1)
}

/// Register a new credential for `rp_id` with hmac-secret enabled and return
/// its id. The device asks the user to confirm.
pub(super) fn make_credential(
    device: &mut Device,
    rp_id: &str,
    cancel: &AtomicBool,
    on_touch: &(dyn Fn() + Sync),
) -> Result<Vec<u8>, Failure> {
    let mut client_data_hash = [0u8; 32];
    OsRng.fill_bytes(&mut client_data_hash);
    let mut user_id = [0u8; 16];
    OsRng.fill_bytes(&mut user_id);
    let request = encode(
        MAKE_CREDENTIAL,
        vec![
            (int(1), Value::Bytes(client_data_hash.to_vec())),
            (
                int(2),
                Value::Map(vec![(text("id"), text(rp_id)), (text("name"), text(rp_id))]),
            ),
            (
                int(3),
                Value::Map(vec![
                    (text("id"), Value::Bytes(user_id.to_vec())),
                    (text("name"), text("keepassxcr")),
                    (text("displayName"), text("keepassxcr")),
                ]),
            ),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ])]),
            ),
            (
                int(6),
                Value::Map(vec![(text(HMAC_SECRET), Value::Bool(true))]),
            ),
            (int(7), Value::Map(vec![(text("rk"), Value::Bool(false))])),
        ],
    )?;
    let response = decode_map(&device.cbor(&request, USER_TIMEOUT, cancel, on_touch)?)?;
    parse_credential(get_bytes(&response, 2)?)
}

/// The credential id in a makeCredential authData, after checking that the
/// device enabled hmac-secret for it.
pub(super) fn parse_credential(auth_data: &[u8]) -> Result<Vec<u8>, Failure> {
    let malformed = || fido2_error("the device sent malformed authenticator data");
    let flags = *auth_data.get(32).ok_or_else(malformed)?;
    if flags & FLAG_AT == 0 {
        return Err(malformed());
    }
    // AAGUID (16), then the credential id's length.
    let len_at = AUTH_DATA_HEADER + 16;
    let len = auth_data.get(len_at..len_at + 2).ok_or_else(malformed)?;
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    let id_end = len_at + 2 + len;
    let credential_id = auth_data.get(len_at + 2..id_end).ok_or_else(malformed)?;

    // The credential's public key, a CBOR map of unknown length, then the extensions.
    let mut rest = Cursor::new(auth_data.get(id_end..).ok_or_else(malformed)?);
    ciborium::from_reader::<Value, _>(&mut rest).map_err(|_| malformed())?;
    let enabled = flags & FLAG_ED != 0
        && match ciborium::from_reader::<Value, _>(&mut rest) {
            Ok(Value::Map(extensions)) => {
                get_text(&extensions, HMAC_SECRET) == Some(&Value::Bool(true))
            }
            _ => false,
        };
    if !enabled {
        return Err(fido2_error(
            "the device did not enable hmac-secret for the new credential",
        ));
    }
    Ok(credential_id.to_vec())
}

/// Ask the device for hmac-secret of `salt` under `credential_id`.
///
/// No `uv` option is sent: the answer depends on whether the device verified
/// the user, and leaving it out keeps the answer the same on every unlock.
/// With `user_presence` false the request carries `"up": false`, asking the
/// device not to wait for a confirmation. Presence does not change the answer.
pub(super) fn hmac_secret(
    device: &mut Device,
    rp_id: &str,
    credential_id: &[u8],
    salt: &[u8; SALT_LEN],
    user_presence: bool,
    cancel: &AtomicBool,
    on_touch: &(dyn Fn() + Sync),
) -> Result<Secret, Failure> {
    let request = encode(
        CLIENT_PIN,
        vec![(int(1), int(1)), (int(2), int(GET_KEY_AGREEMENT))],
    )?;
    let response = decode_map(&device.cbor(&request, QUICK_TIMEOUT, cancel, on_touch)?)?;
    let device_key = get(&response, 1)
        .ok_or_else(|| fido2_error("the device sent no key agreement"))
        .and_then(parse_cose_key)?;

    let ours = EphemeralSecret::random(&mut OsRng);
    let shared = shared_secret(&ours, &device_key);
    let salt_enc = aes_cbc(&shared, salt, true);
    let salt_auth = authenticate(&shared, &salt_enc)?;

    let mut client_data_hash = [0u8; 32];
    OsRng.fill_bytes(&mut client_data_hash);
    let mut fields = vec![
        (int(1), text(rp_id)),
        (int(2), Value::Bytes(client_data_hash.to_vec())),
        (
            int(3),
            Value::Array(vec![Value::Map(vec![
                (text("id"), Value::Bytes(credential_id.to_vec())),
                (text("type"), text("public-key")),
            ])]),
        ),
        (
            int(4),
            Value::Map(vec![(
                text(HMAC_SECRET),
                Value::Map(vec![
                    (int(1), cose_key(&PublicKey::from(&ours))),
                    (int(2), Value::Bytes(salt_enc.to_vec())),
                    (int(3), Value::Bytes(salt_auth.to_vec())),
                ]),
            )]),
        ),
    ];
    if !user_presence {
        fields.push((int(5), Value::Map(vec![(text("up"), Value::Bool(false))])));
    }
    let request = encode(GET_ASSERTION, fields)?;
    let response = decode_map(&device.cbor(&request, USER_TIMEOUT, cancel, on_touch)?)?;
    let auth_data = get_bytes(&response, 2)?;

    let output = auth_data
        .get(32)
        .filter(|flags| *flags & FLAG_ED != 0)
        .and_then(|_| auth_data.get(AUTH_DATA_HEADER..))
        .and_then(|bytes| match ciborium::from_reader(bytes) {
            Ok(Value::Map(extensions)) => get_text(&extensions, HMAC_SECRET)
                .and_then(Value::as_bytes)
                .and_then(|output| <[u8; SALT_LEN]>::try_from(output.as_slice()).ok()),
            _ => None,
        })
        .ok_or_else(|| fido2_error("the device returned no hmac-secret"))?;
    Ok(Zeroizing::new(aes_cbc(&shared, &output, false)))
}

/// A P-256 public key as a COSE_Key for ECDH-ES+HKDF-256, as CTAP2 wants it.
pub(super) fn cose_key(key: &PublicKey) -> Value {
    let point = key.to_encoded_point(false);
    let coordinate =
        |c: Option<&p256::FieldBytes>| Value::Bytes(c.map(|c| c.to_vec()).unwrap_or_default());
    Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(-25)),
        (int(-1), int(1)),
        (int(-2), coordinate(point.x())),
        (int(-3), coordinate(point.y())),
    ])
}

/// Parse a COSE_Key holding a P-256 public key.
pub(super) fn parse_cose_key(value: &Value) -> Result<PublicKey, Failure> {
    let invalid = || fido2_error("the device sent an invalid public key");
    let map = value.as_map().ok_or_else(invalid)?;
    let coordinate = |key| {
        get(map, key)
            .and_then(Value::as_bytes)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or_else(invalid)
    };
    let point = EncodedPoint::from_affine_coordinates(
        &coordinate(-2)?.into(),
        &coordinate(-3)?.into(),
        false,
    );
    Option::from(PublicKey::from_encoded_point(&point)).ok_or_else(invalid)
}

/// PIN/UV protocol 1 shared secret: SHA-256 of the ECDH x coordinate.
pub(super) fn shared_secret(ours: &EphemeralSecret, theirs: &PublicKey) -> Zeroizing<[u8; 32]> {
    let shared = ours.diffie_hellman(theirs);
    Zeroizing::new(sha256(shared.raw_secret_bytes()))
}

/// AES-256-CBC with a zero IV and no padding, over one 32-byte value.
pub(super) fn aes_cbc(key: &[u8; 32], data: &[u8; 32], encrypt: bool) -> [u8; 32] {
    let mut buffer = *data;
    let iv = [0u8; 16];
    // Both calls only fail when the buffer is not whole blocks; 32 bytes is two.
    if encrypt {
        let _ = cbc::Encryptor::<Aes256>::new(key.into(), &iv.into())
            .encrypt_padded_mut::<NoPadding>(&mut buffer, data.len());
    } else {
        let _ = cbc::Decryptor::<Aes256>::new(key.into(), &iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut buffer);
    }
    buffer
}

/// PIN/UV protocol 1 authenticate: the first 16 bytes of HMAC-SHA-256.
pub(super) fn authenticate(key: &[u8; 32], message: &[u8]) -> Result<[u8; 16], Failure> {
    let mac = hmac_sha256(key, message)?;
    let mut left = [0u8; 16];
    left.copy_from_slice(&mac[..16]);
    Ok(left)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_key_round_trips() {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = PublicKey::from(&secret);
        assert_eq!(parse_cose_key(&cose_key(&public)).expect("parse"), public);
        assert!(parse_cose_key(&Value::Map(vec![(int(-2), Value::Bytes(vec![1; 32]))])).is_err());
    }

    #[test]
    fn both_sides_agree_on_the_shared_secret() {
        let platform = EphemeralSecret::random(&mut OsRng);
        let device = EphemeralSecret::random(&mut OsRng);
        assert_eq!(
            *shared_secret(&platform, &PublicKey::from(&device)),
            *shared_secret(&device, &PublicKey::from(&platform))
        );
    }

    #[test]
    fn aes_cbc_round_trips_and_chains_blocks() {
        let key = [7u8; 32];
        let data = [3u8; 32];
        let encrypted = aes_cbc(&key, &data, true);
        assert_ne!(encrypted, data);
        // CBC: identical plaintext blocks give different ciphertext blocks.
        assert_ne!(encrypted[..16], encrypted[16..]);
        assert_eq!(aes_cbc(&key, &encrypted, false), data);
    }

    #[test]
    fn canonical_request_encoding() {
        let request = encode(CLIENT_PIN, vec![(int(1), int(1)), (int(2), int(2))]).expect("encode");
        assert_eq!(request, [CLIENT_PIN, 0xa2, 0x01, 0x01, 0x02, 0x02]);
    }
}
