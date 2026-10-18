//! The CTAP2 commands keepassxcr needs: getInfo, clientPIN, makeCredential
//! and getAssertion with the hmac-secret extension.

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::fido2::cbor::Value;
use crate::fido2::ctaphid::{CtapHid, Transport};
use crate::fido2::fido2_error;
use crate::fido2::pinuv::{self, KeyAgreement, Protocol, SharedSecret};

const CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CMD_GET_ASSERTION: u8 = 0x02;
const CMD_GET_INFO: u8 = 0x04;
const CMD_CLIENT_PIN: u8 = 0x06;

const PIN_GET_RETRIES: i64 = 1;
const PIN_GET_KEY_AGREEMENT: i64 = 2;
const PIN_GET_TOKEN: i64 = 5;
const PIN_GET_TOKEN_WITH_PERMISSIONS: i64 = 9;
const PERMISSION_MAKE_CREDENTIAL: i64 = 0x01;
const PERMISSION_GET_ASSERTION: i64 = 0x02;

pub const ERR_NO_CREDENTIALS: u8 = 0x2e;
const ERR_PIN_INVALID: u8 = 0x31;

/// Flag in authenticator data: the user was verified (PIN).
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

const HMAC_SECRET: &str = "hmac-secret";

/// Asks for the key's PIN when one is needed.
pub type PinPrompt<'a> = &'a mut dyn FnMut() -> AppResult<Zeroizing<String>>;

/// What the authenticator reports about itself.
#[derive(Debug, Clone)]
pub struct Info {
    pub extensions: Vec<String>,
    /// `Some(true)`: a PIN is set; `Some(false)`: supported but unset.
    pub client_pin: Option<bool>,
    /// CTAP 2.1 PIN tokens with permissions.
    pub pin_uv_auth_token: bool,
    pub protocols: Vec<Protocol>,
}

/// A FIDO2 authenticator on one CTAPHID channel.
pub struct Authenticator<T> {
    hid: CtapHid<T>,
    info: Info,
}

impl<T: Transport> Authenticator<T> {
    /// Open a channel and read the authenticator's info.
    ///
    /// # Errors
    ///
    /// Fails when the device does not speak CTAP2.
    pub fn open(transport: T) -> AppResult<Self> {
        let mut hid = CtapHid::open(transport)?;
        let body = command(&mut hid, CMD_GET_INFO, None, &mut || {})?;
        let info = parse_info(&body)?;
        Ok(Self { hid, info })
    }

    pub fn info(&self) -> &Info {
        &self.info
    }

    pub fn supports_hmac_secret(&self) -> bool {
        self.info.extensions.iter().any(|name| name == HMAC_SECRET)
    }

    pub fn has_pin(&self) -> bool {
        self.info.client_pin == Some(true)
    }

    fn protocol(&self) -> Protocol {
        if self.info.protocols.contains(&Protocol::Two) {
            Protocol::Two
        } else {
            Protocol::One
        }
    }

    /// Agree on a shared secret for this operation.
    fn shared_secret(&mut self) -> AppResult<(KeyAgreement, SharedSecret)> {
        let protocol = self.protocol();
        let request = Value::int_map(vec![
            (1, Value::Int(protocol.number())),
            (2, Value::Int(PIN_GET_KEY_AGREEMENT)),
        ]);
        let response = command(&mut self.hid, CMD_CLIENT_PIN, Some(request), &mut || {})?;
        let peer = response
            .get_int(1)
            .ok_or_else(|| fido2_error("the security key sent no key agreement"))?;
        let ours = KeyAgreement::new();
        let shared = ours.agree(protocol, peer)?;
        Ok((ours, shared))
    }

    /// Get a PIN token for `permissions` on `rp_id`.
    fn pin_token(
        &mut self,
        ours: &KeyAgreement,
        shared: &SharedSecret,
        rp_id: &str,
        permissions: i64,
        pin: PinPrompt<'_>,
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        let pin = pin()?;
        if pin.chars().count() < 4 {
            return Err(fido2_error("a security key PIN has at least 4 characters"));
        }
        let pin_hash_enc = shared.encrypt(&pinuv::pin_hash(&pin))?;
        let mut entries = vec![
            (1, Value::Int(shared.protocol.number())),
            (3, ours.cose_public_key()),
            (6, Value::Bytes(pin_hash_enc)),
        ];
        if self.info.pin_uv_auth_token {
            entries.push((2, Value::Int(PIN_GET_TOKEN_WITH_PERMISSIONS)));
            entries.push((9, Value::Int(permissions)));
            entries.push((10, Value::text(rp_id)));
        } else {
            entries.push((2, Value::Int(PIN_GET_TOKEN)));
        }
        let response = match command(
            &mut self.hid,
            CMD_CLIENT_PIN,
            Some(Value::int_map(entries)),
            &mut || {},
        ) {
            Err(AppError::Fido2Status(ERR_PIN_INVALID, _)) => {
                let retries = self.pin_retries().ok();
                return Err(fido2_error(match retries {
                    Some(left) => format!("wrong security key PIN ({left} tries left)"),
                    None => "wrong security key PIN".to_string(),
                }));
            }
            other => other?,
        };
        let token = response
            .get_int(2)
            .and_then(Value::as_bytes)
            .ok_or_else(|| fido2_error("the security key sent no PIN token"))?;
        shared.decrypt(token)
    }

    fn pin_retries(&mut self) -> AppResult<i64> {
        let request = Value::int_map(vec![
            (1, Value::Int(self.protocol().number())),
            (2, Value::Int(PIN_GET_RETRIES)),
        ]);
        let response = command(&mut self.hid, CMD_CLIENT_PIN, Some(request), &mut || {})?;
        response
            .get_int(3)
            .and_then(Value::as_int)
            .ok_or_else(|| fido2_error("the security key sent no retry count"))
    }

    /// Create a non-resident credential with hmac-secret for `rp_id`.
    /// Uses the PIN when the key has one, as CTAP requires for new
    /// credentials. Returns the credential id.
    ///
    /// # Errors
    ///
    /// Fails when the key refuses, times out, or lacks hmac-secret.
    pub fn make_credential(
        &mut self,
        rp_id: &str,
        user_name: &str,
        pin: PinPrompt<'_>,
        on_touch: &mut dyn FnMut(),
    ) -> AppResult<Vec<u8>> {
        if !self.supports_hmac_secret() {
            return Err(fido2_error(
                "this security key does not support the hmac-secret extension",
            ));
        }
        let mut client_data_hash = [0u8; 32];
        OsRng.fill_bytes(&mut client_data_hash);
        let mut user_id = [0u8; 16];
        OsRng.fill_bytes(&mut user_id);
        let mut entries = vec![
            (1, Value::Bytes(client_data_hash.to_vec())),
            (
                2,
                Value::text_map(vec![
                    ("id", Value::text(rp_id)),
                    ("name", Value::text(rp_id)),
                ]),
            ),
            (
                3,
                Value::text_map(vec![
                    ("id", Value::Bytes(user_id.to_vec())),
                    ("name", Value::text(user_name)),
                    ("displayName", Value::text(user_name)),
                ]),
            ),
            (
                4,
                Value::Array(vec![Value::text_map(vec![
                    ("alg", Value::Int(-7)),
                    ("type", Value::text("public-key")),
                ])]),
            ),
            (6, Value::text_map(vec![(HMAC_SECRET, Value::Bool(true))])),
            (7, Value::text_map(vec![("rk", Value::Bool(false))])),
        ];
        if self.has_pin() {
            let (ours, shared) = self.shared_secret()?;
            let token = self.pin_token(&ours, &shared, rp_id, PERMISSION_MAKE_CREDENTIAL, pin)?;
            entries.push((
                8,
                Value::Bytes(pinuv::authenticate(
                    shared.protocol,
                    &token,
                    &client_data_hash,
                )),
            ));
            entries.push((9, Value::Int(shared.protocol.number())));
        }
        let response = command(
            &mut self.hid,
            CMD_MAKE_CREDENTIAL,
            Some(Value::int_map(entries)),
            on_touch,
        )?;
        let auth_data = response
            .get_int(2)
            .and_then(Value::as_bytes)
            .ok_or_else(|| fido2_error("the security key sent no authenticator data"))?;
        let parsed = parse_auth_data(auth_data, rp_id)?;
        if parsed
            .extensions
            .get_text(HMAC_SECRET)
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(fido2_error(
                "the security key did not enable hmac-secret for the new credential",
            ));
        }
        parsed
            .credential_id
            .ok_or_else(|| fido2_error("the security key sent no credential id"))
    }

    /// Which of `credential_ids` this key holds, without a touch or PIN.
    ///
    /// # Errors
    ///
    /// Fails when the key does not answer the silent check.
    pub fn find_credential(
        &mut self,
        rp_id: &str,
        credential_ids: &[&[u8]],
    ) -> AppResult<Option<Vec<u8>>> {
        let request = Value::int_map(vec![
            (1, Value::text(rp_id)),
            (2, Value::Bytes(vec![0u8; 32])),
            (3, allow_list(credential_ids)),
            (5, Value::text_map(vec![("up", Value::Bool(false))])),
        ]);
        let response = match command(&mut self.hid, CMD_GET_ASSERTION, Some(request), &mut || {}) {
            Err(AppError::Fido2Status(ERR_NO_CREDENTIALS, _)) => return Ok(None),
            other => other?,
        };
        let id = response
            .get_int(1)
            .and_then(|credential| credential.get_text("id"))
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec);
        // With a single entry the key may leave the credential out.
        Ok(id.or_else(|| (credential_ids.len() == 1).then(|| credential_ids[0].to_vec())))
    }

    /// The hmac-secret output for `salt` from `credential_id`. With `uv`,
    /// the PIN is checked and the key's "with UV" secret is used, so the same
    /// choice must be made every time for a given credential.
    ///
    /// # Errors
    ///
    /// Fails when the key does not hold the credential, refuses, or times out.
    pub fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        uv: bool,
        pin: PinPrompt<'_>,
        on_touch: &mut dyn FnMut(),
    ) -> AppResult<Zeroizing<[u8; 32]>> {
        let mut client_data_hash = [0u8; 32];
        OsRng.fill_bytes(&mut client_data_hash);
        let (ours, shared) = self.shared_secret()?;
        let salt_enc = shared.encrypt(salt)?;
        let mut extension = vec![
            (1, ours.cose_public_key()),
            (2, Value::Bytes(salt_enc.clone())),
            (3, Value::Bytes(shared.authenticate(&salt_enc))),
        ];
        if shared.protocol == Protocol::Two {
            extension.push((4, Value::Int(2)));
        }
        let mut entries = vec![
            (1, Value::text(rp_id)),
            (2, Value::Bytes(client_data_hash.to_vec())),
            (3, allow_list(&[credential_id])),
            (
                4,
                Value::text_map(vec![(HMAC_SECRET, Value::int_map(extension))]),
            ),
            (5, Value::text_map(vec![("up", Value::Bool(true))])),
        ];
        if uv {
            if !self.has_pin() {
                return Err(fido2_error(
                    "this key file needs the security key's PIN, but the key has no PIN set",
                ));
            }
            let token = self.pin_token(&ours, &shared, rp_id, PERMISSION_GET_ASSERTION, pin)?;
            entries.push((
                6,
                Value::Bytes(pinuv::authenticate(
                    shared.protocol,
                    &token,
                    &client_data_hash,
                )),
            ));
            entries.push((7, Value::Int(shared.protocol.number())));
        }
        let response = command(
            &mut self.hid,
            CMD_GET_ASSERTION,
            Some(Value::int_map(entries)),
            on_touch,
        )?;
        let auth_data = response
            .get_int(2)
            .and_then(Value::as_bytes)
            .ok_or_else(|| fido2_error("the security key sent no authenticator data"))?;
        let parsed = parse_auth_data(auth_data, rp_id)?;
        if uv && parsed.flags & FLAG_UV == 0 {
            return Err(fido2_error("the security key did not verify the PIN"));
        }
        let encrypted = parsed
            .extensions
            .get_text(HMAC_SECRET)
            .and_then(Value::as_bytes)
            .ok_or_else(|| fido2_error("the security key sent no hmac-secret output"))?;
        let output = shared.decrypt(encrypted)?;
        if output.len() != 32 {
            return Err(fido2_error("the hmac-secret output has the wrong length"));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&output);
        Ok(secret)
    }
}

fn allow_list(credential_ids: &[&[u8]]) -> Value {
    Value::Array(
        credential_ids
            .iter()
            .map(|id| {
                Value::text_map(vec![
                    ("id", Value::Bytes(id.to_vec())),
                    ("type", Value::text("public-key")),
                ])
            })
            .collect(),
    )
}

/// Send one CTAP2 command and decode its CBOR answer.
fn command<T: Transport>(
    hid: &mut CtapHid<T>,
    cmd: u8,
    params: Option<Value>,
    on_touch: &mut dyn FnMut(),
) -> AppResult<Value> {
    let mut payload = vec![cmd];
    if let Some(params) = params {
        payload.extend_from_slice(&params.encode());
    }
    let (status, body) = hid.cbor(&payload, on_touch)?;
    if status != 0 {
        return Err(AppError::Fido2Status(status, status_message(status)));
    }
    if body.is_empty() {
        return Ok(Value::Map(Vec::new()));
    }
    Value::decode(&body)
}

fn status_message(status: u8) -> String {
    match status {
        0x01 => "the security key does not know this command",
        0x02 | 0x11 | 0x14 => "the security key rejected the request",
        0x26 => "the security key does not support ES256 credentials",
        0x27 => "the security key refused the operation",
        0x28 => "the security key's credential storage is full",
        0x2b | 0x2c => "the security key does not support a requested option",
        0x2d => "cancelled",
        ERR_NO_CREDENTIALS => "this security key is not enrolled in this key file",
        0x2f => "timed out waiting for a touch",
        0x30 => "the security key does not allow this",
        ERR_PIN_INVALID => "wrong security key PIN",
        0x32 => "the security key's PIN is blocked; reset the key's FIDO application",
        0x33 => "the security key rejected the PIN authentication",
        0x34 => "too many wrong PINs; unplug the security key and try again",
        0x35 => "no PIN is set on the security key",
        0x36 => "the security key requires its PIN; set one with 'ykman fido access change-pin'",
        0x37 => "the PIN does not meet the security key's policy",
        _ => return format!("the security key reported error {status:#04x}"),
    }
    .to_string()
}

fn parse_info(info: &Value) -> AppResult<Info> {
    let extensions = info
        .get_int(2)
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|ext| ext.as_text().map(str::to_string))
        .collect();
    let options = info.get_int(4);
    let option = |name: &str| {
        options
            .and_then(|o| o.get_text(name))
            .and_then(Value::as_bool)
    };
    let mut protocols: Vec<Protocol> = info
        .get_int(6)
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|p| p.as_int().and_then(Protocol::from_number))
        .collect();
    if protocols.is_empty() {
        protocols.push(Protocol::One);
    }
    Ok(Info {
        extensions,
        client_pin: option("clientPin"),
        pin_uv_auth_token: option("pinUvAuthToken") == Some(true),
        protocols,
    })
}

struct AuthData {
    flags: u8,
    credential_id: Option<Vec<u8>>,
    extensions: Value,
}

/// Parse authenticator data and check it is for `rp_id`.
fn parse_auth_data(data: &[u8], rp_id: &str) -> AppResult<AuthData> {
    let malformed = || fido2_error("the security key sent malformed authenticator data");
    if data.len() < 37 {
        return Err(malformed());
    }
    if data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err(fido2_error("the security key answered for another site"));
    }
    let flags = data[32];
    let mut rest = &data[37..];
    let mut credential_id = None;
    if flags & FLAG_AT != 0 {
        if rest.len() < 18 {
            return Err(malformed());
        }
        let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        let id = rest.get(18..18 + len).ok_or_else(malformed)?;
        credential_id = Some(id.to_vec());
        rest = &rest[18 + len..];
        let (_public_key, used) = Value::decode_prefix(rest)?;
        rest = &rest[used..];
    }
    let extensions = if flags & FLAG_ED != 0 {
        Value::decode(rest)?
    } else if rest.is_empty() {
        Value::Map(Vec::new())
    } else {
        return Err(malformed());
    };
    Ok(AuthData {
        flags,
        credential_id,
        extensions,
    })
}
