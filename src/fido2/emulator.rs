//! A software FIDO2 authenticator that speaks the device side of CTAPHID
//! and the CTAP2 commands keepassxcr uses, including hmac-secret and both
//! PIN/UV auth protocols.
//!
//! Used by the unit tests, and by the CLI when built with the
//! `software-fido2` feature. Release builds do not contain it.

use std::collections::VecDeque;

use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::AppResult;
use crate::fido2::cbor::Value;
use crate::fido2::ctaphid::{
    Assembler, BROADCAST_CID, CMD_CBOR, CMD_INIT, CMD_KEEPALIVE, PACKET_LEN, STATUS_UPNEEDED,
    Transport, frame,
};
use crate::fido2::fido2_error;
use crate::fido2::pinuv::{self, KeyAgreement, Protocol, SharedSecret, cose_key};

/// Environment variable configuring emulated keys for test builds:
/// comma-separated `<hex secret>[:pin=<PIN>][:v1]`.
pub const ENV: &str = "KEEPASSXCR_SOFTWARE_FIDO2";

const CHANNEL: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
const ERR_MISSING_PARAMETER: u8 = 0x14;
const ERR_NO_CREDENTIALS: u8 = 0x2e;
const ERR_PIN_INVALID: u8 = 0x31;
const ERR_PIN_AUTH_INVALID: u8 = 0x33;
const ERR_PIN_NOT_SET: u8 = 0x35;
const ERR_PUAT_REQUIRED: u8 = 0x36;
const ERR_INVALID_COMMAND: u8 = 0x01;
const ERR_INVALID_PARAMETER: u8 = 0x02;

/// An issued PIN token: the token, its protocol, permissions and relying party.
type PinToken = (Zeroizing<[u8; 32]>, Protocol, i64, Option<String>);

/// An emulated security key.
pub struct EmulatedAuthenticator {
    secret: Zeroizing<Vec<u8>>,
    pin: Option<String>,
    /// CTAP 2.0 only: PIN protocol one and plain PIN tokens.
    legacy: bool,
    key_agreement: KeyAgreement,
    token: Option<PinToken>,
    retries: i64,
    incoming: Option<Assembler>,
    outgoing: VecDeque<[u8; PACKET_LEN]>,
}

impl EmulatedAuthenticator {
    pub fn new(secret: &[u8], pin: Option<&str>, legacy: bool) -> Self {
        Self {
            secret: Zeroizing::new(secret.to_vec()),
            pin: pin.map(str::to_string),
            legacy,
            key_agreement: KeyAgreement::new(),
            token: None,
            retries: 8,
            incoming: None,
            outgoing: VecDeque::new(),
        }
    }

    /// The keys configured in [`ENV`], if any.
    ///
    /// # Errors
    ///
    /// Fails when the variable is malformed.
    pub fn from_env() -> AppResult<Option<Vec<Self>>> {
        let Ok(spec) = std::env::var(ENV) else {
            return Ok(None);
        };
        let mut keys = Vec::new();
        for one in spec.split(',').filter(|one| !one.is_empty()) {
            let mut parts = one.split(':');
            let secret = hex::decode(parts.next().unwrap_or_default())
                .map_err(|_| fido2_error(format!("{ENV}: secret is not hex")))?;
            let mut pin = None;
            let mut legacy = false;
            for option in parts {
                match option {
                    "v1" => legacy = true,
                    _ if option.starts_with("pin=") => pin = Some(&option[4..]),
                    _ => return Err(fido2_error(format!("{ENV}: unknown option '{option}'"))),
                }
            }
            keys.push(Self::new(&secret, pin, legacy));
        }
        Ok(Some(keys))
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    fn credential_id(&self, rp_hash: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let tag = self.mac(&[b"cred", rp_hash, &nonce]);
        [&nonce[..], &tag[..16]].concat()
    }

    fn owns(&self, id: &[u8], rp_hash: &[u8]) -> bool {
        id.len() == 32 && self.mac(&[b"cred", rp_hash, &id[..16]])[..16] == id[16..]
    }

    fn reply(&mut self, cmd: u8, data: &[u8]) {
        if let Ok(packets) = frame(CHANNEL, cmd, data) {
            self.outgoing.extend(packets);
        }
    }

    fn handle(&mut self, cid: [u8; 4], cmd: u8, data: &[u8]) {
        match cmd {
            CMD_INIT if cid == BROADCAST_CID => {
                let mut answer = data[..8.min(data.len())].to_vec();
                answer.extend_from_slice(&CHANNEL);
                answer.extend_from_slice(&[2, 5, 7, 1, 0x04]);
                if let Ok(packets) = frame(BROADCAST_CID, CMD_INIT, &answer) {
                    self.outgoing.extend(packets);
                }
            }
            CMD_CBOR if cid == CHANNEL => {
                let (status, body) = match self.ctap(data) {
                    Ok(body) => (0u8, body.map(|v| v.encode()).unwrap_or_default()),
                    Err(status) => (status, Vec::new()),
                };
                let mut answer = vec![status];
                answer.extend_from_slice(&body);
                self.reply(CMD_CBOR, &answer);
            }
            _ => {}
        }
    }

    fn ctap(&mut self, data: &[u8]) -> Result<Option<Value>, u8> {
        let (&cmd, params) = data.split_first().ok_or(ERR_INVALID_COMMAND)?;
        let params = if params.is_empty() {
            Value::Map(Vec::new())
        } else {
            Value::decode(params).map_err(|_| ERR_INVALID_PARAMETER)?
        };
        match cmd {
            0x04 => Ok(Some(self.get_info())),
            0x06 => self.client_pin(&params).map(Some),
            0x01 => self.make_credential(&params).map(Some),
            0x02 => self.get_assertion(&params).map(Some),
            _ => Err(ERR_INVALID_COMMAND),
        }
    }

    fn protocols(&self) -> Vec<Protocol> {
        if self.legacy {
            vec![Protocol::One]
        } else {
            vec![Protocol::Two, Protocol::One]
        }
    }

    fn get_info(&self) -> Value {
        let mut options = vec![
            ("rk", Value::Bool(true)),
            ("up", Value::Bool(true)),
            ("plat", Value::Bool(false)),
            ("clientPin", Value::Bool(self.pin.is_some())),
        ];
        if !self.legacy {
            options.push(("pinUvAuthToken", Value::Bool(true)));
        }
        let versions = if self.legacy {
            vec![Value::text("FIDO_2_0")]
        } else {
            vec![Value::text("FIDO_2_0"), Value::text("FIDO_2_1")]
        };
        Value::int_map(vec![
            (1, Value::Array(versions)),
            (2, Value::Array(vec![Value::text("hmac-secret")])),
            (3, Value::Bytes(vec![0u8; 16])),
            (4, Value::text_map(options)),
            (
                6,
                Value::Array(
                    self.protocols()
                        .into_iter()
                        .map(|p| Value::Int(p.number()))
                        .collect(),
                ),
            ),
        ])
    }

    fn protocol_param(&self, value: Option<&Value>) -> Result<Protocol, u8> {
        let protocol = value
            .and_then(Value::as_int)
            .and_then(Protocol::from_number)
            .ok_or(ERR_MISSING_PARAMETER)?;
        if self.protocols().contains(&protocol) {
            Ok(protocol)
        } else {
            Err(ERR_INVALID_PARAMETER)
        }
    }

    fn shared(&self, protocol: Protocol, platform_key: Option<&Value>) -> Result<SharedSecret, u8> {
        self.key_agreement
            .agree(protocol, platform_key.ok_or(ERR_MISSING_PARAMETER)?)
            .map_err(|_| ERR_INVALID_PARAMETER)
    }

    fn client_pin(&mut self, params: &Value) -> Result<Value, u8> {
        let protocol = self.protocol_param(params.get_int(1))?;
        match params.get_int(2).and_then(Value::as_int) {
            Some(1) => Ok(Value::int_map(vec![(3, Value::Int(self.retries))])),
            Some(2) => Ok(Value::int_map(vec![(
                1,
                self.key_agreement.cose_public_key(),
            )])),
            Some(sub @ (5 | 9)) => {
                if sub == 9 && self.legacy {
                    return Err(ERR_INVALID_COMMAND);
                }
                let pin = self.pin.clone().ok_or(ERR_PIN_NOT_SET)?;
                let shared = self.shared(protocol, params.get_int(3))?;
                let hash_enc = params
                    .get_int(6)
                    .and_then(Value::as_bytes)
                    .ok_or(ERR_MISSING_PARAMETER)?;
                let hash = shared.decrypt(hash_enc).map_err(|_| ERR_PIN_INVALID)?;
                if hash[..] != pinuv::pin_hash(&pin)[..] {
                    self.retries -= 1;
                    // A wrong PIN also changes the key agreement key.
                    self.key_agreement = KeyAgreement::new();
                    return Err(ERR_PIN_INVALID);
                }
                self.retries = 8;
                let mut token = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(&mut token[..]);
                let permissions = if sub == 9 {
                    params
                        .get_int(9)
                        .and_then(Value::as_int)
                        .ok_or(ERR_MISSING_PARAMETER)?
                } else {
                    0x03
                };
                let rp_id = params
                    .get_int(10)
                    .and_then(Value::as_text)
                    .map(str::to_string);
                let encrypted = shared
                    .encrypt(&token[..])
                    .map_err(|_| ERR_INVALID_PARAMETER)?;
                self.token = Some((token, protocol, permissions, rp_id));
                Ok(Value::int_map(vec![(2, Value::Bytes(encrypted))]))
            }
            _ => Err(ERR_INVALID_PARAMETER),
        }
    }

    /// Check a pinUvAuthParam over `client_data_hash`. Returns whether the
    /// user was verified.
    fn check_uv(
        &self,
        param: Option<&Value>,
        protocol: Option<&Value>,
        client_data_hash: &[u8],
        permission: i64,
        rp_id: &str,
    ) -> Result<bool, u8> {
        let Some(param) = param.and_then(Value::as_bytes) else {
            return Ok(false);
        };
        let protocol = self.protocol_param(protocol)?;
        let (token, token_protocol, permissions, token_rp) =
            self.token.as_ref().ok_or(ERR_PIN_AUTH_INVALID)?;
        if *token_protocol != protocol
            || permissions & permission == 0
            || token_rp.as_deref().is_some_and(|rp| rp != rp_id)
            || pinuv::authenticate(protocol, &token[..], client_data_hash) != param
        {
            return Err(ERR_PIN_AUTH_INVALID);
        }
        Ok(true)
    }

    fn wait_for_touch(&mut self) {
        let mut keepalive = [0u8; PACKET_LEN];
        keepalive[..4].copy_from_slice(&CHANNEL);
        keepalive[4] = 0x80 | CMD_KEEPALIVE;
        keepalive[6] = 1;
        keepalive[7] = STATUS_UPNEEDED;
        self.outgoing.push_back(keepalive);
    }

    fn make_credential(&mut self, params: &Value) -> Result<Value, u8> {
        let cdh = params
            .get_int(1)
            .and_then(Value::as_bytes)
            .ok_or(ERR_MISSING_PARAMETER)?;
        let rp_id = params
            .get_int(2)
            .and_then(|rp| rp.get_text("id"))
            .and_then(Value::as_text)
            .ok_or(ERR_MISSING_PARAMETER)?
            .to_string();
        let es256 = params
            .get_int(4)
            .and_then(Value::as_array)
            .is_some_and(|algs| {
                algs.iter()
                    .any(|alg| alg.get_text("alg").and_then(Value::as_int) == Some(-7))
            });
        if !es256 {
            return Err(0x26);
        }
        let uv = self.check_uv(params.get_int(8), params.get_int(9), cdh, 0x01, &rp_id)?;
        if self.pin.is_some() && !uv {
            return Err(ERR_PUAT_REQUIRED);
        }
        let hmac_secret = params
            .get_int(6)
            .and_then(|ext| ext.get_text("hmac-secret"))
            .and_then(Value::as_bool)
            == Some(true);
        self.wait_for_touch();
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let id = self.credential_id(&rp_hash);
        let mut auth_data = rp_hash.to_vec();
        let mut flags = 0x01 | 0x40;
        if uv {
            flags |= 0x04;
        }
        if hmac_secret {
            flags |= 0x80;
        }
        auth_data.push(flags);
        auth_data.extend_from_slice(&[0, 0, 0, 0]);
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&(id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&id);
        auth_data.extend_from_slice(
            &cose_key(&p256::SecretKey::random(&mut OsRng).public_key()).encode(),
        );
        if hmac_secret {
            auth_data.extend_from_slice(
                &Value::text_map(vec![("hmac-secret", Value::Bool(true))]).encode(),
            );
        }
        Ok(Value::int_map(vec![
            (1, Value::text("none")),
            (2, Value::Bytes(auth_data)),
            (3, Value::Map(Vec::new())),
        ]))
    }

    fn get_assertion(&mut self, params: &Value) -> Result<Value, u8> {
        let rp_id = params
            .get_int(1)
            .and_then(Value::as_text)
            .ok_or(ERR_MISSING_PARAMETER)?
            .to_string();
        let cdh = params
            .get_int(2)
            .and_then(Value::as_bytes)
            .ok_or(ERR_MISSING_PARAMETER)?;
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let id = params
            .get_int(3)
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|c| c.get_text("id").and_then(Value::as_bytes))
            .find(|id| self.owns(id, &rp_hash))
            .ok_or(ERR_NO_CREDENTIALS)?
            .to_vec();
        let up = params
            .get_int(5)
            .and_then(|o| o.get_text("up"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let uv = self.check_uv(params.get_int(6), params.get_int(7), cdh, 0x02, &rp_id)?;

        let mut flags = 0u8;
        let mut extensions = None;
        if up {
            flags |= 0x01;
            self.wait_for_touch();
        }
        if uv {
            flags |= 0x04;
        }
        if let Some(input) = params
            .get_int(4)
            .and_then(|ext| ext.get_text("hmac-secret"))
        {
            if !up {
                return Err(0x2c);
            }
            let protocol = match input.get_int(4) {
                Some(value) => self.protocol_param(Some(value))?,
                None => Protocol::One,
            };
            let shared = self.shared(protocol, input.get_int(1))?;
            let salt_enc = input
                .get_int(2)
                .and_then(Value::as_bytes)
                .ok_or(ERR_MISSING_PARAMETER)?;
            let salt_auth = input
                .get_int(3)
                .and_then(Value::as_bytes)
                .ok_or(ERR_MISSING_PARAMETER)?;
            if shared.authenticate(salt_enc) != salt_auth {
                return Err(ERR_INVALID_PARAMETER);
            }
            let salts = shared
                .decrypt(salt_enc)
                .map_err(|_| ERR_INVALID_PARAMETER)?;
            if salts.len() != 32 && salts.len() != 64 {
                return Err(ERR_INVALID_PARAMETER);
            }
            let cred_random = self.mac(&[if uv { b"uv" } else { b"nu" }, &id]);
            let mut output = Zeroizing::new(Vec::new());
            for salt in salts.chunks(32) {
                let mut mac = Hmac::<Sha256>::new_from_slice(&cred_random).expect("any key");
                mac.update(salt);
                output.extend_from_slice(&mac.finalize().into_bytes());
            }
            let encrypted = shared.encrypt(&output).map_err(|_| ERR_INVALID_PARAMETER)?;
            flags |= 0x80;
            extensions = Some(Value::text_map(vec![(
                "hmac-secret",
                Value::Bytes(encrypted),
            )]));
        }
        let mut auth_data = rp_hash.to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        if let Some(extensions) = extensions {
            auth_data.extend_from_slice(&extensions.encode());
        }
        Ok(Value::int_map(vec![
            (
                1,
                Value::text_map(vec![
                    ("id", Value::Bytes(id)),
                    ("type", Value::text("public-key")),
                ]),
            ),
            (2, Value::Bytes(auth_data)),
            (3, Value::Bytes(vec![0u8; 64])),
        ]))
    }
}

impl Transport for EmulatedAuthenticator {
    fn write_packet(&mut self, packet: &[u8; PACKET_LEN]) -> AppResult<()> {
        let mut cid = [0u8; 4];
        cid.copy_from_slice(&packet[..4]);
        if let Some(assembler) = Assembler::start(packet) {
            self.incoming = Some(assembler);
        } else if let Some(assembler) = self.incoming.as_mut() {
            assembler.push(packet)?;
        }
        if self.incoming.as_ref().is_some_and(Assembler::is_complete)
            && let Some(assembler) = self.incoming.take()
        {
            let (cmd, data) = assembler.finish();
            self.handle(cid, cmd, &data);
        }
        Ok(())
    }

    fn read_packet(&mut self, _timeout_ms: i32) -> AppResult<Option<[u8; PACKET_LEN]>> {
        Ok(self.outgoing.pop_front())
    }
}

/// Lets tests keep a key between several opened channels.
impl Transport for &mut EmulatedAuthenticator {
    fn write_packet(&mut self, packet: &[u8; PACKET_LEN]) -> AppResult<()> {
        (**self).write_packet(packet)
    }

    fn read_packet(&mut self, timeout_ms: i32) -> AppResult<Option<[u8; PACKET_LEN]>> {
        (**self).read_packet(timeout_ms)
    }
}
