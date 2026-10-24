//! A software FIDO2 authenticator that speaks the device side of CTAPHID and
//! the CTAP2 commands keepassxcr sends.
//!
//! Used by the unit tests, and by the CLI when built with the
//! `software-fido2` feature, so the whole hmac-secret path (CBOR, ECDH, the
//! salt encryption) is tested without hardware. Release builds do not contain it.
//!
//! Like a Ledger, it derives everything from one secret, so separate runs
//! with the same `KEEPASSXCR_SOFTWARE_FIDO2` answer the same: a credential id
//! is a random nonce and a tag over it, and the hmac-secret key of a
//! credential is an HMAC of its id.

use std::collections::VecDeque;
use std::time::Duration;

use ciborium::Value;
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::crypto::{hmac_sha256, sha256};
use crate::error::{AppError, AppResult};
use crate::fido2::ctap::{
    self, AUTH_DATA_HEADER, CLIENT_PIN, FLAG_AT, FLAG_ED, GET_ASSERTION, GET_INFO,
    GET_KEY_AGREEMENT, HMAC_SECRET, MAKE_CREDENTIAL, Map, decode_map, get, get_bytes, get_text,
    int, text,
};
use crate::fido2::ctaphid::{
    Assembler, BROADCAST_CID, CMD_CBOR, CMD_INIT, CMD_KEEPALIVE, Channel, Packet, STATUS_UPNEEDED,
    frame, packet_cid,
};
use crate::fido2::{Failure, SALT_LEN};

/// Environment variable holding the emulated device's secret, in hex.
const ENV: &str = "KEEPASSXCR_SOFTWARE_FIDO2";
/// The channel id the emulator hands out.
const CID: u32 = 0x0000_0001;

/// CTAP2 status codes the emulator returns.
const ERR_INVALID_CBOR: u8 = 0x12;
const ERR_UNSUPPORTED_OPTION: u8 = 0x2b;
const ERR_NO_CREDENTIALS: u8 = 0x2e;
const ERR_PIN_AUTH_INVALID: u8 = 0x33;

/// An emulated FIDO2 device.
pub struct Emulator {
    master: Zeroizing<Vec<u8>>,
    assembler: Assembler,
    outbox: VecDeque<Packet>,
    key_agreement: Option<EphemeralSecret>,
}

impl Emulator {
    /// A device deriving its credentials from `master`.
    pub fn new(master: Vec<u8>) -> Self {
        Self {
            master: Zeroizing::new(master),
            assembler: Assembler::default(),
            outbox: VecDeque::new(),
            key_agreement: None,
        }
    }

    /// The device configured in `KEEPASSXCR_SOFTWARE_FIDO2`, if set.
    ///
    /// # Errors
    ///
    /// Fails when the variable is not hex.
    #[cfg_attr(not(feature = "software-fido2"), allow(dead_code))]
    pub fn from_env() -> AppResult<Option<Self>> {
        let Some(value) = std::env::var_os(ENV).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let master = hex::decode(value.to_string_lossy().as_bytes())
            .map_err(|_| AppError::InvalidInput(format!("{ENV} must be hex")))?;
        Ok(Some(Self::new(master)))
    }

    fn mac(&self, label: &[u8], data: &[u8]) -> [u8; 32] {
        let mut message = label.to_vec();
        message.extend_from_slice(data);
        hmac_sha256(&self.master, &message).unwrap_or_default()
    }

    /// Queue a message for the host on channel `cid`.
    fn queue(&mut self, cid: u32, command: u8, data: &[u8]) {
        if let Ok(packets) = frame(cid, command, data) {
            self.outbox.extend(packets);
        }
    }

    fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        let Some((&command, body)) = request.split_first() else {
            return vec![ERR_INVALID_CBOR];
        };
        let map = match command {
            GET_INFO => Ok(Vec::new()),
            _ => decode_map(body).map_err(|_| ERR_INVALID_CBOR),
        };
        let response = map.and_then(|map| match command {
            GET_INFO => Ok(self.get_info()),
            CLIENT_PIN => self.client_pin(&map),
            MAKE_CREDENTIAL => self.make_credential(&map),
            GET_ASSERTION => self.get_assertion(&map),
            _ => Err(0x01),
        });
        match response {
            Ok(map) => {
                let mut bytes = vec![0];
                let _ = ciborium::into_writer(&Value::Map(map), &mut bytes);
                bytes
            }
            Err(status) => vec![status],
        }
    }

    fn get_info(&self) -> Map {
        vec![
            (int(1), Value::Array(vec![text("FIDO_2_0")])),
            (int(2), Value::Array(vec![text(HMAC_SECRET)])),
            (int(3), Value::Bytes(vec![0; 16])),
            (int(6), Value::Array(vec![int(1)])),
        ]
    }

    fn client_pin(&mut self, request: &Map) -> Result<Map, u8> {
        if get(request, 1) != Some(&int(1)) || get(request, 2) != Some(&int(GET_KEY_AGREEMENT)) {
            return Err(ERR_UNSUPPORTED_OPTION);
        }
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = PublicKey::from(&secret);
        self.key_agreement = Some(secret);
        Ok(vec![(int(1), ctap::cose_key(&public))])
    }

    fn make_credential(&mut self, request: &Map) -> Result<Map, u8> {
        let rp_id = rp_id(
            get(request, 2)
                .and_then(Value::as_map)
                .ok_or(ERR_INVALID_CBOR)?,
        )?;
        let extensions = get(request, 6)
            .and_then(Value::as_map)
            .ok_or(ERR_UNSUPPORTED_OPTION)?;
        if get_text(extensions, HMAC_SECRET) != Some(&Value::Bool(true)) {
            return Err(ERR_UNSUPPORTED_OPTION);
        }
        self.queue(CID, CMD_KEEPALIVE, &[STATUS_UPNEEDED]);

        let mut credential_id = vec![0u8; 16];
        OsRng.fill_bytes(&mut credential_id);
        let tag = self.mac(rp_id.as_bytes(), &credential_id);
        credential_id.extend_from_slice(&tag[..16]);

        let mut auth_data = auth_data_header(&rp_id, 0x01 | FLAG_AT | FLAG_ED);
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&credential_id);
        let credential_key = PublicKey::from(&EphemeralSecret::random(&mut OsRng));
        let _ = ciborium::into_writer(&ctap::cose_key(&credential_key), &mut auth_data);
        let extensions = Value::Map(vec![(text(HMAC_SECRET), Value::Bool(true))]);
        let _ = ciborium::into_writer(&extensions, &mut auth_data);

        Ok(vec![
            (int(1), text("none")),
            (int(2), Value::Bytes(auth_data)),
            (int(3), Value::Map(Vec::new())),
        ])
    }

    fn get_assertion(&mut self, request: &Map) -> Result<Map, u8> {
        let rp_id = get(request, 1)
            .and_then(Value::as_text)
            .ok_or(ERR_INVALID_CBOR)?
            .to_string();
        // A real Ledger answers differently with `uv`; refusing it here keeps
        // keepassxcr from ever sending it.
        if let Some(options) = get(request, 5).and_then(Value::as_map)
            && get_text(options, "uv").is_some()
        {
            return Err(ERR_UNSUPPORTED_OPTION);
        }
        let credential_id = get(request, 3)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_map)
            .filter_map(|descriptor| get_text(descriptor, "id").and_then(Value::as_bytes))
            .find(|id| self.owns(&rp_id, id))
            .cloned()
            .ok_or(ERR_NO_CREDENTIALS)?;

        let extension = get(request, 4)
            .and_then(Value::as_map)
            .and_then(|extensions| get_text(extensions, HMAC_SECRET))
            .and_then(Value::as_map)
            .ok_or(ERR_UNSUPPORTED_OPTION)?;
        let platform_key = get(extension, 1)
            .ok_or(ERR_INVALID_CBOR)
            .and_then(|key| ctap::parse_cose_key(key).map_err(|_| ERR_INVALID_CBOR))?;
        let salt_enc: [u8; SALT_LEN] = get_bytes(extension, 2)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(ERR_INVALID_CBOR)?;
        let salt_auth = get_bytes(extension, 3).map_err(|_| ERR_INVALID_CBOR)?;
        let agreement = self.key_agreement.as_ref().ok_or(ERR_PIN_AUTH_INVALID)?;
        let shared = ctap::shared_secret(agreement, &platform_key);
        if ctap::authenticate(&shared, &salt_enc)
            .ok()
            .as_ref()
            .map(|mac| &mac[..])
            != Some(salt_auth)
        {
            return Err(ERR_PIN_AUTH_INVALID);
        }
        self.queue(CID, CMD_KEEPALIVE, &[STATUS_UPNEEDED]);

        let salt = ctap::aes_cbc(&shared, &salt_enc, false);
        let cred_random = Zeroizing::new(self.mac(b"cred", &credential_id));
        let output = Zeroizing::new(hmac_sha256(&cred_random[..], &salt).map_err(|_| 0x01u8)?);
        let encrypted = ctap::aes_cbc(&shared, &output, true);

        let mut auth_data = auth_data_header(&rp_id, 0x01 | FLAG_ED);
        let extensions = Value::Map(vec![(text(HMAC_SECRET), Value::Bytes(encrypted.to_vec()))]);
        let _ = ciborium::into_writer(&extensions, &mut auth_data);
        Ok(vec![
            (
                int(1),
                Value::Map(vec![
                    (text("id"), Value::Bytes(credential_id)),
                    (text("type"), text("public-key")),
                ]),
            ),
            (int(2), Value::Bytes(auth_data)),
            (int(3), Value::Bytes(vec![0; 64])),
        ])
    }

    /// Whether `id` is a credential this device made for `rp_id`.
    fn owns(&self, rp_id: &str, id: &[u8]) -> bool {
        id.len() == 32 && self.mac(rp_id.as_bytes(), &id[..16])[..16] == id[16..]
    }
}

fn rp_id(rp: &Map) -> Result<String, u8> {
    get_text(rp, "id")
        .and_then(Value::as_text)
        .map(str::to_string)
        .ok_or(ERR_INVALID_CBOR)
}

/// rpIdHash, flags and a zero signature counter.
fn auth_data_header(rp_id: &str, flags: u8) -> Vec<u8> {
    let mut auth_data = Vec::with_capacity(AUTH_DATA_HEADER);
    auth_data.extend_from_slice(&sha256(rp_id.as_bytes()));
    auth_data.push(flags);
    auth_data.extend_from_slice(&[0; 4]);
    auth_data
}

impl Channel for Emulator {
    fn send(&mut self, packet: &Packet) -> Result<(), Failure> {
        let cid = packet_cid(packet);
        let Some((command, data)) = self.assembler.push(packet)? else {
            return Ok(());
        };
        match command {
            CMD_INIT if cid == BROADCAST_CID => {
                let mut answer = data;
                answer.truncate(8);
                answer.extend_from_slice(&CID.to_be_bytes());
                // Protocol version, device version, capabilities: CBOR.
                answer.extend_from_slice(&[2, 0, 0, 0, 0x04]);
                self.queue(BROADCAST_CID, CMD_INIT, &answer);
            }
            CMD_CBOR if cid == CID => {
                let response = self.handle(&data);
                self.queue(CID, CMD_CBOR, &response);
            }
            // CANCEL: every command is answered at once, so nothing is pending.
            _ => {}
        }
        Ok(())
    }

    fn receive(&mut self, timeout: Duration) -> Result<Option<Packet>, Failure> {
        let packet = self.outbox.pop_front();
        if packet.is_none() {
            std::thread::sleep(timeout);
        }
        Ok(packet)
    }
}
