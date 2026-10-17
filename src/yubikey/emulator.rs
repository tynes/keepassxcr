//! A software YubiKey that speaks the device side of the OTP HID protocol.
//!
//! Used by the unit tests, and by the CLI when built with the
//! `software-yubikey` feature, so the whole challenge-response path can be
//! tested without hardware. Release builds do not contain it.

use std::collections::VecDeque;

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

use crate::error::AppResult;
use crate::yubikey::CHALLENGE_LEN;
use crate::yubikey::otp::{
    CMD_DEVICE_SERIAL, CMD_HMAC_1, CMD_HMAC_2, DUMMY_REPORT_WRITE, REPORT_LEN, RESP_PENDING_FLAG,
    RESP_TIMEOUT_WAIT_FLAG, SEQUENCE_MASK, SLOT_WRITE_FLAG, Transport, crc16,
};

/// How a slot reads the 64-byte challenge, as set with `ykman otp chalresp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Default: trailing bytes equal to the last byte are padding and dropped.
    Variable,
    /// `--totp`-style fixed 64-byte input (`HMAC_LT64` off).
    Fixed,
}

/// What the key does when a challenge needs a touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Touch {
    /// Answer at once.
    None,
    /// Report "waiting for touch" this many times, then answer.
    After(u32),
    /// Report "waiting for touch" a few times, then give up without answering.
    Never,
}

/// Status polls an untouched key reports before it gives up.
const UNTOUCHED_POLLS: u32 = 3;

/// An emulated YubiKey with the same HMAC-SHA1 secret in both slots.
pub struct EmulatedKey {
    secret: Zeroizing<Vec<u8>>,
    mode: Mode,
    programmed: [bool; 2],
    touch: Touch,
    prog_seq: u8,
    frame: Zeroizing<[u8; CHALLENGE_LEN + 6]>,
    /// Polls left in the current "waiting for touch" phase.
    waiting: u32,
    /// Answer reports still to be read, then the end-of-answer marker.
    answer: Option<VecDeque<[u8; REPORT_LEN]>>,
}

impl EmulatedKey {
    /// Serial number the emulated key reports.
    pub const SERIAL: u32 = 7_370_001;

    /// A key with `secret` programmed in both slots.
    pub fn new(secret: &[u8], mode: Mode) -> Self {
        Self {
            secret: Zeroizing::new(secret.to_vec()),
            mode,
            programmed: [true, true],
            touch: Touch::None,
            prog_seq: 1,
            frame: Zeroizing::new([0; CHALLENGE_LEN + 6]),
            waiting: 0,
            answer: None,
        }
    }

    /// Build a key from `KEEPASSXCR_SOFTWARE_YUBIKEY=<hex secret>[:fixed][:touch]`.
    ///
    /// # Errors
    ///
    /// Fails when the variable is set but malformed.
    #[cfg(feature = "software-yubikey")]
    pub fn from_env() -> AppResult<Option<Self>> {
        let Ok(spec) = std::env::var("KEEPASSXCR_SOFTWARE_YUBIKEY") else {
            return Ok(None);
        };
        let mut parts = spec.split(':');
        let secret = hex::decode(parts.next().unwrap_or_default()).map_err(|_| {
            crate::error::AppError::InvalidInput(
                "KEEPASSXCR_SOFTWARE_YUBIKEY must start with a hex secret".to_string(),
            )
        })?;
        let mut key = Self::new(&secret, Mode::Variable);
        for option in parts {
            match option {
                "fixed" => key.mode = Mode::Fixed,
                "touch" => key.require_touch(2),
                other => {
                    return Err(crate::error::AppError::InvalidInput(format!(
                        "unknown KEEPASSXCR_SOFTWARE_YUBIKEY option '{other}'"
                    )));
                }
            }
        }
        Ok(Some(key))
    }

    /// Make challenges wait for a touch for `polls` status reads.
    pub fn require_touch(&mut self, polls: u32) {
        self.touch = Touch::After(polls);
    }

    /// Make challenges wait for a touch that never comes.
    #[cfg(test)]
    pub fn never_touched(&mut self) {
        self.touch = Touch::Never;
    }

    /// Leave `slot` (1 or 2) unprogrammed.
    #[cfg(test)]
    pub fn clear_slot(&mut self, slot: u8) {
        self.programmed[usize::from(slot - 1)] = false;
    }

    fn status_report(&self, flags: u8) -> [u8; REPORT_LEN] {
        [0, 5, 4, 3, self.prog_seq, 0, 0, flags]
    }

    fn execute(&mut self) {
        let payload = &self.frame[..CHALLENGE_LEN];
        let command = self.frame[CHALLENGE_LEN];
        let crc =
            u16::from_le_bytes([self.frame[CHALLENGE_LEN + 1], self.frame[CHALLENGE_LEN + 2]]);
        if crc != crc16(payload) {
            return;
        }
        let data = match command {
            CMD_HMAC_1 | CMD_HMAC_2 => {
                let slot = usize::from(command == CMD_HMAC_2);
                if !self.programmed[slot] {
                    return;
                }
                self.waiting = match self.touch {
                    Touch::None => 0,
                    Touch::After(polls) => polls,
                    Touch::Never => UNTOUCHED_POLLS,
                };
                if self.touch == Touch::Never {
                    return;
                }
                self.hmac(payload).to_vec()
            }
            CMD_DEVICE_SERIAL => Self::SERIAL.to_be_bytes().to_vec(),
            _ => return,
        };
        self.answer = Some(answer_reports(&data));
    }

    fn hmac(&self, payload: &[u8]) -> [u8; 20] {
        let input = match self.mode {
            Mode::Fixed => payload,
            Mode::Variable => {
                let last = payload[CHALLENGE_LEN - 1];
                let kept = payload
                    .iter()
                    .rposition(|&byte| byte != last)
                    .map_or(0, |i| i + 1);
                &payload[..kept]
            }
        };
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&self.secret).expect("any key length");
        mac.update(input);
        mac.finalize().into_bytes().into()
    }
}

/// Split `data` plus its complemented CRC into sequenced answer reports.
fn answer_reports(data: &[u8]) -> VecDeque<[u8; REPORT_LEN]> {
    let mut framed = data.to_vec();
    framed.extend_from_slice(&(!crc16(data)).to_le_bytes());
    framed
        .chunks(REPORT_LEN - 1)
        .enumerate()
        .map(|(seq, chunk)| {
            let mut report = [0u8; REPORT_LEN];
            report[..chunk.len()].copy_from_slice(chunk);
            report[REPORT_LEN - 1] = RESP_PENDING_FLAG | seq as u8;
            report
        })
        .collect()
}

impl Transport for EmulatedKey {
    fn read_report(&mut self) -> AppResult<[u8; REPORT_LEN]> {
        if self.waiting > 0 {
            self.waiting -= 1;
            return Ok(self.status_report(RESP_TIMEOUT_WAIT_FLAG | 0x0f));
        }
        Ok(match self.answer.as_mut() {
            Some(reports) => {
                reports
                    .pop_front()
                    .unwrap_or([0, 0, 0, 0, 0, 0, 0, RESP_PENDING_FLAG])
            }
            None => self.status_report(0),
        })
    }

    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> AppResult<()> {
        let status = report[REPORT_LEN - 1];
        if status == DUMMY_REPORT_WRITE {
            self.answer = None;
            return Ok(());
        }
        if status & SLOT_WRITE_FLAG == 0 {
            return Ok(());
        }
        let seq = usize::from(status & SEQUENCE_MASK);
        if seq == 0 {
            self.frame.fill(0);
            self.answer = None;
        }
        let Some(target) = self.frame.get_mut(seq * 7..seq * 7 + 7) else {
            return Ok(());
        };
        target.copy_from_slice(&report[..7]);
        if seq == 9 {
            self.execute();
        }
        Ok(())
    }
}
