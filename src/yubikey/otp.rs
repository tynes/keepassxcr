//! The YubiKey OTP HID protocol: commands go out as a 70-byte frame split over
//! 8-byte feature reports, and answers come back the same way.
//!
//! This is the protocol ykpers (which KeePassXC uses) and Yubico's yubikit
//! speak to the key's OTP interface. It is written against [`Transport`] so it
//! can be tested against an emulated key.

use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::yubikey::{CHALLENGE_LEN, RESPONSE_LEN, Response};

/// Bytes in one feature report.
pub const REPORT_LEN: usize = 8;
/// Payload bytes carried by one report; the last byte is the status/sequence byte.
const REPORT_DATA_LEN: usize = REPORT_LEN - 1;
/// Payload, slot command, CRC-16 and three filler bytes.
const FRAME_LEN: usize = CHALLENGE_LEN + 6;
/// Reports needed for one frame.
const FRAME_REPORTS: usize = FRAME_LEN / REPORT_DATA_LEN;

/// Set by the host on each report it writes; cleared by the key once read.
pub const SLOT_WRITE_FLAG: u8 = 0x80;
/// Set on reports that carry part of a response.
pub const RESP_PENDING_FLAG: u8 = 0x40;
/// Set while the key waits for a touch.
pub const RESP_TIMEOUT_WAIT_FLAG: u8 = 0x20;
/// Low bits of the status byte: the report's sequence number.
pub const SEQUENCE_MASK: u8 = 0x1f;
/// Status byte of the write that ends a response and resets the key's read state.
pub const DUMMY_REPORT_WRITE: u8 = 0x8f;
/// Position of the programming sequence counter in a status report.
pub const STATUS_OFFSET_PROG_SEQ: usize = 4;
/// CRC-16 of data followed by its complemented CRC.
pub const CRC_OK_RESIDUAL: u16 = 0xf0b8;

/// Slot command: HMAC-SHA1 challenge-response with slot 1.
pub const CMD_HMAC_1: u8 = 0x30;
/// Slot command: HMAC-SHA1 challenge-response with slot 2.
pub const CMD_HMAC_2: u8 = 0x38;
/// Slot command: read the serial number.
pub const CMD_DEVICE_SERIAL: u8 = 0x10;

/// How long to wait for the key to accept a report.
const WRITE_READY_TIMEOUT: Duration = Duration::from_secs(1);
/// Upper bound on one command, touch included. The key gives up by itself
/// after about 15 seconds without a touch.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Raw access to a key's OTP interface, one feature report at a time.
pub trait Transport {
    /// Read one feature report.
    fn read_report(&mut self) -> AppResult<[u8; REPORT_LEN]>;
    /// Write one feature report.
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> AppResult<()>;
}

/// Speaks the OTP protocol over a [`Transport`].
pub struct Otp<T: Transport> {
    transport: T,
    /// Pause between status polls; zero in tests.
    poll_interval: Duration,
}

impl<T: Transport> Otp<T> {
    /// Wrap a transport, polling every 20 ms like ykpers.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            poll_interval: Duration::from_millis(20),
        }
    }

    /// Wrap a transport that answers instantly, e.g. an emulated key.
    #[cfg(any(test, feature = "software-yubikey"))]
    pub fn without_delay(transport: T) -> Self {
        Self {
            transport,
            poll_interval: Duration::ZERO,
        }
    }

    /// HMAC-SHA1 of a padded 64-byte challenge with the secret in `slot` (1 or 2).
    ///
    /// `on_touch` runs once when the key starts waiting for a touch.
    ///
    /// # Errors
    ///
    /// Fails when the slot is not programmed for HMAC-SHA1, nobody touched the
    /// key in time, or the answer is corrupt.
    pub fn hmac_sha1(
        &mut self,
        slot: u8,
        challenge: &[u8; CHALLENGE_LEN],
        on_touch: &mut dyn FnMut(),
    ) -> AppResult<Response> {
        let command = match slot {
            1 => CMD_HMAC_1,
            2 => CMD_HMAC_2,
            _ => return Err(yubikey_error(format!("invalid slot {slot}"))),
        };
        let answer = self.send_and_receive(command, challenge, on_touch)?;
        let response = checked_response::<RESPONSE_LEN>(&answer)
            .ok_or_else(|| yubikey_error("corrupt challenge-response answer".to_string()))?;
        Ok(Zeroizing::new(response))
    }

    /// The key's serial number.
    ///
    /// # Errors
    ///
    /// Fails when the key hides its serial or the answer is corrupt.
    pub fn serial(&mut self) -> AppResult<u32> {
        let answer = self.send_and_receive(CMD_DEVICE_SERIAL, &[0; CHALLENGE_LEN], &mut || {})?;
        checked_response::<4>(&answer)
            .map(u32::from_be_bytes)
            .ok_or_else(|| yubikey_error("could not read the serial number".to_string()))
    }

    fn send_and_receive(
        &mut self,
        command: u8,
        payload: &[u8; CHALLENGE_LEN],
        on_touch: &mut dyn FnMut(),
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        let prog_seq = self.transport.read_report()?[STATUS_OFFSET_PROG_SEQ];
        self.send_frame(command, payload)?;
        let result = self.read_frame(prog_seq, on_touch);
        if result.is_err() {
            // Leave the key ready for the next command.
            let _ = self.reset();
        }
        result
    }

    fn send_frame(&mut self, command: u8, payload: &[u8; CHALLENGE_LEN]) -> AppResult<()> {
        let mut frame = Zeroizing::new([0u8; FRAME_LEN]);
        frame[..CHALLENGE_LEN].copy_from_slice(payload);
        frame[CHALLENGE_LEN] = command;
        frame[CHALLENGE_LEN + 1..CHALLENGE_LEN + 3].copy_from_slice(&crc16(payload).to_le_bytes());
        for (seq, chunk) in frame.chunks(REPORT_DATA_LEN).enumerate() {
            // All-zero reports are skipped, except the first and the last.
            if seq != 0 && seq != FRAME_REPORTS - 1 && chunk.iter().all(|&byte| byte == 0) {
                continue;
            }
            let mut report = Zeroizing::new([0u8; REPORT_LEN]);
            report[..REPORT_DATA_LEN].copy_from_slice(chunk);
            report[REPORT_DATA_LEN] = SLOT_WRITE_FLAG | seq as u8;
            self.await_ready_to_write()?;
            self.transport.write_report(&report)?;
        }
        Ok(())
    }

    fn await_ready_to_write(&mut self) -> AppResult<()> {
        let deadline = Instant::now() + WRITE_READY_TIMEOUT;
        loop {
            if self.transport.read_report()?[REPORT_DATA_LEN] & SLOT_WRITE_FLAG == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(yubikey_error(
                    "the key does not accept commands".to_string(),
                ));
            }
            thread::sleep(self.poll_interval);
        }
    }

    fn read_frame(
        &mut self,
        prog_seq: u8,
        on_touch: &mut dyn FnMut(),
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        let mut response = Zeroizing::new(Vec::new());
        let mut seq = 0u8;
        let mut waited_for_touch = false;
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            let report = Zeroizing::new(self.transport.read_report()?);
            let status = report[REPORT_DATA_LEN];
            if status & RESP_PENDING_FLAG != 0 {
                if status & SEQUENCE_MASK == seq {
                    response.extend_from_slice(&report[..REPORT_DATA_LEN]);
                    seq += 1;
                } else if status & SEQUENCE_MASK == 0 {
                    // The sequence wrapped back to zero: the answer is complete.
                    self.reset()?;
                    return Ok(response);
                }
            } else if status == 0 {
                // A plain status report: the key finished without an answer.
                if !response.is_empty() {
                    return Err(yubikey_error("the answer was cut short".to_string()));
                }
                if waited_for_touch {
                    return Err(yubikey_error("timed out waiting for a touch".to_string()));
                }
                let message = if report[STATUS_OFFSET_PROG_SEQ] == prog_seq {
                    "the slot is not set up for HMAC-SHA1 challenge-response"
                } else {
                    "the key rejected the command"
                };
                return Err(yubikey_error(message.to_string()));
            } else if status & RESP_TIMEOUT_WAIT_FLAG != 0 && !waited_for_touch {
                waited_for_touch = true;
                on_touch();
            }
            if Instant::now() >= deadline {
                return Err(yubikey_error("timed out waiting for the key".to_string()));
            }
            thread::sleep(self.poll_interval);
        }
    }

    fn reset(&mut self) -> AppResult<()> {
        let mut report = [0u8; REPORT_LEN];
        report[REPORT_DATA_LEN] = DUMMY_REPORT_WRITE;
        self.transport.write_report(&report)
    }
}

/// The first `N` bytes of an answer, if its CRC over `N + 2` bytes checks out.
fn checked_response<const N: usize>(answer: &[u8]) -> Option<[u8; N]> {
    let checked = answer.get(..N + 2)?;
    if crc16(checked) != CRC_OK_RESIDUAL {
        return None;
    }
    checked[..N].try_into().ok()
}

/// CRC-16 as used by the YubiKey (ISO 13239, reflected, initial value 0xffff).
pub fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(0xffff, |crc, &byte| {
        (0..8).fold(crc ^ u16::from(byte), |crc, _| {
            if crc & 1 == 1 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            }
        })
    })
}

pub(super) fn yubikey_error(message: String) -> AppError {
    AppError::YubiKey(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yubikey::emulator::{EmulatedKey, Mode};
    use crate::yubikey::pad_challenge;

    fn hmac(secret: &[u8], data: &[u8]) -> [u8; RESPONSE_LEN] {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).expect("any key length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    #[test]
    fn crc_residual_of_data_and_complemented_crc() {
        let data = b"123456789";
        assert_eq!(crc16(data), 0x6f91);
        let mut framed = data.to_vec();
        framed.extend_from_slice(&(!crc16(data)).to_le_bytes());
        assert_eq!(crc16(&framed), CRC_OK_RESIDUAL);
    }

    #[test]
    fn variable_mode_answers_hmac_of_unpadded_challenge() {
        let secret = [7u8; 20];
        let challenge = [0x11u8; 32];
        let mut otp = Otp::without_delay(EmulatedKey::new(&secret, Mode::Variable));
        let response = otp
            .hmac_sha1(2, &pad_challenge(&challenge).expect("short"), &mut || {})
            .expect("answer");
        assert_eq!(*response, hmac(&secret, &challenge));
    }

    #[test]
    fn variable_mode_also_strips_challenge_bytes_equal_to_padding() {
        // A seed ending in 0x20 loses those bytes too, as on a real key.
        let secret = [9u8; 20];
        let mut challenge = [0x33u8; 32];
        challenge[30] = 0x20;
        challenge[31] = 0x20;
        let mut otp = Otp::without_delay(EmulatedKey::new(&secret, Mode::Variable));
        let response = otp
            .hmac_sha1(1, &pad_challenge(&challenge).expect("short"), &mut || {})
            .expect("answer");
        assert_eq!(*response, hmac(&secret, &challenge[..30]));
    }

    #[test]
    fn fixed_mode_answers_hmac_of_all_64_bytes() {
        let secret = [1u8; 20];
        let padded = pad_challenge(&[0x44u8; 32]).expect("short");
        let mut otp = Otp::without_delay(EmulatedKey::new(&secret, Mode::Fixed));
        let response = otp.hmac_sha1(2, &padded, &mut || {}).expect("answer");
        assert_eq!(*response, hmac(&secret, &padded));
    }

    #[test]
    fn touch_callback_runs_once_while_waiting() {
        let mut key = EmulatedKey::new(&[3u8; 20], Mode::Variable);
        key.require_touch(5);
        let mut otp = Otp::without_delay(key);
        let mut touches = 0;
        otp.hmac_sha1(2, &[0x55; CHALLENGE_LEN], &mut || touches += 1)
            .expect("answer");
        assert_eq!(touches, 1);
    }

    #[test]
    fn unprogrammed_slot_is_reported() {
        let mut key = EmulatedKey::new(&[3u8; 20], Mode::Variable);
        key.clear_slot(1);
        let mut otp = Otp::without_delay(key);
        let err = otp
            .hmac_sha1(1, &[0x55; CHALLENGE_LEN], &mut || {})
            .expect_err("slot 1 is empty");
        assert!(err.to_string().contains("not set up"), "{err}");
    }

    #[test]
    fn untouched_key_times_out() {
        let mut key = EmulatedKey::new(&[3u8; 20], Mode::Variable);
        key.never_touched();
        let mut otp = Otp::without_delay(key);
        let err = otp
            .hmac_sha1(2, &[0x55; CHALLENGE_LEN], &mut || {})
            .expect_err("no touch");
        assert!(err.to_string().contains("touch"), "{err}");
    }

    #[test]
    fn reads_serial() {
        let mut otp = Otp::without_delay(EmulatedKey::new(&[3u8; 20], Mode::Variable));
        assert_eq!(otp.serial().expect("serial"), EmulatedKey::SERIAL);
    }

    #[test]
    fn commands_can_follow_each_other() {
        let secret = [5u8; 20];
        let mut otp = Otp::without_delay(EmulatedKey::new(&secret, Mode::Variable));
        for byte in [1u8, 2, 3] {
            let challenge = [byte; 32];
            let response = otp
                .hmac_sha1(2, &pad_challenge(&challenge).expect("short"), &mut || {})
                .expect("answer");
            assert_eq!(*response, hmac(&secret, &challenge));
        }
        otp.serial().expect("serial");
    }

    #[test]
    fn frame_reports_match_yubikit() {
        // Reports yubikit (yubikey-manager 5.x, `OtpProtocol._send_frame`)
        // writes for calculate_hmac_sha1(SLOT.TWO, challenge) with the same
        // 64-byte padded challenge, recorded once.
        let mut recorder = RecordingTransport::default();
        let challenge: Vec<u8> = (0..32).collect();
        let padded = pad_challenge(&challenge).expect("short");
        let mut otp = Otp::without_delay(&mut recorder);
        let _ = otp.send_frame(CMD_HMAC_2, &padded);
        let written: Vec<String> = recorder.written.iter().map(hex::encode).collect();
        let expected = [
            "0001020304050680",
            "0708090a0b0c0d81",
            "0e0f101112131482",
            "15161718191a1b83",
            "1c1d1e1f20202084",
            "2020202020202085",
            "2020202020202086",
            "2020202020202087",
            "2020202020202088",
            "2038cead00000089",
        ];
        assert_eq!(written, expected);
    }

    #[derive(Default)]
    struct RecordingTransport {
        written: Vec<[u8; REPORT_LEN]>,
    }

    impl Transport for &mut RecordingTransport {
        fn read_report(&mut self) -> AppResult<[u8; REPORT_LEN]> {
            Ok([0; REPORT_LEN])
        }

        fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> AppResult<()> {
            self.written.push(*report);
            Ok(())
        }
    }
}
