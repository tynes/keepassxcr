//! CTAPHID: the USB HID framing FIDO2 commands travel in.
//!
//! A message is split into 64-byte packets: an init packet (channel id,
//! command, length, 57 bytes of data) and continuation packets (channel id,
//! sequence number, 59 bytes of data). While a command waits for a touch the
//! device sends KEEPALIVE packets; the host can abort with CANCEL.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rand::RngCore;
use rand::rngs::OsRng;

use crate::fido2::{Failure, fido2_error};

/// Bytes in one HID report.
pub(super) const PACKET_LEN: usize = 64;
/// One HID report.
pub(super) type Packet = [u8; PACKET_LEN];

pub(super) const BROADCAST_CID: u32 = 0xffff_ffff;
pub(super) const CMD_INIT: u8 = 0x86;
pub(super) const CMD_CBOR: u8 = 0x90;
pub(super) const CMD_CANCEL: u8 = 0x91;
pub(super) const CMD_KEEPALIVE: u8 = 0xbb;
pub(super) const CMD_ERROR: u8 = 0xbf;
/// KEEPALIVE status: the device waits for the user.
pub(super) const STATUS_UPNEEDED: u8 = 2;

const INIT_DATA: usize = PACKET_LEN - 7;
const CONT_DATA: usize = PACKET_LEN - 5;
/// Largest message: one init packet and 128 continuation packets.
const MAX_MESSAGE: usize = INIT_DATA + 128 * CONT_DATA;

/// How long one read waits before checking for cancellation and the deadline.
const POLL: Duration = Duration::from_millis(100);
/// How long a command may take, including reading the device's screen and
/// confirming on it.
pub(super) const USER_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a command that never waits for the user may take.
pub(super) const QUICK_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a device cancelled by another's win may take to stop.
const CANCEL_GRACE: Duration = Duration::from_secs(1);

/// A FIDO HID interface, or the emulated one.
pub(super) trait Channel: Send {
    /// Write one report.
    fn send(&mut self, packet: &Packet) -> Result<(), Failure>;
    /// Read one report, or `None` when nothing arrives within `timeout`.
    fn receive(&mut self, timeout: Duration) -> Result<Option<Packet>, Failure>;
}

/// Split a message into packets for channel `cid`.
pub(super) fn frame(cid: u32, command: u8, data: &[u8]) -> Result<Vec<Packet>, Failure> {
    let len = u16::try_from(data.len())
        .ok()
        .filter(|_| data.len() <= MAX_MESSAGE)
        .ok_or_else(|| fido2_error("message too long for the device"))?;
    let mut packets =
        Vec::with_capacity(1 + data.len().saturating_sub(INIT_DATA).div_ceil(CONT_DATA));
    let mut first = [0u8; PACKET_LEN];
    first[..4].copy_from_slice(&cid.to_be_bytes());
    first[4] = command;
    first[5..7].copy_from_slice(&len.to_be_bytes());
    let (head, rest) = data.split_at(data.len().min(INIT_DATA));
    first[7..7 + head.len()].copy_from_slice(head);
    packets.push(first);
    for (seq, chunk) in rest.chunks(CONT_DATA).enumerate() {
        let mut packet = [0u8; PACKET_LEN];
        packet[..4].copy_from_slice(&cid.to_be_bytes());
        // At most 128 continuation packets, checked above.
        packet[4] = seq as u8;
        packet[5..5 + chunk.len()].copy_from_slice(chunk);
        packets.push(packet);
    }
    Ok(packets)
}

/// The channel id a packet belongs to.
pub(super) fn packet_cid(packet: &Packet) -> u32 {
    u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]])
}

/// Puts packets back together into one message.
#[derive(Default)]
pub(super) struct Assembler {
    command: u8,
    expected: usize,
    data: Vec<u8>,
    next_seq: u8,
}

impl Assembler {
    /// Add a packet; returns the command and data once the message is whole.
    pub(super) fn push(&mut self, packet: &Packet) -> Result<Option<(u8, Vec<u8>)>, Failure> {
        if packet[4] & 0x80 != 0 {
            let expected = usize::from(u16::from_be_bytes([packet[5], packet[6]]));
            if expected > MAX_MESSAGE {
                return Err(fido2_error("device sent an oversized message"));
            }
            *self = Self {
                command: packet[4],
                expected,
                data: Vec::with_capacity(expected),
                next_seq: 0,
            };
            let take = expected.min(INIT_DATA);
            self.data.extend_from_slice(&packet[7..7 + take]);
        } else {
            if packet[4] != self.next_seq || self.data.len() >= self.expected {
                return Err(fido2_error("device sent packets out of order"));
            }
            self.next_seq = self.next_seq.wrapping_add(1);
            let take = (self.expected - self.data.len()).min(CONT_DATA);
            self.data.extend_from_slice(&packet[5..5 + take]);
        }
        if self.data.len() < self.expected {
            return Ok(None);
        }
        let data = std::mem::take(&mut self.data);
        Ok(Some((self.command, data)))
    }
}

/// An open FIDO2 device with its own channel.
pub(super) struct Device {
    channel: Box<dyn Channel>,
    cid: u32,
}

impl Device {
    /// Allocate a channel on `channel` with CTAPHID_INIT.
    pub(super) fn open(mut channel: Box<dyn Channel>) -> Result<Self, Failure> {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        for packet in frame(BROADCAST_CID, CMD_INIT, &nonce)? {
            channel.send(&packet)?;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut assembler = Assembler::default();
        while Instant::now() < deadline {
            let Some(packet) = channel.receive(POLL)? else {
                continue;
            };
            if packet_cid(&packet) != BROADCAST_CID {
                continue;
            }
            if let Some((command, data)) = assembler.push(&packet)?
                && command == CMD_INIT
                && data.len() >= 12
                && data[..8] == nonce
            {
                let cid = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                return Ok(Self { channel, cid });
            }
        }
        Err(fido2_error("the device did not answer"))
    }

    /// Send a CBOR command and return the response after its status byte.
    ///
    /// `on_touch` runs when the device first asks for the user; setting
    /// `cancel` aborts a command that is waiting for them.
    pub(super) fn cbor(
        &mut self,
        request: &[u8],
        timeout: Duration,
        cancel: &AtomicBool,
        on_touch: &(dyn Fn() + Sync),
    ) -> Result<Vec<u8>, Failure> {
        for packet in frame(self.cid, CMD_CBOR, request)? {
            self.channel.send(&packet)?;
        }
        let deadline = Instant::now() + timeout;
        let mut cancel_sent = None;
        let mut assembler = Assembler::default();
        let mut cancelled = false;
        let mut prompted = false;
        loop {
            if !cancelled && (cancel.load(Ordering::Relaxed) || Instant::now() > deadline) {
                cancelled = true;
                cancel_sent = Some(Instant::now());
                // The device answers the pending command with KEEPALIVE_CANCEL.
                for packet in frame(self.cid, CMD_CANCEL, &[])? {
                    self.channel.send(&packet)?;
                }
            }
            // A device that lost the race and ignores CANCEL must not hold up the winner.
            if cancel.load(Ordering::Relaxed)
                && cancel_sent.is_some_and(|sent: Instant| sent.elapsed() > CANCEL_GRACE)
            {
                return Err(Failure::Cancelled);
            }
            if cancelled && Instant::now() > deadline + Duration::from_secs(2) {
                return Err(fido2_error("the device did not answer in time"));
            }
            let Some(packet) = self.channel.receive(POLL)? else {
                continue;
            };
            if packet_cid(&packet) != self.cid {
                continue;
            }
            let Some((command, data)) = assembler.push(&packet)? else {
                continue;
            };
            match command {
                CMD_KEEPALIVE => {
                    if data.first() == Some(&STATUS_UPNEEDED) && !prompted {
                        prompted = true;
                        on_touch();
                    }
                }
                CMD_CBOR => {
                    let (&status, body) = data
                        .split_first()
                        .ok_or_else(|| fido2_error("empty response from the device"))?;
                    return match status {
                        0 => Ok(body.to_vec()),
                        _ if cancelled && cancel.load(Ordering::Relaxed) => Err(Failure::Cancelled),
                        _ if cancelled => Err(fido2_error("timed out waiting for the device")),
                        status => Err(Failure::from_status(status)),
                    };
                }
                CMD_ERROR => {
                    return Err(fido2_error(format!(
                        "device reported transport error {:#04x}",
                        data.first().copied().unwrap_or(0)
                    )));
                }
                other => {
                    return Err(fido2_error(format!(
                        "device sent unexpected command {other:#04x}"
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_and_reassembles_long_messages() {
        let data: Vec<u8> = (0..300u16).map(|i| i as u8).collect();
        let packets = frame(0x0102_0304, CMD_CBOR, &data).expect("frame");
        assert_eq!(packets.len(), 1 + (300 - INIT_DATA).div_ceil(CONT_DATA));
        assert_eq!(packets[0][4], CMD_CBOR);
        assert_eq!(packets[1][4], 0);
        assert_eq!(packets[2][4], 1);

        let mut assembler = Assembler::default();
        let mut result = None;
        for packet in &packets {
            assert_eq!(packet_cid(packet), 0x0102_0304);
            result = assembler.push(packet).expect("push");
        }
        assert_eq!(result, Some((CMD_CBOR, data)));
    }

    #[test]
    fn short_message_fits_one_packet() {
        let packets = frame(1, CMD_INIT, &[9; 8]).expect("frame");
        assert_eq!(packets.len(), 1);
        let mut assembler = Assembler::default();
        assert_eq!(
            assembler.push(&packets[0]).expect("push"),
            Some((CMD_INIT, vec![9; 8]))
        );
    }

    #[test]
    fn rejects_out_of_order_packets() {
        let packets = frame(1, CMD_CBOR, &[0; 200]).expect("frame");
        let mut assembler = Assembler::default();
        assembler.push(&packets[0]).expect("init");
        assert!(assembler.push(&packets[2]).is_err());
    }

    #[test]
    fn rejects_oversized_messages() {
        assert!(frame(1, CMD_CBOR, &vec![0; MAX_MESSAGE + 1]).is_err());
        let mut packet = [0u8; PACKET_LEN];
        packet[4] = CMD_CBOR;
        packet[5..7].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(Assembler::default().push(&packet).is_err());
    }
}
