//! CTAPHID: how CTAP2 messages travel over 64-byte USB HID reports
//! (FIDO CTAP 2.1, section 11.2).

use rand::RngCore;
use rand::rngs::OsRng;

use crate::error::AppResult;
use crate::fido2::fido2_error;

/// Bytes in one HID report.
pub const PACKET_LEN: usize = 64;
const INIT_DATA: usize = PACKET_LEN - 7;
const CONT_DATA: usize = PACKET_LEN - 5;
/// Longest message the framing can carry.
const MAX_MESSAGE: usize = INIT_DATA + 128 * CONT_DATA;

pub const CMD_INIT: u8 = 0x06;
pub const CMD_CBOR: u8 = 0x10;
pub const CMD_KEEPALIVE: u8 = 0x3b;
pub const CMD_ERROR: u8 = 0x3f;
pub const BROADCAST_CID: [u8; 4] = [0xff; 4];
/// Keepalive status: waiting for the user to touch the key.
pub const STATUS_UPNEEDED: u8 = 2;

/// Milliseconds to wait for one report before giving up on the key. Keepalives
/// arrive every 100 ms while the key waits for a touch.
const READ_TIMEOUT_MS: i32 = 5_000;

/// Raw HID reports to and from a FIDO device.
pub trait Transport {
    fn write_packet(&mut self, packet: &[u8; PACKET_LEN]) -> AppResult<()>;
    /// The next report, or `None` after `timeout_ms` without one.
    fn read_packet(&mut self, timeout_ms: i32) -> AppResult<Option<[u8; PACKET_LEN]>>;
}

/// One CTAPHID channel to a device.
pub struct CtapHid<T> {
    transport: T,
    cid: [u8; 4],
}

impl<T: Transport> CtapHid<T> {
    /// Allocate a channel on the device.
    ///
    /// # Errors
    ///
    /// Fails when the device does not answer CTAPHID_INIT.
    pub fn open(mut transport: T) -> AppResult<Self> {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        send(&mut transport, BROADCAST_CID, CMD_INIT, &nonce)?;
        loop {
            let (cmd, data) = receive(&mut transport, BROADCAST_CID)?;
            // Answers to other clients' INITs share the broadcast channel.
            if cmd == CMD_INIT && data.len() >= 17 && data[..8] == nonce {
                let mut cid = [0u8; 4];
                cid.copy_from_slice(&data[8..12]);
                return Ok(Self { transport, cid });
            }
            if cmd == CMD_ERROR {
                return Err(fido2_error(format!(
                    "the security key refused a channel (error {})",
                    data.first().copied().unwrap_or(0)
                )));
            }
        }
    }

    /// Send a CTAP2 command and return the status byte and CBOR body.
    /// `on_touch` runs once when the key starts waiting for a touch.
    ///
    /// # Errors
    ///
    /// Fails on transport errors or a CTAPHID error.
    pub fn cbor(&mut self, payload: &[u8], on_touch: &mut dyn FnMut()) -> AppResult<(u8, Vec<u8>)> {
        send(&mut self.transport, self.cid, CMD_CBOR, payload)?;
        let mut prompted = false;
        loop {
            let (cmd, data) = receive(&mut self.transport, self.cid)?;
            match cmd {
                CMD_KEEPALIVE => {
                    if data.first() == Some(&STATUS_UPNEEDED) && !prompted {
                        prompted = true;
                        on_touch();
                    }
                }
                CMD_CBOR => {
                    let (status, body) = data
                        .split_first()
                        .ok_or_else(|| fido2_error("empty answer from the security key"))?;
                    return Ok((*status, body.to_vec()));
                }
                CMD_ERROR => {
                    return Err(fido2_error(format!(
                        "the security key reported transport error {}",
                        data.first().copied().unwrap_or(0)
                    )));
                }
                other => {
                    return Err(fido2_error(format!(
                        "unexpected CTAPHID command {other:#04x} from the security key"
                    )));
                }
            }
        }
    }
}

/// Frame `data` into an init packet and continuation packets.
pub fn frame(cid: [u8; 4], cmd: u8, data: &[u8]) -> AppResult<Vec<[u8; PACKET_LEN]>> {
    if data.len() > MAX_MESSAGE {
        return Err(fido2_error("message too long for CTAPHID"));
    }
    let mut packets = Vec::new();
    let mut packet = [0u8; PACKET_LEN];
    packet[..4].copy_from_slice(&cid);
    packet[4] = 0x80 | cmd;
    packet[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let first = data.len().min(INIT_DATA);
    packet[7..7 + first].copy_from_slice(&data[..first]);
    packets.push(packet);
    for (seq, chunk) in data[first..].chunks(CONT_DATA).enumerate() {
        let mut packet = [0u8; PACKET_LEN];
        packet[..4].copy_from_slice(&cid);
        packet[4] = seq as u8;
        packet[5..5 + chunk.len()].copy_from_slice(chunk);
        packets.push(packet);
    }
    Ok(packets)
}

/// Collects packets into one message.
pub struct Assembler {
    cmd: u8,
    expected: usize,
    data: Vec<u8>,
    seq: u8,
}

impl Assembler {
    /// Start from an init packet. Returns `None` for a continuation packet.
    pub fn start(packet: &[u8; PACKET_LEN]) -> Option<Self> {
        if packet[4] & 0x80 == 0 {
            return None;
        }
        let expected = usize::from(u16::from_be_bytes([packet[5], packet[6]]));
        let first = expected.min(INIT_DATA);
        Some(Self {
            cmd: packet[4] & 0x7f,
            expected,
            data: packet[7..7 + first].to_vec(),
            seq: 0,
        })
    }

    /// Add a continuation packet.
    ///
    /// # Errors
    ///
    /// Fails on a packet out of sequence.
    pub fn push(&mut self, packet: &[u8; PACKET_LEN]) -> AppResult<()> {
        if packet[4] != self.seq {
            return Err(fido2_error("CTAPHID packet out of sequence"));
        }
        self.seq = self.seq.wrapping_add(1);
        let take = (self.expected - self.data.len()).min(CONT_DATA);
        self.data.extend_from_slice(&packet[5..5 + take]);
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.data.len() >= self.expected
    }

    pub fn finish(self) -> (u8, Vec<u8>) {
        (self.cmd, self.data)
    }
}

fn send<T: Transport>(transport: &mut T, cid: [u8; 4], cmd: u8, data: &[u8]) -> AppResult<()> {
    for packet in frame(cid, cmd, data)? {
        transport.write_packet(&packet)?;
    }
    Ok(())
}

fn receive<T: Transport>(transport: &mut T, cid: [u8; 4]) -> AppResult<(u8, Vec<u8>)> {
    let mut read = || {
        transport
            .read_packet(READ_TIMEOUT_MS)?
            .ok_or_else(|| fido2_error("the security key stopped answering"))
    };
    let mut assembler = loop {
        let packet = read()?;
        if packet[..4] != cid {
            continue;
        }
        if let Some(assembler) = Assembler::start(&packet) {
            break assembler;
        }
    };
    while !assembler.is_complete() {
        let packet = read()?;
        if packet[..4] == cid {
            assembler.push(&packet)?;
        }
    }
    Ok(assembler.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_and_reassembles_long_messages() {
        let data: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let packets = frame([1, 2, 3, 4], CMD_CBOR, &data).unwrap();
        // 57 + 4 * 59 < 300 <= 57 + 5 * 59
        assert_eq!(packets.len(), 6);
        assert_eq!(&packets[0][..7], &[1, 2, 3, 4, 0x90, 0x01, 0x2c]);
        assert_eq!(packets[1][4], 0);
        assert_eq!(packets[5][4], 4);
        let mut assembler = Assembler::start(&packets[0]).unwrap();
        for packet in &packets[1..] {
            assembler.push(packet).unwrap();
        }
        assert!(assembler.is_complete());
        assert_eq!(assembler.finish(), (CMD_CBOR, data));
    }

    #[test]
    fn rejects_out_of_order_packets() {
        let data = vec![7u8; 200];
        let packets = frame([1, 2, 3, 4], CMD_CBOR, &data).unwrap();
        let mut assembler = Assembler::start(&packets[0]).unwrap();
        assert!(assembler.push(&packets[2]).is_err());
    }
}
