//! USB access to FIDO security keys through `hidapi`: the CTAPHID interface
//! (usage page 0xF1D0). On macOS this needs no special permission, unlike
//! the YubiKey OTP interface.

use hidapi::{HidApi, HidDevice};

use crate::error::AppResult;
use crate::fido2::ctaphid::{PACKET_LEN, Transport};
use crate::fido2::fido2_error;

const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE: u16 = 0x01;

/// Every plugged-in FIDO device that could be opened.
///
/// # Errors
///
/// Fails when USB cannot be used at all, or the only keys cannot be opened.
pub fn devices() -> AppResult<Vec<Box<dyn Transport>>> {
    let api = HidApi::new().map_err(|err| fido2_error(format!("USB is unavailable: {err}")))?;
    let mut infos: Vec<_> = api
        .device_list()
        .filter(|info| info.usage_page() == FIDO_USAGE_PAGE && info.usage() == FIDO_USAGE)
        .collect();
    infos.dedup_by(|a, b| a.path() == b.path());
    let mut devices: Vec<Box<dyn Transport>> = Vec::new();
    let mut last_error = None;
    for info in infos {
        match info.open_device(&api) {
            Ok(device) => devices.push(Box::new(HidTransport(device))),
            Err(err) => last_error = Some(err),
        }
    }
    if let (true, Some(err)) = (devices.is_empty(), last_error) {
        return Err(fido2_error(format!(
            "could not open the security key: {err}"
        )));
    }
    Ok(devices)
}

/// CTAPHID reports have no report id, so id 0 goes in front of each write.
struct HidTransport(HidDevice);

impl Transport for HidTransport {
    fn write_packet(&mut self, packet: &[u8; PACKET_LEN]) -> AppResult<()> {
        let mut buffer = [0u8; PACKET_LEN + 1];
        buffer[1..].copy_from_slice(packet);
        self.0
            .write(&buffer)
            .map(|_| ())
            .map_err(|err| fido2_error(format!("writing to the security key failed: {err}")))
    }

    fn read_packet(&mut self, timeout_ms: i32) -> AppResult<Option<[u8; PACKET_LEN]>> {
        let mut buffer = [0u8; PACKET_LEN];
        let read = self
            .0
            .read_timeout(&mut buffer, timeout_ms)
            .map_err(|err| fido2_error(format!("reading from the security key failed: {err}")))?;
        Ok(match read {
            0 => None,
            PACKET_LEN => Some(buffer),
            _ => return Err(fido2_error("short read from the security key")),
        })
    }
}
