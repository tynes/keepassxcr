//! USB access to FIDO2 devices through `hidapi`.
//!
//! Any vendor's device works: FIDO interfaces are found by their HID usage
//! page, then kept only if they support hmac-secret.

use std::time::Duration;

use hidapi::{DeviceInfo, HidApi, HidDevice};
use tracing::debug;

use crate::error::{AppError, AppResult};
use crate::fido2::ctaphid::{Channel, Device, PACKET_LEN, Packet};
use crate::fido2::{Failure, ctap, fido2_error};

/// HID usage page and usage of a FIDO interface (CTAPHID).
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE: u16 = 0x01;

/// Open every FIDO2 device plugged in that supports hmac-secret.
///
/// # Errors
///
/// Fails when USB is unavailable, or no suitable device is found.
pub(super) fn devices() -> AppResult<Vec<Device>> {
    let api = HidApi::new().map_err(|err| AppError::Fido2(format!("USB is unavailable: {err}")))?;
    let mut interfaces: Vec<&DeviceInfo> = api
        .device_list()
        .filter(|info| info.usage_page() == FIDO_USAGE_PAGE && info.usage() == FIDO_USAGE)
        .collect();
    interfaces.dedup_by(|a, b| a.path() == b.path());

    let mut devices = Vec::new();
    let mut open_error = None;
    let mut unsupported = 0;
    for info in &interfaces {
        let name = info.product_string().unwrap_or("FIDO device").to_string();
        let opened = info
            .open_device(&api)
            .map_err(|err| {
                AppError::Fido2(format!("could not open {name}: {err}{}", permission_hint()))
            })
            .and_then(|device| {
                Device::open(Box::new(HidChannel(device))).map_err(|failure| match failure {
                    Failure::Error(err) => err,
                    _ => AppError::Fido2(format!("{name} did not answer")),
                })
            });
        let mut device = match opened {
            Ok(device) => device,
            Err(err) => {
                debug!("skipping {name}: {err}");
                open_error.get_or_insert(err);
                continue;
            }
        };
        match ctap::supports_hmac_secret(&mut device) {
            Ok(true) => devices.push(device),
            _ => {
                debug!("skipping {name}: no hmac-secret");
                unsupported += 1;
            }
        }
    }
    if !devices.is_empty() {
        return Ok(devices);
    }
    Err(if unsupported > 0 {
        AppError::Fido2(
            "the FIDO2 device does not support hmac-secret; on a Ledger, open the Security Key app"
                .to_string(),
        )
    } else if let Some(err) = open_error {
        err
    } else {
        AppError::Fido2(format!(
            "no FIDO2 device found; plug it in (on a Ledger, unlock it and open the Security Key \
             app){}",
            permission_hint()
        ))
    })
}

fn permission_hint() -> &'static str {
    if cfg!(target_os = "linux") {
        " and make sure you can open its hidraw device (your distribution's FIDO udev rule, or \
         Ledger's udev rules)"
    } else {
        ""
    }
}

/// CTAPHID reports over hidapi. FIDO interfaces have no report ids, so
/// report id 0 goes in front of each write.
struct HidChannel(HidDevice);

impl Channel for HidChannel {
    fn send(&mut self, packet: &Packet) -> Result<(), Failure> {
        let mut buffer = [0u8; PACKET_LEN + 1];
        buffer[1..].copy_from_slice(packet);
        self.0
            .write(&buffer)
            .map(|_| ())
            .map_err(|err| fido2_error(format!("writing to the device failed: {err}")))
    }

    fn receive(&mut self, timeout: Duration) -> Result<Option<Packet>, Failure> {
        let mut packet = [0u8; PACKET_LEN];
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let read = self
            .0
            .read_timeout(&mut packet, millis)
            .map_err(|err| fido2_error(format!("reading from the device failed: {err}")))?;
        Ok((read > 0).then_some(packet))
    }
}
