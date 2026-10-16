//! USB access to a YubiKey's OTP interface through `hidapi`.
//!
//! On macOS this goes through IOKit, opened shared so the key keeps working as
//! a keyboard; on Linux through hidraw.

use hidapi::{DeviceInfo, HidApi, HidDevice};

use crate::error::AppResult;
use crate::yubikey::otp::{Otp, REPORT_LEN, Transport, yubikey_error};
use crate::yubikey::{CHALLENGE_LEN, Response, YubiKeySlot};

/// Yubico's USB vendor id.
const YUBICO_VENDOR_ID: u16 = 0x1050;
/// HID usage of the OTP interface: Generic Desktop / Keyboard.
const OTP_USAGE_PAGE: u16 = 0x0001;
const OTP_USAGE: u16 = 0x0006;

/// Send a padded challenge to the YubiKey in `slot`, over USB.
///
/// # Errors
///
/// Fails when no matching key is plugged in, it cannot be opened, or the
/// challenge fails.
pub fn challenge(
    slot: YubiKeySlot,
    padded: &[u8; CHALLENGE_LEN],
    on_touch: &mut dyn FnMut(),
) -> AppResult<Response> {
    let api = HidApi::new().map_err(|err| yubikey_error(format!("USB is unavailable: {err}")))?;
    let mut candidates: Vec<&DeviceInfo> = api
        .device_list()
        .filter(|info| is_otp_interface(info))
        .collect();
    candidates.dedup_by(|a, b| a.path() == b.path());
    if candidates.is_empty() {
        return Err(yubikey_error(not_found_message()));
    }

    let mut last_error = None;
    for info in candidates {
        let device = match info.open_device(&api) {
            Ok(device) => device,
            Err(err) => {
                last_error = Some(open_error(&err));
                continue;
            }
        };
        let mut otp = Otp::new(HidTransport(device));
        if let Some(wanted) = slot.serial {
            match otp.serial() {
                Ok(serial) if serial == wanted => {}
                _ => continue,
            }
        }
        return otp.hmac_sha1(slot.slot, padded, on_touch);
    }
    Err(match (slot.serial, last_error) {
        (Some(serial), None) => yubikey_error(format!(
            "no YubiKey with serial number {serial} is plugged in"
        )),
        (_, Some(err)) => err,
        (None, None) => yubikey_error(not_found_message()),
    })
}

fn is_otp_interface(info: &DeviceInfo) -> bool {
    info.vendor_id() == YUBICO_VENDOR_ID
        && ((info.usage_page() == OTP_USAGE_PAGE && info.usage() == OTP_USAGE)
            // Backends that cannot read usages: the OTP interface is interface 0.
            || (info.usage_page() == 0 && info.interface_number() == 0))
}

fn not_found_message() -> String {
    if cfg!(target_os = "linux") {
        "no YubiKey found; plug it in, enable its OTP interface (ykman config usb) and make \
         sure you can open its hidraw device (Yubico's udev rule)"
            .to_string()
    } else {
        "no YubiKey found; plug it in and make sure its OTP interface is enabled \
         (ykman config usb)"
            .to_string()
    }
}

fn open_error(err: &hidapi::HidError) -> crate::error::AppError {
    if cfg!(target_os = "macos") {
        yubikey_error(format!(
            "could not open the YubiKey ({err}); allow your terminal under System Settings > \
             Privacy & Security > Input Monitoring"
        ))
    } else {
        yubikey_error(format!("could not open the YubiKey: {err}"))
    }
}

/// Feature reports over hidapi. The OTP interface has no report ids, so
/// report id 0 goes in front of each buffer.
struct HidTransport(HidDevice);

impl Transport for HidTransport {
    fn read_report(&mut self) -> AppResult<[u8; REPORT_LEN]> {
        let mut buffer = [0u8; REPORT_LEN + 1];
        let read = self
            .0
            .get_feature_report(&mut buffer)
            .map_err(|err| yubikey_error(format!("reading from the key failed: {err}")))?;
        if read < REPORT_LEN + 1 {
            return Err(yubikey_error("short read from the key".to_string()));
        }
        let mut report = [0u8; REPORT_LEN];
        report.copy_from_slice(&buffer[1..]);
        Ok(report)
    }

    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> AppResult<()> {
        let mut buffer = [0u8; REPORT_LEN + 1];
        buffer[1..].copy_from_slice(report);
        self.0
            .send_feature_report(&buffer)
            .map_err(|err| yubikey_error(format!("writing to the key failed: {err}")))
    }
}
