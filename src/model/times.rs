//! KDBX timestamps and the `Times` block of entries and groups.

use base64::Engine as _;
use time::OffsetDateTime;

/// Seconds between 0001-01-01T00:00:00Z and the Unix epoch.
pub const SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH: i64 = 62_135_596_800;

/// A point in time as KDBX stores it: whole seconds since
/// 0001-01-01T00:00:00 UTC.
///
/// Kept as a plain count rather than a calendar date so that any value a
/// file holds survives a save, even one outside the calendar range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The current time, truncated to whole seconds.
    pub fn now() -> Self {
        Self::from_datetime(OffsetDateTime::now_utc())
    }

    /// Convert a date and time, dropping fractions of a second.
    pub fn from_datetime(time: OffsetDateTime) -> Self {
        Self(time.unix_timestamp() + SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH)
    }

    /// Wrap a count of seconds since 0001-01-01 UTC.
    pub fn from_secs(secs: i64) -> Self {
        Self(secs)
    }

    /// Seconds since 0001-01-01 UTC.
    pub fn secs(self) -> i64 {
        self.0
    }

    /// As a date and time, if it is within the calendar range.
    pub fn to_datetime(self) -> Option<OffsetDateTime> {
        let unix = self.0.checked_sub(SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH)?;
        OffsetDateTime::from_unix_timestamp(unix).ok()
    }

    /// Parse either encoding: KDBX4's base64 of little-endian seconds, or
    /// the ISO 8601 text of KDBX3 (which some KDBX4 writers use too).
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.contains('-') || text.contains(':') {
            let parsed =
                OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).ok()?;
            return Some(Self::from_datetime(parsed));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text)
            .ok()?;
        let array: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
        Some(Self(i64::from_le_bytes(array)))
    }

    /// The KDBX4 encoding: base64 of the little-endian seconds.
    pub fn to_base64(self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0.to_le_bytes())
    }

    /// The KDBX3 encoding: ISO 8601 in UTC, such as `2024-01-01T00:00:00Z`.
    ///
    /// Falls back to the base64 form for a value outside the calendar
    /// range, which KeePassXC also reads.
    pub fn to_iso(self) -> String {
        match self.to_datetime() {
            Some(time) if (1..=9999).contains(&time.year()) => format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                time.year(),
                u8::from(time.month()),
                time.day(),
                time.hour(),
                time.minute(),
                time.second()
            ),
            _ => self.to_base64(),
        }
    }
}

/// The `Times` block of an entry or group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Times {
    /// When the item was created.
    pub creation: Timestamp,
    /// When the item's data last changed.
    pub last_modification: Timestamp,
    /// When the item was last used.
    pub last_access: Timestamp,
    /// When the item expires, if `expires` is set.
    pub expiry: Timestamp,
    /// Whether `expiry` applies.
    pub expires: bool,
    /// How many times the item was used.
    pub usage_count: u64,
    /// When the item last moved to another group.
    pub location_changed: Timestamp,
}

impl Times {
    /// Times for an item created now, like KeePassXC's defaults.
    pub fn now() -> Self {
        let now = Timestamp::now();
        Self {
            creation: now,
            last_modification: now,
            last_access: now,
            expiry: now,
            expires: false,
            usage_count: 0,
            location_changed: now,
        }
    }
}

impl Default for Times {
    fn default() -> Self {
        Self::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_encodings() {
        // 2024-01-01T00:00:00Z in both encodings.
        let secs: i64 = 1_704_067_200 + SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH;
        let iso = Timestamp::parse("2024-01-01T00:00:00Z").expect("iso");
        let b64 = Timestamp::parse(&Timestamp::from_secs(secs).to_base64()).expect("b64");
        assert_eq!(iso.secs(), secs);
        assert_eq!(b64.secs(), secs);
        assert_eq!(iso.to_iso(), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn out_of_range_values_survive() {
        for secs in [i64::MIN, -1, i64::MAX] {
            let stamp = Timestamp::from_secs(secs);
            assert_eq!(Timestamp::parse(&stamp.to_iso()), Some(stamp));
            assert_eq!(Timestamp::parse(&stamp.to_base64()), Some(stamp));
        }
    }
}
