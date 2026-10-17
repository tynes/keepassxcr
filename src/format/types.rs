use crate::format::constants::{FILE_VERSION_3_1, FILE_VERSION_4_0, FILE_VERSION_4_1};

/// Supported KDBX versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxVersion {
    /// KDBX 3.1.
    V3_1,
    /// KDBX 4.0.
    V4_0,
    /// KDBX 4.1, which adds group tags, previous parent groups, entries
    /// excluded from reports and named custom icons.
    V4_1,
}

impl KdbxVersion {
    /// Parse a version number.
    pub fn from_u32(version: u32) -> Option<Self> {
        match version {
            FILE_VERSION_3_1 => Some(Self::V3_1),
            FILE_VERSION_4_0 => Some(Self::V4_0),
            FILE_VERSION_4_1 => Some(Self::V4_1),
            _ => None,
        }
    }

    /// Return the version number written in the file header.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::V3_1 => FILE_VERSION_3_1,
            Self::V4_0 => FILE_VERSION_4_0,
            Self::V4_1 => FILE_VERSION_4_1,
        }
    }

    /// True for KDBX4 formats.
    pub fn is_kdbx4(self) -> bool {
        matches!(self, Self::V4_0 | Self::V4_1)
    }
}

/// Compression settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression.
    None,
    /// Gzip compression.
    Gzip,
}

impl Compression {
    /// Convert from raw flag.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Gzip),
            _ => None,
        }
    }

    /// Convert to raw flag.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Gzip => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdbx_version_roundtrip() {
        let v = KdbxVersion::from_u32(FILE_VERSION_3_1).expect("version");
        assert_eq!(v, KdbxVersion::V3_1);
        assert_eq!(v.as_u32(), FILE_VERSION_3_1);
        for raw in [FILE_VERSION_4_0, FILE_VERSION_4_1] {
            let v = KdbxVersion::from_u32(raw).expect("version");
            assert!(v.is_kdbx4());
            assert_eq!(v.as_u32(), raw);
        }
    }

    #[test]
    fn compression_roundtrip() {
        assert_eq!(Compression::from_u32(1), Some(Compression::Gzip));
        assert_eq!(Compression::Gzip.as_u32(), 1);
    }
}
