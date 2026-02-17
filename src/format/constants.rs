/// KDBX signature 1.
pub const KDBX_SIGNATURE_1: u32 = 0x9AA2D903;
/// KDBX signature 2.
pub const KDBX_SIGNATURE_2: u32 = 0xB54BFB67;

/// File version mask for critical bits.
pub const FILE_VERSION_CRITICAL_MASK: u32 = 0xFFFF0000;
/// KDBX 3.1 version number.
pub const FILE_VERSION_3_1: u32 = 0x0003_0001;
/// KDBX 4.0 version number.
pub const FILE_VERSION_4_0: u32 = 0x0004_0000;
/// KDBX 4.1 version number.
pub const FILE_VERSION_4_1: u32 = 0x0004_0001;

/// Variant map version.
pub const VARIANT_MAP_VERSION: u16 = 0x0100;
/// Variant map critical mask.
pub const VARIANT_MAP_CRITICAL_MASK: u16 = 0xFF00;

/// Header field IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderFieldId {
    /// End of header marker.
    EndOfHeader = 0,
    /// Comment field.
    Comment = 1,
    /// Cipher UUID.
    CipherId = 2,
    /// Compression flags.
    CompressionFlags = 3,
    /// Master seed.
    MasterSeed = 4,
    /// Transform seed (KDBX3).
    TransformSeed = 5,
    /// Transform rounds (KDBX3).
    TransformRounds = 6,
    /// Encryption IV.
    EncryptionIv = 7,
    /// Protected stream key.
    ProtectedStreamKey = 8,
    /// Stream start bytes (KDBX3).
    StreamStartBytes = 9,
    /// Inner random stream ID.
    InnerRandomStreamId = 10,
    /// KDF parameters (KDBX4).
    KdfParameters = 11,
    /// Public custom data.
    PublicCustomData = 12,
}

/// Inner header field IDs for KDBX4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InnerHeaderFieldId {
    /// End of inner header.
    End = 0,
    /// Inner random stream ID.
    InnerRandomStreamId = 1,
    /// Inner random stream key.
    InnerRandomStreamKey = 2,
    /// Binary attachment.
    Binary = 3,
}

/// Variant map field types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VariantFieldType {
    /// End of map.
    End = 0,
    /// UInt32.
    UInt32 = 0x04,
    /// UInt64.
    UInt64 = 0x05,
    /// Bool.
    Bool = 0x08,
    /// Int32.
    Int32 = 0x0C,
    /// Int64.
    Int64 = 0x0D,
    /// String.
    String = 0x18,
    /// Byte array.
    ByteArray = 0x42,
}
