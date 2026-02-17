use uuid::Uuid;

/// KeePassXC AES-128 cipher UUID.
pub const CIPHER_AES128: Uuid = Uuid::from_bytes([
    97, 171, 5, 161, 148, 100, 65, 195, 141, 116, 58, 86, 61, 248, 221, 53,
]);
/// KeePassXC AES-256 cipher UUID.
pub const CIPHER_AES256: Uuid = Uuid::from_bytes([
    49, 193, 242, 230, 191, 113, 67, 80, 190, 88, 5, 33, 106, 252, 90, 255,
]);
/// KeePassXC Twofish cipher UUID.
pub const CIPHER_TWOFISH: Uuid = Uuid::from_bytes([
    173, 104, 242, 159, 87, 111, 75, 185, 163, 106, 212, 122, 249, 101, 52, 108,
]);
/// KeePassXC ChaCha20 cipher UUID.
pub const CIPHER_CHACHA20: Uuid = Uuid::from_bytes([
    214, 3, 138, 43, 139, 111, 76, 181, 165, 36, 51, 154, 49, 219, 181, 154,
]);

/// KeePassXC AES-KDF UUID for KDBX3.
pub const KDF_AES_KDBX3: Uuid = Uuid::from_bytes([
    201, 217, 243, 154, 98, 138, 68, 96, 191, 116, 13, 8, 193, 138, 79, 234,
]);
/// KeePassXC AES-KDF UUID for KDBX4.
pub const KDF_AES_KDBX4: Uuid = Uuid::from_bytes([
    124, 2, 187, 130, 121, 167, 74, 192, 146, 125, 17, 74, 0, 100, 130, 56,
]);
/// KeePassXC Argon2d KDF UUID.
pub const KDF_ARGON2D: Uuid = Uuid::from_bytes([
    239, 99, 109, 223, 140, 41, 68, 75, 145, 247, 169, 164, 3, 227, 10, 12,
]);
/// KeePassXC Argon2id KDF UUID.
pub const KDF_ARGON2ID: Uuid = Uuid::from_bytes([
    158, 41, 139, 25, 86, 219, 71, 115, 178, 61, 252, 62, 198, 240, 161, 230,
]);

/// Inner stream Salsa20 IV used by KeePass2.
pub const INNER_STREAM_SALSA20_IV: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
