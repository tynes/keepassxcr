//! KDBX format readers and writers.

// This code parses untrusted files: a malformed one must give an error, never
// a panic, so indexing and unwrap are not allowed here (tests excepted).
#![cfg_attr(
    not(test),
    deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)
)]

mod block_stream;
mod constants;
mod kdbx;
mod types;
mod variant_map;

pub use block_stream::{
    decode_hashed_blocks, decode_hmac_blocks, encode_hashed_blocks, encode_hmac_blocks,
    hmac_block_key,
};
pub use constants::{
    FILE_VERSION_3_1, FILE_VERSION_4_0, FILE_VERSION_4_1, FILE_VERSION_CRITICAL_MASK,
    HeaderFieldId, InnerHeaderFieldId, KDBX_SIGNATURE_1, KDBX_SIGNATURE_2, VariantFieldType,
};
pub use kdbx::{Credentials, CredentialsBuilder, KdbxFile, read_kdbx, write_kdbx};
pub use types::{Compression, KdbxVersion};
pub use variant_map::{VariantValue, read_variant_map, write_variant_map};
