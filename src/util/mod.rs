//! Utility helpers for the CLI and format layers.

mod byteio;
#[cfg(unix)]
pub mod forward;
#[cfg(unix)]
pub mod unix;

pub use byteio::{
    read_array, read_u16_le, read_u32_le, read_u64_le, read_vec, write_u16_le, write_u32_le,
};
