use std::io::{Read, Write};

use crate::error::AppResult;

/// Read a u16 in little-endian order.
pub fn read_u16_le<R: Read>(reader: &mut R) -> AppResult<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

/// Read a u32 in little-endian order.
pub fn read_u32_le<R: Read>(reader: &mut R) -> AppResult<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Read a u64 in little-endian order.
pub fn read_u64_le<R: Read>(reader: &mut R) -> AppResult<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Write a u16 in little-endian order.
pub fn write_u16_le<W: Write>(writer: &mut W, value: u16) -> AppResult<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

/// Write a u32 in little-endian order.
pub fn write_u32_le<W: Write>(writer: &mut W, value: u32) -> AppResult<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

/// Read an exact number of bytes into a vector.
///
/// `len` usually comes from the file, so the buffer grows as data actually
/// arrives instead of being allocated up front: a bogus length in a short or
/// hostile file fails with "unexpected end of file" rather than a huge
/// allocation.
pub fn read_vec<R: Read>(reader: &mut R, len: usize) -> AppResult<Vec<u8>> {
    let mut buf = Vec::new();
    reader.take(len as u64).read_to_end(&mut buf)?;
    if buf.len() != len {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    Ok(buf)
}

/// Read an exact number of bytes into an array.
pub fn read_array<const N: usize, R: Read>(reader: &mut R) -> AppResult<[u8; N]> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_u32() {
        let mut buf = Vec::new();
        write_u32_le(&mut buf, 0xAABBCCDD).expect("write");
        let mut cursor = std::io::Cursor::new(buf);
        let value = read_u32_le(&mut cursor).expect("read");
        assert_eq!(value, 0xAABBCCDD);
    }
}
