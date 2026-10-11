//! reading the zip archives homebrew comes in as .vpk, stored or deflated,
//! enough to list them and take a file out.

use crate::read::{u16_at, u32_at};
use crate::Error;

/// the signatures that start the end record, a central directory entry and
/// a local header.
const END: u32 = 0x0605_4B50;
const CENTRAL: u32 = 0x0201_4B50;
const LOCAL: u32 = 0x0403_4B50;

pub struct Entry {
    pub name: String,
    method: u16,
    /// its size as stored.
    compressed_size: u32,
    size: u32,
    /// where its local header starts.
    local_header: u32,
}

/// the archive's files, from its central directory.
pub fn entries(bytes: &[u8]) -> Result<Vec<Entry>, Error> {
    // the end record comes last, but for a comment of up to 64K after it
    let floor = bytes.len().saturating_sub(0x10000 + 22);
    let end = (floor..=bytes.len().saturating_sub(22))
        .rev()
        .find(|&at| u32_at(bytes, at) == Some(END))
        .ok_or(Error::Vpk("the .vpk is not a zip, it has no end of central directory"))?;
    let count = u16_at(bytes, end + 10).ok_or(Error::Truncated("the zip directory"))? as usize;
    let mut at = u32_at(bytes, end + 16).ok_or(Error::Truncated("the zip directory"))? as usize;
    if at == 0xFFFF_FFFF {
        return Err(Error::Vpk("the .vpk is a zip64, which this does not read"));
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let field = |offset: usize| u32_at(bytes, at + offset).ok_or(Error::Truncated("the zip directory"));
        let half = |offset: usize| u16_at(bytes, at + offset).ok_or(Error::Truncated("the zip directory"));
        if field(0)? != CENTRAL {
            return Err(Error::Malformed("a zip directory entry"));
        }
        let name_length = half(28)? as usize;
        let skip = name_length + half(30)? as usize + half(32)? as usize;
        let name = bytes.get(at + 46..at + 46 + name_length).ok_or(Error::Truncated("the zip directory"))?;
        entries.push(Entry {
            name: String::from_utf8_lossy(name).replace('\\', "/"),
            method: half(10)?,
            compressed_size: field(20)?,
            size: field(24)?,
            local_header: field(42)?,
        });
        at += 46 + skip;
    }
    Ok(entries)
}

/// an entry's bytes.
pub fn read(bytes: &[u8], entry: &Entry) -> Result<Vec<u8>, Error> {
    let at = entry.local_header as usize;
    if u32_at(bytes, at) != Some(LOCAL) {
        return Err(Error::Malformed("a zip local header"));
    }
    let (Some(name), Some(extra)) = (u16_at(bytes, at + 26), u16_at(bytes, at + 28)) else {
        return Err(Error::Truncated("a zip entry"));
    };
    let start = at + 30 + name as usize + extra as usize;
    let stored = bytes.get(start..start + entry.compressed_size as usize).ok_or(Error::Truncated("a zip entry"))?;
    let data = match entry.method {
        0 => stored.to_vec(),
        8 => miniz_oxide::inflate::decompress_to_vec(stored).map_err(|_| Error::Malformed("a deflated zip entry"))?,
        _ => {
            return Err(Error::Vpk(
                "a file in the .vpk is compressed some way other than deflate, which this does not read",
            ))
        }
    };
    if data.len() != entry.size as usize {
        return Err(Error::Malformed("a zip entry of another size than its header says"));
    }
    Ok(data)
}
