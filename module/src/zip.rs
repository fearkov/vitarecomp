//! reading the zip archives homebrew comes in as .vpk, stored or deflated,
//! enough to list them and take a file out.

use crate::read::{u16_at, u32_at};
use crate::Error;

const END: u32 = 0x0605_4B50;
const CENTRAL: u32 = 0x0201_4B50;
const LOCAL: u32 = 0x0403_4B50;

pub struct Entry {
    pub name: String,
    method: u16,
    compressed: u32,
    size: u32,
    local: u32,
}

/// the archive's files, from its central directory.
pub fn entries(bytes: &[u8]) -> Result<Vec<Entry>, Error> {
    // the end record is the last thing, followed by a comment of up to 64K
    let floor = bytes.len().saturating_sub(0x10000 + 22);
    let end = (floor..=bytes.len().saturating_sub(22))
        .rev()
        .find(|&at| u32_at(bytes, at) == Some(END))
        .ok_or(Error::Malformed("zip, without an end of central directory"))?;
    let count = u16_at(bytes, end + 10).ok_or(Error::Truncated("the zip directory"))? as usize;
    let mut at = u32_at(bytes, end + 16).ok_or(Error::Truncated("the zip directory"))? as usize;
    if at == 0xFFFF_FFFF {
        return Err(Error::Malformed("zip64, which .vpk files never need"));
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let field = |offset: usize| u32_at(bytes, at + offset).ok_or(Error::Truncated("the zip directory"));
        let half = |offset: usize| u16_at(bytes, at + offset).ok_or(Error::Truncated("the zip directory"));
        if field(0)? != CENTRAL {
            return Err(Error::Malformed("zip directory entry"));
        }
        let name_length = half(28)? as usize;
        let skip = name_length + half(30)? as usize + half(32)? as usize;
        let name = bytes.get(at + 46..at + 46 + name_length).ok_or(Error::Truncated("the zip directory"))?;
        entries.push(Entry {
            name: String::from_utf8_lossy(name).replace('\\', "/"),
            method: half(10)?,
            compressed: field(20)?,
            size: field(24)?,
            local: field(42)?,
        });
        at += 46 + skip;
    }
    Ok(entries)
}

/// an entry's bytes.
pub fn read(bytes: &[u8], entry: &Entry) -> Result<Vec<u8>, Error> {
    let at = entry.local as usize;
    if u32_at(bytes, at) != Some(LOCAL) {
        return Err(Error::Malformed("zip local header"));
    }
    let (Some(name), Some(extra)) = (u16_at(bytes, at + 26), u16_at(bytes, at + 28)) else {
        return Err(Error::Truncated("a zip entry"));
    };
    let start = at + 30 + name as usize + extra as usize;
    let stored = bytes.get(start..start + entry.compressed as usize).ok_or(Error::Truncated("a zip entry"))?;
    let data = match entry.method {
        0 => stored.to_vec(),
        8 => miniz_oxide::inflate::decompress_to_vec(stored).map_err(|_| Error::Malformed("deflated zip entry"))?,
        _ => return Err(Error::Malformed("zip entry compressed some other way than deflate")),
    };
    if data.len() != entry.size as usize {
        return Err(Error::Malformed("zip entry of another size than its header says"));
    }
    Ok(data)
}
