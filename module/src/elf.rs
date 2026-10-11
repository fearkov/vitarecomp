//! the ELF inside every Vita executable and module, its header and its
//! program headers. sections do not matter, the system loads segments.

use crate::read::{u16_at, u32_at};

/// an executable that has to be loaded at the addresses it was linked at,
/// what games made with older SDKs are.
pub const ET_SCE_EXEC: u16 = 0xFE00;
/// one that can go anywhere, every .suprx and the eboot.bin of newer games.
pub const ET_SCE_RELEXEC: u16 = 0xFE04;

const EM_ARM: u16 = 40;

pub const PT_LOAD: u32 = 1;
/// the relocations, in the Vita's own packed formats.
pub const PT_SCE_RELA: u32 = 0x6000_0000;
pub const PT_SCE_COMMENT: u32 = 0x6FFF_FF00;
pub const PT_SCE_VERSION: u32 = 0x6FFF_FF01;
pub const PT_ARM_EXIDX: u32 = 0x7000_0001;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub struct Header {
    pub kind: u16,
    pub machine: u16,
    pub entry: u32,
    pub flags: u32,
    pub program_headers: u32,
    pub program_header_count: u16,
}

pub struct ProgramHeader {
    pub kind: u32,
    pub offset: u32,
    pub address: u32,
    pub file_size: u32,
    pub memory_size: u32,
    pub flags: u32,
    pub align: u32,
}

/// the header of a 32-bit little-endian ELF at the start of bytes.
pub fn header(bytes: &[u8]) -> Option<Header> {
    if bytes.get(..4)? != b"\x7FELF" || bytes.get(4..6)? != [1, 1] {
        return None;
    }
    Some(Header {
        kind: u16_at(bytes, 0x10)?,
        machine: u16_at(bytes, 0x12)?,
        entry: u32_at(bytes, 0x18)?,
        program_headers: u32_at(bytes, 0x1C)?,
        flags: u32_at(bytes, 0x24)?,
        program_header_count: u16_at(bytes, 0x2C)?,
    })
}

impl Header {
    pub fn is_arm(&self) -> bool {
        self.machine == EM_ARM
    }
}

/// count program headers from at.
pub fn program_headers(bytes: &[u8], at: usize, count: usize) -> Option<Vec<ProgramHeader>> {
    (0..count)
        .map(|i| {
            let entry = bytes.get(at + i * 0x20..at + (i + 1) * 0x20)?;
            Some(ProgramHeader {
                kind: u32_at(entry, 0)?,
                offset: u32_at(entry, 4)?,
                address: u32_at(entry, 8)?,
                file_size: u32_at(entry, 0x10)?,
                memory_size: u32_at(entry, 0x14)?,
                flags: u32_at(entry, 0x18)?,
                align: u32_at(entry, 0x1C)?,
            })
        })
        .collect()
}
