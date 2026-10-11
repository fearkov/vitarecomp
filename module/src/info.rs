//! a module's SceModuleInfo and the tables it leads to: the libraries the
//! module exports and those it imports, each function and variable by NID.
//!
//! module info's own fields are offsets into the segment that holds it, the
//! top two bits naming that segment. the pointers in the export and import
//! tables are addresses the module was linked with, which relocations
//! change wherever the module ends up.

use std::ops::Range;

use crate::read::{text_at, u16_at, u32_at, u8_at};
use crate::{bytes_at, locate, Error, Module, Segment};

/// the version of module info every Vita SDK from 0.940 on writes.
const INFO_VERSION: u8 = 6;
const INFO_SIZE: usize = 0x5C;
/// the bytes module info keeps the name in, with or without a NUL.
const NAME_SIZE: usize = 27;
/// an export with this attribute is the module's own, without a name.
const MAIN_EXPORT: u16 = 0x8000;

pub struct Info {
    pub name: String,
    pub attributes: u16,
    /// major and minor.
    pub version: (u8, u8),
    /// a hash of the module's file, which Sony's tools and vita-make-fself
    /// put in, zero in an ELF straight from vita-elf-create, and which tells
    /// builds of a module apart.
    pub fingerprint: u32,
    /// where the structure is, the segment and how far into it.
    pub segment: usize,
    pub offset: u32,
    /// module_start and module_stop, odd for Thumb.
    pub start: Option<u32>,
    pub stop: Option<u32>,
    pub tls: Option<Tls>,
    /// the tables C++ exceptions unwind with, which also list where
    /// functions start.
    pub exidx: Range<u32>,
    pub extab: Range<u32>,
    exports: Range<u32>,
    imports: Range<u32>,
}

/// the initial image of a module's thread local storage.
pub struct Tls {
    pub address: u32,
    pub file_size: u32,
    pub memory_size: u32,
}

/// a library the module exports, with the addresses of its functions and
/// variables by NID.
pub struct Export {
    /// none for the module's own, which carries module_start and the rest.
    pub name: Option<String>,
    pub nid: u32,
    pub version: u16,
    pub attributes: u16,
    pub functions: Vec<(u32, u32)>,
    pub variables: Vec<(u32, u32)>,
    pub tls: Vec<(u32, u32)>,
}

impl Export {
    pub fn is_noname(&self) -> bool {
        self.attributes & MAIN_EXPORT != 0 || (self.nid == 0 && self.name.is_none())
    }

    pub fn function(&self, nid: u32) -> Option<u32> {
        self.functions.iter().find(|&&(function_nid, _)| function_nid == nid).map(|&(_, address)| address)
    }

    pub fn variable(&self, nid: u32) -> Option<u32> {
        self.variables.iter().find(|&&(variable_nid, _)| variable_nid == nid).map(|&(_, address)| address)
    }
}

/// a library the module imports.
pub struct Import {
    pub name: Option<String>,
    pub nid: u32,
    pub version: u16,
    pub attributes: u16,
    pub functions: Vec<ImportedFunction>,
    pub variables: Vec<ImportedVariable>,
    pub tls: Vec<ImportedVariable>,
}

pub struct ImportedFunction {
    pub nid: u32,
    /// the thunk calls go through, which the system fills in: three ARM
    /// instructions and the address of a table of references.
    pub stub: u32,
    /// the places that hold the function's address, which the module takes
    /// rather than calls.
    pub references: Vec<Reference>,
}

pub struct ImportedVariable {
    pub nid: u32,
    /// the places that refer to the variable, each patched by its kind with
    /// the variable's address plus its addend.
    pub references: Vec<Reference>,
}

/// a place where a module refers to something it imports, a relocation
/// whose symbol is that thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference {
    pub kind: u8,
    pub segment: u8,
    pub offset: u32,
    pub addend: i32,
}

/// what the system starts an executable's process with, the parameters of
/// its main thread and of libc, which the executable exports as
/// module_proc_param.
pub struct ProcessParam {
    pub version: u32,
    pub sdk_version: u32,
    /// each of these is a variable of the executable, the field holding its
    /// address, none when the field is zero and the system's default goes.
    pub main_thread_name: Option<String>,
    pub main_thread_priority: Option<u32>,
    pub main_thread_stack_size: Option<u32>,
    pub main_thread_attributes: Option<u32>,
    pub process_name: Option<String>,
    pub preload_inhibit: Option<u32>,
    pub main_thread_affinity: Option<u32>,
    /// the address of SceLibcParam, which the system's libc reads.
    pub libc_param: Option<u32>,
}

/// a module info field, an offset into a segment named by its top two bits,
/// as an address, or none when it holds nothing.
fn offset_address(segments: &[Segment], value: u32) -> Option<u32> {
    if value == 0 || value == u32::MAX {
        return None;
    }
    let segment = segments.get((value >> 30) as usize)?;
    Some(segment.address.wrapping_add(value & 0x3FFF_FFFF))
}

impl Info {
    /// the module info e_entry leads to, the segment in its top two bits and
    /// the offset in the rest.
    pub fn read(segments: &[Segment], entry: u32) -> Result<Info, Error> {
        let segment = (entry >> 30) as usize;
        let offset = entry & 0x3FFF_FFFF;
        let info = segments
            .get(segment)
            .and_then(|segment| segment.bytes.get(offset as usize..offset as usize + INFO_SIZE))
            .ok_or(Error::Outside("the module info"))?;
        let word = |at: usize| u32_at(info, at).unwrap_or_default();
        let version = u8_at(info, 0x1F).unwrap_or_default();
        if version != INFO_VERSION {
            return Err(Error::InfoVersion(version));
        }
        let at = |field: usize| offset_address(segments, word(field));
        let range = |top: usize, end: usize| at(top).unwrap_or(0)..at(end).unwrap_or(0);
        let tls = (word(0x3C) != 0 || word(0x40) != 0).then(|| Tls {
            address: at(0x38).unwrap_or(0),
            file_size: word(0x3C),
            memory_size: word(0x40),
        });
        // the vitasdk writes the version as a halfword, the major on top
        let version = u16_at(info, 2).unwrap_or_default();
        Ok(Info {
            name: text_at(info, 4, NAME_SIZE).unwrap_or_default(),
            attributes: u16_at(info, 0).unwrap_or_default(),
            version: ((version >> 8) as u8, version as u8),
            fingerprint: word(0x34),
            segment,
            offset,
            start: at(0x44),
            stop: at(0x48),
            tls,
            exidx: range(0x4C, 0x50),
            extab: range(0x54, 0x58),
            exports: range(0x24, 0x28),
            imports: range(0x2C, 0x30),
        })
    }

    /// the address of the structure itself.
    pub fn address(&self, segments: &[Segment]) -> u32 {
        segments[self.segment].address.wrapping_add(self.offset)
    }
}

/// a table of count words at an address, NIDs or addresses.
fn words(segments: &[Segment], address: u32, count: usize) -> Result<Vec<u32>, Error> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let bytes = bytes_at(segments, address, count * 4).ok_or(Error::Outside("a table of NIDs or addresses"))?;
    Ok(bytes.as_chunks::<4>().0.iter().map(|&word| u32::from_le_bytes(word)).collect())
}

fn name(segments: &[Segment], address: u32) -> Option<String> {
    if address == 0 {
        return None;
    }
    let (index, offset) = locate(segments, address)?;
    text_at(&segments[index].bytes, offset as usize, 256)
}

/// the entries of a table of structures that say their own size in their
/// first byte, between two addresses.
fn entries(segments: &[Segment], range: &Range<u32>, what: &'static str) -> Result<Vec<Vec<u8>>, Error> {
    let mut found = Vec::new();
    let mut at = range.start;
    while at < range.end {
        let size = bytes_at(segments, at, 1).ok_or(Error::Outside(what))?[0] as u32;
        if size == 0 {
            return Err(Error::Malformed(what));
        }
        found.push(bytes_at(segments, at, size as usize).ok_or(Error::Outside(what))?.to_vec());
        at += size;
    }
    Ok(found)
}

pub fn exports(segments: &[Segment], info: &Info) -> Result<Vec<Export>, Error> {
    entries(segments, &info.exports, "an export")?
        .into_iter()
        .map(|entry| {
            let field = |at: usize| u32_at(&entry, at).ok_or(Error::Malformed("an export"));
            let half = |at: usize| u16_at(&entry, at).ok_or(Error::Malformed("an export"));
            let (functions, variables, tls) = (half(6)? as usize, half(8)? as usize, half(0xA)? as usize);
            let total = functions + variables + tls;
            let nids = words(segments, field(0x18)?, total)?;
            let addresses = words(segments, field(0x1C)?, total)?;
            let pairs = |range: Range<usize>| range.map(|i| (nids[i], addresses[i])).collect();
            Ok(Export {
                name: name(segments, field(0x14)?),
                nid: field(0x10)?,
                version: half(2)?,
                attributes: half(4)?,
                functions: pairs(0..functions),
                variables: pairs(functions..functions + variables),
                tls: pairs(functions + variables..total),
            })
        })
        .collect()
}

/// the libraries a module imports. vitasdk says whether the vitasdk made
/// it, which decides the order of a long reference's words where nothing
/// else does.
pub fn imports(segments: &[Segment], info: &Info, vitasdk: bool) -> Result<Vec<Import>, Error> {
    entries(segments, &info.imports, "an import")?
        .into_iter()
        .map(|entry| {
            let field = |at: usize| u32_at(&entry, at).ok_or(Error::Malformed("an import"));
            let half = |at: usize| u16_at(&entry, at).ok_or(Error::Malformed("an import"));
            let (functions, variables, tls) = (half(6)? as usize, half(8)? as usize, half(0xA)? as usize);
            // two layouts, told apart by their size: 0x34 with the SDK
            // version and TLS tables, 0x24 without
            let (nid, name_at, tables) = match entry.len() {
                0x34 => (field(0x10)?, field(0x14)?, 0x1C),
                0x24 => (field(0xC)?, field(0x10)?, 0x14),
                _ => return Err(Error::Malformed("an import of neither 0x24 nor 0x34 bytes")),
            };
            let function_nids = words(segments, field(tables)?, functions)?;
            let stubs = words(segments, field(tables + 4)?, functions)?;
            // a 0x24 import keeps its TLS variables after the others, in the
            // same tables
            let both = if entry.len() == 0x34 { variables } else { variables + tls };
            let mut variable_nids = words(segments, field(tables + 8)?, both)?;
            let mut variable_tables = words(segments, field(tables + 0xC)?, both)?;
            let (tls_nids, tls_tables) = if entry.len() == 0x34 {
                (words(segments, field(0x2C)?, tls)?, words(segments, field(0x30)?, tls)?)
            } else {
                (variable_nids.split_off(variables), variable_tables.split_off(variables))
            };
            let functions = function_nids
                .iter()
                .zip(&stubs)
                .map(|(&nid, &stub)| {
                    // the thunk's last word leads to the places that take the
                    // function's address, if any do
                    let table = bytes_at(segments, stub.wrapping_add(12), 4).and_then(|word| u32_at(word, 0));
                    let references = table.map_or(Ok(Vec::new()), |table| references(segments, table, vitasdk))?;
                    Ok(ImportedFunction { nid, stub, references })
                })
                .collect::<Result<_, Error>>()?;
            let variables = |nids: &[u32], tables: &[u32]| {
                nids.iter()
                    .zip(tables)
                    .map(|(&nid, &table)| {
                        Ok(ImportedVariable { nid, references: references(segments, table, vitasdk)? })
                    })
                    .collect::<Result<Vec<_>, Error>>()
            };
            Ok(Import {
                name: name(segments, name_at),
                nid,
                version: half(2)?,
                attributes: half(4)?,
                functions,
                variables: variables(&variable_nids, &variable_tables)?,
                tls: variables(&tls_nids, &tls_tables)?,
            })
        })
        .collect()
}

/// a reftable: a word with its size, and references in two forms, the
/// short one with a 16-bit addend, the long one with a whole word for it.
fn references(segments: &[Segment], table: u32, vitasdk: bool) -> Result<Vec<Reference>, Error> {
    if table == 0 {
        return Ok(Vec::new());
    }
    let header = bytes_at(segments, table, 4).and_then(|word| u32_at(word, 0)).ok_or(Error::Outside("a reftable"))?;
    // the size takes 24 bits since some firmware, 12 before it, when the
    // bits above were left unused
    let mut size = (header >> 4) & 0xFF_FFFF;
    if bytes_at(segments, table, size as usize).is_none() {
        size = (header >> 4) & 0xFFF;
    }
    let bytes = bytes_at(segments, table, size as usize).ok_or(Error::Outside("a reftable"))?;
    // whether an offset is a word's place in a loaded segment
    let inside = |segment: u8, offset: u32| {
        segments
            .get(segment as usize)
            .is_some_and(|segment| segment.is_load() && offset.checked_add(4).is_some_and(|end| end <= segment.size()))
    };
    let mut found = Vec::new();
    let mut at = 4;
    while at < bytes.len() {
        let word = u32_at(bytes, at).ok_or(Error::Malformed("a reftable"))?;
        let segment = ((word >> 4) & 0xF) as u8;
        let kind = (word >> 8) as u8;
        let reference = match word & 0xF {
            1 => {
                let offset = u32_at(bytes, at + 4).ok_or(Error::Malformed("a reftable"))?;
                at += 8;
                Reference { kind, segment, offset, addend: (word >> 16) as i16 as i32 }
            }
            // the vitasdk writes the offset and then the addend, and the
            // wiki and VitaLoaderRedux, which follows the system's loader,
            // have them the other way around. the reading that puts the place
            // inside its segment goes, and where both do the maker decides
            2 => {
                let (Some(first), Some(second)) = (u32_at(bytes, at + 4), u32_at(bytes, at + 8)) else {
                    return Err(Error::Malformed("a reftable"));
                };
                at += 12;
                let (offset, addend) = match (inside(segment, first), inside(segment, second)) {
                    (true, false) => (first, second),
                    (false, true) => (second, first),
                    _ if vitasdk => (first, second),
                    _ => (second, first),
                };
                Reference { kind, segment, offset, addend: addend as i32 }
            }
            _ => return Err(Error::Malformed("a reftable entry")),
        };
        if !inside(reference.segment, reference.offset) {
            return Err(Error::Malformed("a reference outside its segment"));
        }
        found.push(reference);
    }
    Ok(found)
}

impl ProcessParam {
    pub fn read(module: &Module, address: u32) -> Option<ProcessParam> {
        let field = |at: u32| module.word(address.wrapping_add(at));
        if module.bytes(address.wrapping_add(4), 4)? != b"PSP2" {
            return None;
        }
        let size = field(0)?;
        // a field past the end of an older, shorter structure says nothing
        let pointer = |at: u32| (at + 4 <= size).then(|| field(at)).flatten().filter(|&value| value != 0);
        let value = |at: u32| pointer(at).and_then(|address| module.word(address));
        let text = |at: u32| pointer(at).and_then(|address| name(&module.segments, address));
        Some(ProcessParam {
            version: field(8)?,
            sdk_version: field(0xC)?,
            main_thread_name: text(0x10),
            main_thread_priority: value(0x14),
            main_thread_stack_size: value(0x18),
            main_thread_attributes: value(0x1C),
            process_name: text(0x20),
            preload_inhibit: value(0x24),
            main_thread_affinity: value(0x28),
            libc_param: pointer(0x2C),
        })
    }
}
