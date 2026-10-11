//! reading the PlayStation Vita's executables and modules, a game's eboot.bin
//! and its .suprx files, whether they come as a SELF or as a plain ELF:
//! their segments, what they export and import by NID, and the relocations
//! that let the system load them anywhere.

pub mod elf;
pub mod game;
mod info;
pub mod nid;
mod read;
pub mod relocation;
pub mod sfo;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
mod zip;

use std::path::Path;

use read::{u32_at, u64_at};

pub use elf::{ET_SCE_EXEC, ET_SCE_RELEXEC, PT_LOAD, PT_SCE_RELA};
pub use info::{Export, Import, ImportedFunction, ImportedVariable, Info, ProcessParam, Reference, Tls};
pub use relocation::Relocation;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("neither a SELF nor an ELF")]
    NotAModule,

    #[error("the SELF is encrypted, it has to be dumped decrypted")]
    Encrypted,

    #[error("an ELF of type 0x{0:04X} for machine {1}, not a Vita module")]
    NotVita(u16, u16),

    #[error("{0} runs past the end of the file")]
    Truncated(&'static str),

    #[error("segment {0} can't be decompressed")]
    Compression(usize),

    #[error("malformed {0}")]
    Malformed(&'static str),

    #[error("relocation entry of unknown format {0}")]
    UnknownRelocation(u32),

    #[error("{0} is not in the game")]
    NotFound(String),
}

/// what a module came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    /// a plain ELF, the way some dumps leave them.
    Elf,
    /// a SELF whose segments can be read, decrypted by a dump or made so by
    /// the vitasdk, with the authority id of its app info.
    SelfFile { authority: u64, compressed: bool },
}

impl Container {
    /// whether a SELF was made by the vitasdk rather than by Sony's tools.
    pub fn is_homebrew(&self) -> bool {
        matches!(self, Container::SelfFile { authority, .. } if authority & !3 == 0x2F00_0000_0000_0000)
    }
}

/// a program header and the bytes the file has for it.
pub struct Segment {
    pub kind: u32,
    pub flags: u32,
    /// where the module was linked to have it, which the system may move.
    pub address: u32,
    pub memory_size: u32,
    pub align: u32,
    pub bytes: Vec<u8>,
}

impl Segment {
    pub fn is_load(&self) -> bool {
        self.kind == PT_LOAD
    }

    pub fn is_executable(&self) -> bool {
        self.flags & elf::PF_X != 0
    }

    /// how far it reaches past address, its bytes and the zeros after them.
    pub fn size(&self) -> u32 {
        self.memory_size.max(self.bytes.len() as u32)
    }

    pub fn contains(&self, address: u32) -> bool {
        self.is_load() && address.wrapping_sub(self.address) < self.size()
    }
}

pub struct Module {
    pub container: Container,
    /// ET_SCE_EXEC or ET_SCE_RELEXEC.
    pub kind: u16,
    pub flags: u32,
    pub entry: u32,
    /// every program header, in order, since relocations name segments by
    /// their index.
    pub segments: Vec<Segment>,
    pub info: Info,
    pub exports: Vec<Export>,
    pub imports: Vec<Import>,
    pub relocations: Vec<Relocation>,
    /// how many relocation entries came in each of the ten formats.
    pub relocation_formats: [usize; 10],
}

impl Module {
    pub fn open(path: &Path) -> Result<Module, Error> {
        Module::parse(&std::fs::read(path)?)
    }

    /// a module from the bytes of its file.
    pub fn parse(bytes: &[u8]) -> Result<Module, Error> {
        let (container, header, segments) = match bytes.get(..4) {
            Some(b"\x7FELF") => unpack_elf(bytes)?,
            Some(b"SCE\0") => unpack_self(bytes)?,
            _ => return Err(Error::NotAModule),
        };
        if !header.is_arm() || !matches!(header.kind, ET_SCE_EXEC | ET_SCE_RELEXEC) {
            return Err(Error::NotVita(header.kind, header.machine));
        }
        let info = Info::read(&segments, header.entry)?;
        let exports = info::exports(&segments, &info)?;
        let imports = info::imports(&segments, &info)?;
        let mut relocation_formats = [0; 10];
        let mut relocations = Vec::new();
        for segment in segments.iter().filter(|segment| segment.kind == PT_SCE_RELA) {
            relocations.extend(relocation::decode(&segment.bytes, &segments, &mut relocation_formats)?);
        }
        Ok(Module {
            container,
            kind: header.kind,
            flags: header.flags,
            entry: header.entry,
            segments,
            info,
            exports,
            imports,
            relocations,
            relocation_formats,
        })
    }

    /// whether it has to sit where it was linked.
    pub fn is_fixed(&self) -> bool {
        self.kind == ET_SCE_EXEC
    }

    /// the loadable segment an address the module was linked with falls
    /// in, and how far into it.
    pub fn locate(&self, address: u32) -> Option<(usize, u32)> {
        locate(&self.segments, address)
    }

    /// count bytes the file has at an address the module was linked with.
    pub fn bytes(&self, address: u32, count: usize) -> Option<&[u8]> {
        bytes_at(&self.segments, address, count)
    }

    pub fn word(&self, address: u32) -> Option<u32> {
        u32_at(self.bytes(address, 4)?, 0)
    }

    /// the library of the module's own entry points and structures, which
    /// has no name.
    pub fn noname(&self) -> Option<&Export> {
        self.exports.iter().find(|export| export.is_noname())
    }

    /// where the module starts, module_start, odd for Thumb.
    pub fn start(&self) -> Option<u32> {
        self.noname().and_then(|noname| noname.function(nid::MODULE_START)).or(self.info.start)
    }

    /// the parameters of the process an executable starts, none for other
    /// modules.
    pub fn process_param(&self) -> Option<ProcessParam> {
        ProcessParam::read(self, self.noname()?.variable(nid::PROCESS_PARAM)?)
    }

    /// the relocations whose place doesn't hold the instruction they patch,
    /// a movw for a movw, a branch for a call. there are none when the
    /// relocations are read right.
    pub fn misplaced_relocations(&self) -> Vec<&Relocation> {
        self.relocations
            .iter()
            .filter(|relocation| {
                let segment = &self.segments[relocation.segment as usize];
                match u32_at(&segment.bytes, relocation.offset as usize) {
                    Some(word) => !relocation::fits(relocation.kind, word),
                    // in what the file leaves to zeros, where only data goes
                    None => relocation::patches_code(relocation.kind),
                }
            })
            .collect()
    }

    /// the loadable segments as they are once each is at its base, as long
    /// as their memory size, every relocation applied. a segment that isn't
    /// loaded gets nothing, its base doesn't matter.
    pub fn relocated(&self, bases: &[u32]) -> Result<Vec<Vec<u8>>, Error> {
        let mut images: Vec<Vec<u8>> = self
            .segments
            .iter()
            .map(|segment| {
                let mut image = segment.bytes.clone();
                if segment.is_load() {
                    image.resize(segment.size() as usize, 0);
                }
                image
            })
            .collect();
        let base = |segment: u8| {
            bases.get(segment as usize).copied().ok_or(Error::Malformed("relocation to a segment without a base"))
        };
        for relocation in &self.relocations {
            let place = base(relocation.segment)?.wrapping_add(relocation.offset);
            let target = relocation.target(relocation.symbol.map_or(Ok(0), base)?);
            let image = &mut images[relocation.segment as usize];
            let at = relocation.offset as usize;
            let word = u32_at(image, at).ok_or(Error::Malformed("relocation past its segment"))?;
            let patched = relocation::patch(relocation.kind, word, place, target)
                .ok_or(Error::Malformed("relocation of a kind the Vita doesn't have"))?;
            image[at..at + 4].copy_from_slice(&patched.to_le_bytes());
        }
        Ok(images)
    }
}

/// the loadable segment an address falls in, and how far into it.
pub(crate) fn locate(segments: &[Segment], address: u32) -> Option<(usize, u32)> {
    let index = segments.iter().position(|segment| segment.contains(address))?;
    Some((index, address - segments[index].address))
}

/// count bytes of a loadable segment's file at an address.
pub(crate) fn bytes_at(segments: &[Segment], address: u32, count: usize) -> Option<&[u8]> {
    let (index, offset) = locate(segments, address)?;
    segments[index].bytes.get(offset as usize..(offset as usize).checked_add(count)?)
}

fn unpack_elf(bytes: &[u8]) -> Result<(Container, elf::Header, Vec<Segment>), Error> {
    let header = elf::header(bytes).ok_or(Error::Truncated("the ELF header"))?;
    let program_headers =
        elf::program_headers(bytes, header.program_headers as usize, header.program_header_count as usize)
            .ok_or(Error::Truncated("the program headers"))?;
    let segments = program_headers
        .into_iter()
        .map(|ph| {
            let start = ph.offset as usize;
            let bytes = bytes.get(start..start + ph.file_size as usize).ok_or(Error::Truncated("a segment"))?.to_vec();
            Ok(segment(&ph, bytes))
        })
        .collect::<Result<_, Error>>()?;
    Ok((Container::Elf, header, segments))
}

/// the parts of a SELF's header that lead to the ELF in it: a copy of the
/// ELF header and its program headers, and where each segment's bytes
/// are, possibly compressed.
fn unpack_self(bytes: &[u8]) -> Result<(Container, elf::Header, Vec<Segment>), Error> {
    let field = |at: usize| u64_at(bytes, at).map(|value| value as usize).ok_or(Error::Truncated("the SELF header"));
    let (app_info, elf_at, program_headers_at, segment_info) = (field(0x38)?, field(0x40)?, field(0x48)?, field(0x58)?);
    let header = elf::header(bytes.get(elf_at..).unwrap_or_default()).ok_or(Error::Truncated("the ELF header"))?;
    let count = header.program_header_count as usize;
    let program_headers =
        elf::program_headers(bytes, program_headers_at, count).ok_or(Error::Truncated("the program headers"))?;
    let authority = u64_at(bytes, app_info).ok_or(Error::Truncated("the app info"))?;
    let mut compressed = false;
    let mut segments = Vec::with_capacity(count);
    for (index, ph) in program_headers.iter().enumerate() {
        let info = segment_info + index * 0x20;
        let (Some(offset), Some(length), Some(compression), Some(encryption)) =
            (u64_at(bytes, info), u64_at(bytes, info + 8), u64_at(bytes, info + 0x10), u64_at(bytes, info + 0x18))
        else {
            return Err(Error::Truncated("the segment info"));
        };
        // 1 encrypted, 2 plain
        if encryption == 1 && length != 0 {
            return Err(Error::Encrypted);
        }
        let stored = bytes.get(offset as usize..(offset + length) as usize).ok_or(Error::Truncated("a segment"))?;
        // even a segment with no bytes in the file can come as a
        // compressed empty stream
        let data = if compression == 2 && length != 0 {
            compressed = true;
            miniz_oxide::inflate::decompress_to_vec_zlib(stored).map_err(|_| Error::Compression(index))?
        } else {
            stored.to_vec()
        };
        if data.len() != ph.file_size as usize {
            return Err(Error::Compression(index));
        }
        segments.push(segment(ph, data));
    }
    Ok((Container::SelfFile { authority, compressed }, header, segments))
}

fn segment(ph: &elf::ProgramHeader, bytes: Vec<u8>) -> Segment {
    Segment { kind: ph.kind, flags: ph.flags, address: ph.address, memory_size: ph.memory_size, align: ph.align, bytes }
}
