//! reading the PlayStation Vita's executables and modules, a game's eboot.bin
//! and its .suprx files, whether they come as a SELF or as a plain ELF:
//! their segments, what they export and import by NID, and the relocations
//! that let the system load them anywhere; and the games they come in, a
//! folder or a .vpk with its param.sfo.

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

    #[error("{0} points outside the module")]
    Outside(&'static str),

    #[error("segment {0} cannot be decompressed")]
    Compression(usize),

    #[error("segment {0} is 0x{1:X} bytes in the SELF, its program header says 0x{2:X}")]
    SegmentSize(usize, usize, u32),

    #[error("{0} is malformed")]
    Malformed(&'static str),

    #[error("module info of version {0}, not the 6 every SDK from 0.940 on writes")]
    InfoVersion(u8),

    #[error("relocation entry of unknown format {0}")]
    UnknownRelocation(u32),

    #[error("no base given for segment {0}")]
    NoBase(u8),

    #[error("a fixed module cannot move from where it was linked")]
    Fixed,

    /// a .vpk this cannot read, said in a whole sentence.
    #[error("{0}")]
    Vpk(&'static str),

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
    /// whether a SELF carries an authority id vita-make-fself gives when it
    /// is not told one, 0x2F00000000000001, or ...02 and ...03 for -s and
    /// -ss. one made with -a looks like Sony's.
    pub fn is_homebrew(&self) -> bool {
        matches!(self, Container::SelfFile { authority, .. } if authority & !3 == 0x2F00_0000_0000_0000)
    }
}

/// a program header and the bytes the file has for it.
pub struct Segment {
    pub kind: u32,
    pub flags: u32,
    /// the address the segment was linked at, which a relocatable module
    /// need not be loaded at.
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
        // the vitasdk's own modules: its SELFs, and its ELFs, which have no
        // fingerprint until vita-make-fself puts one in
        let vitasdk = container.is_homebrew() || (container == Container::Elf && info.fingerprint == 0);
        let exports = info::exports(&segments, &info)?;
        let imports = info::imports(&segments, &info, vitasdk)?;
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

    /// the relocations whose place does not hold the instruction their kind
    /// patches, a movw under MOVW_ABS_NC, a bl or blx under THM_CALL. there
    /// are none when the relocations are read right.
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

    /// every segment, by index, as it is once each loadable one is at its
    /// base: as long as its memory size, with every relocation applied. a
    /// segment that is not loaded comes back empty. bases holds a base for
    /// each segment by index, of which only those relocations name matter,
    /// and a fixed module has to keep the addresses it was linked at.
    pub fn relocated(&self, bases: &[u32]) -> Result<Vec<Vec<u8>>, Error> {
        if self.is_fixed()
            && self.segments.iter().zip(bases).any(|(segment, &base)| segment.is_load() && base != segment.address)
        {
            return Err(Error::Fixed);
        }
        let mut images: Vec<Vec<u8>> = self
            .segments
            .iter()
            .map(|segment| {
                if !segment.is_load() {
                    return Vec::new();
                }
                let mut image = segment.bytes.clone();
                image.resize(segment.size() as usize, 0);
                image
            })
            .collect();
        let base = |segment: u8| bases.get(segment as usize).copied().ok_or(Error::NoBase(segment));
        for relocation in &self.relocations {
            let place = base(relocation.segment)?.wrapping_add(relocation.offset);
            let target = relocation.target(relocation.symbol.map_or(Ok(0), base)?);
            let image = &mut images[relocation.segment as usize];
            let at = relocation.offset as usize;
            let word = u32_at(image, at).ok_or(Error::Malformed("a relocation past its segment"))?;
            let patched = relocation::patch(relocation.kind, word, place, target)
                .ok_or(Error::Malformed("a relocation of a kind the Vita does not have"))?;
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
        .map(|program_header| {
            let start = program_header.offset as usize;
            let end = start + program_header.file_size as usize;
            let bytes = bytes.get(start..end).ok_or(Error::Truncated("a segment"))?.to_vec();
            Ok(segment(&program_header, bytes))
        })
        .collect::<Result<_, Error>>()?;
    Ok((Container::Elf, header, segments))
}

/// the ELF a SELF holds: its header and program headers from the copies the
/// SELF keeps, and each segment's bytes from where the segment info puts
/// them, inflated when they are compressed.
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
    for (index, program_header) in program_headers.iter().enumerate() {
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
        // a segment the ELF has no bytes of can still be stored as a
        // compressed empty stream, eight bytes of zlib, so whatever is stored
        // is inflated
        let inflate = compression == 2 && length != 0;
        let mut data = if inflate {
            compressed = true;
            miniz_oxide::inflate::decompress_to_vec_zlib(stored).map_err(|_| Error::Compression(index))?
        } else {
            stored.to_vec()
        };
        // vita-make-fself pads what it stores to a whole word
        let size = program_header.file_size as usize;
        if data.len() < size || (inflate && data.len() != size) {
            return Err(Error::SegmentSize(index, data.len(), program_header.file_size));
        }
        data.truncate(size);
        segments.push(segment(program_header, data));
    }
    Ok((Container::SelfFile { authority, compressed }, header, segments))
}

fn segment(header: &elf::ProgramHeader, bytes: Vec<u8>) -> Segment {
    Segment {
        kind: header.kind,
        flags: header.flags,
        address: header.address,
        memory_size: header.memory_size,
        align: header.align,
        bytes,
    }
}
