//! modules, SELFs, param.sfo files and .vpk archives made up for tests, laid
//! out the way the vitasdk lays them out, so that whatever reads them can be
//! tested with no game at hand.

use crate::elf::{PF_R, PF_W, PF_X, PT_LOAD, PT_SCE_RELA};
use crate::nid;
use crate::sfo::{self, Value};
use crate::ET_SCE_RELEXEC;

/// where the vitasdk links the text segment of everything.
pub const TEXT: u32 = 0x8100_0000;
/// where modules built here link their data, past any text they have.
pub const DATA: u32 = 0x8101_0000;

/// what a thunk holds before the system fills it in, in vitasdk modules:
/// mvn r0, #0 then bx lr, and a nop.
pub const THUNK: [u32; 3] = [0xE3E0_0000, 0xE12F_FF1E, 0xE1A0_0000];

pub struct LibraryExport {
    pub name: String,
    pub nid: u32,
    pub functions: Vec<(u32, u32)>,
    pub variables: Vec<(u32, u32)>,
}

pub struct LibraryImport {
    pub name: String,
    pub nid: u32,
    pub functions: Vec<u32>,
    /// each variable's NID and the references to it in its reftable, which
    /// the module takes in the long form when an addend needs a whole word.
    pub variables: Vec<(u32, Vec<crate::Reference>)>,
    /// the 0x34 byte layout with TLS tables rather than the 0x24 one.
    pub long: bool,
}

/// a module to build, its code and data where TEXT and DATA say.
pub struct ModuleBuilder {
    pub name: String,
    pub kind: u16,
    pub code: Vec<u8>,
    pub data: Vec<u8>,
    pub bss: u32,
    /// module_start's address, odd for Thumb.
    pub start: Option<u32>,
    pub exports: Vec<LibraryExport>,
    pub imports: Vec<LibraryImport>,
    /// a PT_SCE_RELA table as it is in the file, none when empty.
    pub relocations: Vec<u8>,
    /// whether it is an executable and carries SceProcessParam, with these
    /// main thread priority and stack size variables.
    pub process: Option<(u32, u32)>,
}

impl Default for ModuleBuilder {
    fn default() -> Self {
        ModuleBuilder {
            name: "test".to_owned(),
            kind: ET_SCE_RELEXEC,
            code: vec![0x70, 0x47],
            data: Vec::new(),
            bss: 0,
            start: Some(TEXT | 1),
            exports: Vec::new(),
            imports: Vec::new(),
            relocations: Vec::new(),
            process: None,
        }
    }
}

/// the text segment as it grows, and where things in it are.
struct Text {
    bytes: Vec<u8>,
}

impl Text {
    fn here(&self) -> u32 {
        TEXT + self.bytes.len() as u32
    }

    fn align(&mut self, to: usize) {
        self.bytes.resize(self.bytes.len().next_multiple_of(to), 0);
    }

    fn word(&mut self, value: u32) -> u32 {
        let at = self.here();
        self.bytes.extend_from_slice(&value.to_le_bytes());
        at
    }

    fn words(&mut self, values: &[u32]) -> u32 {
        let at = self.here();
        for &value in values {
            self.word(value);
        }
        at
    }

    fn text(&mut self, text: &str) -> u32 {
        let at = self.here();
        self.bytes.extend_from_slice(text.as_bytes());
        self.bytes.push(0);
        self.align(4);
        at
    }
}

impl ModuleBuilder {
    /// the module as an ELF file, the way vita-elf-create writes one.
    pub fn build(&self) -> Vec<u8> {
        let mut text = Text { bytes: self.code.clone() };
        text.align(16);

        // the tables first, so the structures can point at them
        let process = self.process.map(|(priority, stack)| {
            let priority = text.word(priority);
            let stack = text.word(stack);
            let name = text.text("main");
            let param = text.words(&[0x34, u32::from_le_bytes(*b"PSP2"), 6, 0x0357_0011]);
            text.words(&[name, priority, stack, 0, 0, 0, 0, 0, 0]);
            param
        });
        let info_at = text.here();
        text.bytes.resize(text.bytes.len() + 0x5C, 0);

        let mut noname = vec![(nid::MODULE_INFO, info_at)];
        if let Some(param) = process {
            noname.push((nid::PROCESS_PARAM, param));
        }
        let noname_functions: Vec<_> = self.start.map(|start| (nid::MODULE_START, start)).into_iter().collect();
        let mut libraries = vec![(None, 0, 0x8000u16, noname_functions, noname)];
        for export in &self.exports {
            libraries.push((
                Some(export.name.as_str()),
                export.nid,
                0x0001,
                export.functions.clone(),
                export.variables.clone(),
            ));
        }
        let mut export_entries = Vec::new();
        for (name, nid, attributes, functions, variables) in &libraries {
            let all: Vec<_> = functions.iter().chain(variables).copied().collect();
            let nids = text.words(&all.iter().map(|&(nid, _)| nid).collect::<Vec<_>>());
            let addresses = text.words(&all.iter().map(|&(_, address)| address).collect::<Vec<_>>());
            let name = name.map_or(0, |name| text.text(name));
            export_entries.push((*nid, *attributes, functions.len(), variables.len(), name, nids, addresses));
        }
        let exports_top = text.here();
        for (nid, attributes, functions, variables, name, nids, addresses) in export_entries {
            text.bytes.extend_from_slice(&[0x20, 0]);
            text.bytes.extend_from_slice(&1u16.to_le_bytes());
            text.bytes.extend_from_slice(&attributes.to_le_bytes());
            text.bytes.extend_from_slice(&(functions as u16).to_le_bytes());
            text.bytes.extend_from_slice(&(variables as u16).to_le_bytes());
            text.bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            text.words(&[nid, name, nids, addresses]);
        }
        let exports_end = text.here();

        let mut import_entries = Vec::new();
        for import in &self.imports {
            let stubs: Vec<u32> = import
                .functions
                .iter()
                .map(|_| {
                    let at = text.words(&THUNK);
                    text.word(0);
                    at
                })
                .collect();
            let function_nids = text.words(&import.functions);
            let stub_table = text.words(&stubs);
            let tables: Vec<u32> =
                import.variables.iter().map(|(_, references)| reftable(&mut text, references)).collect();
            let variable_nids = text.words(&import.variables.iter().map(|&(nid, _)| nid).collect::<Vec<_>>());
            let variable_table = text.words(&tables);
            let name = text.text(&import.name);
            import_entries.push((import, name, function_nids, stub_table, variable_nids, variable_table));
        }
        let imports_top = text.here();
        for (import, name, function_nids, stub_table, variable_nids, variable_table) in import_entries {
            let size: u8 = if import.long { 0x34 } else { 0x24 };
            text.bytes.extend_from_slice(&[size, 0]);
            text.bytes.extend_from_slice(&1u16.to_le_bytes());
            text.bytes.extend_from_slice(&0x0008u16.to_le_bytes());
            text.bytes.extend_from_slice(&(import.functions.len() as u16).to_le_bytes());
            text.bytes.extend_from_slice(&(import.variables.len() as u16).to_le_bytes());
            text.bytes.extend_from_slice(&0u16.to_le_bytes());
            if import.long {
                text.words(&[0, import.nid, name, 0, function_nids, stub_table, variable_nids, variable_table, 0, 0]);
            } else {
                text.words(&[import.nid, name, function_nids, stub_table, variable_nids, variable_table]);
            }
        }
        let imports_end = text.here();

        // module info, its fields offsets into the text segment
        let offset = |address: u32| address - TEXT;
        let mut info = Vec::with_capacity(0x5C);
        info.extend_from_slice(&0u16.to_le_bytes());
        info.extend_from_slice(&[1, 1]);
        let mut name = [0u8; 27];
        name[..self.name.len().min(26)].copy_from_slice(&self.name.as_bytes()[..self.name.len().min(26)]);
        info.extend_from_slice(&name);
        info.push(6);
        for value in [
            0,
            offset(exports_top),
            offset(exports_end),
            offset(imports_top),
            offset(imports_end),
            0x1234_5678,
            0,
            0,
            0,
            self.start.map_or(u32::MAX, offset),
            u32::MAX,
            0,
            0,
            0,
            0,
        ] {
            info.extend_from_slice(&u32::to_le_bytes(value));
        }
        text.bytes[(info_at - TEXT) as usize..][..0x5C].copy_from_slice(&info);

        elf(
            self.kind,
            info_at - TEXT,
            &[
                (PT_LOAD, PF_R | PF_X, TEXT, text.bytes, 0),
                (PT_LOAD, PF_R | PF_W, DATA, self.data.clone(), self.bss),
                (PT_SCE_RELA, 0, 0, self.relocations.clone(), 0),
            ],
        )
    }
}

/// a reftable with the references given, at the text's end.
fn reftable(text: &mut Text, references: &[crate::Reference]) -> u32 {
    let mut entries = Vec::new();
    for reference in references {
        let first = |form: u32| form | (reference.segment as u32) << 4 | (reference.kind as u32) << 8;
        if reference.addend as i16 as i32 == reference.addend {
            entries.push(first(1) | (reference.addend as u16 as u32) << 16);
            entries.push(reference.offset);
        } else {
            entries.extend([first(2), reference.offset, reference.addend as u32]);
        }
    }
    let at = text.word((4 + entries.len() as u32 * 4) << 4);
    text.words(&entries);
    at
}

/// an ELF of the Vita's kind with segments of (type, flags, address, bytes,
/// zeros after them), the empty ones left out but for the first two, whose
/// index relocations name.
pub fn elf(kind: u16, entry: u32, segments: &[(u32, u32, u32, Vec<u8>, u32)]) -> Vec<u8> {
    let segments: Vec<_> = segments
        .iter()
        .enumerate()
        .filter(|(index, segment)| *index < 2 || !segment.3.is_empty())
        .map(|(_, s)| s)
        .collect();
    let mut out = vec![0u8; 0x34 + 0x20 * segments.len()];
    out[..4].copy_from_slice(b"\x7FELF");
    out[4..7].copy_from_slice(&[1, 1, 1]);
    out[0x10..0x12].copy_from_slice(&kind.to_le_bytes());
    out[0x12..0x14].copy_from_slice(&40u16.to_le_bytes());
    out[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    out[0x18..0x1C].copy_from_slice(&entry.to_le_bytes());
    out[0x1C..0x20].copy_from_slice(&0x34u32.to_le_bytes());
    out[0x24..0x28].copy_from_slice(&0x0500_0400u32.to_le_bytes());
    out[0x28..0x2A].copy_from_slice(&0x34u16.to_le_bytes());
    out[0x2A..0x2C].copy_from_slice(&0x20u16.to_le_bytes());
    out[0x2C..0x2E].copy_from_slice(&(segments.len() as u16).to_le_bytes());
    out[0x2E..0x30].copy_from_slice(&0x28u16.to_le_bytes());
    for (index, (kind, flags, address, bytes, zeros)) in segments.iter().enumerate() {
        out.resize(out.len().next_multiple_of(16), 0);
        let offset = out.len() as u32;
        out.extend_from_slice(bytes);
        let header = 0x34 + index * 0x20;
        let memory = if *kind == PT_LOAD { bytes.len() as u32 + zeros } else { 0 };
        let align = if *kind == PT_LOAD { 0x1000 } else { 0x10 };
        for (at, value) in
            [kind, &offset, address, address, &(bytes.len() as u32), &memory, flags, &align].into_iter().enumerate()
        {
            out[header + at * 4..header + at * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    out
}

/// an ELF wrapped in a SELF the way vita-make-fself does, its segments
/// compressed or not, or marked encrypted for tests of what happens then.
pub fn self_file(elf: &[u8], compress: bool, encrypted: bool) -> Vec<u8> {
    let header = crate::elf::header(elf).expect("an ELF");
    let count = header.program_header_count as usize;
    let headers = crate::elf::program_headers(elf, header.program_headers as usize, count).expect("program headers");
    let segment_info = 0xE0 + 0x20 * count;
    let header_length = (segment_info + 0x20 * count + 0x10).next_multiple_of(0x100);
    let mut out = vec![0u8; header_length];
    let mut field = |at: usize, value: u64| out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    field(0x30, 4);
    field(0x38, 0x80);
    field(0x40, 0xA0);
    field(0x48, 0xE0);
    field(0x58, segment_info as u64);
    field(0x60, (segment_info + 0x20 * count) as u64);
    field(0x10, header_length as u64);
    field(0x18, elf.len() as u64);
    field(0x80, 0x2F00_0000_0000_0002);
    out[..4].copy_from_slice(b"SCE\0");
    out[4..8].copy_from_slice(&3u32.to_le_bytes());
    out[8..10].copy_from_slice(&0xC0u16.to_le_bytes());
    out[0xA..0xC].copy_from_slice(&1u16.to_le_bytes());
    out[0x8C..0x90].copy_from_slice(&8u32.to_le_bytes());
    out[0xA0..0xD4].copy_from_slice(&elf[..0x34]);
    out[0xE0..0xE0 + 0x20 * count].copy_from_slice(&elf[header.program_headers as usize..][..0x20 * count]);
    for (index, ph) in headers.iter().enumerate() {
        let bytes = &elf[ph.offset as usize..(ph.offset + ph.file_size) as usize];
        let stored = if compress { miniz_oxide::deflate::compress_to_vec_zlib(bytes, 6) } else { bytes.to_vec() };
        let offset = out.len() as u64;
        out.extend_from_slice(&stored);
        let info = segment_info + index * 0x20;
        let values = [offset, stored.len() as u64, if compress { 2 } else { 1 }, if encrypted { 1 } else { 2 }];
        for (at, value) in values.into_iter().enumerate() {
            out[info + at * 8..info + at * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    let size = out.len() as u64;
    out[0x20..0x28].copy_from_slice(&size.to_le_bytes());
    out
}

/// a param.sfo with the entries given, laid out as vita-mksfoex does.
pub fn sfo(entries: &[(&str, Value)]) -> Vec<u8> {
    let mut keys = Vec::new();
    let mut data = Vec::new();
    let mut table = Vec::new();
    for (key, value) in entries {
        let key_at = keys.len() as u16;
        keys.extend_from_slice(key.as_bytes());
        keys.push(0);
        let data_at = data.len() as u32;
        let (format, bytes) = match value {
            Value::Text(text) => (sfo::TEXT, [text.as_bytes(), &[0u8][..]].concat()),
            Value::Number(number) => (sfo::NUMBER, number.to_le_bytes().to_vec()),
        };
        let room = bytes.len().next_multiple_of(4);
        table.extend_from_slice(&key_at.to_le_bytes());
        table.extend_from_slice(&format.to_le_bytes());
        table.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        table.extend_from_slice(&(room as u32).to_le_bytes());
        table.extend_from_slice(&data_at.to_le_bytes());
        data.extend_from_slice(&bytes);
        data.resize(data.len().next_multiple_of(4), 0);
    }
    keys.resize(keys.len().next_multiple_of(4), 0);
    let keys_at = 0x14 + table.len() as u32;
    let data_at = keys_at + keys.len() as u32;
    let mut out = b"\0PSF".to_vec();
    out.extend_from_slice(&0x101u32.to_le_bytes());
    out.extend_from_slice(&keys_at.to_le_bytes());
    out.extend_from_slice(&data_at.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    out.extend(table);
    out.extend(keys);
    out.extend(data);
    out
}

/// a .vpk with the files given, each deflated or stored.
pub fn vpk(files: &[(&str, &[u8])], deflate: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for (name, bytes) in files {
        let stored = if deflate { miniz_oxide::deflate::compress_to_vec(bytes, 6) } else { bytes.to_vec() };
        let method: u16 = if deflate { 8 } else { 0 };
        let local = out.len() as u32;
        let sizes = [0u32, stored.len() as u32, bytes.len() as u32];
        out.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0]);
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        sizes.iter().for_each(|size| out.extend_from_slice(&size.to_le_bytes()));
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&stored);
        directory.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        directory.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
        directory.extend_from_slice(&method.to_le_bytes());
        directory.extend_from_slice(&[0; 4]);
        sizes.iter().for_each(|size| directory.extend_from_slice(&size.to_le_bytes()));
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&[0; 12]);
        directory.extend_from_slice(&local.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let at = out.len() as u32;
    let size = directory.len() as u32;
    out.extend(directory);
    out.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&at.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}
