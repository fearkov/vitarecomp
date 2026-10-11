//! the reader on modules the vitasdk built, kept in tests/fixtures, and on
//! modules, SELFs and games the testing builders make up.

use std::path::Path;

use vita_module::game::Game;
use vita_module::relocation::{R_ARM_ABS32, R_ARM_THM_MOVT_ABS, R_ARM_THM_MOVW_ABS_NC};
use vita_module::sfo::Value;
use vita_module::testing::{self, LibraryExport, LibraryImport, ModuleBuilder, TEXT};
use vita_module::{nid, Container, Error, Module, Reference};

fn fixture(name: &str) -> Module {
    Module::open(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).unwrap()
}

fn words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// the immediate of a Thumb movw or movt.
fn immediate(word: u32) -> u32 {
    let (first, second) = (word & 0xFFFF, word >> 16);
    (first & 0xF) << 12 | (first >> 10 & 1) << 11 | (second >> 12 & 7) << 8 | second & 0xFF
}

#[test]
fn a_module_the_vitasdk_built_reads_whole() {
    let module = fixture("tiny.velf");
    assert_eq!(module.container, Container::Elf);
    assert!(!module.is_fixed());
    assert_eq!(module.info.name, "tiny.elf");
    assert_eq!(module.start(), Some(0x8100_0001));
    let imported: Vec<_> = module
        .imports
        .iter()
        .flat_map(|import| import.functions.iter().map(move |function| (import.nid, function.nid)))
        .collect();
    assert_eq!(imported, [(0xCAE9_ACE6, 0x7595_D9AA), (0x859A_24B1, 0x4B67_5D05)]);
    // every import goes through a thunk of three ARM instructions
    for function in module.imports.iter().flat_map(|import| &import.functions) {
        assert_eq!(module.word(function.stub), Some(testing::THUNK[0]));
    }
    assert!(module.process_param().is_some());
    assert_eq!(module.relocations.len(), 27);
    assert!(module.misplaced_relocations().is_empty());
}

#[test]
fn a_fake_self_holds_the_same_module() {
    let elf = fixture("tiny.velf");
    let wrapped = fixture("tiny.self");
    assert!(matches!(wrapped.container, Container::SelfFile { compressed: true, .. }));
    assert!(wrapped.container.is_homebrew());
    // vita-make-fself fills in the fingerprint and nothing else
    let fingerprint = elf.info.offset as usize + 0x34;
    let mut text = wrapped.segments[0].bytes.clone();
    text[fingerprint..fingerprint + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(text, elf.segments[0].bytes);
    assert_eq!(wrapped.segments[1].bytes, elf.segments[1].bytes);
    assert_eq!(wrapped.relocations, elf.relocations);
}

/// psp2rela repacks a module's relocations in the short formats retail games
/// use, and moves its data segment. both must end up the same in memory.
#[test]
fn short_relocation_formats_place_a_module_like_the_long_ones() {
    let plain = fixture("tiny.velf");
    let short = fixture("tiny.rela.velf");
    assert_eq!(plain.relocation_formats[0], plain.relocation_formats.iter().sum::<usize>());
    assert!(short.relocation_formats[2..].iter().sum::<usize>() > 0);
    assert!(plain.misplaced_relocations().is_empty() && short.misplaced_relocations().is_empty());
    let bases = [0x9000_0000, 0x9010_0000, 0, 0];
    let (plain, short) = (plain.relocated(&bases).unwrap(), short.relocated(&bases).unwrap());
    assert_eq!(plain[0], short[0]);
    assert_eq!(plain[1], short[1]);
}

#[test]
fn relocations_follow_the_segments_wherever_they_go() {
    // movw r0, #0 and movt r0, #0 in Thumb, then a word for a data address
    let code = words(&[0x0000_F240, 0x0000_F2C0]);
    let relocations = words(&[
        // format 0: the pair building data's address plus 8, the movt two
        // halfwords after the movw
        1 << 4 | (R_ARM_THM_MOVW_ABS_NC as u32) << 8 | (R_ARM_THM_MOVT_ABS as u32) << 20 | 2 << 28,
        8,
        0,
        // format 0: a pointer in data to the Thumb function at 0x10 of text
        (R_ARM_ABS32 as u32) << 8 | 1 << 16,
        0x11,
        4,
    ]);
    let builder = ModuleBuilder { code, data: vec![0; 8], relocations, ..Default::default() };
    let module = Module::parse(&builder.build()).unwrap();
    assert!(module.misplaced_relocations().is_empty());
    let images = module.relocated(&[0x9000_0000, 0x9800_0000, 0]).unwrap();
    let address = immediate(word(&images[0], 4)) << 16 | immediate(word(&images[0], 0));
    assert_eq!(address, 0x9800_0008);
    assert_eq!(word(&images[1], 4), 0x9000_0011);
}

#[test]
fn a_made_up_module_reads_back() {
    let stack_guard = [
        Reference { kind: R_ARM_ABS32, segment: 1, offset: 4, addend: 0 },
        Reference { kind: R_ARM_ABS32, segment: 1, offset: 8, addend: 0x12345 },
    ];
    let builder = ModuleBuilder {
        name: "made up".to_owned(),
        data: vec![0; 16],
        process: Some((0x60, 0x2000)),
        imports: vec![
            LibraryImport {
                name: "SceDisplayUser".to_owned(),
                nid: 0x4FAA_CD11,
                functions: vec![0x7A41_0B64],
                variables: Vec::new(),
                long: true,
            },
            LibraryImport {
                name: "SceLibKernel".to_owned(),
                nid: 0xCAE9_ACE6,
                functions: vec![0x7595_D9AA, 0xB295_EB61],
                variables: vec![(0x93B8_AA67, stack_guard.to_vec())],
                long: false,
            },
        ],
        exports: vec![LibraryExport {
            name: "MadeUp".to_owned(),
            nid: 0x1111_2222,
            functions: vec![(0x3333_4444, TEXT | 1)],
            variables: Vec::new(),
        }],
        ..Default::default()
    };
    let module = Module::parse(&builder.build()).unwrap();
    assert_eq!(module.info.name, "made up");

    let [display, kernel] = &module.imports[..] else { panic!("{} imports", module.imports.len()) };
    assert_eq!(display.name.as_deref(), Some("SceDisplayUser"));
    assert_eq!(nid::name(display.nid, display.functions[0].nid), Some("sceDisplaySetFrameBuf"));
    assert_eq!(module.word(display.functions[0].stub), Some(testing::THUNK[0]));
    let functions: Vec<_> = kernel.functions.iter().map(|function| function.nid).collect();
    assert_eq!(functions, [0x7595_D9AA, 0xB295_EB61]);
    assert_eq!(kernel.variables[0].nid, 0x93B8_AA67);
    assert_eq!(kernel.variables[0].references, stack_guard);
    assert_eq!(nid::name(kernel.nid, kernel.variables[0].nid), Some("__stack_chk_guard"));

    let export = module.exports.iter().find(|export| export.name.as_deref() == Some("MadeUp")).unwrap();
    assert_eq!(export.function(0x3333_4444), Some(TEXT | 1));
    assert_eq!(module.start(), Some(TEXT | 1));

    let param = module.process_param().unwrap();
    assert_eq!(param.main_thread_name.as_deref(), Some("main"));
    assert_eq!((param.main_thread_priority, param.main_thread_stack_size), (Some(0x60), Some(0x2000)));
    assert_eq!(param.main_thread_affinity, None);
}

#[test]
fn a_self_reads_compressed_or_not_and_never_encrypted() {
    let elf = ModuleBuilder::default().build();
    for compressed in [false, true] {
        let module = Module::parse(&testing::self_file(&elf, compressed, false)).unwrap();
        assert_eq!(module.container, Container::SelfFile { authority: 0x2F00_0000_0000_0002, compressed });
    }
    assert!(matches!(Module::parse(&testing::self_file(&elf, true, true)), Err(Error::Encrypted)));
    assert!(matches!(Module::parse(b"not a module"), Err(Error::NotAModule)));
}

/// a game's files, a homebrew's eboot.bin and a module of its own.
fn game_files() -> Vec<(&'static str, Vec<u8>)> {
    let eboot = testing::self_file(&ModuleBuilder::default().build(), true, false);
    let extra = ModuleBuilder { name: "libextra".to_owned(), ..Default::default() };
    let sfo = testing::sfo(&[
        ("CATEGORY", Value::Text("gd".to_owned())),
        ("TITLE", Value::Text("Made Up".to_owned())),
        ("TITLE_ID", Value::Text("ABCD12345".to_owned())),
    ]);
    vec![
        ("eboot.bin", eboot),
        ("sce_module/libextra.suprx", testing::self_file(&extra.build(), false, false)),
        ("sce_sys/param.sfo", sfo),
    ]
}

fn check(game: &Game) {
    assert_eq!(game.title_id(), Some("ABCD12345"));
    assert_eq!(game.title(), Some("Made Up"));
    assert_eq!(game.modules(), ["eboot.bin", "sce_module/libextra.suprx"]);
    let extra = Module::parse(&game.read("SCE_MODULE/LIBEXTRA.SUPRX").unwrap()).unwrap();
    assert_eq!(extra.info.name, "libextra");
}

#[test]
fn a_vpk_holds_a_game() {
    let files = game_files();
    let files: Vec<(&str, &[u8])> = files.iter().map(|(name, bytes)| (*name, bytes.as_slice())).collect();
    for deflate in [false, true] {
        let path = std::env::temp_dir().join(format!("vita-module-{}-{deflate}.vpk", std::process::id()));
        std::fs::write(&path, testing::vpk(&files, deflate)).unwrap();
        let game = Game::open(&path);
        std::fs::remove_file(&path).unwrap();
        check(&game.unwrap());
    }
}

#[test]
fn a_folder_holds_a_game() {
    let root = std::env::temp_dir().join(format!("vita-module-{}-game", std::process::id()));
    for (name, bytes) in game_files() {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    // a folder is read as the game asks for its files, so it stays until then
    check(&Game::open(&root).unwrap());
    std::fs::remove_dir_all(&root).unwrap();
}
