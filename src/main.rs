use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use vita_module::game::Game;
use vita_module::relocation;
use vita_module::sfo::Value;
use vita_module::{nid, Container, Module, ET_SCE_EXEC, PT_LOAD, PT_SCE_RELA};

/// a line of what info shows, into a string, which can't fail.
macro_rules! say {
    ($out:expr) => {
        writeln!($out).unwrap()
    };
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).unwrap()
    };
}

const USAGE: &str = "usage: vitarecomp info <eboot.bin, .suprx, a game's folder or .vpk> [--all]

info shows what a module is made of: its segments, its relocations and the
libraries it exports and imports, by NID. --all lists every import rather
than how many each library has, and every export.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let all = args.iter().any(|arg| arg == "--all");
    let paths: Vec<&String> = args.iter().filter(|arg| !arg.starts_with("--")).collect();
    match paths.as_slice() {
        [command, path] if command.as_str() == "info" => match info(Path::new(path), all) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{path}: {error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn info(path: &Path, all: bool) -> Result<(), vita_module::Error> {
    let mut out = String::new();
    if path.is_dir() || path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("vpk")) {
        let game = Game::open(path)?;
        say!(out, "{} {}", game.title_id().unwrap_or("(no title id)"), game.title().unwrap_or("(no title)"));
        if let Some(sfo) = &game.sfo {
            for key in ["APP_VER", "CATEGORY", "CONTENT_ID", "PSP2_SYSTEM_VER", "ATTRIBUTE", "ATTRIBUTE2"] {
                match sfo.get(key) {
                    Some(Value::Text(text)) => say!(out, "  {key} {text}"),
                    Some(Value::Number(number)) => say!(out, "  {key} 0x{number:X}"),
                    None => {}
                }
            }
        }
        for module in game.modules() {
            say!(out);
            match Module::parse(&game.read(module)?) {
                Ok(parsed) => show(&mut out, module, &parsed, all),
                Err(error) => say!(out, "{module}: {error}"),
            }
        }
    } else {
        show(&mut out, &path.display().to_string(), &Module::open(path)?, all);
    }
    // a closed pipe, from head say, is not worth a panic
    let _ = std::io::stdout().write_all(out.as_bytes());
    Ok(())
}

/// how many entries there are, in words.
fn entries(count: usize) -> String {
    if count == 1 {
        "1 entry".to_owned()
    } else {
        format!("{count} entries")
    }
}

/// how many libraries there are, in words.
fn libraries(count: usize) -> String {
    if count == 1 {
        "1 library".to_owned()
    } else {
        format!("{count} libraries")
    }
}

/// how many of something there are, in words.
fn count(count: usize, what: &str) -> String {
    if count == 1 {
        format!("1 {what}")
    } else {
        format!("{count} {what}s")
    }
}

fn show(out: &mut String, name: &str, module: &Module, all: bool) {
    let container = match module.container {
        Container::Elf => "ELF".to_owned(),
        Container::SelfFile { compressed, .. } => {
            let maker = if module.container.is_homebrew() { "made by the vitasdk" } else { "decrypted" };
            format!("SELF, {maker}{}", if compressed { ", compressed" } else { "" })
        }
    };
    let kind = if module.kind == ET_SCE_EXEC { "fixed (ET_SCE_EXEC)" } else { "relocatable (ET_SCE_RELEXEC)" };
    let info = &module.info;
    say!(out, "{name}: {container}, {kind}");
    say!(
        out,
        "  module {} {}.{}, attributes 0x{:04X}, fingerprint 0x{:08X}",
        info.name,
        info.version.0,
        info.version.1,
        info.attributes,
        info.fingerprint
    );

    say!(out, "  segments");
    for (index, segment) in module.segments.iter().enumerate() {
        let kind = match segment.kind {
            PT_LOAD => "LOAD".to_owned(),
            PT_SCE_RELA => "SCE_RELA".to_owned(),
            vita_module::elf::PT_SCE_COMMENT => "SCE_COMMENT".to_owned(),
            vita_module::elf::PT_SCE_VERSION => "SCE_VERSION".to_owned(),
            vita_module::elf::PT_ARM_EXIDX => "ARM_EXIDX".to_owned(),
            other => format!("0x{other:08X}"),
        };
        let flags: String = [(4, 'R'), (2, 'W'), (1, 'X')]
            .iter()
            .map(|&(bit, letter)| if segment.flags & bit != 0 { letter } else { '-' })
            .collect();
        if segment.is_load() {
            say!(
                out,
                "    {index} {kind:<11} {flags} 0x{:08X}  0x{:X} bytes in the file, 0x{:X} in memory",
                segment.address,
                segment.bytes.len(),
                segment.memory_size
            );
        } else {
            say!(out, "    {index} {kind:<11} {flags}             0x{:X} bytes", segment.bytes.len());
        }
    }

    let code = |address: u32| format!("0x{address:08X}{}", if address & 1 != 0 { " (Thumb)" } else { "" });
    match module.start() {
        Some(start) => say!(out, "  module_start {}", code(start)),
        None => say!(out, "  no module_start"),
    }
    if let Some(stop) = info.stop {
        say!(out, "  module_stop {}", code(stop));
    }
    if !info.exidx.is_empty() {
        say!(
            out,
            "  unwind tables 0x{:08X}..0x{:08X}, {}",
            info.exidx.start,
            info.exidx.end,
            entries(((info.exidx.end - info.exidx.start) / 8) as usize)
        );
    }
    if let Some(tls) = &info.tls {
        say!(
            out,
            "  thread local storage at 0x{:08X}, 0x{:X} bytes, 0x{:X} of them set",
            tls.address,
            tls.memory_size,
            tls.file_size
        );
    }
    if let Some(param) = module.process_param() {
        let sdk = param.sdk_version;
        say!(
            out,
            "  process parameters version {}, SDK {:X}.{:03X}.{:03X}",
            param.version,
            sdk >> 24,
            (sdk >> 12) & 0xFFF,
            sdk & 0xFFF
        );
        let number = |value: Option<u32>| value.map_or("default".to_owned(), |value| format!("0x{value:X}"));
        say!(
            out,
            "    main thread {}, priority {}, stack {}, affinity {}",
            param.main_thread_name.as_deref().unwrap_or("unnamed"),
            number(param.main_thread_priority),
            number(param.main_thread_stack_size),
            number(param.main_thread_affinity)
        );
        if let Some(inhibit) = param.preload_inhibit {
            say!(out, "    modules not preloaded 0x{inhibit:08X}");
        }
        if let Some(libc) = param.libc_param {
            say!(out, "    libc parameters at 0x{libc:08X}");
        }
    }

    let entries_text = entries(module.relocation_formats.iter().sum());
    let formats: Vec<String> = module
        .relocation_formats
        .iter()
        .enumerate()
        .filter(|(_, &count)| count > 0)
        .map(|(format, count)| format!("{count} of format {format}"))
        .collect();
    say!(out, "  {} in {} ({})", count(module.relocations.len(), "relocation"), entries_text, formats.join(", "));
    let mut kinds: BTreeMap<u8, usize> = BTreeMap::new();
    for relocation in &module.relocations {
        *kinds.entry(relocation.kind).or_default() += 1;
    }
    let kinds: Vec<String> = kinds.iter().map(|(&kind, count)| format!("{} {count}", relocation::name(kind))).collect();
    if !kinds.is_empty() {
        say!(out, "    {}", kinds.join(", "));
    }
    let misplaced = module.misplaced_relocations();
    if !misplaced.is_empty() {
        say!(out, "    {} of them don't patch what their kind patches, the first:", misplaced.len());
        for relocation in misplaced.iter().take(5) {
            say!(
                out,
                "      {} in segment {} at 0x{:X}",
                relocation::name(relocation.kind),
                relocation.segment,
                relocation.offset
            );
        }
    }

    say!(out, "  exports");
    for export in &module.exports {
        let library = match &export.name {
            Some(name) => format!("{name} 0x{:08X}", export.nid),
            None => "the module's own".to_owned(),
        };
        let nid_of = if export.is_noname() { 0 } else { export.nid };
        say!(
            out,
            "    {library}, {} and {}, attributes 0x{:04X}",
            count(export.functions.len(), "function"),
            count(export.variables.len(), "variable"),
            export.attributes
        );
        if all || export.is_noname() {
            for &(nid, address) in export.functions.iter().chain(&export.variables) {
                say!(out, "      0x{nid:08X} {:<40} 0x{address:08X}", nid::name(nid_of, nid).unwrap_or("?"));
            }
        }
    }

    let functions: usize = module.imports.iter().map(|import| import.functions.len()).sum();
    let variables: usize = module.imports.iter().map(|import| import.variables.len()).sum();
    let unknown: usize = module
        .imports
        .iter()
        .map(|import| {
            let names = |nid: u32| nid::name(import.nid, nid).is_none() as usize;
            import.functions.iter().map(|f| names(f.nid)).sum::<usize>()
                + import.variables.iter().map(|v| names(v.nid)).sum::<usize>()
        })
        .sum();
    say!(
        out,
        "  imports, {}, {} and {}, {unknown} of them without a known name",
        libraries(module.imports.len()),
        count(functions, "function"),
        count(variables, "variable")
    );
    for import in &module.imports {
        let name = import.name.as_deref().or(nid::library(import.nid)).unwrap_or("?");
        say!(
            out,
            "    {name} 0x{:08X}, {} and {}, version {}, attributes 0x{:04X}",
            import.nid,
            count(import.functions.len(), "function"),
            count(import.variables.len(), "variable"),
            import.version,
            import.attributes
        );
        if !all {
            continue;
        }
        for function in &import.functions {
            let taken = match function.references.len() {
                0 => String::new(),
                times => format!(", its address taken {}", count(times, "time")),
            };
            say!(
                out,
                "      0x{:08X} {:<40} stub 0x{:08X}{taken}",
                function.nid,
                nid::name(import.nid, function.nid).unwrap_or("?"),
                function.stub
            );
        }
        for variable in &import.variables {
            say!(
                out,
                "      0x{:08X} {:<40} variable, {}",
                variable.nid,
                nid::name(import.nid, variable.nid).unwrap_or("?"),
                count(variable.references.len(), "reference")
            );
        }
    }
}
