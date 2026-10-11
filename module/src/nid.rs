//! the names behind NIDs. modules link by NID alone, a number made from a
//! function's name and a secret of its library's, so the names come from the
//! vitasdk's database of the ones people found, written into nids.txt by
//! examples/nids.rs. a NID nobody found has no name.

use std::collections::HashMap;
use std::sync::OnceLock;

/// the functions and variables every module exports without a library
/// name, by the same NIDs.
pub const MODULE_START: u32 = 0x935C_D196;
pub const MODULE_STOP: u32 = 0x79F8_E492;
pub const MODULE_EXIT: u32 = 0x9134_82A9;
pub const MODULE_BOOTSTART: u32 = 0x5C42_4D40;
pub const MODULE_INFO: u32 = 0x6C22_24BA;
pub const PROCESS_PARAM: u32 = 0x70FB_A1E7;
pub const MODULE_SDK_VERSION: u32 = 0x936C_8A78;
pub const START_THREAD_PARAMETER: u32 = 0x1A98_22A4;
pub const STOP_THREAD_PARAMETER: u32 = 0xD208_86EB;

const NONAME: [(u32, &str); 9] = [
    (MODULE_START, "module_start"),
    (MODULE_STOP, "module_stop"),
    (MODULE_EXIT, "module_exit"),
    (MODULE_BOOTSTART, "module_bootstart"),
    (MODULE_INFO, "module_info"),
    (PROCESS_PARAM, "module_proc_param"),
    (MODULE_SDK_VERSION, "module_sdk_version"),
    (START_THREAD_PARAMETER, "sce_module_start_thread_parameter"),
    (STOP_THREAD_PARAMETER, "sce_module_stop_thread_parameter"),
];

const TABLE: &str = include_str!("../nids.txt");

struct Names {
    libraries: HashMap<u32, &'static str>,
    entries: HashMap<(u32, u32), &'static str>,
}

fn names() -> &'static Names {
    static NAMES: OnceLock<Names> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut names = Names { libraries: HashMap::new(), entries: HashMap::new() };
        let mut library = 0;
        for line in TABLE.lines().filter(|line| !line.starts_with('#')) {
            let (header, line) = match line.strip_prefix("= ") {
                Some(rest) => (true, rest),
                None => (false, line),
            };
            let Some((nid, name)) = line.split_once(' ') else {
                continue;
            };
            let Ok(nid) = u32::from_str_radix(nid, 16) else {
                continue;
            };
            if header {
                library = nid;
                names.libraries.insert(nid, name);
            } else {
                names.entries.insert((library, nid), name);
            }
        }
        names
    })
}

/// the name of the library with a NID.
pub fn library(nid: u32) -> Option<&'static str> {
    names().libraries.get(&nid).copied()
}

/// the name of a function or variable of a library, the library by its NID,
/// zero for the one modules export without a name.
pub fn name(library: u32, nid: u32) -> Option<&'static str> {
    if library == 0 {
        return NONAME.iter().find(|&&(at, _)| at == nid).map(|&(_, name)| name);
    }
    names().entries.get(&(library, nid)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_come_by_library() {
        assert_eq!(library(0x5ED8_F994), Some("SceDisplay"));
        assert_eq!(name(0x5ED8_F994, 0x5795_E898), Some("sceDisplayWaitVblankStart"));
        assert_eq!(name(0xCAE9_ACE6, 0x7595_D9AA), Some("sceKernelExitProcess"));
        assert_eq!(name(0, MODULE_START), Some("module_start"));
        assert_eq!(name(0x5ED8_F994, 0x1234_5678), None);
    }
}
