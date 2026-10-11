//! cargo run -p vita-module --example nids -- <vita-headers>/db/360 > module/nids.txt
//!
//! writes the table of NID names nid.rs reads, from the vitasdk's database
//! of them: every library a game can import, leaving out the kernel's own.

use std::collections::BTreeMap;
use std::path::Path;

/// a library's NID and the NIDs and names of what it has.
type Library = (u32, BTreeMap<u32, String>);

fn main() {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: nids <vita-headers>/db/360");
        std::process::exit(2);
    };
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| {
            eprintln!("could not read {dir}, {error}");
            std::process::exit(1);
        })
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "yml"))
        .collect();
    files.sort();
    let mut libraries: BTreeMap<String, Library> = BTreeMap::new();
    for path in &files {
        read(path, &mut libraries);
    }
    println!("# the names of the NIDs a game can import, by library, from the database in vita-headers'");
    println!("# db/360 (MIT, Copyright 2017 vitasdk, see NOTICE), written by examples/nids.rs");
    for (name, (nid, entries)) in &libraries {
        println!("= {nid:08X} {name}");
        for (nid, name) in entries {
            println!("{nid:08X} {name}");
        }
    }
}

/// adds the user libraries in one file of the database to libraries. the
/// files are YAML, but regular enough to read by indentation: modules, their
/// libraries, and in each a kernel flag, a NID and lists of functions and
/// variables.
fn read(path: &Path, libraries: &mut BTreeMap<String, Library>) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut library: Option<(String, bool, u32)> = None;
    let mut entries = BTreeMap::new();
    let mut in_list = false;
    let mut flush = |library: &mut Option<(String, bool, u32)>, entries: &mut BTreeMap<u32, String>| {
        if let Some((name, kernel, nid)) = library.take() {
            if !kernel {
                let (_, all) = libraries.entry(name).or_insert((nid, BTreeMap::new()));
                all.append(entries);
            }
        }
        entries.clear();
    };
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        match indent {
            // a library under a module's libraries
            6 => {
                flush(&mut library, &mut entries);
                library = Some((key.to_owned(), false, 0));
                in_list = false;
            }
            8 => {
                in_list = matches!(key, "functions" | "variables");
                if let Some((_, kernel, nid)) = library.as_mut() {
                    match key {
                        "kernel" => *kernel = value == "true",
                        "nid" => *nid = number(value),
                        _ => {}
                    }
                }
            }
            10 if in_list => {
                entries.insert(number(value), key.to_owned());
            }
            _ if indent < 6 => {
                flush(&mut library, &mut entries);
                in_list = false;
            }
            _ => {}
        }
    }
    flush(&mut library, &mut entries);
}

fn number(text: &str) -> u32 {
    u32::from_str_radix(text.trim_start_matches("0x"), 16).unwrap_or_else(|_| panic!("not a NID: {text}"))
}
