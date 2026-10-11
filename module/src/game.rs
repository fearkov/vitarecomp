//! a game as it was dumped, the folder the console keeps it in, which app0:
//! is, or the .vpk homebrew is packed as: its eboot.bin, the modules it
//! brings along in sce_module and elsewhere, and its param.sfo.

use std::path::{Path, PathBuf};

use crate::sfo::Sfo;
use crate::{zip, Error};

pub const EBOOT: &str = "eboot.bin";
pub const SFO: &str = "sce_sys/param.sfo";

enum Source {
    Folder(PathBuf),
    Vpk { bytes: Vec<u8>, entries: Vec<zip::Entry> },
}

pub struct Game {
    source: Source,
    /// every file, by its path under app0: with forward slashes.
    pub files: Vec<String>,
    pub sfo: Option<Sfo>,
}

impl Game {
    /// the game at path, a folder holding an eboot.bin or a .vpk.
    pub fn open(path: &Path) -> Result<Game, Error> {
        let source = if path.is_dir() {
            Source::Folder(path.to_owned())
        } else {
            let bytes = std::fs::read(path)?;
            let entries = zip::entries(&bytes)?;
            Source::Vpk { bytes, entries }
        };
        let mut files = match &source {
            Source::Folder(root) => {
                let mut files = Vec::new();
                walk(root, root, &mut files)?;
                files
            }
            Source::Vpk { entries, .. } => {
                entries.iter().filter(|entry| !entry.name.ends_with('/')).map(|entry| entry.name.clone()).collect()
            }
        };
        files.sort();
        let mut game = Game { source, files, sfo: None };
        if !game.has(EBOOT) {
            return Err(Error::NotFound(EBOOT.to_owned()));
        }
        game.sfo = game.read(SFO).ok().and_then(|bytes| Sfo::parse(&bytes));
        Ok(game)
    }

    /// whether the game has a file, ignoring case like the console does.
    pub fn has(&self, path: &str) -> bool {
        self.find(path).is_some()
    }

    fn find(&self, path: &str) -> Option<&String> {
        self.files.iter().find(|file| file.eq_ignore_ascii_case(path))
    }

    pub fn read(&self, path: &str) -> Result<Vec<u8>, Error> {
        let name = self.find(path).ok_or_else(|| Error::NotFound(path.to_owned()))?;
        match &self.source {
            Source::Folder(root) => Ok(std::fs::read(root.join(name))?),
            Source::Vpk { bytes, entries } => {
                let entry =
                    entries.iter().find(|entry| &entry.name == name).ok_or_else(|| Error::NotFound(path.to_owned()))?;
                zip::read(bytes, entry)
            }
        }
    }

    pub fn title_id(&self) -> Option<&str> {
        self.sfo.as_ref()?.title_id()
    }

    pub fn title(&self) -> Option<&str> {
        self.sfo.as_ref()?.title()
    }

    /// the game's code, eboot.bin and then every other module it has, the
    /// .suprx and .prx files in sce_module and wherever else it keeps them.
    pub fn modules(&self) -> Vec<&str> {
        let eboot = self.find(EBOOT).map(String::as_str);
        let modules = self.files.iter().map(String::as_str).filter(|file| {
            let lower = file.to_ascii_lowercase();
            lower.ends_with(".suprx") || lower.ends_with(".prx")
        });
        eboot.into_iter().chain(modules).collect()
    }
}

fn walk(root: &Path, dir: &Path, files: &mut Vec<String>) -> Result<(), Error> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk(root, &path, files)?;
        } else if let Ok(relative) = path.strip_prefix(root) {
            files.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}
