//! param.sfo, the table of a game's title, id, version and what kind of
//! content it is, which sits in sce_sys.

use crate::read::{u16_at, u32_at};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Number(u32),
}

pub struct Sfo {
    pub entries: Vec<(String, Value)>,
}

/// how an entry's data is kept: text, in two flavors, or a number.
pub(crate) const TEXT: u16 = 0x0204;
const SPECIAL_TEXT: u16 = 0x0004;
pub(crate) const NUMBER: u16 = 0x0404;

impl Sfo {
    pub fn parse(bytes: &[u8]) -> Option<Sfo> {
        if bytes.get(..4)? != b"\0PSF" {
            return None;
        }
        let keys = u32_at(bytes, 8)? as usize;
        let data = u32_at(bytes, 0xC)? as usize;
        let count = u32_at(bytes, 0x10)? as usize;
        let entries = (0..count)
            .map(|i| {
                let at = 0x14 + i * 0x10;
                let key = crate::read::text_at(bytes, keys + u16_at(bytes, at)? as usize, 64)?;
                let length = u32_at(bytes, at + 4)? as usize;
                let start = data + u32_at(bytes, at + 0xC)? as usize;
                let value = match u16_at(bytes, at + 2)? {
                    NUMBER => Value::Number(u32_at(bytes, start)?),
                    TEXT | SPECIAL_TEXT => {
                        let raw = bytes.get(start..start + length)?;
                        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                        Value::Text(String::from_utf8_lossy(&raw[..end]).into_owned())
                    }
                    _ => return None,
                };
                Some((key, value))
            })
            .collect::<Option<_>>()?;
        Some(Sfo { entries })
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    pub fn text(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            Value::Text(text) => Some(text),
            Value::Number(_) => None,
        }
    }

    pub fn number(&self, key: &str) -> Option<u32> {
        match self.get(key)? {
            Value::Number(number) => Some(*number),
            Value::Text(_) => None,
        }
    }

    /// TITLE_ID, nine characters such as PCSE00120.
    pub fn title_id(&self) -> Option<&str> {
        self.text("TITLE_ID")
    }

    pub fn title(&self) -> Option<&str> {
        self.text("TITLE")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn entries_come_back_as_written() {
        let bytes = testing::sfo(&[
            ("APP_VER", Value::Text("01.00".into())),
            ("ATTRIBUTE2", Value::Number(0xC)),
            ("TITLE", Value::Text("Hello World".into())),
            ("TITLE_ID", Value::Text("VSDK00007".into())),
        ]);
        let sfo = Sfo::parse(&bytes).unwrap();
        assert_eq!(sfo.title_id(), Some("VSDK00007"));
        assert_eq!(sfo.title(), Some("Hello World"));
        assert_eq!(sfo.number("ATTRIBUTE2"), Some(0xC));
        assert_eq!(sfo.text("ATTRIBUTE2"), None);
    }
}
