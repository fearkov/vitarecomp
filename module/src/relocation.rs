//! the relocations in a module's PT_SCE_RELA segments, every place where the
//! module holds an address of its own, which has to change when the system
//! loads a segment somewhere other than where it was linked.
//!
//! ten formats pack them. 0 and 1 say everything, the others say only what
//! changed from the entry before, a step from its offset and maybe a new
//! symbol and addend, which is how retail modules keep them short.
//! 3, 4 and 5 relocate the pairs of movw and movt that build an address,
//! and 6 to 9 the words that hold one, whose segment and addend come from
//! the word itself, the address it was linked with.

use crate::read::u32_at;
use crate::{Error, Segment};

pub const R_ARM_NONE: u8 = 0;
pub const R_ARM_ABS32: u8 = 2;
pub const R_ARM_REL32: u8 = 3;
pub const R_ARM_THM_CALL: u8 = 10;
pub const R_ARM_CALL: u8 = 28;
pub const R_ARM_JUMP24: u8 = 29;
/// the same as ABS32, on the Vita.
pub const R_ARM_TARGET1: u8 = 38;
pub const R_ARM_V4BX: u8 = 40;
/// the same as REL32, on the Vita.
pub const R_ARM_TARGET2: u8 = 41;
pub const R_ARM_PREL31: u8 = 42;
pub const R_ARM_MOVW_ABS_NC: u8 = 43;
pub const R_ARM_MOVT_ABS: u8 = 44;
pub const R_ARM_THM_MOVW_ABS_NC: u8 = 47;
pub const R_ARM_THM_MOVT_ABS: u8 = 48;
/// ignored.
pub const R_ARM_RBASE: u8 = 255;

/// the segment number that means no segment, an absolute symbol.
const ABSOLUTE: u32 = 0xF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Relocation {
    /// the place, a segment and how far into it.
    pub segment: u8,
    pub offset: u32,
    pub kind: u8,
    /// the segment whose address the value is relative to, none for an
    /// absolute one.
    pub symbol: Option<u8>,
    pub addend: u32,
}

impl Relocation {
    /// S + A, the symbol's address once its segment is at base plus the
    /// addend, which is what patch() takes. a branch goes 4 bytes past it in
    /// Thumb and 8 in ARM, as its addend takes away the pc's lead.
    pub fn target(&self, base: u32) -> u32 {
        base.wrapping_add(self.addend)
    }
}

pub fn name(kind: u8) -> &'static str {
    match kind {
        R_ARM_NONE => "NONE",
        R_ARM_ABS32 => "ABS32",
        R_ARM_REL32 => "REL32",
        R_ARM_THM_CALL => "THM_CALL",
        R_ARM_CALL => "CALL",
        R_ARM_JUMP24 => "JUMP24",
        R_ARM_TARGET1 => "TARGET1",
        R_ARM_V4BX => "V4BX",
        R_ARM_TARGET2 => "TARGET2",
        R_ARM_PREL31 => "PREL31",
        R_ARM_MOVW_ABS_NC => "MOVW_ABS_NC",
        R_ARM_MOVT_ABS => "MOVT_ABS",
        R_ARM_THM_MOVW_ABS_NC => "THM_MOVW_ABS_NC",
        R_ARM_THM_MOVT_ABS => "THM_MOVT_ABS",
        R_ARM_RBASE => "RBASE",
        _ => "unknown",
    }
}

/// what the entries before have set, which the short formats go on from.
#[derive(Default)]
struct State {
    segment: u8,
    offset: u32,
    symbol: Option<u8>,
    addend: u32,
    kind: u8,
    /// the kind of the second place of a pair, the movt of a movw.
    second: u8,
}

fn bits(word: u32, low: u32, count: u32) -> u32 {
    (word >> low) & ((1 << count) - 1)
}

fn symbol(segment: u32) -> Option<u8> {
    (segment != ABSOLUTE).then_some(segment as u8)
}

/// the relocations in a PT_SCE_RELA segment's bytes, counting the entries of
/// each format.
pub fn decode(table: &[u8], segments: &[Segment], formats: &mut [usize; 10]) -> Result<Vec<Relocation>, Error> {
    let mut found = Vec::new();
    let mut state = State::default();
    let mut at = 0;
    while at < table.len() {
        let word = |index: usize| u32_at(table, at + index * 4).ok_or(Error::Truncated("a relocation"));
        let first = word(0)?;
        let format = first & 0xF;
        let emit = |found: &mut Vec<Relocation>, state: &State, kind: u8, offset: u32| {
            if !matches!(kind, R_ARM_NONE | R_ARM_V4BX | R_ARM_RBASE) {
                found.push(Relocation {
                    segment: state.segment,
                    offset,
                    kind,
                    symbol: state.symbol,
                    addend: state.addend,
                });
            }
        };
        let size = match format {
            0 => {
                state.symbol = symbol(bits(first, 4, 4));
                state.kind = bits(first, 8, 8) as u8;
                state.segment = bits(first, 16, 4) as u8;
                state.second = bits(first, 20, 8) as u8;
                state.addend = word(1)?;
                state.offset = word(2)?;
                emit(&mut found, &state, state.kind, state.offset);
                // the second place counts in halfwords
                emit(&mut found, &state, state.second, state.offset + bits(first, 28, 4) * 2);
                12
            }
            1 => {
                let second = word(1)?;
                state.symbol = symbol(bits(first, 4, 4));
                state.kind = bits(first, 8, 8) as u8;
                state.segment = bits(first, 16, 4) as u8;
                state.offset = bits(first, 20, 12) | bits(second, 0, 10) << 12;
                state.addend = bits(second, 10, 22);
                state.second = R_ARM_NONE;
                emit(&mut found, &state, state.kind, state.offset);
                8
            }
            2 => {
                state.symbol = symbol(bits(first, 4, 4));
                state.kind = bits(first, 8, 8) as u8;
                state.offset = state.offset.wrapping_add(bits(first, 16, 16));
                state.addend = word(1)?;
                state.second = R_ARM_NONE;
                emit(&mut found, &state, state.kind, state.offset);
                8
            }
            3 => {
                let thumb = bits(first, 8, 1) != 0;
                state.symbol = symbol(bits(first, 4, 4));
                state.offset = state.offset.wrapping_add(bits(first, 9, 18));
                state.addend = bits(word(1)?, 0, 22);
                (state.kind, state.second) = if thumb {
                    (R_ARM_THM_MOVW_ABS_NC, R_ARM_THM_MOVT_ABS)
                } else {
                    (R_ARM_MOVW_ABS_NC, R_ARM_MOVT_ABS)
                };
                pair(&mut found, &state, bits(first, 27, 5), emit);
                8
            }
            4 => {
                state.offset = state.offset.wrapping_add(bits(first, 4, 23));
                pair(&mut found, &state, bits(first, 27, 5), emit);
                4
            }
            5 => {
                state.offset = state.offset.wrapping_add(bits(first, 4, 9));
                pair(&mut found, &state, bits(first, 13, 5), emit);
                state.offset = state.offset.wrapping_add(bits(first, 18, 9));
                pair(&mut found, &state, bits(first, 27, 5), emit);
                4
            }
            6 => {
                state.offset = state.offset.wrapping_add(bits(first, 4, 28));
                stored(&mut found, &mut state, segments)?;
                4
            }
            7..=9 => {
                // steps in words, as many as the 28 bits hold, the first
                // always and the others until only zeros are left
                let width = match format {
                    7 => 7,
                    8 => 4,
                    _ => 2,
                };
                let mut steps = bits(first, 4, 28);
                loop {
                    state.offset = state.offset.wrapping_add(bits(steps, 0, width) * 4);
                    stored(&mut found, &mut state, segments)?;
                    steps >>= width;
                    if steps == 0 {
                        break;
                    }
                }
                4
            }
            other => return Err(Error::UnknownRelocation(other)),
        };
        formats[format as usize] += 1;
        at += size;
    }
    // a damaged table could name segments the module does not load, or
    // places outside them
    let loaded = |segment: u8| segments.get(segment as usize).is_some_and(Segment::is_load);
    for relocation in &mut found {
        if !loaded(relocation.segment) || !relocation.symbol.is_none_or(loaded) {
            return Err(Error::Malformed("a relocation naming a segment the module does not load"));
        }
        let segment = &segments[relocation.segment as usize];
        if relocation.offset.checked_add(4).is_none_or(|end| end > segment.size()) {
            return Err(Error::Malformed("a relocation outside its segment"));
        }
        if relocation.kind == R_ARM_PREL31 {
            // the vitasdk takes a PREL31's 31 bits without their sign, so its
            // addend can be 2^31 off; the offset the place holds, from the
            // addresses the module was linked at, sets it right
            let place = segment.address.wrapping_add(relocation.offset);
            let symbol = relocation.symbol.map_or(0, |symbol| segments[symbol as usize].address);
            let field = symbol.wrapping_add(relocation.addend).wrapping_sub(place) & 0x7FFF_FFFF;
            let offset = ((field << 1) as i32 >> 1) as u32;
            relocation.addend = place.wrapping_add(offset).wrapping_sub(symbol);
        }
    }
    Ok(found)
}

/// a movw and the movt distance bytes after it, or whatever pair the entry
/// before set.
fn pair(
    found: &mut Vec<Relocation>,
    state: &State,
    distance: u32,
    emit: impl Fn(&mut Vec<Relocation>, &State, u8, u32),
) {
    emit(found, state, state.kind, state.offset);
    emit(found, state, state.second, state.offset.wrapping_add(distance));
}

/// an ABS32 at the state's place whose symbol and addend come from the word
/// there, an address the module was linked with: the segment it falls in,
/// and how far into it.
fn stored(found: &mut Vec<Relocation>, state: &mut State, segments: &[Segment]) -> Result<(), Error> {
    let value = segments
        .get(state.segment as usize)
        .and_then(|segment| u32_at(&segment.bytes, state.offset as usize))
        .ok_or(Error::Malformed("a relocation outside its segment"))?;
    let (symbol, addend) = match crate::locate(segments, value) {
        Some((index, offset)) => (Some(index as u8), offset),
        None => (None, value),
    };
    (state.kind, state.second, state.symbol, state.addend) = (R_ARM_ABS32, R_ARM_NONE, symbol, addend);
    found.push(Relocation { segment: state.segment, offset: state.offset, kind: R_ARM_ABS32, symbol, addend });
    Ok(())
}

/// whether a kind of relocation patches an instruction rather than a word
/// of data.
pub fn patches_code(kind: u8) -> bool {
    matches!(
        kind,
        R_ARM_THM_CALL
            | R_ARM_CALL
            | R_ARM_JUMP24
            | R_ARM_MOVW_ABS_NC
            | R_ARM_MOVT_ABS
            | R_ARM_THM_MOVW_ABS_NC
            | R_ARM_THM_MOVT_ABS
    )
}

/// whether word, as it is at a relocation's place, is what that kind of
/// relocation patches. for Thumb the first halfword is the low one.
pub fn fits(kind: u8, word: u32) -> bool {
    let (first, second) = (word & 0xFFFF, word >> 16);
    match kind {
        // bl, b.w, which takes the same offset, or blx with an even one
        R_ARM_THM_CALL => {
            first & 0xF800 == 0xF000 && (matches!(second & 0xD000, 0xD000 | 0x9000) || second & 0xD001 == 0xC000)
        }
        // b or bl, possibly conditional, or blx with an immediate
        R_ARM_CALL | R_ARM_JUMP24 => (word >> 25) & 7 == 0b101,
        R_ARM_MOVW_ABS_NC => word & 0x0FF0_0000 == 0x0300_0000,
        R_ARM_MOVT_ABS => word & 0x0FF0_0000 == 0x0340_0000,
        R_ARM_THM_MOVW_ABS_NC => first & 0xFBF0 == 0xF240 && second & 0x8000 == 0,
        R_ARM_THM_MOVT_ABS => first & 0xFBF0 == 0xF2C0 && second & 0x8000 == 0,
        _ => true,
    }
}

/// the word at a relocation's place once it refers to target, the symbol's
/// address plus the addend, place being where the word is now. none for a
/// kind the Vita does not have.
pub fn patch(kind: u8, word: u32, place: u32, target: u32) -> Option<u32> {
    let relative = target.wrapping_sub(place);
    Some(match kind {
        R_ARM_ABS32 | R_ARM_TARGET1 => target,
        R_ARM_REL32 | R_ARM_TARGET2 => relative,
        R_ARM_PREL31 => word & 0x8000_0000 | relative & 0x7FFF_FFFF,
        R_ARM_THM_CALL => thumb_branch(word, relative),
        // the top byte stays, and with it a blx's H bit, the halfword of its
        // offset, which segments moved by whole words never change. the
        // vitasdk's addends leave it out
        R_ARM_CALL | R_ARM_JUMP24 => word & 0xFF00_0000 | (relative >> 2) & 0x00FF_FFFF,
        R_ARM_MOVW_ABS_NC => arm_move(word, target & 0xFFFF),
        R_ARM_MOVT_ABS => arm_move(word, target >> 16),
        R_ARM_THM_MOVW_ABS_NC => thumb_move(word, target & 0xFFFF),
        R_ARM_THM_MOVT_ABS => thumb_move(word, target >> 16),
        R_ARM_NONE | R_ARM_V4BX | R_ARM_RBASE => word,
        _ => return None,
    })
}

/// a Thumb bl, blx or b.w with a new offset, its bits spread over both
/// halfwords, the ones in the second flipped against the sign.
fn thumb_branch(word: u32, offset: u32) -> u32 {
    let sign = offset >> 24 & 1;
    let j1 = (offset >> 23 & 1 ^ sign) ^ 1;
    let j2 = (offset >> 22 & 1 ^ sign) ^ 1;
    let first = word & 0xF800 | sign << 10 | offset >> 12 & 0x3FF;
    let second = (word >> 16) & 0xD000 | j1 << 13 | j2 << 11 | offset >> 1 & 0x7FF;
    first | second << 16
}

/// an ARM movw or movt with a new immediate.
fn arm_move(word: u32, value: u32) -> u32 {
    word & 0xFFF0_F000 | (value >> 12) << 16 | value & 0xFFF
}

/// a Thumb movw or movt with a new immediate, i:imm4 in the first halfword
/// and imm3:imm8 in the second.
fn thumb_move(word: u32, value: u32) -> u32 {
    let first = word & 0xFBF0 | (value >> 11 & 1) << 10 | value >> 12 & 0xF;
    let second = (word >> 16) & 0x8F00 | (value >> 8 & 7) << 12 | value & 0xFF;
    first | second << 16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(address: u32, bytes: Vec<u8>) -> Segment {
        Segment { kind: crate::PT_LOAD, flags: 6, address, memory_size: bytes.len() as u32, align: 16, bytes }
    }

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn the_short_formats_go_on_from_the_entry_before() {
        let segments = [data(0x8100_0000, vec![0; 0x100]), data(0x8100_1000, vec![0; 0x100])];
        let table = words(&[
            // format 0, symbol segment 1, ABS32, place in segment 0 at 0x10,
            // addend 0x20
            1 << 4 | 2 << 8,
            0x20,
            0x10,
            // format 2, symbol segment 0, ABS32, 8 bytes on, addend 0x44
            2 | 2 << 8 | 8 << 16,
            0x44,
            // format 3, Thumb movw/movt from segment 1, 0x10 on, the movt 4
            // bytes after, addend 0x30
            3 | 1 << 4 | 1 << 8 | 0x10 << 9 | 4 << 27,
            0x30,
            // format 4, the same pair 0x20 on, the movt 6 bytes after
            4 | 0x20 << 4 | 6 << 27,
        ]);
        let mut formats = [0; 10];
        let found = decode(&table, &segments, &mut formats).unwrap();
        assert_eq!(formats[..5], [1, 0, 1, 1, 1]);
        let seen: Vec<_> = found.iter().map(|r| (r.offset, r.kind, r.symbol, r.addend)).collect();
        assert_eq!(
            seen,
            [
                (0x10, R_ARM_ABS32, Some(1), 0x20),
                (0x18, R_ARM_ABS32, Some(0), 0x44),
                (0x28, R_ARM_THM_MOVW_ABS_NC, Some(1), 0x30),
                (0x2C, R_ARM_THM_MOVT_ABS, Some(1), 0x30),
                (0x48, R_ARM_THM_MOVW_ABS_NC, Some(1), 0x30),
                (0x4E, R_ARM_THM_MOVT_ABS, Some(1), 0x30),
            ]
        );
    }

    #[test]
    fn stored_addresses_name_their_own_segment() {
        let mut text = vec![0; 0x40];
        text[0x10..0x14].copy_from_slice(&0x8100_1008u32.to_le_bytes());
        text[0x18..0x1C].copy_from_slice(&0x8100_0004u32.to_le_bytes());
        text[0x24..0x28].copy_from_slice(&0x0000_1234u32.to_le_bytes());
        let segments = [data(0x8100_0000, text), data(0x8100_1000, vec![0; 0x10])];
        let table = words(&[
            // format 1 to set the place, segment 0 at 0
            1 | 0xF << 4,
            0,
            // format 6, 0x10 on
            6 | 0x10 << 4,
            // format 8, words 2 and then 3 on
            8 | 2 << 4 | 3 << 8,
        ]);
        let mut formats = [0; 10];
        let found = decode(&table, &segments, &mut formats).unwrap();
        let seen: Vec<_> = found.iter().map(|r| (r.offset, r.symbol, r.addend)).collect();
        // the format 1 entry relocates nothing, its kind is NONE
        assert_eq!(seen, [(0x10, Some(1), 8), (0x18, Some(0), 4), (0x24, None, 0x1234)]);
    }

    #[test]
    fn instructions_take_their_new_immediates() {
        // movw r0, #0 and movt r0, #0 in Thumb
        let movw = 0x0000_F240;
        let movt = 0x0000_F2C0;
        let target = 0x8123_4567;
        let low = patch(R_ARM_THM_MOVW_ABS_NC, movw, 0, target).unwrap();
        let high = patch(R_ARM_THM_MOVT_ABS, movt, 0, target).unwrap();
        let immediate = |word: u32| {
            let (first, second) = (word & 0xFFFF, word >> 16);
            (first & 0xF) << 12 | (first >> 10 & 1) << 11 | (second >> 12 & 7) << 8 | second & 0xFF
        };
        assert_eq!((immediate(low), immediate(high)), (0x4567, 0x8123));
        assert!(fits(R_ARM_THM_MOVW_ABS_NC, low) && fits(R_ARM_THM_MOVT_ABS, high));

        // bl from 0x1000 back to 0x0F00, the offset is from the pc, 4 on
        let bl = patch(R_ARM_THM_CALL, 0xF800_F000, 0x1000, 0x0F00 - 4).unwrap();
        assert_eq!(bl, 0xFF7E_F7FF);
        assert!(fits(R_ARM_THM_CALL, bl));

        // movw r1, #0 in ARM
        assert_eq!(patch(R_ARM_MOVW_ABS_NC, 0xE300_1000, 0, 0xABCD).unwrap(), 0xE30A_1BCD);

        // a blx from 0x8100021C to Thumb at 0x8100023A, its H bit set, as
        // the vitasdk relocates it: an addend without the halfword
        let blx = 0xFB00_0005;
        assert_eq!(patch(R_ARM_CALL, blx, 0x8100_021C, 0x8100_0230).unwrap(), blx);
        assert_eq!(patch(R_ARM_CALL, blx, 0x9000_021C, 0x9000_0230).unwrap(), blx);
    }

    #[test]
    fn only_branches_take_thumb_calls() {
        // bl, b.w and blx
        assert!(fits(R_ARM_THM_CALL, 0xF800_F000));
        assert!(fits(R_ARM_THM_CALL, 0xB800_F000));
        assert!(fits(R_ARM_THM_CALL, 0xE800_F000));
        // a blx with H set, a bne.w and a dmb
        assert!(!fits(R_ARM_THM_CALL, 0xE801_F000));
        assert!(!fits(R_ARM_THM_CALL, 0x8000_F040));
        assert!(!fits(R_ARM_THM_CALL, 0x8F5B_F3BF));
    }

    #[test]
    fn prel31_addends_get_their_sign() {
        // an unwind table entry at 0x8100_0020 pointing back 0x20 bytes to a
        // function, which the vitasdk gives the addend 0x8000_0000, its 31
        // bits taken as 0x7FFF_FFE0 ahead rather than 0x20 behind
        let mut text = vec![0; 0x40];
        text[0x20..0x24].copy_from_slice(&0x7FFF_FFE0u32.to_le_bytes());
        let segments = [data(0x8100_0000, text)];
        let table = words(&[(R_ARM_PREL31 as u32) << 8, 0x8000_0000, 0x20]);
        let mut formats = [0; 10];
        let found = decode(&table, &segments, &mut formats).unwrap();
        assert_eq!((found[0].symbol, found[0].addend), (Some(0), 0));
        assert_eq!(found[0].target(0x8100_0000), 0x8100_0000);
        // and relocating still writes the same word
        assert_eq!(patch(R_ARM_PREL31, 0x7FFF_FFE0, 0x8100_0020, 0x8100_0000).unwrap(), 0x7FFF_FFE0);
    }
}
