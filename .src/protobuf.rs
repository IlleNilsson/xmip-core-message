//! The Protocol Buffers wire format, walked: a message is a run of fields,
//! each a varint tag — the field number and the wire type — followed by as
//! many bytes as the wire type says; a length-delimited stream is messages
//! each behind a varint length. The walk finds where every top-level field's
//! value lies and what wire type carries it; nothing is decoded.
//!
//! One walk for everything in Xmip that reads the format: the protobuf shape
//! sections by it, and the protobuf contract checks a schema against the
//! fields it finds. Until 2026-09-23 the contract had its own, which refused
//! every group — a proto2 message with one, or an unknown field that was
//! one — and let field numbers past the format's range through
//! (open-problems.md, problem 25, row c).

use crate::Stop;
use crate::scan::{encode_varint, varint};
use std::ops::Range;

/// The largest field number the format allows.
const LARGEST_FIELD: u64 = (1 << 29) - 1;

/// Groups nested deeper than this are refused rather than the stack.
const DEEPEST: usize = 64;

/// How a field's value is carried, named as the specification names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireType {
    /// A varint: `int32`, `int64`, `uint`, `sint`, `bool`, an enum.
    Varint,
    /// Eight bytes: `fixed64`, `sfixed64`, `double`.
    I64,
    /// A length then that many bytes: a string, bytes, an embedded message,
    /// a packed repeated field.
    Len,
    /// A start-group tag to its end-group tag; proto2's legacy nesting.
    Group,
    /// Four bytes: `fixed32`, `sfixed32`, `float`.
    I32,
}

impl WireType {
    /// The number the tag carries for this wire type; a group's start tag.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Varint => 0,
            Self::I64 => 1,
            Self::Len => 2,
            Self::Group => 3,
            Self::I32 => 5,
        }
    }

    /// The media type suffix a part of this wire type carries.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Varint => "varint",
            Self::I64 => "i64",
            Self::Len => "len",
            Self::Group => "group",
            Self::I32 => "i32",
        }
    }
}

/// One top-level field: its number, its wire type and where its value lies
/// — the varint's bytes, the eight or four bytes, the bytes behind a
/// length, or the bytes between a group's two tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub number: u32,
    pub wire: WireType,
    pub value: Range<usize>,
}

/// The top-level fields of the message that is `bytes[range]`.
///
/// # Errors
/// A field number outside the format's range, a wire type the format does
/// not have, a group that never ends or ends without starting, or a message
/// that ends inside a field.
pub fn fields(bytes: &[u8], range: Range<usize>) -> Result<Vec<Field>, Stop> {
    let mut reader = Reader::new(bytes, range);
    let mut fields = Vec::new();
    while let Some(tag) = reader.tag()? {
        let value = reader.value(tag)?;
        fields.push(Field {
            number: tag.number,
            wire: tag.wire,
            value,
        });
    }
    Ok(fields)
}

/// The messages of a length-delimited stream: each behind its varint
/// length, the last ending exactly where the bytes do.
///
/// # Errors
/// The stream ends inside a message's length or inside the message.
pub fn delimited(bytes: &[u8]) -> Result<Vec<Range<usize>>, Stop> {
    let mut at = 0;
    let mut messages = Vec::new();
    while at < bytes.len() {
        let (length, start) = varint(bytes, at)?;
        let end = usize::try_from(length)
            .ok()
            .and_then(|length| start.checked_add(length))
            .filter(|end| *end <= bytes.len())
            .ok_or(("the stream ends inside a message", bytes.len()))?;
        messages.push(start..end);
        at = end;
    }
    Ok(messages)
}

/// The tag of field `number` carried as `wire`.
#[must_use]
pub fn encode_tag(number: u32, wire: WireType) -> Vec<u8> {
    encode_varint((u64::from(number) << 3) | u64::from(wire.number()))
}

/// Field `number` holding `bytes` behind their length.
#[must_use]
pub fn encode_delimited(number: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = encode_tag(number, WireType::Len);
    out.extend(encode_varint(bytes.len() as u64));
    out.extend_from_slice(bytes);
    out
}

/// A field's tag: its number, its wire type and the byte it starts at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    pub number: u32,
    pub wire: WireType,
    pub at: usize,
}

/// The walk one field at a time: a tag, then its value.
///
/// Split in two so that a reader holding a schema can judge the tag before
/// the value is read. A known field whose wire type is not the schema's is
/// the departure, and it is found at the tag; read the value first and the
/// same bytes read as a length run past the end, and the operator is told
/// the message is cut short instead of which field is wrong.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    /// At the start of the message that is `bytes[range]`.
    #[must_use]
    pub fn new(bytes: &'a [u8], range: Range<usize>) -> Self {
        Self {
            bytes: &bytes[..range.end],
            at: range.start,
            end: range.end,
        }
    }

    /// The next field's tag, or `None` where the message ends.
    ///
    /// # Errors
    /// A field number outside the format's range, a wire type the format
    /// does not have, or an end-group tag with no group open.
    pub fn tag(&mut self) -> Result<Option<Tag>, Stop> {
        if self.at >= self.end {
            return Ok(None);
        }
        match self.any_tag()? {
            (tag, false) => Ok(Some(tag)),
            (tag, true) => Err(("an end group without its start", tag.at)),
        }
    }

    /// Where the value of the field `tag` lies, and past it.
    ///
    /// # Errors
    /// The message ends inside the value, or a group never ends.
    pub fn value(&mut self, tag: Tag) -> Result<Range<usize>, Stop> {
        self.value_at(tag, 0)
    }

    /// A tag, and whether it closes a group.
    fn any_tag(&mut self) -> Result<(Tag, bool), Stop> {
        let at = self.at;
        let (raw, next) = varint(self.bytes, at)?;
        let number = match raw >> 3 {
            n @ 1..=LARGEST_FIELD => {
                u32::try_from(n).map_err(|_| ("a field number too large", at))?
            }
            _ => return Err(("a field number outside the format's range", at)),
        };
        let (wire, closes) = match raw & 7 {
            0 => (WireType::Varint, false),
            1 => (WireType::I64, false),
            2 => (WireType::Len, false),
            3 => (WireType::Group, false),
            4 => (WireType::Group, true),
            5 => (WireType::I32, false),
            _ => return Err(("a wire type the format does not have", at)),
        };
        self.at = next;
        Ok((Tag { number, wire, at }, closes))
    }

    fn value_at(&mut self, tag: Tag, depth: usize) -> Result<Range<usize>, Stop> {
        let at = self.at;
        let value = match tag.wire {
            WireType::Varint => at..varint(self.bytes, at)?.1,
            WireType::I64 => at..at + 8,
            WireType::I32 => at..at + 4,
            WireType::Len => {
                let (length, start) = varint(self.bytes, at)?;
                let length = usize::try_from(length).map_err(|_| ("a length too large", at))?;
                start..start.saturating_add(length)
            }
            WireType::Group => return self.group(tag, depth),
        };
        if value.end > self.end {
            return Err(("the message ends inside a field", self.end));
        }
        self.at = value.end;
        Ok(value)
    }

    /// A group's fields, to the end tag that carries its number; the value
    /// is the bytes between the two tags.
    fn group(&mut self, open: Tag, depth: usize) -> Result<Range<usize>, Stop> {
        if depth >= DEEPEST {
            return Err(("groups nested too deep", open.at));
        }
        let start = self.at;
        while self.at < self.end {
            match self.any_tag()? {
                (tag, true) if tag.number == open.number => return Ok(start..tag.at),
                (tag, true) => return Err(("an end group without its start", tag.at)),
                (tag, false) => {
                    self.value_at(tag, depth + 1)?;
                }
            }
        }
        Err(("a group never ends", self.end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cut_varint_stops_the_walk_where_the_bytes_end() {
        assert_eq!(
            fields(b"\x08\x80", 0..2),
            Err(("the bytes end inside a varint", 2))
        );
        assert_eq!(
            delimited(b"\x02\x08\x01\x80"),
            Err(("the bytes end inside a varint", 4))
        );
    }

    #[test]
    fn a_group_is_walked_to_its_end_tag_and_nesting_is_bounded() {
        let bytes = b"\x0b\x08\x01\x13\x10\x02\x14\x0c\x18\x03";
        let fields = fields(bytes, 0..bytes.len()).expect("walks");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].wire, WireType::Group);
        assert_eq!(fields[0].value, 1..7);
        assert_eq!(fields[1].number, 3);
        assert_eq!(fields[1].value, 9..10);

        let deep: Vec<u8> = std::iter::repeat_n(0x0b, DEEPEST + 1).collect();
        assert_eq!(
            super::fields(&deep, 0..deep.len()),
            Err(("groups nested too deep", DEEPEST))
        );
        assert_eq!(
            super::fields(b"\x0b\x08\x01", 0..3),
            Err(("a group never ends", 3))
        );
        assert_eq!(
            super::fields(b"\x0b\x14", 0..2),
            Err(("an end group without its start", 1))
        );
    }
}
