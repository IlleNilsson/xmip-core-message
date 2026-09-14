//! The record walk the delimited and the positioned shapes share (ADR-0044).
//!
//! A CSV is records of fields cut by a separator, a field quoted when it
//! carries the separator, a line break or the quote itself; a fixed-width
//! file is lines cut at the positions a caller names. `csv` and
//! `fixed-width` read through this module rather than each walking on its
//! own. The walk hands back byte ranges into the content it was given, so a
//! shape's parts are slices of the Stream and nothing is decoded on the way.
//! Where the walk cannot continue it stops with the reason and the byte.

use crate::Stop;
use std::ops::Range;

/// A record is text: UTF-8 without a NUL byte. The byte where it stops
/// being one, if it does.
///
/// # Errors
/// The reason and the byte at which the bytes stopped being text.
pub fn text(bytes: &[u8]) -> Result<(), Stop> {
    if let Some(at) = bytes.iter().position(|byte| *byte == 0) {
        return Err(("a NUL byte", at));
    }
    std::str::from_utf8(bytes)
        .map(|_| ())
        .map_err(|error| ("not UTF-8", error.valid_up_to()))
}

/// The lines of `bytes`: the range of each without its terminator. A line
/// ends at `\n`, a `\r` before it belonging to the terminator; the last line
/// needs no terminator, and a terminator at the very end opens no empty
/// line after it.
#[must_use]
pub fn lines(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |n| start + n);
        let text_end = if end > start && bytes[end - 1] == b'\r' {
            end - 1
        } else {
            end
        };
        lines.push(start..text_end);
        start = end + 1;
    }
    lines
}

/// The two characters a delimited record is cut by: the separator between
/// fields and the quote that lets a field carry the separator, a line break
/// or the quote doubled. RFC 4180 with the separator free, because the
/// estate meets semicolons, tabs and pipes as often as commas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delimited {
    pub separator: u8,
    pub quote: u8,
}

impl Default for Delimited {
    fn default() -> Self {
        Self::separated_by(b',')
    }
}

/// The separators a delimited record is sniffed for, in the order a tie is
/// broken.
const SEPARATORS: [u8; 4] = [b',', b';', b'\t', b'|'];

impl Delimited {
    /// Records cut by `separator`, quoted with the double quote.
    #[must_use]
    pub const fn separated_by(separator: u8) -> Self {
        Self {
            separator,
            quote: b'"',
        }
    }

    /// The separator the first line uses most outside quotes, among comma,
    /// semicolon, tab and pipe; `None` when the first line uses none.
    #[must_use]
    pub fn sniff(bytes: &[u8]) -> Option<Self> {
        let line = lines(bytes).into_iter().next()?;
        let mut counts = [0usize; SEPARATORS.len()];
        let mut quoted = false;
        for byte in &bytes[line] {
            if *byte == b'"' {
                quoted = !quoted;
            } else if let Some(index) = (!quoted)
                .then(|| SEPARATORS.iter().position(|s| s == byte))
                .flatten()
            {
                counts[index] += 1;
            }
        }
        let (index, most) =
            counts.iter().enumerate().fold(
                (0, 0),
                |best, (i, n)| if *n > best.1 { (i, *n) } else { best },
            );
        (most > 0).then(|| Self::separated_by(SEPARATORS[index]))
    }

    /// The records of `bytes`, in order, each stopping the walk where it
    /// cannot be cut.
    #[must_use]
    pub const fn records<'a>(&self, bytes: &'a [u8]) -> Records<'a> {
        Records {
            delimited: *self,
            bytes,
            at: 0,
            number: 0,
            stopped: false,
        }
    }

    /// The text of a field as written: a quoted field without its quotes
    /// and with its doubled quotes made single, any other field as it is.
    #[must_use]
    pub fn unquote(&self, field: &[u8]) -> Vec<u8> {
        let Some(inner) = field
            .strip_prefix(&[self.quote])
            .and_then(|rest| rest.strip_suffix(&[self.quote]))
        else {
            return field.to_vec();
        };
        let mut text = Vec::with_capacity(inner.len());
        let mut skip = false;
        for byte in inner {
            if skip {
                skip = false;
                continue;
            }
            if *byte == self.quote {
                skip = true;
            }
            text.push(*byte);
        }
        text
    }
}

/// One delimited record: where it lies and where its fields lie within it,
/// quotes as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// One-based, in the order of the content.
    pub number: usize,
    /// The bytes the record occupies, its terminator excluded.
    pub range: Range<usize>,
    pub fields: Vec<Range<usize>>,
}

impl Record {
    /// The bytes of the field at `index`, quotes as written.
    #[must_use]
    pub fn field<'a>(&self, bytes: &'a [u8], index: usize) -> Option<&'a [u8]> {
        self.fields.get(index).map(|range| &bytes[range.clone()])
    }
}

/// The walk over delimited records, one per `next`.
#[derive(Debug)]
pub struct Records<'a> {
    delimited: Delimited,
    bytes: &'a [u8],
    at: usize,
    number: usize,
    stopped: bool,
}

impl Records<'_> {
    /// The field at `at`: quoted to its closing quote, else to the separator
    /// or the line's end.
    fn field(&mut self) -> Result<Range<usize>, Stop> {
        let start = self.at;
        let Delimited { separator, quote } = self.delimited;
        if self.bytes.get(start) == Some(&quote) {
            let mut at = start + 1;
            loop {
                match self.bytes.get(at) {
                    None => return Err(("unterminated quoted field", start)),
                    Some(byte) if *byte == quote => {
                        if self.bytes.get(at + 1) == Some(&quote) {
                            at += 2;
                        } else {
                            self.at = at + 1;
                            return Ok(start..at + 1);
                        }
                    }
                    Some(_) => at += 1,
                }
            }
        }
        let mut end = self.bytes[start..]
            .iter()
            .position(|byte| *byte == separator || *byte == b'\n')
            .map_or(self.bytes.len(), |n| start + n);
        if self.bytes.get(end) == Some(&b'\n') && end > start && self.bytes[end - 1] == b'\r' {
            end -= 1;
        }
        self.at = end;
        Ok(start..end)
    }

    fn record(&mut self) -> Result<Record, Stop> {
        let start = self.at;
        let mut fields = Vec::new();
        let end = loop {
            fields.push(self.field()?);
            match self.bytes.get(self.at) {
                Some(byte) if *byte == self.delimited.separator => self.at += 1,
                Some(b'\r') if self.bytes.get(self.at + 1) == Some(&b'\n') => {
                    let end = self.at;
                    self.at += 2;
                    break end;
                }
                Some(b'\n') => {
                    let end = self.at;
                    self.at += 1;
                    break end;
                }
                None => break self.at,
                Some(_) => return Err(("content after a closing quote", self.at)),
            }
        };
        self.number += 1;
        Ok(Record {
            number: self.number,
            range: start..end,
            fields,
        })
    }
}

impl Iterator for Records<'_> {
    type Item = Result<Record, Stop>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped || self.at >= self.bytes.len() {
            return None;
        }
        let record = self.record();
        self.stopped = record.is_err();
        Some(record)
    }
}

/// One position a caller names on a fixed-width line: `start` bytes in,
/// `width` bytes wide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub name: String,
    pub start: usize,
    pub width: usize,
}

impl Position {
    #[must_use]
    pub fn new(name: impl Into<String>, start: usize, width: usize) -> Self {
        Self {
            name: name.into(),
            start,
            width,
        }
    }

    /// The byte after the last this position covers.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.start + self.width
    }
}

/// The positions cut from `line`, in the order they are named. `offset` is
/// where the line begins in its content, so a stop can say where.
///
/// # Errors
/// The line ends before a position does; the stop is at the line's end.
pub fn positioned<'a>(
    line: &'a [u8],
    offset: usize,
    positions: &'a [Position],
) -> Result<Vec<(&'a str, &'a [u8])>, Stop> {
    positions
        .iter()
        .map(|position| {
            line.get(position.start..position.end())
                .map(|bytes| (position.name.as_str(), bytes))
                .ok_or((
                    "the line is shorter than its positions",
                    offset + line.len(),
                ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_end_at_either_terminator_and_the_last_needs_none() {
        assert_eq!(lines(b"a\r\nbb\nc"), vec![0..1, 3..5, 6..7]);
        assert_eq!(lines(b"a\n\nb\n"), vec![0..1, 2..2, 3..4]);
        assert_eq!(lines(b""), Vec::<Range<usize>>::new());
        assert_eq!(text(b"ab"), Ok(()));
        assert_eq!(text(b"a\x00b"), Err(("a NUL byte", 1)));
        assert_eq!(text(b"ab\xff"), Err(("not UTF-8", 2)));
    }

    #[test]
    fn a_quoted_field_carries_the_separator_a_line_break_and_a_doubled_quote() {
        let bytes = b"a,\"b,c\r\nd\",\"e\"\"f\",,g\r\nh\n";
        let delimited = Delimited::default();
        let records: Vec<Record> = delimited
            .records(bytes)
            .collect::<Result<_, _>>()
            .expect("cuts");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].number, 1);
        assert_eq!(records[0].range, 0..20);
        assert_eq!(records[0].fields.len(), 5);
        assert_eq!(records[0].field(bytes, 1), Some(b"\"b,c\r\nd\"".as_slice()));
        assert_eq!(delimited.unquote(b"\"b,c\r\nd\""), b"b,c\r\nd");
        assert_eq!(delimited.unquote(b"\"e\"\"f\""), b"e\"f");
        assert_eq!(records[0].field(bytes, 3), Some(b"".as_slice()));
        assert_eq!(records[0].field(bytes, 4), Some(b"g".as_slice()));
        assert_eq!(records[1].range, 22..23);
        assert_eq!(records[1].fields, vec![22..23]);
    }

    #[test]
    fn the_walk_stops_at_an_open_quote_or_at_content_after_a_closing_one() {
        let open: Vec<Result<Record, Stop>> = Delimited::default().records(b"a,\"b\nc").collect();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0], Err(("unterminated quoted field", 2)));

        let after: Vec<Result<Record, Stop>> = Delimited::default().records(b"\"a\"b,c").collect();
        assert_eq!(after[0], Err(("content after a closing quote", 3)));
    }

    #[test]
    fn the_separator_is_sniffed_from_the_first_line_outside_quotes() {
        assert_eq!(
            Delimited::sniff(b"a;b;\"c,d,e\"\n1;2;3").map(|d| d.separator),
            Some(b';')
        );
        assert_eq!(
            Delimited::sniff(b"a\tb\tc").map(|d| d.separator),
            Some(b'\t')
        );
        assert_eq!(Delimited::sniff(b"a|b,c").map(|d| d.separator), Some(b','));
        assert_eq!(Delimited::sniff(b"plain"), None);
        assert_eq!(Delimited::sniff(b""), None);
        let semicolon = Delimited::separated_by(b';');
        let record = semicolon
            .records(b"a,b;c")
            .next()
            .expect("one")
            .expect("cuts");
        assert_eq!(record.fields, vec![0..3, 4..5]);
    }

    #[test]
    fn positions_cut_a_line_and_a_short_line_stops_at_its_end() {
        let positions = [Position::new("id", 0, 3), Position::new("name", 3, 4)];
        let cut = positioned(b"001Anna", 10, &positions).expect("fits");
        assert_eq!(
            cut,
            vec![("id", b"001".as_slice()), ("name", b"Anna".as_slice())]
        );
        assert_eq!(
            positioned(b"001An", 10, &positions),
            Err(("the line is shorter than its positions", 15))
        );
        assert_eq!(positions[1].end(), 7);
    }
}
