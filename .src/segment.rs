//! The segment walk the EDI shapes share. `edi-edifact`, `edi-x12`,
//! `edi-tradacoms` and `hl7-er7` are each a run of segments: a tag, then
//! elements split by one character and their components by another, closed
//! by one terminator character, with a release character that makes the next
//! byte literal where the syntax has one. What differs between them is which
//! characters those are and where the head announces them — `UNA`, `ISA`,
//! `STX`, `MSH` — so the walk lives here once (ADR-0044) and each shape
//! brings its delimiters to it.
//!
//! A segment is the bytes from its tag to its terminator, the terminator
//! excluded: it is framing, as a multipart boundary is. Whitespace between
//! segments is skipped, because interchanges are written one segment per
//! line as often as not; a terminator that is itself a line break is honoured
//! before that. Elements are handed back raw — releases in place, components
//! unsplit — because a shape sections and a contract reads. Where the walk
//! cannot continue it stops with the reason and the byte, as every walk in
//! this crate does.

use crate::{Part, Stop};

/// The characters that cut an interchange into segments and elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delimiters {
    /// Ends a segment: `'` for EDIFACT and TRADACOMS, `~` usually for X12,
    /// CR for HL7.
    pub terminator: u8,
    /// Separates elements: `+`, `*`, `|`.
    pub element: u8,
    /// Separates the components of a composite element: `:`, `^`.
    pub composite: u8,
    /// Follows the tag: the element separator everywhere but TRADACOMS,
    /// where a tag is followed by `=`.
    pub tag: u8,
    /// Makes the next byte literal: `?` for EDIFACT and TRADACOMS. X12 and
    /// HL7 have none.
    pub release: Option<u8>,
}

impl Delimiters {
    /// A delimiter set with the tag followed by the element separator and
    /// no release character.
    #[must_use]
    pub const fn new(terminator: u8, element: u8, composite: u8) -> Self {
        Self {
            terminator,
            element,
            composite,
            tag: element,
            release: None,
        }
    }

    #[must_use]
    pub const fn with_tag(mut self, tag: u8) -> Self {
        self.tag = tag;
        self
    }

    #[must_use]
    pub const fn with_release(mut self, release: u8) -> Self {
        self.release = Some(release);
        self
    }

    /// `bytes` cut on `separator`, a released separator left where it is.
    #[must_use]
    pub fn split<'a>(&self, bytes: &'a [u8], separator: u8) -> Vec<&'a [u8]> {
        let mut pieces = Vec::new();
        let mut start = 0;
        let mut at = 0;
        while at < bytes.len() {
            if Some(bytes[at]) == self.release {
                at += 2;
                continue;
            }
            if bytes[at] == separator {
                pieces.push(&bytes[start..at]);
                start = at + 1;
            }
            at += 1;
        }
        pieces.push(&bytes[start.min(bytes.len())..]);
        pieces
    }

    /// `bytes` with every release character taken out and the byte it
    /// released kept: `?+` is `+`, `??` is `?`.
    #[must_use]
    pub fn unreleased(&self, bytes: &[u8]) -> Vec<u8> {
        let Some(release) = self.release else {
            return bytes.to_vec();
        };
        let mut out = Vec::with_capacity(bytes.len());
        let mut released = false;
        for &byte in bytes {
            if byte == release && !released {
                released = true;
                continue;
            }
            released = false;
            out.push(byte);
        }
        out
    }
}

/// One segment: its tag, its bytes without the terminator, and where it
/// starts in the interchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub tag: &'a str,
    pub bytes: &'a [u8],
    pub offset: usize,
}

impl<'a> Segment<'a> {
    /// The elements after the tag, in order, raw. The first is element
    /// zero: EDIFACT's UNH01, X12's ST01, HL7's MSH-2 (MSH-1 being the
    /// separator itself).
    #[must_use]
    pub fn elements(&self, delimiters: &Delimiters) -> Vec<&'a [u8]> {
        let rest = &self.bytes[self.tag.len()..];
        let rest = rest.strip_prefix(&[delimiters.tag]).unwrap_or(rest);
        if rest.is_empty() {
            return Vec::new();
        }
        delimiters.split(rest, delimiters.element)
    }

    /// Element `n`, counted from zero after the tag.
    #[must_use]
    pub fn element(&self, n: usize, delimiters: &Delimiters) -> Option<&'a [u8]> {
        self.elements(delimiters).get(n).copied()
    }

    /// Component `n` of element `element`, both counted from zero.
    #[must_use]
    pub fn component(&self, element: usize, n: usize, delimiters: &Delimiters) -> Option<&'a [u8]> {
        let element = self.element(element, delimiters)?;
        delimiters
            .split(element, delimiters.composite)
            .get(n)
            .copied()
    }

    /// The part this segment becomes: named by its tag, its bytes, the
    /// media type the shape gives it.
    #[must_use]
    pub fn part(&self, media_type: &str) -> Part {
        Part::new(
            Some(self.tag.to_string()),
            self.bytes,
            Some(media_type.to_string()),
        )
    }
}

/// Every segment of `bytes`, in order. A tag is the run of ASCII letters
/// and digits a segment opens with.
///
/// # Errors
/// No segment at all, a segment without a tag, or a last segment without
/// its terminator.
pub fn segments<'a>(bytes: &'a [u8], delimiters: &Delimiters) -> Result<Vec<Segment<'a>>, Stop> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != delimiters.terminator && bytes[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }
        let end =
            terminator_at(bytes, at, delimiters).ok_or(("a segment without its terminator", at))?;
        let tag_len = bytes[at..end]
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric())
            .count();
        if tag_len == 0 {
            return Err(("a segment without a tag", at));
        }
        let tag = std::str::from_utf8(&bytes[at..at + tag_len]).unwrap_or("");
        found.push(Segment {
            tag,
            bytes: &bytes[at..end],
            offset: at,
        });
        at = end + 1;
    }
    if found.is_empty() {
        return Err(("no segment at all", 0));
    }
    Ok(found)
}

/// The parts of `segments`, one each, all with `media_type`.
#[must_use]
pub fn parts(segments: &[Segment<'_>], media_type: &str) -> Vec<Part> {
    segments
        .iter()
        .map(|segment| segment.part(media_type))
        .collect()
}

/// The first segment tagged `tag`.
#[must_use]
pub fn first<'s, 'a>(segments: &'s [Segment<'a>], tag: &str) -> Option<&'s Segment<'a>> {
    segments.iter().find(|segment| segment.tag == tag)
}

/// The next unreleased terminator at or after `from`.
fn terminator_at(bytes: &[u8], from: usize, delimiters: &Delimiters) -> Option<usize> {
    let mut at = from;
    while at < bytes.len() {
        if Some(bytes[at]) == delimiters.release {
            at += 2;
            continue;
        }
        if bytes[at] == delimiters.terminator {
            return Some(at);
        }
        at += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ShapeError;

    const EDIFACT: Delimiters = Delimiters::new(b'\'', b'+', b':').with_release(b'?');

    #[test]
    fn an_interchange_is_walked_into_tagged_segments_with_whitespace_between_them_skipped() {
        let bytes =
            b"UNB+UNOA:1+S+R'\r\nUNH+1+ORDERS:D:96A:UN'\nFTX+AAA+++Bob?'s ?+ co'\n\nUNZ+1+1'\n";
        let walked = segments(bytes, &EDIFACT).expect("well-formed");
        let tags: Vec<&str> = walked.iter().map(|s| s.tag).collect();
        assert_eq!(tags, ["UNB", "UNH", "FTX", "UNZ"]);
        assert_eq!(walked[2].bytes, b"FTX+AAA+++Bob?'s ?+ co");
        assert_eq!(walked[2].offset, 40);
        assert_eq!(walked[3].bytes, b"UNZ+1+1");

        let parts = parts(&walked, "application/edifact");
        assert_eq!(parts[1].name.as_deref(), Some("UNH"));
        assert_eq!(parts[1].bytes, b"UNH+1+ORDERS:D:96A:UN");
        assert_eq!(parts[1].media_type.as_deref(), Some("application/edifact"));
        assert_eq!(first(&walked, "UNH").map(|s| s.offset), Some(17));
        assert_eq!(first(&walked, "BGM"), None);
    }

    #[test]
    fn elements_and_components_are_counted_from_zero_after_the_tag_with_releases_in_place() {
        let walked = segments(b"FTX+AAA+++Bob?'s ?+ co:x'", &EDIFACT).expect("well-formed");
        let ftx = walked[0];
        let elements = ftx.elements(&EDIFACT);
        assert_eq!(elements.len(), 4);
        assert_eq!(elements[3], b"Bob?'s ?+ co:x");
        assert_eq!(ftx.element(1, &EDIFACT), Some(&b""[..]));
        assert_eq!(ftx.component(3, 0, &EDIFACT), Some(&b"Bob?'s ?+ co"[..]));
        assert_eq!(ftx.component(3, 1, &EDIFACT), Some(&b"x"[..]));
        assert_eq!(ftx.component(3, 2, &EDIFACT), None);
        assert_eq!(ftx.element(4, &EDIFACT), None);
        assert_eq!(EDIFACT.unreleased(b"Bob?'s ?+ co ??"), b"Bob's + co ?");

        let tradacoms = Delimiters::new(b'\'', b'+', b':')
            .with_tag(b'=')
            .with_release(b'?');
        let walked = segments(b"MHD=1+ORDHDR:9'MTR=6'", &tradacoms).expect("well-formed");
        assert_eq!(walked[0].component(1, 0, &tradacoms), Some(&b"ORDHDR"[..]));
        assert_eq!(walked[1].elements(&tradacoms), [&b"6"[..]]);

        let bare = segments(b"UNZ'", &EDIFACT).expect("well-formed");
        assert!(bare[0].elements(&EDIFACT).is_empty());
    }

    #[test]
    fn a_walk_stops_where_a_segment_has_no_tag_or_no_terminator_or_there_is_none() {
        let untagged = segments(b"UNB+1'+x'", &EDIFACT).expect_err("no tag");
        assert_eq!(untagged, ("a segment without a tag", 6));

        let cut = segments(b"UNB+1'UNH+1+ORDERS?'", &EDIFACT).expect_err("released end");
        assert_eq!(cut, ("a segment without its terminator", 6));

        let none = segments(b" \r\n", &EDIFACT).expect_err("nothing");
        assert_eq!(none, ("no segment at all", 0));
        assert_eq!(
            ShapeError::refused("edi-edifact", none).to_string(),
            "edi-edifact: no segment at all at byte 0"
        );
    }

    #[test]
    fn a_terminator_that_is_a_line_break_is_honoured_and_a_split_keeps_released_separators() {
        let hl7 = Delimiters::new(b'\r', b'|', b'^');
        let walked = segments(b"MSH|^~\\&|A|B\r\nPID|1||X^Y\r\n", &hl7).expect("well-formed");
        assert_eq!(walked.len(), 2);
        assert_eq!(walked[0].element(0, &hl7), Some(&b"^~\\&"[..]));
        assert_eq!(walked[1].component(2, 1, &hl7), Some(&b"Y"[..]));

        assert_eq!(EDIFACT.split(b"a?+b+c", b'+'), [&b"a?+b"[..], b"c"]);
        assert_eq!(EDIFACT.split(b"", b'+'), [&b""[..]]);
        assert_eq!(EDIFACT.split(b"a+", b'+'), [&b"a"[..], b""]);
        assert_eq!(EDIFACT.split(b"a?", b'+'), [&b"a?"[..]]);
    }
}
