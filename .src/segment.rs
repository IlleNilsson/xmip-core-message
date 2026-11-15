//! The one segment walk. A UN/EDIFACT, ASC X12 or TRADACOMS interchange and
//! an HL7 v2 message in ER7 are each a run of segments: a tag, then
//! elements split by one character and their components by another, ended
//! by a terminator, with a release character that makes the next byte
//! literal where the syntax has one. What differs between them is which
//! characters those are, where the head announces them — `UNA`, `ISA`,
//! `STX`, `MSH` — and how a segment may end, so the walk lives here once
//! (ADR-0044) and each syntax hands it its [`Delimiters`]: the
//! `edi-edifact`, `edi-x12`, `edi-tradacoms` and `hl7-er7` shapes, and the
//! EDIFACT, X12 and HL7 v2 contracts, which the `edi` and `hl7-v2` paths
//! read through.
//!
//! A segment is the bytes from its tag to its terminator, the first one no
//! release stands before, the terminator excluded: it is framing, as a
//! multipart boundary is. Whitespace before a segment is skipped, because
//! interchanges are written one segment per line as often as not; a
//! terminator that is itself a line break is honored before that, and where
//! every line break ends a segment, as in ER7, only line breaks stand
//! between two segments. A walk
//! yields a segment at a time and cuts nothing: a segment's tag is read at
//! once, its elements and components only when asked, raw — releases in
//! place — because a shape sections, a contract reads and a path answers
//! from one segment of many. Where the walk cannot continue it stops with
//! the reason and the byte, as every walk in this crate does, and yields
//! nothing after. A segment is cut into its pieces in [`piece`].

pub mod piece;

use crate::{Part, Stop};

/// The characters that cut an interchange into segments and elements, and
/// how a segment may end.
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
    /// Whether every line break ends a segment, CR and LF alike, so an empty
    /// line is none and nothing else stands between two segments: HL7 v2
    /// ends a segment at CR and is met with LF as often.
    pub line_breaks: bool,
    /// Whether the last segment may end where the text does, its
    /// terminator left out: the HL7 v2 contract reads a message so.
    pub open_end: bool,
}

impl Delimiters {
    /// A delimiter set with the tag followed by the element separator, no
    /// release character, and every segment ended by its terminator.
    #[must_use]
    pub const fn new(terminator: u8, element: u8, composite: u8) -> Self {
        Self {
            terminator,
            element,
            composite,
            tag: element,
            release: None,
            line_breaks: false,
            open_end: false,
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

    /// Every line break ending a segment, CR and LF alike.
    #[must_use]
    pub const fn ended_by_line_breaks(mut self) -> Self {
        self.line_breaks = true;
        self
    }

    /// The last segment ending where the text does, with or without its
    /// terminator.
    #[must_use]
    pub const fn open_at_the_end(mut self) -> Self {
        self.open_end = true;
        self
    }

    /// The segments of `bytes`, one at a time, in the order they lie.
    #[must_use]
    pub const fn walk<'a>(&self, bytes: &'a [u8]) -> Walk<'a> {
        Walk {
            bytes,
            delimiters: *self,
            at: 0,
            walked: false,
            ended: false,
        }
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

    /// Where the first byte `stops` takes lies in `bytes` from `from`, a
    /// byte a release stands before passed over, else the end; and whether
    /// a release was passed on the way.
    fn scan(&self, bytes: &[u8], from: usize, stops: impl Fn(u8) -> bool) -> (usize, bool) {
        let mut at = from;
        let mut released = false;
        while let Some(&byte) = bytes.get(at) {
            if Some(byte) == self.release {
                released = true;
                at += 2;
            } else if stops(byte) {
                return (at, released);
            } else {
                at += 1;
            }
        }
        (bytes.len(), released)
    }

    /// Where a segment starts at or after `from`: whitespace passed over
    /// that is not the terminator, or every line break and nothing else
    /// where every line break ends a segment.
    fn start(&self, bytes: &[u8], from: usize) -> usize {
        let mut at = from;
        while let Some(&byte) = bytes.get(at) {
            let between = if self.line_breaks {
                byte == b'\r' || byte == b'\n'
            } else {
                byte.is_ascii_whitespace() && byte != self.terminator
            };
            if !between {
                break;
            }
            at += 1;
        }
        at
    }

    /// Where the segment that starts at `from` ends: at its terminator, the
    /// first no release stands before, or at the first line break where
    /// every line break ends one; none where nothing ends it.
    fn end(&self, bytes: &[u8], from: usize) -> Option<usize> {
        let terminator = self.terminator;
        let line_break = |byte: u8| byte == b'\r' || byte == b'\n';
        match self.release {
            None if !self.line_breaks => found(bytes, from, terminator, terminator),
            None if line_break(terminator) => found(bytes, from, b'\r', b'\n'),
            Some(release) if !self.line_breaks => self.unreleased_terminator(bytes, from, release),
            _ => {
                let (end, _) =
                    self.scan(bytes, from, |byte| byte == terminator || line_break(byte));
                (end < bytes.len()).then_some(end)
            }
        }
    }

    /// The first terminator from `from`, where a segment starts, that no
    /// release stands before. A terminator is released when an odd run of
    /// release characters stands before it, each pair releasing the second:
    /// so it is found by a search for the terminator alone, and the release
    /// characters are counted only where one is met.
    fn unreleased_terminator(&self, bytes: &[u8], from: usize, release: u8) -> Option<usize> {
        // A release character that is the terminator too releases every one.
        if release == self.terminator {
            return None;
        }
        let mut search = from;
        loop {
            let at = found(bytes, search, self.terminator, self.terminator)?;
            if released_before(&bytes[from..at], release).is_multiple_of(2) {
                return Some(at);
            }
            search = at + 1;
        }
    }

    /// Whether the segment from `start`, which nothing ends, may be the
    /// last: not where the text ends on a release character, and only where
    /// a last segment may go without its terminator.
    fn unterminated(&self, bytes: &[u8], start: usize) -> Result<(), Stop> {
        let releases = self
            .release
            .map_or(0, |release| released_before(&bytes[start..], release));
        if !releases.is_multiple_of(2) {
            return Err(("the text ends on a release character", bytes.len() - 1));
        }
        if self.open_end {
            Ok(())
        } else {
            Err(("a segment without its terminator", start))
        }
    }
}

/// How many release characters stand at the end of `bytes`.
fn released_before(bytes: &[u8], release: u8) -> usize {
    bytes
        .iter()
        .rev()
        .take_while(|&&byte| byte == release)
        .count()
}

/// Where `a` or `b` first lies in `bytes` at or after `from`, eight bytes
/// read at a time: a byte equal to the one sought is zero once the two are
/// exclusive-ored, and a word's first zero byte is the lowest one
/// `(word - 0x01…) & !word & 0x80…` marks (Hacker's Delight, 6-1), the
/// marks above it being borrowed from it.
fn found(bytes: &[u8], from: usize, a: u8, b: u8) -> Option<usize> {
    const ONES: u64 = u64::from_ne_bytes([0x01; 8]);
    const HIGHS: u64 = u64::from_ne_bytes([0x80; 8]);
    let zero = |word: u64| word.wrapping_sub(ONES) & !word & HIGHS;
    let (spread_a, spread_b) = (ONES * u64::from(a), ONES * u64::from(b));
    // One byte sought is one word compared, not two.
    let both = a != b;
    let rest = bytes.get(from..)?;
    let (words, tail) = rest.as_chunks::<8>();
    for (n, &word) in words.iter().enumerate() {
        let word = u64::from_le_bytes(word);
        let marked = zero(word ^ spread_a) | if both { zero(word ^ spread_b) } else { 0 };
        if marked != 0 {
            return Some(from + n * 8 + (marked.trailing_zeros() / 8) as usize);
        }
    }
    tail.iter()
        .position(|&byte| byte == a || byte == b)
        .map(|at| from + words.len() * 8 + at)
}

/// The segments of an interchange, one at a time, in the order they lie,
/// as [`Delimiters::walk`] begins them. After a stop it yields nothing.
#[derive(Clone, Debug)]
pub struct Walk<'a> {
    bytes: &'a [u8],
    delimiters: Delimiters,
    /// Where the next segment is looked for.
    at: usize,
    /// Whether a segment was yielded.
    walked: bool,
    /// Whether the walk has stopped or reached the end.
    ended: bool,
}

impl<'a> Iterator for Walk<'a> {
    type Item = Result<Segment<'a>, Stop>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        let (bytes, delimiters) = (self.bytes, self.delimiters);
        let start = delimiters.start(bytes, self.at);
        if start >= bytes.len() {
            self.ended = true;
            return (!self.walked).then_some(Err(("no segment at all", 0)));
        }
        let end = match delimiters.end(bytes, start) {
            Some(end) => end,
            None => match delimiters.unterminated(bytes, start) {
                Ok(()) => bytes.len(),
                Err(stop) => {
                    self.ended = true;
                    return Some(Err(stop));
                }
            },
        };
        let segment = &bytes[start..end];
        let tagged = segment
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric())
            .count();
        self.at = end + 1;
        self.walked = true;
        Some(Ok(Segment {
            tag: std::str::from_utf8(&segment[..tagged]).unwrap_or(""),
            bytes: segment,
            offset: start,
        }))
    }
}

/// One segment: its tag, its bytes without the terminator, and where it
/// starts in what was walked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    /// The ASCII letters and digits the segment opens with: `UNH`, `ST`,
    /// `MSH`. Empty where it opens with neither; what a tag must be is each
    /// syntax's to hold.
    pub tag: &'a str,
    pub bytes: &'a [u8],
    pub offset: usize,
}

impl Segment<'_> {
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

/// Every segment of `bytes`, in order, each with a tag.
///
/// # Errors
/// Where the walk stops — no segment at all, a last segment without its
/// terminator, a text ending on a release character — or a segment opens
/// with no tag.
pub fn segments<'a>(bytes: &'a [u8], delimiters: &Delimiters) -> Result<Vec<Segment<'a>>, Stop> {
    delimiters
        .walk(bytes)
        .map(|walked| {
            walked.and_then(|segment| {
                if segment.tag.is_empty() {
                    Err(("a segment without a tag", segment.offset))
                } else {
                    Ok(segment)
                }
            })
        })
        .collect()
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

        let released = segments(b"UNB+1'UNZ+1?", &EDIFACT).expect_err("ends released");
        assert_eq!(released, ("the text ends on a release character", 11));
        let paired = segments(b"UNB+1'UNZ+1??", &EDIFACT).expect_err("paired");
        assert_eq!(paired, ("a segment without its terminator", 6));
        // A release character that is the terminator too releases every one.
        let both = Delimiters::new(b'\'', b'+', b':').with_release(b'\'');
        let all = segments(b"UNB+1'UNZ'", &both).expect_err("all released");
        assert_eq!(all.0, "the text ends on a release character");
    }

    #[test]
    fn a_walk_yields_a_segment_at_a_time_and_ends_where_it_stops() {
        let mut walk = EDIFACT.walk(b"UNB+1'UNH+1'unz+1");
        assert_eq!(walk.next().map(|s| s.map(|s| s.tag)), Some(Ok("UNB")));
        assert_eq!(walk.next().map(|s| s.map(|s| s.tag)), Some(Ok("UNH")));
        let stopped = walk.next().expect("three").expect_err("no terminator");
        assert_eq!(stopped, ("a segment without its terminator", 12));
        assert!(walk.next().is_none(), "a walk ends where it stops");

        // An empty segment is yielded, its tag empty, for a syntax to judge.
        let x12 = Delimiters::new(b'~', b'*', b'>');
        let walked: Vec<&[u8]> = x12
            .walk(b"ST*1~~SE*2~")
            .map(|s| s.expect("walked").bytes)
            .collect();
        assert_eq!(walked, [&b"ST*1"[..], b"", b"SE*2"]);
    }

    #[test]
    fn a_terminator_that_is_a_line_break_is_honored_and_line_breaks_may_end_every_segment() {
        let hl7 = Delimiters::new(b'\r', b'|', b'^');
        let walked = segments(b"MSH|^~\\&|A|B\r\nPID|1||X^Y\r\n", &hl7).expect("well-formed");
        assert_eq!(walked.len(), 2);
        assert_eq!(walked[0].element(0, &hl7), Some(&b"^~\\&"[..]));
        assert_eq!(walked[1].component(2, 1, &hl7), Some(&b"Y"[..]));

        // X12's terminator, the last byte of its ISA, may be a line break.
        let x12 = Delimiters::new(b'\n', b'*', b'>');
        let walked = segments(b"ST*850*1\nSE*2*1\n", &x12).expect("well-formed");
        assert_eq!(walked.len(), 2);
        assert_eq!(walked[1].element(1, &x12), Some(&b"1"[..]));

        // Every line break, an empty line none, and the last segment open.
        let lines = hl7.ended_by_line_breaks();
        let mixed = b"MSH|^~\\&|A\r\n\nPID|1\nOBX|2";
        let cut = segments(mixed, &lines).expect_err("closed");
        assert_eq!(cut, ("a segment without its terminator", 19));
        let walked = segments(mixed, &lines.open_at_the_end()).expect("open");
        let tags: Vec<&str> = walked.iter().map(|s| s.tag).collect();
        assert_eq!(tags, ["MSH", "PID", "OBX"]);
        assert_eq!(walked[2].bytes, b"OBX|2");
        // Nothing but line breaks stands between two segments there.
        let spaced = segments(b"MSH|^~\\&|A\r PID|1\r", &lines).expect_err("spaced");
        assert_eq!(spaced, ("a segment without a tag", 11));
    }

    #[test]
    fn the_terminator_is_found_eight_bytes_at_a_time_wherever_it_lies() {
        for length in 0..40 {
            for needle in 0..length {
                let mut bytes = vec![0x80_u8; length];
                for (at, byte) in bytes.iter_mut().enumerate() {
                    *byte = [0x80, 0xFF, b'x', 0x01, 0x00][at % 5];
                }
                bytes[needle] = b'~';
                for from in 0..=needle {
                    assert_eq!(found(&bytes, from, b'~', b'~'), Some(needle));
                    assert_eq!(found(&bytes, from, b'\r', b'~'), Some(needle));
                }
                assert_eq!(found(&bytes, needle + 1, b'~', b'~'), None);
            }
        }
        assert_eq!(found(b"ab", 3, b'a', b'a'), None);
    }
}
