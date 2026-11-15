//! A segment cut into its pieces: its components, each in the element it is
//! in, cut at every separator no release stands before, and only when a
//! syntax asks for one. A shape reads an element or a component of it raw;
//! a contract reads every piece into its tree, or the one its path points
//! at.

use std::ops::Range;

use super::{Delimiters, Segment};

impl<'a> Segment<'a> {
    /// Its components, one at a time, raw, the tag's own element first.
    #[must_use]
    pub const fn pieces(&self, delimiters: &Delimiters) -> Pieces<'a> {
        Pieces {
            bytes: self.bytes,
            delimiters: *delimiters,
            at: 0,
            element: 0,
            component: 0,
            done: false,
        }
    }

    /// Element `n`, counted from zero after the tag — EDIFACT's UNH01,
    /// X12's ST01, HL7's MSH-2 (MSH-1 being the separator itself) — raw,
    /// its components unsplit.
    #[must_use]
    pub fn element(&self, n: usize, delimiters: &Delimiters) -> Option<&'a [u8]> {
        let mut span: Option<Range<usize>> = None;
        for piece in self
            .pieces(delimiters)
            .take_while(|piece| piece.element <= n + 1)
        {
            if piece.element == n + 1 {
                let start = span.as_ref().map_or(piece.at.start, |span| span.start);
                span = Some(start..piece.at.end);
            }
        }
        span.map(|span| &self.bytes[span])
    }

    /// Component `n` of element `element`, both counted from zero after the
    /// tag, raw.
    #[must_use]
    pub fn component(&self, element: usize, n: usize, delimiters: &Delimiters) -> Option<&'a [u8]> {
        self.pieces(delimiters)
            .take_while(|piece| piece.element <= element + 1)
            .find(|piece| piece.element == element + 1 && piece.component == n)
            .map(|piece| &self.bytes[piece.at])
    }
}

/// One component of a segment, as [`Segment::pieces`] cuts it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    /// The element it is in: the tag's own is 0, so EDIFACT's UNH01 and
    /// X12's ST01 are 1.
    pub element: usize,
    /// Its place in its element, from 0.
    pub component: usize,
    /// Where it lies in the segment's bytes, releases in place.
    pub at: Range<usize>,
    /// Whether a release character stands in it, to be taken out
    /// ([`Delimiters::unreleased`]) where its value is read.
    pub released: bool,
}

/// A segment's components, one at a time, in the order they lie: cut at
/// every element and component separator no release stands before, the
/// tag's own element at the separator that follows a tag as well.
#[derive(Clone, Debug)]
pub struct Pieces<'a> {
    bytes: &'a [u8],
    delimiters: Delimiters,
    at: usize,
    element: usize,
    component: usize,
    done: bool,
}

impl Iterator for Pieces<'_> {
    type Item = Piece;

    fn next(&mut self) -> Option<Piece> {
        if self.done {
            return None;
        }
        let d = self.delimiters;
        let tagged = self.element == 0;
        // An element separator ends an element even where the component
        // separator is the same character.
        let ends = |byte: u8| byte == d.element || (tagged && byte == d.tag);
        let (end, released) = d.scan(self.bytes, self.at, |byte| {
            ends(byte) || byte == d.composite
        });
        let piece = Piece {
            element: self.element,
            component: self.component,
            at: self.at..end,
            released,
        };
        match self.bytes.get(end) {
            None => self.done = true,
            Some(&byte) if ends(byte) => {
                self.element += 1;
                self.component = 0;
            }
            Some(_) => self.component += 1,
        }
        self.at = end + 1;
        Some(piece)
    }
}

#[cfg(test)]
mod tests {
    use crate::segment::{Delimiters, segments};

    const EDIFACT: Delimiters = Delimiters::new(b'\'', b'+', b':').with_release(b'?');

    #[test]
    fn elements_and_components_are_counted_from_zero_after_the_tag_with_releases_in_place() {
        let walked = segments(b"FTX+AAA+++Bob?'s ?+ co:x'", &EDIFACT).expect("well-formed");
        let ftx = walked[0];
        assert_eq!(ftx.element(3, &EDIFACT), Some(&b"Bob?'s ?+ co:x"[..]));
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
        assert_eq!(walked[1].element(0, &tradacoms), Some(&b"6"[..]));
        assert_eq!(walked[1].element(1, &tradacoms), None);

        let bare = segments(b"UNZ'", &EDIFACT).expect("well-formed");
        assert_eq!(bare[0].element(0, &EDIFACT), None);
    }

    #[test]
    fn a_segment_is_cut_into_its_pieces_only_when_asked_releases_kept_and_marked() {
        let walked = segments(b"FTX+a?+b+c:d+'", &EDIFACT).expect("well-formed");
        let pieces: Vec<(usize, usize, &[u8], bool)> = walked[0]
            .pieces(&EDIFACT)
            .map(|piece| {
                let bytes = &walked[0].bytes[piece.at];
                (piece.element, piece.component, bytes, piece.released)
            })
            .collect();
        assert_eq!(
            pieces,
            [
                (0, 0, &b"FTX"[..], false),
                (1, 0, b"a?+b", true),
                (2, 0, b"c", false),
                (2, 1, b"d", false),
                (3, 0, b"", false),
            ]
        );
        // The tag's own element: its first component is the tag, released
        // characters read through.
        let walked = segments(b"U?NB+1'", &EDIFACT).expect("well-formed");
        let head = walked[0].pieces(&EDIFACT).next().expect("a tag");
        assert_eq!(EDIFACT.unreleased(&walked[0].bytes[head.at]), b"UNB");
        assert!(head.released);
    }
}
