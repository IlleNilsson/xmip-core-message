//! The byte cursor the scanning shapes share (ADR-0044). A JSON document,
//! an XML document and an Avro schema are each read by a cursor over the
//! bytes that peeks at the next one, skips whitespace and takes a quoted
//! string; `json`, `xml` and `avro` had each written that cursor before it
//! lived here once. What a grammar makes of the bytes stays with the
//! technology (ADR-0044 clause 2): this file is the walking, not the reading.
//!
//! Beside the cursor, the base-128 varint `protobuf` and `avro` both write
//! their integers as, read unsigned. Avro's zig-zag over it is Avro's.

use crate::Stop;

/// Where a scan is in its bytes.
#[derive(Debug)]
pub struct Scan<'a> {
    pub bytes: &'a [u8],
    pub at: usize,
}

impl<'a> Scan<'a> {
    /// A scan at the first byte.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The byte under the cursor, when there is one.
    #[must_use]
    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    /// Everything from the cursor on.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at.min(self.bytes.len())..]
    }

    /// Past any run of space, tab, carriage return and line feed: the
    /// whitespace JSON and XML both name.
    pub fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.at += 1;
        }
    }

    /// The string whose opening quote is under the cursor: the raw bytes
    /// between the quotes, escapes as JSON writes them and left as written.
    /// The cursor ends after the closing quote.
    ///
    /// # Errors
    /// The string never closes, carries a control byte, or carries an
    /// escape JSON does not have.
    pub fn string(&mut self) -> Result<&'a [u8], Stop> {
        let start = self.at + 1;
        self.at = start;
        loop {
            match self.peek() {
                None => return Err(("unterminated string", self.at)),
                Some(b'"') => {
                    let raw = &self.bytes[start..self.at];
                    self.at += 1;
                    return Ok(raw);
                }
                Some(b'\\') => {
                    self.at += 1;
                    self.escape()?;
                }
                Some(byte) if byte < 0x20 => return Err(("control byte in a string", self.at)),
                Some(_) => self.at += 1,
            }
        }
    }

    /// Past the escape whose letter is under the cursor.
    fn escape(&mut self) -> Result<(), Stop> {
        match self.peek() {
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                self.at += 1;
                Ok(())
            }
            Some(b'u') => match self.bytes.get(self.at + 1..self.at + 5) {
                Some(hex) if hex.iter().all(u8::is_ascii_hexdigit) => {
                    self.at += 5;
                    Ok(())
                }
                _ => Err(("bad escape", self.at)),
            },
            _ => Err(("bad escape", self.at)),
        }
    }
}

/// The base-128 little-endian varint at `at`: its value and the byte after
/// it. Seven bits a byte, low bits first, the high bit saying another byte
/// follows; ten bytes carry sixty-four bits and an eleventh is refused.
///
/// # Errors
/// The bytes end inside the varint, or it runs past ten bytes.
pub fn varint(bytes: &[u8], at: usize) -> Result<(u64, usize), Stop> {
    let mut value: u64 = 0;
    for (index, byte) in bytes.get(at..).unwrap_or(&[]).iter().enumerate() {
        if index >= 10 {
            return Err(("a varint runs past ten bytes", at));
        }
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok((value, at + index + 1));
        }
    }
    Err(("the bytes end inside a varint", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cursor_peeks_skips_whitespace_and_takes_a_string_as_written() {
        let mut scan = Scan::new(b" \t\r\n\"a\\\"b\\u00e9\" x");
        scan.whitespace();
        assert_eq!(scan.at, 4);
        assert_eq!(scan.peek(), Some(b'"'));
        assert_eq!(scan.string(), Ok(&b"a\\\"b\\u00e9"[..]));
        assert_eq!(scan.rest(), b" x");
        scan.whitespace();
        assert_eq!(scan.peek(), Some(b'x'));
        scan.at += 1;
        assert_eq!(scan.peek(), None);
        assert_eq!(scan.rest(), b"");
        assert_eq!(Scan::new(b"\"\"").string(), Ok(&b""[..]));
    }

    #[test]
    fn a_string_stops_where_it_cannot_continue() {
        assert_eq!(
            Scan::new(b"\"abc").string(),
            Err(("unterminated string", 4))
        );
        assert_eq!(
            Scan::new(b"\"a\nb\"").string(),
            Err(("control byte in a string", 2))
        );
        assert_eq!(Scan::new(b"\"\\x\"").string(), Err(("bad escape", 2)));
        assert_eq!(Scan::new(b"\"\\u12G4\"").string(), Err(("bad escape", 2)));
        assert_eq!(Scan::new(b"\"\\u12").string(), Err(("bad escape", 2)));
        assert_eq!(Scan::new(b"\"\\").string(), Err(("bad escape", 2)));
    }

    #[test]
    fn a_varint_is_base_128_little_endian_and_stops_where_it_cannot_end() {
        assert_eq!(varint(&[0x96, 0x01], 0), Ok((150, 2)));
        assert_eq!(varint(&[0x00], 0), Ok((0, 1)));
        assert_eq!(varint(&[0x01, 0x02], 1), Ok((2, 2)));
        let largest = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(varint(&largest, 0), Ok((u64::MAX, 10)));
        assert_eq!(
            varint(&[0x80], 0),
            Err(("the bytes end inside a varint", 1))
        );
        assert_eq!(
            varint(&[0x80; 11], 0),
            Err(("a varint runs past ten bytes", 0))
        );
        assert_eq!(varint(&[], 3), Err(("the bytes end inside a varint", 0)));
    }
}
