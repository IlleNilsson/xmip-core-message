//! What the scanning shapes share over the one byte cursor,
//! `codec::cursor::Cursor` (ADR-0044): a quoted string as JSON writes one,
//! which a JSON document and an Avro schema both take, and where a varint
//! lies in the bytes. What a grammar makes of the bytes stays with the
//! technology (ADR-0044 clause 2): this file is the walking, not the reading.
//!
//! The varint and Avro's zig-zag over it are `codec::varint`, the estate's
//! one.

use codec::cursor::Cursor;
use codec::varint::VarintError;

use crate::Stop;

/// The string whose opening quote is under the cursor: the raw bytes between
/// the quotes, escapes as JSON writes them and left as written. The cursor
/// ends after the closing quote.
///
/// # Errors
/// The string never closes, carries a control byte, or carries an escape
/// JSON does not have.
pub fn string<'a>(cursor: &mut Cursor<'a>) -> Result<&'a [u8], Stop> {
    cursor.advance(1);
    let start = cursor.position();
    loop {
        match cursor.peek() {
            None => return Err(("unterminated string", cursor.position())),
            Some(b'"') => {
                let raw = cursor.since(start);
                cursor.advance(1);
                return Ok(raw);
            }
            Some(b'\\') => {
                cursor.advance(1);
                escape(cursor)?;
            }
            Some(byte) if byte < 0x20 => {
                return Err(("control byte in a string", cursor.position()));
            }
            Some(_) => cursor.advance(1),
        }
    }
}

/// Past the escape whose letter is under the cursor.
fn escape(cursor: &mut Cursor<'_>) -> Result<(), Stop> {
    let at = cursor.position();
    match cursor.peek() {
        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
            cursor.advance(1);
            Ok(())
        }
        Some(b'u') => match cursor.remaining().get(1..5) {
            Some(hex) if hex.iter().all(u8::is_ascii_hexdigit) => {
                cursor.advance(5);
                Ok(())
            }
            _ => Err(("bad escape", at)),
        },
        _ => Err(("bad escape", at)),
    }
}

/// The varint at `at`, which `protobuf` and `avro` both write their
/// integers as: its value and the byte after it, a refusal placed where it
/// happened — the end of the bytes for one cut off, its first byte for one
/// past ten bytes. The varint itself is `codec::varint`; the placement is
/// what a shape's [`Stop`] says.
///
/// # Errors
/// The bytes end inside the varint, or it runs past ten bytes.
pub fn varint(bytes: &[u8], at: usize) -> Result<(u64, usize), Stop> {
    match codec::varint::decode(bytes.get(at..).unwrap_or(&[])) {
        Ok((value, length)) => Ok((value, at + length)),
        Err(error @ VarintError::Unterminated) => Err((error.as_str(), bytes.len())),
        Err(error @ VarintError::Overlong) => Err((error.as_str(), at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_is_taken_as_written_and_the_cursor_ends_after_it() {
        let mut cursor = Cursor::new(b" \t\r\n\"a\\\"b\\u00e9\" x");
        cursor.skip_whitespace();
        assert_eq!(cursor.position(), 4);
        assert_eq!(string(&mut cursor), Ok(&b"a\\\"b\\u00e9"[..]));
        assert_eq!(cursor.remaining(), b" x");
        assert_eq!(string(&mut Cursor::new(b"\"\"")), Ok(&b""[..]));
    }

    #[test]
    fn a_string_stops_where_it_cannot_continue() {
        let taken = |bytes: &[u8]| string(&mut Cursor::new(bytes)).map(<[u8]>::to_vec);
        assert_eq!(taken(b"\"abc"), Err(("unterminated string", 4)));
        assert_eq!(taken(b"\"a\nb\""), Err(("control byte in a string", 2)));
        assert_eq!(taken(b"\"\\x\""), Err(("bad escape", 2)));
        assert_eq!(taken(b"\"\\u12G4\""), Err(("bad escape", 2)));
        assert_eq!(taken(b"\"\\u12"), Err(("bad escape", 2)));
        assert_eq!(taken(b"\"\\"), Err(("bad escape", 2)));
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
