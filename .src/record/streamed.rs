//! Delimited records read from a reader a piece at a time, and written:
//! what a transform or a contract that never holds a whole CSV walks it
//! with. The records are cut by the one walk ([`Delimited::records`]);
//! this only says where a piece of the Stream ends on a whole record, so
//! a record is never cut between two pieces, and holds one piece and the
//! record that straddles it at a time.

use std::io::{self, Read};

use super::{Delimited, Record};

/// Why a walk of streamed records stopped.
#[derive(Debug)]
pub enum Walked<E> {
    /// The reader failed.
    Read(io::Error),
    /// The records cannot be cut there: the reason and the byte, counted
    /// from the Stream's start.
    Stopped(&'static str, u64),
    /// What the caller handed each record refused it.
    Refused(E),
}

impl Delimited {
    /// How much of `bytes` ends on a whole record: up to and with the last
    /// line break outside quotes, nothing where there is none.
    #[must_use]
    pub fn complete(&self, bytes: &[u8]) -> usize {
        let mut quoted = false;
        let mut whole = 0;
        for (at, byte) in bytes.iter().enumerate() {
            if *byte == self.quote {
                // A doubled quote toggles twice, as it should.
                quoted = !quoted;
            } else if *byte == b'\n' && !quoted {
                whole = at + 1;
            }
        }
        whole
    }

    /// Walk the records read from `input`, `piece` bytes at a time, handing
    /// each to `each` with the bytes its ranges index; a record is numbered
    /// in the order of the whole Stream.
    ///
    /// # Errors
    /// The reader failed, a record cannot be cut, or `each` refused one.
    pub fn read_records<E>(
        &self,
        input: &mut dyn Read,
        piece: usize,
        mut each: impl FnMut(&[u8], &Record) -> Result<(), E>,
    ) -> Result<(), Walked<E>> {
        let mut buffer: Vec<u8> = Vec::with_capacity(piece);
        let mut offset = 0u64;
        let mut numbered = 0;
        let wanted = u64::try_from(piece).unwrap_or(u64::MAX);
        loop {
            // A whole piece read before the records are cut, however little
            // each read of the reader gives, and nothing zeroed first: a
            // reader giving a record a read cut and cleared a piece for each,
            // and 18 MiB of CSV took eight minutes.
            let read = Read::take(&mut *input, wanted)
                .read_to_end(&mut buffer)
                .map_err(Walked::Read)?;
            let last = read == 0;
            let whole = if last {
                buffer.len()
            } else {
                self.complete(&buffer)
            };
            let before = numbered;
            for record in self.records(&buffer[..whole]) {
                let mut record =
                    record.map_err(|(why, at)| Walked::Stopped(why, offset + at as u64))?;
                record.number += before;
                each(&buffer[..whole], &record).map_err(Walked::Refused)?;
                numbered = record.number;
            }
            offset += whole as u64;
            buffer.drain(..whole);
            if last {
                return Ok(());
            }
        }
    }

    /// Append one record of `fields` to `out`, ended by CR LF (RFC 4180),
    /// each field quoted where it carries the separator, the quote or a
    /// line break, its quotes doubled.
    pub fn write_record<'a>(&self, fields: impl IntoIterator<Item = &'a [u8]>, out: &mut Vec<u8>) {
        for (index, field) in fields.into_iter().enumerate() {
            if index > 0 {
                out.push(self.separator);
            }
            let quoted = field
                .iter()
                .any(|byte| [self.separator, self.quote, b'\r', b'\n'].contains(byte));
            if !quoted {
                out.extend_from_slice(field);
                continue;
            }
            out.push(self.quote);
            for byte in field {
                if *byte == self.quote {
                    out.push(self.quote);
                }
                out.push(*byte);
            }
            out.push(self.quote);
        }
        out.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_piece_ends_on_the_last_line_break_outside_quotes() {
        let csv = Delimited::default();
        assert_eq!(csv.complete(b"a,b\nc,\"d\ne"), 4);
        assert_eq!(csv.complete(b"a,\"\"\"x\"\n"), 8);
        assert_eq!(csv.complete(b"no break"), 0);
    }

    #[test]
    fn records_cut_between_pieces_are_walked_whole_and_numbered_in_order() {
        let csv = Delimited::default();
        let text = b"id,note\r\n1,\"two\nlines\"\r\n2,plain\r\n3,\"a,b\"";
        let mut seen = Vec::new();
        let walked: Result<(), Walked<()>> =
            csv.read_records(&mut &text[..], 5, |bytes, record| {
                let note = csv.unquote(record.field(bytes, 1).unwrap_or_default());
                seen.push((record.number, String::from_utf8_lossy(&note).into_owned()));
                Ok(())
            });
        assert!(walked.is_ok(), "{walked:?}");
        assert_eq!(
            seen,
            [
                (1, "note".into()),
                (2, "two\nlines".into()),
                (3, "plain".into()),
                (4, "a,b".into())
            ]
        );
    }

    #[test]
    fn a_stop_names_its_byte_in_the_whole_stream() {
        let csv = Delimited::default();
        let walked = csv.read_records(&mut &b"a,b\nc,\"d\"x\n"[..], 4, |_, _| Ok::<(), ()>(()));
        assert!(
            matches!(
                walked,
                Err(Walked::Stopped("content after a closing quote", 9))
            ),
            "{walked:?}"
        );
    }

    #[test]
    fn a_record_is_written_quoted_where_it_must_be() {
        let mut out = Vec::new();
        let csv = Delimited::separated_by(b';');
        csv.write_record(
            [&b"plain"[..], b"a;b", b"say \"hi\"", b"two\nlines"],
            &mut out,
        );
        assert_eq!(out, b"plain;\"a;b\";\"say \"\"hi\"\"\";\"two\nlines\"\r\n");
        let read: Vec<_> = csv.records(&out).collect();
        assert_eq!(read.len(), 1);
    }
}
