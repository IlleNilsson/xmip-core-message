//! The shape of received content — the message technologies. ADR-0047.
//!
//! A transport delivers bytes. Before any contract validates them or any path
//! selects inside them, something has to say what they are: one JSON
//! document, a multipart body of three parts, an EDI interchange of segments,
//! a CSV of rows, or bytes that are nothing more than bytes. That is a shape.
//! A shape turns a Stream into the parts that become a Message's Sections and
//! names the message type the content announces — the root element, the
//! top-level type, the interchange kind — when it announces one.
//!
//! The Foundation owns the trait and the choice; a technology owns one shape.
//! Ids are the runtime's to mint, so a shape hands back parts, not Sections.

use stream::Stream;

/// One part of shaped content, before it has an id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// What the shape calls this part: a multipart name, a segment tag, a
    /// row number. `None` for the one part of a single-document shape.
    pub name: Option<String>,
    pub bytes: Vec<u8>,
    pub media_type: Option<String>,
}

impl Part {
    #[must_use]
    pub fn new(
        name: Option<String>,
        bytes: impl Into<Vec<u8>>,
        media_type: Option<String>,
    ) -> Self {
        Self {
            name,
            bytes: bytes.into(),
            media_type,
        }
    }

    /// The whole content as one nameless part with the media type it came
    /// with: what `binary` and `text` answer, and the fallback for the rest.
    #[must_use]
    pub fn whole(stream: &Stream) -> Self {
        Self::new(
            None,
            stream.bytes(),
            stream.media_type().map(str::to_string),
        )
    }
}

/// What a shape made of a Stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shaped {
    pub parts: Vec<Part>,
    /// The type the content announces, in the shape's own terms, when it
    /// announces one. Routing promotes it as `MessageType`.
    pub message_type: Option<String>,
}

/// A message technology: how bytes become the parts of a Message.
pub trait Shape: Send + Sync {
    /// The manifest leaf: `json`, `xml`, `multipart`, `edi-x12`, `binary`.
    fn technology(&self) -> &'static str;

    /// The media types this shape claims, lower-case, without parameters.
    fn media_types(&self) -> &'static [&'static str];

    /// Whether the bytes look like this shape, asked only when no media type
    /// says. `binary` says yes to everything and is asked last.
    fn recognises(&self, bytes: &[u8]) -> bool;

    /// The parts and the announced type.
    ///
    /// # Errors
    /// The content is not well-formed for this shape; the reason says where.
    fn shape(&self, stream: &Stream) -> Result<Shaped, ShapeError>;
}

/// Why content could not take a shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapeError {
    pub technology: String,
    pub reason: String,
    /// Where in the bytes the reason was found, when it was found somewhere.
    pub offset: Option<usize>,
}

impl ShapeError {
    #[must_use]
    pub fn new(technology: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            technology: technology.into(),
            reason: reason.into(),
            offset: None,
        }
    }

    #[must_use]
    pub fn at(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}

impl std::fmt::Display for ShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.offset {
            Some(offset) => write!(f, "{}: {} at byte {offset}", self.technology, self.reason),
            None => write!(f, "{}: {}", self.technology, self.reason),
        }
    }
}

impl std::error::Error for ShapeError {}

/// The media type of a Stream without its parameters, lower-case.
#[must_use]
pub fn media_type_of(stream: &Stream) -> Option<String> {
    stream
        .media_type()
        .map(|media| {
            media
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|media| !media.is_empty())
}

/// The shape for a Stream: the one that claims its media type, else the first
/// that recognises the bytes, in the order given. `None` when nothing does,
/// which a caller resolves with `binary` if it has one.
#[must_use]
pub fn choose<'a>(shapes: &[&'a dyn Shape], stream: &Stream) -> Option<&'a dyn Shape> {
    if let Some(media) = media_type_of(stream) {
        let claimed = shapes
            .iter()
            .find(|shape| shape.media_types().contains(&media.as_str()));
        if let Some(shape) = claimed {
            return Some(*shape);
        }
    }

    shapes
        .iter()
        .find(|shape| shape.recognises(stream.bytes()))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::StreamId;

    struct Lines;

    impl Shape for Lines {
        fn technology(&self) -> &'static str {
            "lines"
        }

        fn media_types(&self) -> &'static [&'static str] {
            &["text/lines"]
        }

        fn recognises(&self, bytes: &[u8]) -> bool {
            bytes.contains(&b'\n')
        }

        fn shape(&self, stream: &Stream) -> Result<Shaped, ShapeError> {
            if stream.is_empty() {
                return Err(ShapeError::new("lines", "no lines at all").at(0));
            }
            let parts = stream
                .bytes()
                .split(|byte| *byte == b'\n')
                .enumerate()
                .map(|(n, line)| Part::new(Some(n.to_string()), line, None))
                .collect();
            Ok(Shaped {
                parts,
                message_type: Some("lines".into()),
            })
        }
    }

    struct Whole;

    impl Shape for Whole {
        fn technology(&self) -> &'static str {
            "binary"
        }

        fn media_types(&self) -> &'static [&'static str] {
            &["application/octet-stream"]
        }

        fn recognises(&self, _: &[u8]) -> bool {
            true
        }

        fn shape(&self, stream: &Stream) -> Result<Shaped, ShapeError> {
            Ok(Shaped {
                parts: vec![Part::whole(stream)],
                message_type: None,
            })
        }
    }

    fn stream(bytes: &[u8], media: Option<&str>) -> Stream {
        Stream::new(StreamId::new(7), bytes.to_vec(), media.map(str::to_string))
    }

    #[test]
    fn a_media_type_chooses_first_and_recognition_second_in_order() {
        let shapes: [&dyn Shape; 2] = [&Lines, &Whole];
        let by_media = choose(&shapes, &stream(b"x", Some("Text/Lines; charset=utf-8")));
        assert_eq!(by_media.map(Shape::technology), Some("lines"));

        let by_look = choose(&shapes, &stream(b"a\nb", None));
        assert_eq!(by_look.map(Shape::technology), Some("lines"));

        let fallback = choose(&shapes, &stream(b"ab", Some("image/png")));
        assert_eq!(fallback.map(Shape::technology), Some("binary"));

        let nothing = choose(&[&Lines], &stream(b"ab", None));
        assert!(nothing.is_none());
    }

    #[test]
    fn shaping_yields_parts_and_a_type_and_says_where_it_failed() {
        let shaped = Lines.shape(&stream(b"a\nb", None)).expect("well-formed");
        assert_eq!(shaped.parts.len(), 2);
        assert_eq!(shaped.parts[1].name.as_deref(), Some("1"));
        assert_eq!(shaped.parts[1].bytes, b"b");
        assert_eq!(shaped.message_type.as_deref(), Some("lines"));

        let failed = Lines.shape(&stream(b"", None)).expect_err("empty");
        assert_eq!(failed.offset, Some(0));
        assert_eq!(failed.to_string(), "lines: no lines at all at byte 0");
    }

    #[test]
    fn the_whole_part_keeps_the_media_type_and_parameters_are_dropped_for_choosing() {
        let source = stream(b"\x00\x01", Some("application/octet-stream; x=1"));
        let whole = Part::whole(&source);
        assert_eq!(
            whole.media_type.as_deref(),
            Some("application/octet-stream; x=1")
        );
        assert_eq!(
            media_type_of(&source).as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(media_type_of(&stream(b"", Some(" ; "))), None);
    }
}
