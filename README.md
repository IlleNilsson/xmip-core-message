# xmip-core-message

The Message: a processing unit over immutable content. A Message has an
identity, metadata, and one or more Sections, each pointing at a Stream; it
carries its generation, its creation source and its treatment — the three
presets a Message declares, `MessageTreatment::CONVERSATION`, `BUSINESS` (the
default) and `PASS_THROUGH`, are written here beside the type — and the shape
readers and records the content technologies share (ADR-0044).

The Protocol Buffers wire format is here once, both halves (`protobuf`):
the walk the protobuf shape sections by and the protobuf contract checks a
schema against, and the writer — a tag, a varint, eight bytes, a
length-delimited field, and an embedded message written in place with its
length put before it afterwards (`write_message`). What writes protobuf in
the estate writes it with these, the observe capability's OTLP exporter
first; nothing carries prost.

The scanning shapes — JSON, XML, an Avro schema — walk `codec::cursor::Cursor`,
the estate's one byte cursor; what they share over it is here in `scan`: a
quoted string as JSON writes one, and where a varint lies in the bytes.

A Message's one binary form, what the Ledger keeps as the body of Xmip
Storage's Message record, is here with the type (`message_record`):
`Message::record` writes it — the form's number, the identifiers, lineage,
treatment and Context in their order, and each Section's Stream by its
identifier, length and media type, never its bytes, which the Ledger keeps
in chunks — and `Message::from_record` reads it back, each Stream kept
(`Stream::kept`) where its caller reads it from, never whole. Binary, not JSON: the estate keeps no JSON at rest
(ADR-0031 clause 3), and the record is written for every Message.

The Stream is immutable and the Message is not: context, promoted properties
and execution history accumulate as it is handled, while the content it refers
to never changes. Content changes only through Assignment or Transformation,
which create a new Stream and a new generation. A Message does not know its
Journey — Journeys reference Messages, never the reverse (ADR-0013 clause 4b) —
and routing alone creates no new Message.

`doc/terminology.md`, *Message and Section*, and
`doc/architecture/runtime-model.md` sections 2 and 3 govern it; each
representation is a technology mounted under this repository, and
`architecture.toml` names them.
