# xmip-core-message

The Message: a processing unit over immutable content. A Message has an
identity, metadata, and one or more Sections, each pointing at a Stream; it
carries its generation, its creation source and its treatment — the three
presets a Message declares, `MessageTreatment::CONVERSATION`, `BUSINESS` (the
default) and `PASS_THROUGH`, are written here beside the type — and the shape
readers and records the content technologies share (ADR-0044).

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
