#![forbid(unsafe_code)]

//! The Message: a processing unit over immutable content.
//!
//! **The Stream is immutable. The Message is not.** Context, promoted
//! properties and execution history accumulate here as the Message is handled.
//! What never changes is the content it refers to. Content changes only through
//! Assignment or Transformation, and those create a new Stream and a new
//! generation rather than editing anything.
//!
//! Merged with the platform repository's `src/journey_model.rs` on 2026-08-26.
//! Sections and Context came from here; generation, creation source and
//! treatment came from there. Two things did not survive the merge:
//!
//! - `journey_id`, per ADR-0013 clause 4b. A Message is published and *then*
//!   subscribers open Journeys over it, so one Message may belong to several. A
//!   single journey identity could not express that. Journeys reference
//!   Messages, never the reverse.
//! - `StreamRef.immutable`, a flag that was always true. It read as though a
//!   mutable Stream were possible; nothing in Xmip permits one. Sections carry
//!   the Stream directly.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use xmip_context::MessageContext;
use xmip_core::{MessageId, SectionId};
use xmip_stream::Stream;

/// What produced this Message.
///
/// `Assignment` and `Transformation` are the two that end a generation.
/// Assignment changes metadata and keeps the content; Transformation produces
/// new content and therefore a new Stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessageCreationSource {
    Receive,
    Assignment,
    Transformation,
    SendPreparation,
}

/// How urgently this Message should be picked up relative to others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessagePriority {
    Immediate,
    High,
    Normal,
    Low,
    Background,
}

/// What kind of work this is, which decides how much ceremony it earns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionProfile {
    /// A caller is waiting. Latency matters more than history.
    Conversation,
    /// The default. Full history, full recovery.
    Business,
    /// Moved, not understood. No content handling on the way through.
    PassThrough,
}

/// What survives a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessageDurability {
    /// Lost on restart, and that is acceptable for this Message.
    Ephemeral,
    /// Written down, but not resumed automatically.
    Durable,
    /// Written down and resumed from where it stopped.
    Recoverable,
}

/// How a Message is to be handled, independent of its format or its size.
///
/// A two-kilobyte order and a two-gigabyte export can both be `Immediate` and
/// `Recoverable`. Treatment is a declaration about the work, not a measurement
/// of the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageTreatment {
    pub priority: MessagePriority,
    pub execution_profile: ExecutionProfile,
    pub durability: MessageDurability,
}

impl Default for MessageTreatment {
    fn default() -> Self {
        Self {
            priority: MessagePriority::Normal,
            execution_profile: ExecutionProfile::Business,
            durability: MessageDurability::Recoverable,
        }
    }
}

/// One addressable part of a Message, over one Stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageSection {
    pub section_id: SectionId,
    pub name: Option<String>,
    pub stream: Stream,
    pub contract: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    message_id: MessageId,
    previous_message_id: Option<MessageId>,
    generation: u32,
    created_by: MessageCreationSource,
    treatment: MessageTreatment,
    sections: Arc<[MessageSection]>,
    context: Arc<MessageContext>,
}

impl Message {
    /// A Message that starts a lineage. Generation zero, no predecessor.
    pub fn received(
        message_id: MessageId,
        sections: impl Into<Arc<[MessageSection]>>,
        context: MessageContext,
        treatment: MessageTreatment,
    ) -> Self {
        Self {
            message_id,
            previous_message_id: None,
            generation: 0,
            created_by: MessageCreationSource::Receive,
            treatment,
            sections: sections.into(),
            context: Arc::new(context),
        }
    }

    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// The Message this one was derived from, if any.
    ///
    /// This is generation lineage within one publication, not the Journey
    /// chain. `previous_journey_id` on the Journey is the separate question of
    /// which Journey a split came out of.
    pub const fn previous_message_id(&self) -> Option<MessageId> {
        self.previous_message_id
    }

    /// How many times content or metadata has changed since Receive.
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn created_by(&self) -> MessageCreationSource {
        self.created_by
    }

    pub const fn treatment(&self) -> MessageTreatment {
        self.treatment
    }

    pub fn sections(&self) -> &[MessageSection] {
        &self.sections
    }

    pub fn context(&self) -> &MessageContext {
        &self.context
    }

    /// New content: a Transformation, or a Send preparation that rewrites.
    ///
    /// The Sections are new because their Streams are new. Nothing was edited —
    /// the previous generation is still exactly as it was.
    pub fn transformed(
        &self,
        message_id: MessageId,
        sections: impl Into<Arc<[MessageSection]>>,
        context: MessageContext,
        created_by: MessageCreationSource,
    ) -> Self {
        Self {
            message_id,
            previous_message_id: Some(self.message_id),
            generation: self.generation + 1,
            created_by,
            treatment: self.treatment,
            sections: sections.into(),
            context: Arc::new(context),
        }
    }

    /// New metadata over the same content: an Assignment.
    ///
    /// The Sections are shared with the previous generation rather than copied,
    /// which is the payoff for the Stream being immutable.
    pub fn assigned(&self, message_id: MessageId, context: MessageContext) -> Self {
        Self {
            message_id,
            previous_message_id: Some(self.message_id),
            generation: self.generation + 1,
            created_by: MessageCreationSource::Assignment,
            treatment: self.treatment,
            sections: Arc::clone(&self.sections),
            context: Arc::new(context),
        }
    }

    /// Treatment is declared once and carried, not re-decided per generation.
    #[must_use]
    pub fn with_treatment(mut self, treatment: MessageTreatment) -> Self {
        self.treatment = treatment;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmip_core::StreamId;

    fn section(stream_id: u128, bytes: &[u8]) -> MessageSection {
        MessageSection {
            section_id: SectionId::new(stream_id),
            name: Some("body".to_string()),
            stream: Stream::new(StreamId::new(stream_id), bytes.to_vec(), None),
            contract: None,
        }
    }

    fn received() -> Message {
        Message::received(
            MessageId::new(1),
            vec![section(10, b"<order/>")],
            MessageContext::new(),
            MessageTreatment::default(),
        )
    }

    #[test]
    fn an_assignment_keeps_the_stream_and_advances_the_generation() {
        let first = received();
        let assigned = first.assigned(
            MessageId::new(2),
            MessageContext::new()
                .with_value("order.id", xmip_context::ContextValue::Text("A-1".into())),
        );

        assert_eq!(assigned.generation(), 1);
        assert_eq!(assigned.created_by(), MessageCreationSource::Assignment);
        assert_eq!(
            first.sections()[0].stream.id(),
            assigned.sections()[0].stream.id(),
            "assignment must not produce a new Stream"
        );
    }

    #[test]
    fn a_transformation_produces_a_new_stream() {
        let first = received();
        let transformed = first.transformed(
            MessageId::new(2),
            vec![section(11, b"<Order/>")],
            MessageContext::new(),
            MessageCreationSource::Transformation,
        );

        assert_ne!(
            first.sections()[0].stream.id(),
            transformed.sections()[0].stream.id()
        );
        assert_eq!(transformed.generation(), 1);
    }

    #[test]
    fn the_previous_generation_is_untouched() {
        let first = received();
        let _ = first.assigned(MessageId::new(2), MessageContext::new());

        assert_eq!(first.generation(), 0);
        assert_eq!(first.previous_message_id(), None);
        assert_eq!(first.created_by(), MessageCreationSource::Receive);
    }

    #[test]
    fn lineage_points_backwards_one_generation_at_a_time() {
        let first = received();
        let second = first.assigned(MessageId::new(2), MessageContext::new());
        let third = second.assigned(MessageId::new(3), MessageContext::new());

        assert_eq!(third.previous_message_id(), Some(second.message_id()));
        assert_eq!(second.previous_message_id(), Some(first.message_id()));
        assert_eq!(third.generation(), 2);
    }

    #[test]
    fn treatment_survives_derivation() {
        let treatment = MessageTreatment {
            priority: MessagePriority::Background,
            execution_profile: ExecutionProfile::PassThrough,
            durability: MessageDurability::Durable,
        };
        let first = received().with_treatment(treatment);
        let second = first.assigned(MessageId::new(2), MessageContext::new());

        assert_eq!(second.treatment(), treatment);
    }

    #[test]
    fn a_message_does_not_know_its_journey() {
        // ADR-0013 clause 4b. One Message may be picked up by several
        // Subscriptions, each opening its own Journey. If this compiles with a
        // journey accessor again, that decision has been undone by accident.
        let message = received();
        let _ = message.message_id();
    }
}
