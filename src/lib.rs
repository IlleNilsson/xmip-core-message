#![forbid(unsafe_code)]

use std::sync::Arc;
use xmip_context::MessageContext;
use xmip_core::{JourneyId, MessageId, SectionId};
use xmip_stream::Stream;

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
    journey_id: JourneyId,
    sections: Arc<[MessageSection]>,
    context: Arc<MessageContext>,
}

impl Message {
    pub fn new(
        message_id: MessageId,
        journey_id: JourneyId,
        sections: impl Into<Arc<[MessageSection]>>,
        context: MessageContext,
    ) -> Self {
        Self {
            message_id,
            journey_id,
            sections: sections.into(),
            context: Arc::new(context),
        }
    }

    pub const fn message_id(&self) -> MessageId { self.message_id }
    pub const fn journey_id(&self) -> JourneyId { self.journey_id }
    pub fn sections(&self) -> &[MessageSection] { &self.sections }
    pub fn context(&self) -> &MessageContext { &self.context }

    pub fn derive(
        &self,
        new_message_id: MessageId,
        sections: impl Into<Arc<[MessageSection]>>,
        context: MessageContext,
    ) -> Self {
        Self::new(new_message_id, self.journey_id, sections, context)
    }
}
