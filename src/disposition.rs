//! Executable demonstration of ingress and message disposition.
//!
//! Records the runtime lifecycle from Xmip-Architecture-Specification-v1.2 section 2
//! and the disposition rules from ADR-0013 as running code. Every gate is printed,
//! and every refusal states what Xmip kept.

use crate::journey_model::{create_initial_message_with_treatment, Journey};
use crate::vertical_slice::business_treatment;

/// Where an identity came from, if anywhere.
pub enum Identity {
    /// Nothing presented by the caller, nothing implied by the Receive Location.
    Absent,
    /// Implied by the Receive Location itself, such as a partner drop folder.
    /// Still an identity: the path, the permissions and the account that could
    /// write there are the evidence. ADR-0019 clause 5.
    Implied(&'static str),
    /// Presented by the caller.
    Presented(&'static str),
}

/// Whether the transport identity and the message identity must resolve to the
/// same Party. ADR-0019 clause 7, which takes its structure from DMARC
/// (RFC 9989):
/// SPF proves the envelope sender, DKIM proves the author domain, and the
/// policy between them is a third thing.
pub enum Alignment {
    /// Record both, never compare. The relaying case, and the default: a
    /// default of Strict refuses every VAN, gateway and broker on day one.
    None,
    /// The same party through a different endpoint, matched at the party.
    Relaxed,
    /// Transport credential and message identity must name the same party.
    Strict,
}

/// What to do when alignment is required and fails.
pub enum OnMisalignment {
    Accept,
    Quarantine,
    Reject,
}

/// What the caller is attempting against Xmip.
pub enum Action {
    Send,
    Post,
    Poll,
}

impl Action {
    fn name(&self) -> &'static str {
        match self {
            Action::Send => "send",
            Action::Post => "post",
            Action::Poll => "poll",
        }
    }
}

/// One incoming Stream and the outcome of every gate it meets.
pub struct Arrival {
    pub receive_location: &'static str,
    pub transport: &'static str,
    pub origin_uri: String,
    pub bytes: usize,
    pub action: Action,
    /// Who opened the connection. Mandatory: transport security runs before
    /// Message creation, so Xmip never parses content from an unauthorized
    /// sender.
    pub transport_identity: Identity,
    pub authentication: Result<&'static str, &'static str>,
    pub authorization: Result<&'static str, &'static str>,
    pub message_creation: Result<&'static str, &'static str>,
    /// On whose behalf the content was produced. Optional, and absent for most
    /// of the estate: a CSV over SFTP has nowhere to carry one. Read only after
    /// Message creation, which is what separates the two layers.
    pub message_identity: Identity,
    pub alignment: Alignment,
    pub on_misalignment: OnMisalignment,
    pub contract: &'static str,
    pub validation: Result<&'static str, &'static str>,
    pub subscriptions: &'static [&'static str],
    pub can_respond: bool,
}

/// What Xmip did with the Stream, and what it kept.
pub enum Disposition {
    RefusedAtIdentification,
    RefusedAtAuthentication,
    RefusedAtAuthorization,
    RefusedAtMessageCreation,
    StoredAtValidation,
    DeadMessageQueue,
    Routed,
}

impl Disposition {
    /// What Xmip retained. This is the column that matters.
    pub fn kept(&self) -> &'static str {
        match self {
            Disposition::RefusedAtIdentification => "nothing",
            Disposition::RefusedAtAuthentication => "nothing",
            Disposition::RefusedAtAuthorization => "nothing",
            Disposition::RefusedAtMessageCreation => "Stream, by xmip-core-retain",
            Disposition::StoredAtValidation => "Message, by xmip-core-retain",
            Disposition::DeadMessageQueue => "Message, in the Xmip DMQ",
            Disposition::Routed => "Message, owned by Xmip",
        }
    }
}

fn step(n: &str, name: &str, detail: &str) {
    println!("  {:>2}  {:<26} {}", n, name, detail);
}

fn refused(gate: &str, kept: &str) {
    println!("      refused at {}", gate);
    println!("      kept: {}   audited as a transport event", kept);
}

/// Walk one Arrival through the lifecycle, printing each step.
///
/// Returns the Disposition and, where one was created, the Journey.
pub fn admit(a: &Arrival) -> (Disposition, Option<Journey>) {
    println!();
    println!(
        "{}   {}   {} bytes   {}",
        a.receive_location,
        a.origin_uri,
        a.bytes,
        a.action.name()
    );

    // Steps 1 to 3: transport security. Always, and before any content is read.
    match a.transport_identity {
        Identity::Absent => {
            step("1", "transport identity", "none presented, none implied");
            refused("transport identification", "nothing");
            return (Disposition::RefusedAtIdentification, None);
        }
        Identity::Implied(who) => {
            step("1", "transport identity", who);
            println!("      implied by the Receive Location, no credential presented");
        }
        Identity::Presented(who) => {
            step("1", "transport identity", who);
        }
    }

    match a.authentication {
        Ok(how) => step("2", "transport authentication", how),
        Err(why) => {
            step("2", "transport authentication", why);
            refused("transport authentication", "nothing");
            return (Disposition::RefusedAtAuthentication, None);
        }
    }

    match a.authorization {
        Ok(how) => step("3", "transport authorization", how),
        Err(why) => {
            step("3", "transport authorization", why);
            refused("transport authorization", "nothing");
            return (Disposition::RefusedAtAuthorization, None);
        }
    }

    // Step 4: Message creation. Nothing before this point parsed any content.
    match a.message_creation {
        Ok(what) => step("4", "message creation", what),
        Err(why) => {
            step("4", "message creation", why);
            println!("      refused at message creation, no Message exists");
            println!("      kept: Stream, by xmip-core-retain   the sender is known");
            return (Disposition::RefusedAtMessageCreation, None);
        }
    }

    step("5", "default promotion", "message.type, destination");
    step(
        "6",
        "configuration inspect",
        "message security not required here",
    );
    // Steps 7 to 9: message security. Optional, and separate. Both identities
    // are kept: collapsing them loses the distinction exactly when a dispute
    // about who sent what needs both. ADR-0019 clause 6.
    match a.message_identity {
        Identity::Absent => {
            step("7", "message identity", "none in this representation");
            step("8", "message authentication", "not applicable");
            step("9", "message authorization", "transport identity decides");
        }
        Identity::Implied(who) | Identity::Presented(who) => {
            step("7", "message identity", who);
            step("8", "message authentication", "verified");

            let aligned = match a.alignment {
                Alignment::None => true,
                Alignment::Relaxed | Alignment::Strict => match a.transport_identity {
                    Identity::Absent => true,
                    Identity::Implied(t) | Identity::Presented(t) => t == who,
                },
            };

            if matches!(a.alignment, Alignment::None) {
                step("9", "message authorization", "not compared, both recorded");
            } else if aligned {
                step("9", "message authorization", "aligned");
            } else {
                match a.on_misalignment {
                    OnMisalignment::Accept => {
                        step("9", "message authorization", "misaligned, accepted");
                        println!("      misalignment recorded and audited");
                    }
                    OnMisalignment::Quarantine => {
                        step("9", "message authorization", "misaligned, quarantined");
                        println!("      to the Xmip DMQ with both identities");
                    }
                    OnMisalignment::Reject => {
                        step("9", "message authorization", "misaligned, rejected");
                        refused("message authorization", "the Message, under retention");
                        return (Disposition::RefusedAtAuthorization, None);
                    }
                }
            }
        }
    }
    step("10", "contract implication", a.contract);
    step("11", "deserialization", "ok");

    // Step 12: Validation. A failure here stops before any Journey exists.
    match a.validation {
        Ok(what) => step("12", "validation", what),
        Err(why) => {
            step("12", "validation", why);
            if a.can_respond {
                println!(
                    "      responded to the caller immediately, the transport carries a reply"
                );
            } else {
                println!("      no reply channel, the audit record is the only trace");
            }
            println!("      no Journey created");
            println!("      kept: Message, by xmip-core-retain");
            return (Disposition::StoredAtValidation, None);
        }
    }

    // Step 13: Journey creation. Only now, and only once.
    let (journey, message) =
        create_initial_message_with_treatment(a.origin_uri.clone(), business_treatment());
    step("13", "journey created", "one Journey for this interchange");
    println!(
        "      journey {}   message {}   state {:?}",
        journey.journey_id, message.message_id, journey.state
    );

    // Routing. Subscriptions are matched within the Journey, not outside it.
    if a.subscriptions.is_empty() {
        println!("      published, 0 subscriptions matched");
        println!("      to the Xmip DMQ, final disposition, notified");
        return (Disposition::DeadMessageQueue, Some(journey));
    }

    println!(
        "      published, {} subscriptions matched",
        a.subscriptions.len()
    );
    for s in a.subscriptions {
        println!("        {}  executed within this Journey", s);
    }

    (Disposition::Routed, Some(journey))
}
