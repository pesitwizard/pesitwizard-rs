//! Protocol state tables (§4.8), reconstructed from the Connect:Express implementation.
//!
//! States are named as in the specification: `CNxx` connection phase, `SFxx` file selection,
//! `OFxx` file open, `TDExx` data transfer where the local entity *writes* (sends) data, `TDLxx`
//! where it *reads* (receives) data, `MGxx` message service. Suffix `A` = requester side,
//! `B` = server side.

use crate::fpdu::FpduKind;

/// Protocol role of the local entity for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Role {
    /// Initiator of the connection (demandeur).
    Requester,
    /// Responder (serveur).
    Server,
}

macro_rules! states {
    ($( $name:ident = $label:expr; )*) => {
        /// Protocol state.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        pub enum State {
            $(
                #[doc = $label]
                $name,
            )*
        }

        impl State {
            /// Specification name of the state.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $( State::$name => stringify!($name), )* }
            }

            /// Description.
            #[must_use]
            pub const fn description(self) -> &'static str {
                match self { $( State::$name => $label, )* }
            }
        }
    };
}

states! {
    Cn01 = "Idle (not connected)";
    Cn02A = "Connection pending (waiting for ACONNECT/RCONNECT)";
    Cn02B = "Connection pending (waiting for the local F.CONNECT response)";
    Cn03 = "Connected";
    Cn04A = "Release pending (waiting for RELCONF)";
    Cn04B = "Release pending (waiting for the local F.RELEASE response)";
    Sf01A = "File creation pending (waiting for ACK(CREATE))";
    Sf01B = "File creation pending (waiting for the local F.CREATE response)";
    Sf02A = "File selection pending (waiting for ACK(SELECT))";
    Sf02B = "File selection pending (waiting for the local F.SELECT response)";
    Sf03 = "File selected";
    Sf04A = "File deselection pending (waiting for ACK(DESELECT))";
    Sf04B = "File deselection pending (waiting for the local F.DESELECT response)";
    Of01A = "File open pending (waiting for ACK(ORF))";
    Of01B = "File open pending (waiting for the local F.OPEN response)";
    Of02 = "Data transfer idle (file open)";
    Of03A = "File close pending (waiting for ACK(CRF))";
    Of03B = "File close pending (waiting for the local F.CLOSE response)";
    Tde01A = "Write start pending (waiting for ACK(WRITE))";
    Tde02A = "Writing: sending data";
    Tde03A = "Writing: resynchronisation pending (waiting for ACK(RESYN))";
    Tde04A = "Writing: resynchronisation pending (waiting for the local F.RESTART response)";
    Tde05A = "Writing: interruption pending (waiting for ACK(IDT))";
    Tde06A = "Writing: interruption pending (waiting for the local F.CANCEL response)";
    Tde07A = "Writing: end of data sent";
    Tde08A = "Writing: end of transfer pending (waiting for ACK(TRANS.END))";
    Tde01B = "Write start pending (waiting for the local F.WRITE response)";
    Tde02B = "Writing: receiving data";
    Tde03B = "Receiving: resynchronisation pending (waiting for ACK(RESYN))";
    Tde04B = "Receiving: resynchronisation pending (waiting for the local F.RESTART response)";
    Tde05B = "Receiving: interruption pending (waiting for ACK(IDT))";
    Tde06B = "Receiving: interruption pending (waiting for the local F.CANCEL response)";
    Tde07B = "Receiving: end of data received";
    Tde08B = "Receiving: end of transfer pending (waiting for the local F.TRANSFER.END response)";
    Tdl01A = "Read start pending (waiting for ACK(READ))";
    Tdl02A = "Reading: receiving data";
    Tdl03A = "Reading: resynchronisation pending (waiting for ACK(RESYN))";
    Tdl04A = "Reading: resynchronisation pending (waiting for the local F.RESTART response)";
    Tdl05A = "Reading: interruption pending (waiting for ACK(IDT))";
    Tdl06A = "Reading: interruption pending (waiting for the local F.CANCEL response)";
    Tdl07A = "Reading: end of data received";
    Tdl08A = "Reading: end of transfer pending (waiting for ACK(TRANS.END))";
    Tdl01B = "Read start pending (waiting for the local F.READ response)";
    Tdl02B = "Reading: sending data";
    Tdl03B = "Sending: resynchronisation pending (waiting for ACK(RESYN))";
    Tdl04B = "Sending: resynchronisation pending (waiting for the local F.RESTART response)";
    Tdl05B = "Sending: interruption pending (waiting for ACK(IDT))";
    Tdl06B = "Sending: interruption pending (waiting for the local F.CANCEL response)";
    Tdl07B = "Sending: end of data sent";
    Tdl08B = "Sending: end of transfer pending (waiting for the local F.TRANSFER.END response)";
    Mg01A = "Message: sending segments";
    Mg01B = "Message: receiving segments";
    Mg04A = "Message sent (waiting for ACK(MSG))";
    Mg04B = "Message received (waiting for the local F.MESSAGE response)";
}

/// Local (service user / implementation) events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalEvent {
    /// F.ABORT request: send ABORT and return to idle.
    Abort,
    /// F.CONNECT request.
    Connect,
    /// F.RELEASE request.
    Release,
    /// F.CREATE request.
    Create,
    /// F.SELECT request.
    Select,
    /// F.DESELECT request.
    Deselect,
    /// F.OPEN request.
    Open,
    /// F.CLOSE request.
    Close,
    /// F.WRITE request.
    Write,
    /// F.READ request.
    Read,
    /// F.MESSAGE request.
    Message,
    /// F.CANCEL request (send IDT).
    Cancel,
    /// F.DATA request (send DTF).
    SendData,
    /// F.CHECK request (send SYN).
    Sync,
    /// F.DATA.END request (send DTF.END).
    DataEnd,
    /// F.TRANSFER.END request (send TRANS.END).
    TransferEnd,
    /// F.RESTART request (send RESYN).
    Resync,
    /// Positive local response to a pending indication (send the positive acknowledgement).
    Accept,
    /// Negative local response to a pending indication (send the negative acknowledgement).
    Reject,
}

/// An event applied to the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Event {
    /// A FPDU received from the peer; `negative` is set for acknowledgements carrying a
    /// non-zero diagnostic.
    Received {
        /// Kind of the received FPDU.
        kind: FpduKind,
        /// Negative acknowledgement flag.
        negative: bool,
    },
    /// A local request or response.
    Local(LocalEvent),
}

impl Event {
    /// Received FPDU event.
    #[must_use]
    pub const fn received(kind: FpduKind, negative: bool) -> Self {
        Event::Received { kind, negative }
    }

    /// Local event.
    #[must_use]
    pub const fn local(e: LocalEvent) -> Self {
        Event::Local(e)
    }
}

/// Outcome of applying an event to a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Move to the given state.
    Next(State),
    /// The event is valid but ignored in this state (e.g. a late ACK(SYN)).
    Ignore,
    /// Protocol error: the event is not allowed in this state.
    Error,
}

impl State {
    /// Initial state.
    pub const INITIAL: State = State::Cn01;

    /// Whether the local entity is currently sending file data.
    #[must_use]
    pub const fn is_sending(self) -> bool {
        matches!(self, State::Tde02A | State::Tdl02B)
    }

    /// Whether the local entity is currently receiving file data.
    #[must_use]
    pub const fn is_receiving(self) -> bool {
        matches!(self, State::Tde02B | State::Tdl02A)
    }

    /// Whether the connection phase is established (CN03 or any deeper phase).
    #[must_use]
    pub const fn is_connected(self) -> bool {
        !matches!(self, State::Cn01 | State::Cn02A | State::Cn02B)
    }

    /// Whether the state belongs to the data transfer phase.
    #[must_use]
    pub fn in_transfer(self) -> bool {
        self.name().starts_with("Td")
    }

    /// Apply an event (§4.8 tables).
    #[must_use]
    pub fn apply(self, event: Event) -> Outcome {
        use FpduKind as K;
        use LocalEvent as L;
        use Outcome::{Error, Ignore, Next};
        use State as S;
        // ABORT (local or received) is valid everywhere and returns to idle.
        if matches!(
            event,
            Event::Local(L::Abort) | Event::Received { kind: K::Abort, .. }
        ) {
            return Next(S::Cn01);
        }
        let recv = |k: K| Event::Received {
            kind: k,
            negative: false,
        };
        let nack = |k: K| Event::Received {
            kind: k,
            negative: true,
        };
        let loc = Event::Local;
        let is_data = matches!(event, Event::Received { kind, .. } if kind.is_data());
        match self {
            S::Cn01 => match event {
                e if e == loc(L::Connect) => Next(S::Cn02A),
                e if e == recv(K::Connect) => Next(S::Cn02B),
                _ => Error,
            },
            S::Cn02A => match event {
                e if e == recv(K::Aconnect) => Next(S::Cn03),
                e if e == recv(K::Rconnect) || e == nack(K::Rconnect) || e == nack(K::Aconnect) => {
                    Next(S::Cn01)
                }
                _ => Error,
            },
            S::Cn02B => match event {
                e if e == loc(L::Accept) => Next(S::Cn03),
                e if e == loc(L::Reject) => Next(S::Cn01),
                _ => Error,
            },
            S::Cn03 => match event {
                e if e == loc(L::Release) => Next(S::Cn04A),
                e if e == recv(K::Release) => Next(S::Cn04B),
                e if e == loc(L::Select) => Next(S::Sf02A),
                e if e == loc(L::Create) => Next(S::Sf01A),
                e if e == recv(K::Select) => Next(S::Sf02B),
                e if e == recv(K::Create) => Next(S::Sf01B),
                e if e == loc(L::Message) => Next(S::Mg01A),
                e if e == recv(K::Msg) => Next(S::Mg04B),
                e if e == recv(K::MsgDm) => Next(S::Mg01B),
                _ => Error,
            },
            S::Cn04A => match event {
                e if e == recv(K::Relconf) => Next(S::Cn01),
                _ => Error,
            },
            S::Cn04B => match event {
                e if e == loc(L::Accept) || e == loc(L::Reject) => Next(S::Cn01),
                _ => Error,
            },
            S::Sf01A => match event {
                e if e == recv(K::AckCreate) => Next(S::Sf03),
                e if e == nack(K::AckCreate) => Next(S::Cn03),
                _ => Error,
            },
            S::Sf01B | S::Sf02B => match event {
                e if e == loc(L::Accept) => Next(S::Sf03),
                e if e == loc(L::Reject) => Next(S::Cn03),
                _ => Error,
            },
            S::Sf02A => match event {
                e if e == recv(K::AckSelect) => Next(S::Sf03),
                e if e == nack(K::AckSelect) => Next(S::Cn03),
                _ => Error,
            },
            S::Sf03 => match event {
                e if e == loc(L::Deselect) => Next(S::Sf04A),
                e if e == recv(K::Deselect) => Next(S::Sf04B),
                e if e == loc(L::Open) => Next(S::Of01A),
                e if e == recv(K::Orf) => Next(S::Of01B),
                _ => Error,
            },
            S::Sf04A => match event {
                e if e == recv(K::AckDeselect) || e == nack(K::AckDeselect) => Next(S::Cn03),
                _ => Error,
            },
            S::Of01A => match event {
                e if e == recv(K::AckOrf) => Next(S::Of02),
                e if e == nack(K::AckOrf) => Next(S::Sf03),
                _ => Error,
            },
            S::Of01B => match event {
                e if e == loc(L::Accept) => Next(S::Of02),
                e if e == loc(L::Reject) => Next(S::Sf03),
                _ => Error,
            },
            S::Of02 => match event {
                e if e == loc(L::Close) => Next(S::Of03A),
                e if e == recv(K::Crf) => Next(S::Of03B),
                e if e == loc(L::Write) => Next(S::Tde01A),
                e if e == recv(K::Write) => Next(S::Tde01B),
                e if e == loc(L::Read) => Next(S::Tdl01A),
                e if e == recv(K::Read) => Next(S::Tdl01B),
                _ => Error,
            },
            S::Of03A => match event {
                e if e == recv(K::AckCrf) || e == nack(K::AckCrf) => Next(S::Sf03),
                _ => Error,
            },
            S::Of03B => match event {
                e if e == loc(L::Accept) || e == loc(L::Reject) => Next(S::Sf03),
                _ => Error,
            },
            S::Tde01A => match event {
                e if e == recv(K::AckWrite) => Next(S::Tde02A),
                e if e == nack(K::AckWrite) => Next(S::Of02),
                _ => Error,
            },
            S::Tde01B => match event {
                e if e == loc(L::Accept) => Next(S::Tde02B),
                e if e == loc(L::Reject) => Next(S::Of02),
                _ => Error,
            },
            S::Tdl01A => match event {
                e if e == recv(K::AckRead) => Next(S::Tdl02A),
                e if e == nack(K::AckRead) => Next(S::Of02),
                _ => Error,
            },
            S::Tdl01B => match event {
                e if e == loc(L::Accept) => Next(S::Tdl02B),
                e if e == loc(L::Reject) => Next(S::Of02),
                _ => Error,
            },
            // ---- sending data (requester writing / server reading) ----
            S::Tde02A | S::Tdl02B => {
                let (s_resync_sent, s_resync_rcvd, s_idt_sent, s_idt_rcvd, s_end) =
                    if self == S::Tde02A {
                        (S::Tde03A, S::Tde04A, S::Tde05A, S::Tde06A, S::Tde07A)
                    } else {
                        (S::Tdl03B, S::Tdl04B, S::Tdl05B, S::Tdl06B, S::Tdl07B)
                    };
                match event {
                    e if e == loc(L::SendData) || e == loc(L::Sync) || e == recv(K::AckSyn) => {
                        Next(self)
                    }
                    e if e == loc(L::DataEnd) => Next(s_end),
                    e if e == loc(L::Resync) => Next(s_resync_sent),
                    e if e == recv(K::Resyn) => Next(s_resync_rcvd),
                    e if e == loc(L::Cancel) => Next(s_idt_sent),
                    e if e == recv(K::Idt) => Next(s_idt_rcvd),
                    _ => Error,
                }
            }
            S::Tde03A | S::Tdl03B => {
                let (s_data, s_resync_rcvd, s_idt_sent, s_idt_rcvd) = if self == S::Tde03A {
                    (S::Tde02A, S::Tde04A, S::Tde05A, S::Tde06A)
                } else {
                    (S::Tdl02B, S::Tdl04B, S::Tdl05B, S::Tdl06B)
                };
                match event {
                    e if e == recv(K::AckResyn) => Next(s_data),
                    e if e == recv(K::AckSyn) || e == recv(K::AckTransEnd) => Ignore,
                    e if e == recv(K::Resyn) => Next(s_resync_rcvd),
                    e if e == loc(L::Cancel) => Next(s_idt_sent),
                    e if e == recv(K::Idt) => Next(s_idt_rcvd),
                    _ => Error,
                }
            }
            S::Tde04A | S::Tdl04B => {
                let (s_data, s_resync_sent, s_idt_sent, s_idt_rcvd) = if self == S::Tde04A {
                    (S::Tde02A, S::Tde03A, S::Tde05A, S::Tde06A)
                } else {
                    (S::Tdl02B, S::Tdl03B, S::Tdl05B, S::Tdl06B)
                };
                match event {
                    e if e == loc(L::Accept) => Next(s_data),
                    e if e == loc(L::Resync) => Next(s_resync_sent),
                    e if e == loc(L::DataEnd)
                        || e == loc(L::SendData)
                        || e == loc(L::Sync)
                        || e == loc(L::TransferEnd) =>
                    {
                        Ignore
                    }
                    e if e == recv(K::AckSyn) => Ignore,
                    e if e == loc(L::Cancel) => Next(s_idt_sent),
                    e if e == recv(K::Idt) => Next(s_idt_rcvd),
                    _ => Error,
                }
            }
            S::Tde07A => match event {
                e if e == loc(L::TransferEnd) => Next(S::Tde08A),
                e if e == recv(K::AckSyn) => Next(S::Tde07A),
                e if e == recv(K::Resyn) => Next(S::Tde04A),
                e if e == loc(L::Cancel) => Next(S::Tde05A),
                e if e == recv(K::Idt) => Next(S::Tde06A),
                _ => Error,
            },
            S::Tde08A => match event {
                e if e == recv(K::AckTransEnd) || e == nack(K::AckTransEnd) => Next(S::Of02),
                e if e == recv(K::AckSyn) => Ignore,
                e if e == recv(K::Resyn) => Next(S::Tde04A),
                e if e == loc(L::Cancel) => Next(S::Tde05A),
                e if e == recv(K::Idt) => Next(S::Tde06A),
                _ => Error,
            },
            S::Tdl07B => match event {
                e if e == recv(K::TransEnd) => Next(S::Tdl08B),
                e if e == recv(K::AckSyn) => Ignore,
                e if e == recv(K::Resyn) => Next(S::Tdl04B),
                e if e == loc(L::Cancel) => Next(S::Tdl05B),
                e if e == recv(K::Idt) => Next(S::Tdl06B),
                _ => Error,
            },
            S::Tdl08B => match event {
                e if e == loc(L::Accept) || e == loc(L::Reject) => Next(S::Of02),
                e if e == loc(L::Resync) => Next(S::Tdl03B),
                e if e == recv(K::AckSyn) => Ignore,
                _ => Error,
            },
            // ---- receiving data (server writing / requester reading) ----
            S::Tde02B | S::Tdl02A => {
                let (s_resync_sent, s_resync_rcvd, s_idt_sent, s_idt_rcvd, s_end) =
                    if self == S::Tde02B {
                        (S::Tde03B, S::Tde04B, S::Tde05B, S::Tde06B, S::Tde07B)
                    } else {
                        (S::Tdl03A, S::Tdl04A, S::Tdl05A, S::Tdl06A, S::Tdl07A)
                    };
                match event {
                    _ if is_data => Next(self),
                    e if e == recv(K::Syn) || e == loc(L::Accept) => Next(self),
                    e if e == recv(K::DtfEnd) => Next(s_end),
                    e if e == loc(L::Resync) => Next(s_resync_sent),
                    e if e == recv(K::Resyn) => Next(s_resync_rcvd),
                    e if e == loc(L::Cancel) => Next(s_idt_sent),
                    e if e == recv(K::Idt) => Next(s_idt_rcvd),
                    _ => Error,
                }
            }
            S::Tde03B | S::Tdl03A => {
                let (s_data, s_resync_rcvd, s_idt_sent, s_idt_rcvd) = if self == S::Tde03B {
                    (S::Tde02B, S::Tde04B, S::Tde05B, S::Tde06B)
                } else {
                    (S::Tdl02A, S::Tdl04A, S::Tdl05A, S::Tdl06A)
                };
                match event {
                    e if e == recv(K::AckResyn) => Next(s_data),
                    _ if is_data => Ignore,
                    e if e == recv(K::Syn) || e == recv(K::DtfEnd) || e == recv(K::TransEnd) => {
                        Ignore
                    }
                    e if e == recv(K::Resyn) => Next(s_resync_rcvd),
                    e if e == loc(L::Cancel) => Next(s_idt_sent),
                    e if e == recv(K::Idt) => Next(s_idt_rcvd),
                    _ => Error,
                }
            }
            S::Tde04B | S::Tdl04A => {
                let (s_data, s_resync_sent, s_idt_sent, s_idt_rcvd) = if self == S::Tde04B {
                    (S::Tde02B, S::Tde03B, S::Tde05B, S::Tde06B)
                } else {
                    (S::Tdl02A, S::Tdl03A, S::Tdl05A, S::Tdl06A)
                };
                match event {
                    e if e == loc(L::Accept) => Next(s_data),
                    e if e == loc(L::Resync) => Next(s_resync_sent),
                    e if e == loc(L::Sync) => Ignore,
                    e if e == loc(L::Cancel) => Next(s_idt_sent),
                    e if e == recv(K::Idt) => Next(s_idt_rcvd),
                    _ => Error,
                }
            }
            S::Tde07B => match event {
                e if e == recv(K::TransEnd) => Next(S::Tde08B),
                e if e == loc(L::Accept) => Next(S::Tde07B),
                e if e == loc(L::Resync) => Next(S::Tde03B),
                e if e == loc(L::Cancel) => Next(S::Tde05B),
                e if e == recv(K::Idt) => Next(S::Tde06B),
                _ => Error,
            },
            S::Tde08B => match event {
                e if e == loc(L::Accept) || e == loc(L::Reject) => Next(S::Of02),
                e if e == loc(L::Resync) => Next(S::Tde03B),
                _ => Error,
            },
            S::Tdl07A => match event {
                e if e == loc(L::TransferEnd) => Next(S::Tdl08A),
                e if e == loc(L::Accept) => Next(S::Tdl07A),
                e if e == loc(L::Resync) => Next(S::Tdl03A),
                e if e == loc(L::Cancel) => Next(S::Tdl05A),
                e if e == recv(K::Idt) => Next(S::Tdl06A),
                _ => Error,
            },
            S::Tdl08A => match event {
                e if e == recv(K::AckTransEnd) || e == nack(K::AckTransEnd) => Next(S::Of02),
                e if e == loc(L::Cancel) => Next(S::Tdl05A),
                e if e == recv(K::Idt) => Next(S::Tdl06A),
                _ => Error,
            },
            // ---- interruption ----
            S::Tde05A | S::Tde05B | S::Tdl05A | S::Tdl05B => match event {
                e if e == recv(K::AckIdt) => Next(S::Of02),
                // collision: both sides sent IDT; the peer's IDT is answered by our ACK(IDT)
                e if e == recv(K::Idt) => Next(match self {
                    S::Tde05A => S::Tde06A,
                    S::Tde05B => S::Tde06B,
                    S::Tdl05A => S::Tdl06A,
                    _ => S::Tdl06B,
                }),
                Event::Received { .. } => Ignore,
                Event::Local(_) => Error,
            },
            S::Tde06A | S::Tde06B | S::Tdl06A | S::Tdl06B => match event {
                e if e == loc(L::Accept) => Next(S::Of02),
                Event::Received { .. } => Ignore,
                Event::Local(_) => Error,
            },
            // ---- messages ----
            S::Mg01A => match event {
                e if e == loc(L::SendData) => Next(S::Mg01A),
                e if e == loc(L::DataEnd) => Next(S::Mg04A),
                // C:X accepts the acknowledgement before the local "end of message" event
                e if e == recv(K::AckMsg) || e == nack(K::AckMsg) => Next(S::Cn03),
                _ => Error,
            },
            S::Mg04A => match event {
                e if e == recv(K::AckMsg) || e == nack(K::AckMsg) => Next(S::Cn03),
                _ => Error,
            },
            S::Mg01B => match event {
                e if e == recv(K::MsgMm) => Next(S::Mg01B),
                e if e == recv(K::MsgFm) => Next(S::Mg04B),
                _ => Error,
            },
            S::Sf04B | S::Mg04B => match event {
                e if e == loc(L::Accept) || e == loc(L::Reject) => Next(S::Cn03),
                _ => Error,
            },
        }
    }
}

/// A small state machine wrapper keeping the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Machine {
    /// Local role.
    pub role: Role,
    state: State,
}

/// Error returned when an event is not allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("event {event:?} not allowed in state {state:?}")]
pub struct TransitionError {
    /// State in which the event was received.
    pub state: State,
    /// Offending event.
    pub event: Event,
}

impl Machine {
    /// New machine in the idle state.
    #[must_use]
    pub const fn new(role: Role) -> Self {
        Self {
            role,
            state: State::INITIAL,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// Apply an event; returns whether it was ignored.
    pub fn apply(&mut self, event: Event) -> Result<bool, TransitionError> {
        match self.state.apply(event) {
            Outcome::Next(s) => {
                self.state = s;
                Ok(false)
            }
            Outcome::Ignore => Ok(true),
            Outcome::Error => Err(TransitionError {
                state: self.state,
                event,
            }),
        }
    }

    /// Whether `event` would be accepted.
    #[must_use]
    pub fn accepts(&self, event: Event) -> bool {
        !matches!(self.state.apply(event), Outcome::Error)
    }

    /// Force a state (used after ABORT or transport failure).
    pub fn reset(&mut self) {
        self.state = State::INITIAL;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use FpduKind as K;
    use LocalEvent as L;

    fn run(role: Role, events: &[Event]) -> Result<State, TransitionError> {
        let mut m = Machine::new(role);
        for e in events {
            m.apply(*e)?;
        }
        Ok(m.state())
    }

    #[test]
    fn requester_write_transfer() {
        let r = |k| Event::received(k, false);
        let l = Event::local;
        let s = run(
            Role::Requester,
            &[
                l(L::Connect),
                r(K::Aconnect),
                l(L::Create),
                r(K::AckCreate),
                l(L::Open),
                r(K::AckOrf),
                l(L::Write),
                r(K::AckWrite),
                l(L::SendData),
                l(L::Sync),
                l(L::SendData),
                r(K::AckSyn),
                l(L::DataEnd),
                r(K::AckSyn),
                l(L::TransferEnd),
                r(K::AckTransEnd),
                l(L::Close),
                r(K::AckCrf),
                l(L::Deselect),
                r(K::AckDeselect),
                l(L::Release),
                r(K::Relconf),
            ],
        );
        assert_eq!(s, Ok(State::Cn01));
    }

    #[test]
    fn server_read_transfer_with_resync_and_idt() {
        let r = |k| Event::received(k, false);
        let l = Event::local;
        let s = run(
            Role::Server,
            &[
                r(K::Connect),
                l(L::Accept),
                r(K::Select),
                l(L::Accept),
                r(K::Orf),
                l(L::Accept),
                r(K::Read),
                l(L::Accept),
                l(L::SendData),
                l(L::Sync),
                r(K::Resyn),
                l(L::Accept),
                l(L::SendData),
                r(K::Idt),
                l(L::Accept),
                r(K::Crf),
                l(L::Accept),
                r(K::Deselect),
                l(L::Accept),
                r(K::Release),
                l(L::Accept),
            ],
        );
        assert_eq!(s, Ok(State::Cn01));
    }

    #[test]
    fn negative_acks_and_errors() {
        let mut m = Machine::new(Role::Requester);
        m.apply(Event::local(L::Connect)).unwrap_or_default();
        m.apply(Event::received(K::Aconnect, false))
            .unwrap_or_default();
        m.apply(Event::local(L::Create)).unwrap_or_default();
        m.apply(Event::received(K::AckCreate, true))
            .unwrap_or_default();
        assert_eq!(m.state(), State::Cn03);
        assert!(m.apply(Event::received(K::Dtf, false)).is_err());
        assert_eq!(m.state(), State::Cn03);
        m.apply(Event::received(K::Abort, false))
            .unwrap_or_default();
        assert_eq!(m.state(), State::Cn01);
    }

    #[test]
    fn late_ack_syn_is_ignored() {
        let mut m = Machine::new(Role::Requester);
        for e in [
            Event::local(L::Connect),
            Event::received(K::Aconnect, false),
            Event::local(L::Create),
            Event::received(K::AckCreate, false),
            Event::local(L::Open),
            Event::received(K::AckOrf, false),
            Event::local(L::Write),
            Event::received(K::AckWrite, false),
            Event::local(L::DataEnd),
            Event::local(L::TransferEnd),
        ] {
            m.apply(e).unwrap_or_default();
        }
        assert_eq!(m.state(), State::Tde08A);
        assert_eq!(m.apply(Event::received(K::AckSyn, false)), Ok(true));
        assert_eq!(m.state(), State::Tde08A);
    }
}
