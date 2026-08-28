//! Error types of the session engines.

use pesit_core::fpdu::{DecodeError, FpduKind};
use pesit_core::state::State;
use pesit_core::Diagnostic;

use crate::transport::TransportError;

/// Error of a PeSIT session.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Transport failure.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// A received FPDU could not be decoded.
    #[error("invalid FPDU received: {0}")]
    Decode(#[from] DecodeError),
    /// A FPDU not allowed in the current state was received.
    #[error("protocol error: unexpected {kind} in state {state:?}")]
    Protocol {
        /// Current state.
        state: State,
        /// Received FPDU kind.
        kind: FpduKind,
    },
    /// The peer aborted the connection.
    #[error("connection aborted by the peer: {diag}{}", message.as_deref().map(|m| format!(" ({m})")).unwrap_or_default())]
    Aborted {
        /// Diagnostic carried by ABORT.
        diag: Diagnostic,
        /// PI 29/PI 99 text, if any.
        message: Option<String>,
    },
    /// The peer answered a request with a negative acknowledgement.
    #[error("{request} refused: {diag}{}", message.as_deref().map(|m| format!(" ({m})")).unwrap_or_default())]
    Refused {
        /// The refused request.
        request: FpduKind,
        /// Diagnostic of the negative acknowledgement.
        diag: Diagnostic,
        /// PI 29/PI 99 text, if any.
        message: Option<String>,
    },
    /// The pre-connection was refused (`NAK0`).
    #[error("pre-connection refused by the server")]
    PreconnectRefused,
    /// Local I/O error (file access).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Record cutting error.
    #[error("record error: {0}")]
    Record(#[from] pesit_core::article::RecordError),
    /// Segmented article reassembly error.
    #[error("{0}")]
    Reassembly(#[from] pesit_core::article::ReassemblyError),
    /// Compressed data error.
    #[error("{0}")]
    Decompress(#[from] pesit_core::compress::DecompressError),
    /// The transfer was cancelled locally.
    #[error("transfer cancelled")]
    Cancelled,
    /// The peer did not answer in time.
    #[error("timeout waiting for {0}")]
    Timeout(&'static str),
    /// Negotiation failure or invalid parameter value.
    #[error("negotiation failure: {0}")]
    Negotiation(String),
    /// Protocol counters mismatch (PI 27/28).
    #[error("{0}")]
    Counts(String),
}

impl SessionError {
    /// Diagnostic to send in an ABORT for this error.
    #[must_use]
    pub fn abort_diag(&self) -> Diagnostic {
        match self {
            SessionError::Transport(_) => Diagnostic::NETWORK_INCIDENT,
            SessionError::Decode(e) => e.diag,
            SessionError::Aborted { diag, .. } | SessionError::Refused { diag, .. } => *diag,
            SessionError::PreconnectRefused => Diagnostic::CALLER_NOT_AUTHORISED,
            SessionError::Io(_) => Diagnostic::IO_ERROR,
            SessionError::Record(_) => Diagnostic::RECORD_TOO_LONG,
            SessionError::Protocol { .. }
            | SessionError::Reassembly(_)
            | SessionError::Decompress(_) => Diagnostic::REMOTE_PROTOCOL_ERROR,
            SessionError::Cancelled => Diagnostic::VOLUNTARY_STOP,
            SessionError::Timeout(_) => Diagnostic::TIMEOUT,
            SessionError::Negotiation(_) => Diagnostic::NEGOTIATION_FAILURE,
            SessionError::Counts(_) => Diagnostic::INVALID_COUNTS,
        }
    }
}
