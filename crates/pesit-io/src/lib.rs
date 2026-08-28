//! Asynchronous PeSIT E transport and session engines (tokio).
//!
//! * [`transport`] — data entity framing over TCP or TLS streams, pre-connection messages.
//! * [`tls`] — rustls configuration helpers.
//! * [`link`] — a full-duplex FPDU link with a background reader.
//! * [`io`] — article sources and sinks (files, memory).
//! * [`checkpoint`] — synchronisation point bookkeeping for restarts.
//! * [`datapath`] — the data transfer phase (sending and receiving articles, sync points,
//!   resynchronisation, interruption) shared by both roles.
//! * [`requester`] — the requester (client) session API.
//! * [`responder`] — the server session driver, generic over an application handler.

pub mod checkpoint;
pub mod datapath;
pub mod error;
pub mod io;
pub mod link;
pub mod requester;
pub mod responder;
pub mod tls;
pub mod transport;

pub use error::SessionError;
pub use link::Link;
pub use transport::{BoxedStream, Framing};
