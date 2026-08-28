//! PeSIT E (Hors-SIT profile) protocol core.
//!
//! This crate contains everything that does not touch the network: parameter and FPDU
//! encoding/decoding ([`fpdu`]), the parameter catalogue ([`pi`]), diagnostics ([`diag`]),
//! the Fletcher checksum used by the "error control" functional unit ([`crc`]), data
//! compression ([`compress`]), EBCDIC translation and the pre-connection messages
//! ([`ebcdic`]), NSDU framing helpers ([`frame`]), article codecs and segmentation
//! ([`article`]) and the protocol state tables ([`state`]).
//!
//! The implementation follows the PeSIT version E specification (14 July 1989) and has been
//! cross-checked against IBM Sterling Connect:Express behaviour (see `docs/`).

pub mod article;
pub mod builder;
pub mod compress;
pub mod crc;
pub mod diag;
pub mod ebcdic;
pub mod fpdu;
pub mod frame;
pub mod params;
pub mod pi;
pub mod state;

pub use diag::Diagnostic;
pub use fpdu::{Fpdu, FpduKind, Param};
pub use pi::{Pgi, Pi};
