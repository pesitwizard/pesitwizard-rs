//! Typed views over frequently used parameter values.

use crate::diag::Diagnostic;
use crate::fpdu::{decode_num, Fpdu};
use crate::pi::Pi;

/// PeSIT protocol versions carried in PI 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Version {
    /// Version D (15 November 1987) = 1.
    D,
    /// Version E (14 July 1989) = 2.
    E,
}

impl Version {
    /// PI 6 value.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Version::D => 1,
            Version::E => 2,
        }
    }

    /// From PI 6 value.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Version::D),
            2 => Some(Version::E),
            _ => None,
        }
    }
}

/// Access type negotiated in CONNECT (PI 22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AccessType {
    /// Requester writes (sends) files.
    Write,
    /// Requester reads (receives) files.
    Read,
    /// Both directions during the connection.
    Mixed,
}

impl AccessType {
    /// PI 22 value.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            AccessType::Write => 0,
            AccessType::Read => 1,
            AccessType::Mixed => 2,
        }
    }

    /// From PI 22 value.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(AccessType::Write),
            1 => Some(AccessType::Read),
            2 => Some(AccessType::Mixed),
            _ => None,
        }
    }

    /// Whether writes (CREATE) are allowed.
    #[must_use]
    pub const fn allows_write(self) -> bool {
        matches!(self, AccessType::Write | AccessType::Mixed)
    }

    /// Whether reads (SELECT) are allowed.
    #[must_use]
    pub const fn allows_read(self) -> bool {
        matches!(self, AccessType::Read | AccessType::Mixed)
    }
}

/// Synchronisation points option (PI 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SyncOption {
    /// Interval between synchronisation points in kilobytes; 0 = no sync points,
    /// 0xFFFF = undefined.
    pub interval_kb: u16,
    /// Acknowledgement window: 0 = no acknowledgement, else the maximum number of
    /// unacknowledged synchronisation points.
    pub window: u8,
}

impl SyncOption {
    /// "Undefined interval" special value.
    pub const UNDEFINED_INTERVAL: u16 = 0xFFFF;

    /// No synchronisation points.
    pub const NONE: SyncOption = SyncOption {
        interval_kb: 0,
        window: 0,
    };

    /// Encode as the 3-byte PI 7 value.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let i = self.interval_kb.to_be_bytes();
        vec![i[0], i[1], self.window]
    }

    /// Decode a PI 7 value (2 or 3 bytes).
    #[must_use]
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            [hi, lo] => Some(Self {
                interval_kb: u16::from_be_bytes([*hi, *lo]),
                window: 0,
            }),
            [hi, lo, w, ..] => Some(Self {
                interval_kb: u16::from_be_bytes([*hi, *lo]),
                window: *w,
            }),
            _ => None,
        }
    }

    /// Whether synchronisation points are in use.
    #[must_use]
    pub const fn enabled(self) -> bool {
        self.interval_kb != 0
    }

    /// Interval in bytes (`None` when disabled or undefined).
    #[must_use]
    pub const fn interval_bytes(self) -> Option<u64> {
        match self.interval_kb {
            0 | Self::UNDEFINED_INTERVAL => None,
            kb => Some(kb as u64 * 1024),
        }
    }

    /// Server-side negotiation: intersection of the requester proposal and local capability
    /// (§3.7 f): smallest interval and smallest window win; option only if both want it.
    #[must_use]
    pub fn negotiate(proposed: SyncOption, local: SyncOption) -> SyncOption {
        if !proposed.enabled() || !local.enabled() {
            return SyncOption::NONE;
        }
        let interval_kb = match (proposed.interval_kb, local.interval_kb) {
            (Self::UNDEFINED_INTERVAL, l) => l,
            (p, Self::UNDEFINED_INTERVAL) => p,
            (p, l) => p.min(l),
        };
        SyncOption {
            interval_kb,
            window: proposed.window.min(local.window),
        }
    }
}

/// Compression negotiation (PI 21).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub enum Compression {
    /// No compression.
    #[default]
    None,
    /// Horizontal (run-length) compression.
    Horizontal,
    /// Vertical (previous article reference) compression.
    Vertical,
    /// Both.
    Mixed,
}

impl Compression {
    /// Encode as the 2-byte PI 21 value.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 2] {
        match self {
            Compression::None => [0, 0],
            Compression::Horizontal => [1, 1],
            Compression::Vertical => [1, 2],
            Compression::Mixed => [1, 3],
        }
    }

    /// Decode a PI 21 value.
    #[must_use]
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            [0, ..] | [] => Some(Compression::None),
            [1, 1] | [1] => Some(Compression::Horizontal),
            [1, 2] => Some(Compression::Vertical),
            [1, 3] => Some(Compression::Mixed),
            _ => None,
        }
    }

    /// Server-side negotiation: the answer must be supported locally and not stronger than the
    /// request (a server may downgrade to `None`).
    #[must_use]
    pub fn negotiate(requested: Compression, local: Compression) -> Compression {
        match (requested, local) {
            (Compression::None, _) | (_, Compression::None) => Compression::None,
            (r, l) if r == l => r,
            (Compression::Mixed, l) => l,
            (r, Compression::Mixed) => r,
            _ => Compression::None,
        }
    }

    /// Numeric code (0..3) as used in configuration.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Compression::None => 0,
            Compression::Horizontal => 1,
            Compression::Vertical => 2,
            Compression::Mixed => 3,
        }
    }

    /// From configuration code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Compression::None),
            1 => Some(Compression::Horizontal),
            2 => Some(Compression::Vertical),
            3 => Some(Compression::Mixed),
            _ => None,
        }
    }
}

/// Article format (PI 31).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub enum ArticleFormat {
    /// Fixed length articles (0x00).
    #[default]
    Fixed,
    /// Variable length articles (0x80).
    Variable,
}

impl ArticleFormat {
    /// PI 31 value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            ArticleFormat::Fixed => 0x00,
            ArticleFormat::Variable => 0x80,
        }
    }

    /// From PI 31 value (bit 7).
    #[must_use]
    pub fn from_bytes(v: &[u8]) -> Self {
        if v.first().is_some_and(|b| b & 0x80 != 0) {
            ArticleFormat::Variable
        } else {
            ArticleFormat::Fixed
        }
    }
}

/// End of transfer code (PI 19) carried by IDT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EndCode {
    /// 4 — error, a restart will follow.
    Error,
    /// 8 — suspension.
    Suspension,
    /// 12 — cancellation by the server.
    CancelByServer,
    /// 16 — cancellation by the requester.
    CancelByRequester,
    /// Any other value.
    Other(u8),
}

impl EndCode {
    /// PI 19 value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            EndCode::Error => 4,
            EndCode::Suspension => 8,
            EndCode::CancelByServer => 12,
            EndCode::CancelByRequester => 16,
            EndCode::Other(c) => c,
        }
    }

    /// From PI 19 value.
    #[must_use]
    pub const fn from_code(c: u8) -> Self {
        match c {
            4 => EndCode::Error,
            8 => EndCode::Suspension,
            12 => EndCode::CancelByServer,
            16 => EndCode::CancelByRequester,
            c => EndCode::Other(c),
        }
    }
}

/// Requested attributes mask (PI 14).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub struct RequestedAttributes {
    /// b1 — logical attributes (PGI 30).
    pub logical: bool,
    /// b2 — physical attributes (PGI 40).
    pub physical: bool,
    /// b3 — historical attributes (PGI 50).
    pub historical: bool,
}

impl RequestedAttributes {
    /// All attribute groups.
    pub const ALL: RequestedAttributes = RequestedAttributes {
        logical: true,
        physical: true,
        historical: true,
    };

    /// PI 14 value (b1 is the most significant bit of the mask byte in PeSIT bit numbering;
    /// implementations, including Connect:Express, use the low bits: 1 = logical, 2 = physical,
    /// 4 = historical).
    #[must_use]
    pub const fn code(self) -> u8 {
        (self.logical as u8) | ((self.physical as u8) << 1) | ((self.historical as u8) << 2)
    }

    /// From PI 14 value.
    #[must_use]
    pub const fn from_code(c: u8) -> Self {
        Self {
            logical: c & 1 != 0,
            physical: c & 2 != 0,
            historical: c & 4 != 0,
        }
    }
}

/// Extract common values from an FPDU.
pub trait FpduExt {
    /// PI 7.
    fn sync_option(&self) -> Option<SyncOption>;
    /// PI 21.
    fn compression(&self) -> Option<Compression>;
    /// PI 22.
    fn access_type(&self) -> Option<AccessType>;
    /// PI 6.
    fn version(&self) -> Option<Version>;
    /// PI 2 or success if absent.
    fn diag_or_ok(&self) -> Diagnostic;
    /// PI 25.
    fn max_entity_size(&self) -> Option<u16>;
    /// PI 13.
    fn transfer_id(&self) -> Option<u32>;
    /// PI 18.
    fn restart_point(&self) -> Option<u32>;
    /// PI 20.
    fn sync_number(&self) -> Option<u32>;
    /// PI 19.
    fn end_code(&self) -> Option<EndCode>;
}

impl FpduExt for Fpdu {
    fn sync_option(&self) -> Option<SyncOption> {
        self.get(Pi::SyncOption).and_then(SyncOption::from_bytes)
    }

    fn compression(&self) -> Option<Compression> {
        self.get(Pi::Compression).and_then(Compression::from_bytes)
    }

    fn access_type(&self) -> Option<AccessType> {
        self.get_num(Pi::AccessType).and_then(AccessType::from_code)
    }

    fn version(&self) -> Option<Version> {
        self.get_num(Pi::Version).and_then(Version::from_code)
    }

    fn diag_or_ok(&self) -> Diagnostic {
        self.diag().unwrap_or(Diagnostic::OK)
    }

    fn max_entity_size(&self) -> Option<u16> {
        self.get_num(Pi::MaxEntitySize)
            .map(|v| v.min(0xFFFF) as u16)
    }

    fn transfer_id(&self) -> Option<u32> {
        self.get(Pi::TransferId).map(|v| decode_num(v) as u32)
    }

    fn restart_point(&self) -> Option<u32> {
        self.get(Pi::RestartPoint).map(|v| decode_num(v) as u32)
    }

    fn sync_number(&self) -> Option<u32> {
        self.get(Pi::SyncNumber).map(|v| decode_num(v) as u32)
    }

    fn end_code(&self) -> Option<EndCode> {
        self.get(Pi::EndCode)
            .and_then(|v| v.first())
            .map(|c| EndCode::from_code(*c))
    }
}

/// Format a `AAMMJJhhmmss` PeSIT date from its components.
#[must_use]
pub fn format_datetime(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> String {
    format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}",
        year % 100,
        month,
        day,
        hour,
        min,
        sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_negotiation() {
        let p = SyncOption {
            interval_kb: 256,
            window: 16,
        };
        let l = SyncOption {
            interval_kb: 32,
            window: 2,
        };
        assert_eq!(
            SyncOption::negotiate(p, l),
            SyncOption {
                interval_kb: 32,
                window: 2
            }
        );
        assert_eq!(SyncOption::negotiate(p, SyncOption::NONE), SyncOption::NONE);
        let u = SyncOption {
            interval_kb: SyncOption::UNDEFINED_INTERVAL,
            window: 1,
        };
        assert_eq!(SyncOption::negotiate(u, l).interval_kb, 32);
        assert_eq!(
            SyncOption::from_bytes(&[1, 0, 4]),
            Some(SyncOption {
                interval_kb: 256,
                window: 4
            })
        );
        assert_eq!(p.to_bytes(), vec![1, 0, 16]);
        assert_eq!(p.interval_bytes(), Some(262_144));
    }

    #[test]
    fn compression_negotiation() {
        assert_eq!(
            Compression::negotiate(Compression::Mixed, Compression::Horizontal),
            Compression::Horizontal
        );
        assert_eq!(
            Compression::negotiate(Compression::Vertical, Compression::Horizontal),
            Compression::None
        );
        assert_eq!(
            Compression::negotiate(Compression::Horizontal, Compression::Mixed),
            Compression::Horizontal
        );
        assert_eq!(Compression::from_bytes(&[1, 3]), Some(Compression::Mixed));
        assert_eq!(Compression::from_bytes(&[0, 1]), Some(Compression::None));
    }

    #[test]
    fn misc_codes() {
        assert_eq!(AccessType::from_code(2), Some(AccessType::Mixed));
        assert_eq!(EndCode::from_code(16), EndCode::CancelByRequester);
        assert_eq!(RequestedAttributes::ALL.code(), 7);
        assert_eq!(ArticleFormat::from_bytes(&[0x80]), ArticleFormat::Variable);
        assert_eq!(format_datetime(2026, 8, 28, 21, 5, 9), "260828210509");
    }
}
