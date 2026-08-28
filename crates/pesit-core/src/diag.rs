//! Diagnostic codes (PI 2, PeSIT E annex D) with the texts used by Connect:Express.

use std::fmt;

/// A PeSIT diagnostic: one byte error type/severity followed by a 16-bit reason code.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Diagnostic {
    /// Error type: 0 = success, 1 = transmission, 2 = file/transfer, 3 = connection/protocol.
    pub kind: u8,
    /// Reason code (e.g. 205, 318).
    pub code: u16,
}

macro_rules! diags {
    ($( $name:ident = ($kind:expr, $code:expr, $text:expr); )*) => {
        impl Diagnostic {
            $(
                #[doc = $text]
                pub const $name: Diagnostic = Diagnostic { kind: $kind, code: $code };
            )*

            /// Text of a known diagnostic, or `None`.
            #[must_use]
            pub fn known_description(self) -> Option<&'static str> {
                match (self.kind, self.code) {
                    $( ($kind, $code) => Some($text), )*
                    _ => None,
                }
            }
        }
    };
}

diags! {
    OK = (0, 0, "Success");
    TRANSMISSION_ERROR = (1, 100, "Transmission error");
    INSUFFICIENT_FILE_CHARACTERISTICS = (2, 200, "Insufficient file characteristics");
    SYSTEM_RESOURCES = (2, 201, "System resources temporarily insufficient");
    USER_RESOURCES = (2, 202, "User resources temporarily insufficient");
    NON_PRIORITY_TRANSFER = (2, 203, "Non-priority transfer");
    FILE_EXISTS = (2, 204, "File already exists");
    FILE_NOT_FOUND = (2, 205, "File not found");
    DISK_QUOTA = (2, 206, "Disk quota would be exceeded");
    FILE_BUSY = (2, 207, "File busy");
    FILE_TOO_OLD = (2, 208, "File too old");
    MESSAGE_NOT_ACCEPTED = (2, 209, "Message of this type not accepted");
    PRESENTATION_NEGOTIATION = (2, 210, "Presentation context negotiation failed");
    CANNOT_OPEN = (2, 211, "Cannot open file");
    CANNOT_CLOSE = (2, 212, "Cannot close file normally");
    IO_ERROR = (2, 213, "Blocking input/output error");
    RESTART_POINT_NEGOTIATION = (2, 214, "Restart point negotiation failed");
    SYSTEM_ERROR = (2, 215, "System-specific error");
    VOLUNTARY_STOP = (2, 216, "Voluntary premature stop");
    TOO_MANY_UNACKED_SYNC = (2, 217, "Too many synchronisation points without acknowledgement");
    RESYNC_IMPOSSIBLE = (2, 218, "Resynchronisation impossible");
    FILE_SPACE_EXHAUSTED = (2, 219, "File space exhausted");
    RECORD_TOO_LONG = (2, 220, "Article longer than expected");
    END_OF_TRANSMISSION_TIMEOUT = (2, 221, "End of transmission timer expired");
    TOO_MUCH_DATA_WITHOUT_SYNC = (2, 222, "Too much data without synchronisation point");
    ABNORMAL_END = (2, 223, "Abnormal end of transfer");
    FILE_LARGER_THAN_ANNOUNCED = (2, 224, "File larger than announced in F.CREATE");
    APPLICATION_CONGESTED = (2, 225, "Application congested, file received but not delivered");
    TRANSFER_REFUSED = (2, 226, "Transfer refused");
    RESTART_NOT_RESTARTABLE = (2, 227, "Restart impossible: transfer not restartable");
    RESTART_UNKNOWN_SYNC = (2, 228, "Restart impossible: unknown synchronisation point");
    RESTART_FILE_MODIFIED = (2, 229, "Restart impossible: file modified");
    RESTART_DELAY_EXCEEDED = (2, 230, "Restart impossible: delay exceeded");
    NO_RESTART_CONTEXT = (2, 233, "No transfer restart context available");
    OTHER_FILE_ERROR = (2, 299, "Other file/transfer error");
    LOCAL_CONGESTION = (3, 300, "Local communication system congested");
    CALLER_UNKNOWN = (3, 301, "Requested identification unknown");
    NOT_ATTACHED_TO_SSAP = (3, 302, "Requester not attached to an SSAP / unauthorised caller");
    REMOTE_CONGESTION = (3, 303, "Remote communication system congested / called partner unknown");
    CALLER_NOT_AUTHORISED = (3, 304, "Requester identification not authorised (security)");
    SELECT_NEGOTIATION = (3, 305, "Negotiation failure: SELECT");
    RESYNC_NEGOTIATION = (3, 306, "Negotiation failure: RESYNC");
    SYNC_NEGOTIATION = (3, 307, "Negotiation failure: SYNC");
    VERSION_NOT_SUPPORTED = (3, 308, "Version number not supported");
    TOO_MANY_CONNECTIONS = (3, 309, "Too many connections already in progress");
    NETWORK_INCIDENT = (3, 310, "Network incident");
    REMOTE_PROTOCOL_ERROR = (3, 311, "Remote PeSIT protocol error");
    SERVICE_CLOSED = (3, 312, "Closure of service requested by user");
    IDLE_CONNECTION_CUT = (3, 313, "Connection cut at end of inactivity timer");
    UNUSED_CONNECTION_CUT = (3, 314, "Unused connection cut to accept a new one");
    NEGOTIATION_FAILURE = (3, 315, "Negotiation failure");
    ADMINISTRATIVE_CUT = (3, 316, "Connection cut by administration");
    TIMEOUT = (3, 317, "Timer expired");
    INVALID_PARAMETER = (3, 318, "Mandatory parameter absent or illegal parameter content");
    INVALID_COUNTS = (3, 319, "Incorrect number of bytes or articles");
    TOO_MANY_RESYNC = (3, 320, "Too many resynchronisations for a transfer");
    CALL_BACKUP_NUMBER = (3, 321, "Call the backup number");
    CALL_BACK_LATER = (3, 322, "Call back later");
    OTHER_CONNECTION_ERROR = (3, 399, "Other connection/protocol error");
}

impl Diagnostic {
    /// Build a diagnostic from its type and reason code.
    #[must_use]
    pub const fn new(kind: u8, code: u16) -> Self {
        Self { kind, code }
    }

    /// Decode the 3-byte wire form (shorter values are accepted, high bytes assumed zero).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [] => None,
            [k] => Some(Self::new(*k, 0)),
            [k, c] => Some(Self::new(*k, u16::from(*c))),
            [k, hi, lo, ..] => Some(Self::new(*k, u16::from_be_bytes([*hi, *lo]))),
        }
    }

    /// Encode as the 3-byte PI 2 value.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 3] {
        let c = self.code.to_be_bytes();
        [self.kind, c[0], c[1]]
    }

    /// Whether the diagnostic denotes success.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        self.kind == 0 && self.code == 0
    }

    /// Description (known text or generic).
    #[must_use]
    pub fn description(self) -> &'static str {
        self.known_description().unwrap_or(match self.kind {
            0 => "Success",
            1 => "Transmission error",
            2 => "File or transfer error",
            3 => "Connection or protocol error",
            _ => "Unknown diagnostic",
        })
    }

    /// Whether a restart (relance) of the transfer is impossible according to this diagnostic.
    #[must_use]
    pub fn forbids_restart(self) -> bool {
        matches!(self.code, 214 | 218 | 227 | 228 | 229 | 230 | 233) && self.kind == 2
    }
}

impl fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "D{}-{:03}", self.kind, self.code)
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "D{}-{:03} {}", self.kind, self.code, self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip() {
        let d = Diagnostic::FILE_NOT_FOUND;
        assert_eq!(d.to_bytes(), [2, 0, 205]);
        assert_eq!(Diagnostic::from_bytes(&[2, 0, 205]), Some(d));
        assert_eq!(Diagnostic::from_bytes(&[0, 0, 0]), Some(Diagnostic::OK));
        assert!(Diagnostic::OK.is_ok());
        assert_eq!(
            Diagnostic::new(3, 318).description(),
            Diagnostic::INVALID_PARAMETER.description()
        );
        assert_eq!(format!("{}", Diagnostic::TIMEOUT), "D3-317 Timer expired");
    }
}
