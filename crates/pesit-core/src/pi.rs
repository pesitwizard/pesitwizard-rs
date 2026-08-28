//! Parameter identifiers (PI) and parameter group identifiers (PGI) of PeSIT E (§4.7.2.2).

use std::fmt;

/// Kind of a parameter value (§4.7.2.1 e).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueKind {
    /// `C` — ASCII character string, trailing blanks not significant.
    Text,
    /// `N` — unsigned binary integer, leading zero bytes removed (at least one byte).
    Number,
    /// `S` — symbolic value, one byte.
    Symbol,
    /// `M` — bit mask (8 to 16 bits).
    Mask,
    /// `D` — date/time as a 12 character string `AAMMJJhhmmss`.
    DateTime,
    /// `A` — aggregate of the above.
    Aggregate,
}

macro_rules! define_pi {
    ($( $name:ident = $code:expr, $kind:ident, $max:expr, $label:expr; )*) => {
        /// Parameter identifier.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum Pi {
            $(
                #[doc = $label]
                $name = $code,
            )*
        }

        impl Pi {
            /// All parameter identifiers in ascending code order.
            pub const ALL: &'static [Pi] = &[$(Pi::$name),*];

            /// Look a parameter up by its wire code.
            #[must_use]
            pub fn from_code(code: u8) -> Option<Pi> {
                match code {
                    $( $code => Some(Pi::$name), )*
                    _ => None,
                }
            }

            /// Wire code of the parameter.
            #[must_use]
            pub const fn code(self) -> u8 {
                self as u8
            }

            /// Value kind of the parameter.
            #[must_use]
            pub const fn kind(self) -> ValueKind {
                match self {
                    $( Pi::$name => ValueKind::$kind, )*
                }
            }

            /// Maximum value length in bytes (0 = unbounded / implementation defined).
            #[must_use]
            pub const fn max_len(self) -> usize {
                match self {
                    $( Pi::$name => $max, )*
                }
            }

            /// Human readable name of the parameter.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $( Pi::$name => $label, )*
                }
            }
        }
    };
}

define_pi! {
    Crc = 1, Symbol, 1, "CRC usage";
    Diag = 2, Aggregate, 3, "Diagnostic";
    Requester = 3, Text, 24, "Requester identification";
    Server = 4, Text, 24, "Server identification";
    AccessControl = 5, Text, 16, "Access control (password)";
    Version = 6, Number, 2, "Protocol version";
    SyncOption = 7, Aggregate, 3, "Synchronisation points option";
    FileType = 11, Number, 8, "File type";
    FileName = 12, Text, 76, "File name";
    TransferId = 13, Number, 3, "Transfer identifier";
    RequestedAttributes = 14, Mask, 1, "Requested attributes";
    Restarted = 15, Symbol, 1, "Transfer restarted";
    DataCode = 16, Symbol, 1, "Data code";
    Priority = 17, Symbol, 1, "Transfer priority";
    RestartPoint = 18, Number, 3, "Restart point";
    EndCode = 19, Symbol, 1, "End of transfer code";
    SyncNumber = 20, Number, 3, "Synchronisation point number";
    Compression = 21, Aggregate, 2, "Compression";
    AccessType = 22, Symbol, 1, "Access type";
    Resync = 23, Symbol, 1, "Resynchronisation";
    MaxEntitySize = 25, Number, 2, "Maximum data entity size";
    Timeout = 26, Number, 2, "Watchdog timer";
    ByteCount = 27, Number, 8, "Number of data bytes";
    ArticleCount = 28, Number, 4, "Number of articles";
    DiagComplement = 29, Aggregate, 254, "Diagnostic complement";
    ArticleFormat = 31, Mask, 1, "Article format";
    ArticleLength = 32, Number, 2, "Article length";
    FileOrganisation = 33, Symbol, 1, "File organisation";
    SignatureFlag = 34, Number, 2, "Signature taken into account";
    SitSeal = 36, Number, 64, "SIT seal";
    FileLabel = 37, Text, 80, "File label";
    KeyLength = 38, Number, 2, "Key length";
    KeyOffset = 39, Number, 2, "Key offset";
    ReservationUnit = 41, Symbol, 1, "Space reservation unit";
    MaxReservation = 42, Number, 4, "Maximum space reservation";
    CreationDate = 51, DateTime, 12, "Creation date and time";
    ExtractionDate = 52, DateTime, 12, "Last extraction date and time";
    ClientId = 61, Text, 24, "Client identifier";
    BankId = 62, Text, 24, "Bank identifier";
    FileAccessControl = 63, Text, 16, "File access control";
    ServerDate = 64, DateTime, 12, "Server date and time";
    AuthType = 71, Aggregate, 3, "Authentication type";
    AuthElements = 72, Number, 0, "Authentication elements";
    SealType = 73, Aggregate, 4, "Sealing type";
    SealElements = 74, Number, 0, "Sealing elements";
    CipherType = 75, Aggregate, 4, "Encryption type";
    CipherElements = 76, Number, 0, "Encryption elements";
    SignatureType = 77, Aggregate, 4, "Signature type";
    Seal = 78, Number, 0, "Seal";
    Signature = 79, Number, 0, "Signature";
    Accreditation = 80, Number, 0, "Accreditation";
    SignatureAck = 81, Number, 0, "Signature acknowledgement";
    SecondSignature = 82, Number, 0, "Second signature";
    SecondAccreditation = 83, Number, 0, "Second accreditation";
    Message = 91, Text, 4096, "Message";
    FreeMessage = 99, Text, 254, "Free message";
}

impl fmt::Display for Pi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PI {} ({})", self.code(), self.name())
    }
}

/// Parameter group identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Pgi {
    /// PGI 9 — file identifier: PI 3, 4, 11, 12.
    FileId = 9,
    /// PGI 30 — logical attributes: PI 31, 32, 33, 34, 36, 37, 38, 39.
    LogicalAttributes = 30,
    /// PGI 40 — physical attributes: PI 41, 42.
    PhysicalAttributes = 40,
    /// PGI 50 — historical attributes: PI 51, 52.
    HistoricalAttributes = 50,
}

impl Pgi {
    /// All parameter groups in ascending code order.
    pub const ALL: &'static [Pgi] = &[
        Pgi::FileId,
        Pgi::LogicalAttributes,
        Pgi::PhysicalAttributes,
        Pgi::HistoricalAttributes,
    ];

    /// Look a group up by its wire code.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Pgi> {
        match code {
            9 => Some(Pgi::FileId),
            30 => Some(Pgi::LogicalAttributes),
            40 => Some(Pgi::PhysicalAttributes),
            50 => Some(Pgi::HistoricalAttributes),
            _ => None,
        }
    }

    /// Wire code of the group.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Pgi::FileId => "File identifier",
            Pgi::LogicalAttributes => "Logical attributes",
            Pgi::PhysicalAttributes => "Physical attributes",
            Pgi::HistoricalAttributes => "Historical attributes",
        }
    }

    /// Parameters that may appear inside this group, with their mandatory flag.
    #[must_use]
    pub const fn members(self) -> &'static [(Pi, bool)] {
        match self {
            Pgi::FileId => &[
                (Pi::Requester, false),
                (Pi::Server, false),
                (Pi::FileType, true),
                (Pi::FileName, true),
            ],
            Pgi::LogicalAttributes => &[
                (Pi::ArticleFormat, false),
                (Pi::ArticleLength, true),
                (Pi::FileOrganisation, false),
                (Pi::SignatureFlag, false),
                (Pi::SitSeal, false),
                (Pi::FileLabel, false),
                (Pi::KeyLength, false),
                (Pi::KeyOffset, false),
            ],
            Pgi::PhysicalAttributes => &[(Pi::ReservationUnit, false), (Pi::MaxReservation, true)],
            Pgi::HistoricalAttributes => &[(Pi::CreationDate, true), (Pi::ExtractionDate, false)],
        }
    }

    /// Whether `pi` belongs to this group.
    #[must_use]
    pub fn contains(self, pi: Pi) -> bool {
        self.members().iter().any(|(m, _)| *m == pi)
    }

    /// Group a parameter belongs to, if any.
    #[must_use]
    pub fn of(pi: Pi) -> Option<Pgi> {
        Pgi::ALL.iter().copied().find(|g| g.contains(pi))
    }
}

impl fmt::Display for Pgi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PGI {} ({})", self.code(), self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for pi in Pi::ALL {
            assert_eq!(Pi::from_code(pi.code()), Some(*pi));
        }
        for pgi in Pgi::ALL {
            assert_eq!(Pgi::from_code(pgi.code()), Some(*pgi));
        }
        assert!(Pi::ALL.windows(2).all(|w| w[0].code() < w[1].code()));
    }

    #[test]
    fn groups() {
        assert_eq!(Pgi::of(Pi::FileName), Some(Pgi::FileId));
        assert_eq!(Pgi::of(Pi::ArticleLength), Some(Pgi::LogicalAttributes));
        assert_eq!(Pgi::of(Pi::Diag), None);
        assert!(Pgi::FileId.contains(Pi::Requester));
    }
}
