//! FPDU (File transfer Protocol Data Unit) kinds, structure, encoding and decoding (§4.7).

use std::fmt;

use crate::diag::Diagnostic;
use crate::pi::{Pgi, Pi};

/// Size of the fixed FPDU header (length, phase, type, id.dst, id.src).
pub const HEADER_LEN: usize = 6;
/// Largest FPDU length representable in the 2-byte length field.
pub const MAX_FPDU_LEN: usize = 0xFFFF;

/// Phase byte values (octet 3).
pub mod phase {
    /// Connection phase FPDUs.
    pub const CONNECTION: u8 = 0x40;
    /// Data FPDUs (DTF, DTFDA, DTFMA, DTFFA).
    pub const DATA: u8 = 0x00;
    /// Every other FPDU.
    pub const OTHER: u8 = 0xC0;
}

macro_rules! define_kinds {
    ($( $name:ident = ($phase:expr, $code:expr, $label:expr); )*) => {
        /// FPDU kind (phase + type bytes).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        pub enum FpduKind {
            $(
                #[doc = $label]
                $name,
            )*
        }

        impl FpduKind {
            /// All kinds.
            pub const ALL: &'static [FpduKind] = &[$(FpduKind::$name),*];

            /// Phase byte (octet 3).
            #[must_use]
            pub const fn phase(self) -> u8 {
                match self { $( FpduKind::$name => $phase, )* }
            }

            /// Type byte (octet 4).
            #[must_use]
            pub const fn type_code(self) -> u8 {
                match self { $( FpduKind::$name => $code, )* }
            }

            /// Protocol name (e.g. `FPDU.ACK(CREATE)`).
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $( FpduKind::$name => $label, )* }
            }

            /// Kind from the phase and type bytes.
            #[must_use]
            pub fn from_codes(phase: u8, type_code: u8) -> Option<FpduKind> {
                match (phase, type_code) {
                    $( ($phase, $code) => Some(FpduKind::$name), )*
                    _ => None,
                }
            }
        }
    };
}

define_kinds! {
    Connect = (0x40, 0x20, "FPDU.CONNECT");
    Aconnect = (0x40, 0x21, "FPDU.ACONNECT");
    Rconnect = (0x40, 0x22, "FPDU.RCONNECT");
    Release = (0x40, 0x23, "FPDU.RELEASE");
    Relconf = (0x40, 0x24, "FPDU.RELCONF");
    Abort = (0x40, 0x25, "FPDU.ABORT");
    Read = (0xC0, 0x01, "FPDU.READ");
    Write = (0xC0, 0x02, "FPDU.WRITE");
    Syn = (0xC0, 0x03, "FPDU.SYN");
    DtfEnd = (0xC0, 0x04, "FPDU.DTF.END");
    Resyn = (0xC0, 0x05, "FPDU.RESYN");
    Idt = (0xC0, 0x06, "FPDU.IDT");
    TransEnd = (0xC0, 0x08, "FPDU.TRANS.END");
    Create = (0xC0, 0x11, "FPDU.CREATE");
    Select = (0xC0, 0x12, "FPDU.SELECT");
    Deselect = (0xC0, 0x13, "FPDU.DESELECT");
    Orf = (0xC0, 0x14, "FPDU.ORF");
    Crf = (0xC0, 0x15, "FPDU.CRF");
    Msg = (0xC0, 0x16, "FPDU.MSG");
    MsgDm = (0xC0, 0x17, "FPDU.MSGDM");
    MsgMm = (0xC0, 0x18, "FPDU.MSGMM");
    MsgFm = (0xC0, 0x19, "FPDU.MSGFM");
    AckCreate = (0xC0, 0x30, "FPDU.ACK(CREATE)");
    AckSelect = (0xC0, 0x31, "FPDU.ACK(SELECT)");
    AckDeselect = (0xC0, 0x32, "FPDU.ACK(DESELECT)");
    AckOrf = (0xC0, 0x33, "FPDU.ACK(ORF)");
    AckCrf = (0xC0, 0x34, "FPDU.ACK(CRF)");
    AckRead = (0xC0, 0x35, "FPDU.ACK(READ)");
    AckWrite = (0xC0, 0x36, "FPDU.ACK(WRITE)");
    AckTransEnd = (0xC0, 0x37, "FPDU.ACK(TRANS.END)");
    AckSyn = (0xC0, 0x38, "FPDU.ACK(SYN)");
    AckResyn = (0xC0, 0x39, "FPDU.ACK(RESYN)");
    AckIdt = (0xC0, 0x3A, "FPDU.ACK(IDT)");
    AckMsg = (0xC0, 0x3B, "FPDU.ACK(MSG)");
    Dtf = (0x00, 0x00, "FPDU.DTF");
    DtfMa = (0x00, 0x40, "FPDU.DTFMA");
    DtfDa = (0x00, 0x41, "FPDU.DTFDA");
    DtfFa = (0x00, 0x42, "FPDU.DTFFA");
}

impl FpduKind {
    /// Whether the FPDU carries file data (DTF, DTFDA, DTFMA, DTFFA).
    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(
            self,
            FpduKind::Dtf | FpduKind::DtfDa | FpduKind::DtfMa | FpduKind::DtfFa
        )
    }

    /// The acknowledgement FPDU expected in answer to this FPDU, if any.
    #[must_use]
    pub const fn ack(self) -> Option<FpduKind> {
        Some(match self {
            FpduKind::Connect => FpduKind::Aconnect,
            FpduKind::Release => FpduKind::Relconf,
            FpduKind::Create => FpduKind::AckCreate,
            FpduKind::Select => FpduKind::AckSelect,
            FpduKind::Deselect => FpduKind::AckDeselect,
            FpduKind::Orf => FpduKind::AckOrf,
            FpduKind::Crf => FpduKind::AckCrf,
            FpduKind::Read => FpduKind::AckRead,
            FpduKind::Write => FpduKind::AckWrite,
            FpduKind::TransEnd => FpduKind::AckTransEnd,
            FpduKind::Syn => FpduKind::AckSyn,
            FpduKind::Resyn => FpduKind::AckResyn,
            FpduKind::Idt => FpduKind::AckIdt,
            FpduKind::Msg | FpduKind::MsgFm => FpduKind::AckMsg,
            _ => return None,
        })
    }

    /// Whether this FPDU is an acknowledgement (positive or negative).
    #[must_use]
    pub const fn is_ack(self) -> bool {
        matches!(
            self,
            FpduKind::Aconnect
                | FpduKind::Rconnect
                | FpduKind::Relconf
                | FpduKind::AckCreate
                | FpduKind::AckSelect
                | FpduKind::AckDeselect
                | FpduKind::AckOrf
                | FpduKind::AckCrf
                | FpduKind::AckRead
                | FpduKind::AckWrite
                | FpduKind::AckTransEnd
                | FpduKind::AckSyn
                | FpduKind::AckResyn
                | FpduKind::AckIdt
                | FpduKind::AckMsg
        )
    }

    /// Whether this FPDU may be concatenated with others in one data entity (§4.5).
    #[must_use]
    pub const fn concatenable(self) -> bool {
        matches!(
            self,
            FpduKind::Dtf
                | FpduKind::DtfDa
                | FpduKind::DtfMa
                | FpduKind::DtfFa
                | FpduKind::DtfEnd
                | FpduKind::Syn
        )
    }

    /// Parameter template: allowed top-level PI/PGI codes in canonical order with their
    /// mandatory flag (§3.6, §4.4, cross-checked with Connect:Express parse templates).
    #[must_use]
    pub fn template(self) -> &'static [ParamRule] {
        use ParamRule as R;
        const fn m(code: u8) -> ParamRule {
            ParamRule {
                code,
                mandatory: true,
            }
        }
        const fn o(code: u8) -> ParamRule {
            ParamRule {
                code,
                mandatory: false,
            }
        }
        const SECURITY_REQ: [ParamRule; 5] = [o(71), o(72), o(73), o(75), o(77)];
        const CONNECT: &[R] = &[
            o(1),
            m(3),
            m(4),
            o(5),
            m(6),
            o(7),
            m(22),
            o(23),
            o(26),
            o(99),
        ];
        const ACONNECT: &[R] = &[o(5), m(6), o(7), o(23), o(99)];
        const DIAG_ONLY: &[R] = &[m(2), o(29)];
        const DIAG_MSG: &[R] = &[m(2), o(29), o(99)];
        const RELCONF: &[R] = &[o(99)];
        const CREATE: &[R] = &[
            m(9),
            m(13),
            o(15),
            o(16),
            m(17),
            m(25),
            m(30),
            m(40),
            o(50),
            o(61),
            o(62),
            o(63),
            SECURITY_REQ[0],
            SECURITY_REQ[1],
            SECURITY_REQ[2],
            SECURITY_REQ[3],
            SECURITY_REQ[4],
            o(80),
            o(99),
        ];
        const ACK_CREATE: &[R] = &[m(2), o(13), o(25), o(29), o(64), o(72), o(80), o(83), o(99)];
        const SELECT: &[R] = &[
            m(9),
            m(13),
            o(14),
            o(15),
            m(17),
            m(25),
            o(61),
            o(62),
            o(63),
            SECURITY_REQ[0],
            SECURITY_REQ[1],
            SECURITY_REQ[2],
            SECURITY_REQ[3],
            SECURITY_REQ[4],
            o(80),
            o(99),
        ];
        const ACK_SELECT: &[R] = &[
            m(2),
            o(9),
            o(13),
            o(16),
            o(25),
            o(29),
            o(30),
            o(40),
            o(50),
            o(61),
            o(62),
            o(64),
            o(72),
            o(80),
            o(83),
            o(99),
        ];
        const ORF: &[R] = &[o(21), o(72), o(74), o(76), o(80), o(83)];
        const ACK_ORF: &[R] = &[m(2), o(21), o(29), o(74), o(76)];
        const READ: &[R] = &[m(18)];
        const ACK_WRITE: &[R] = &[m(2), m(18), o(29)];
        const DTF_END: &[R] = &[m(2), o(29), o(78), o(79), o(82)];
        const SYN: &[R] = &[m(20), o(78)];
        const ACK_SYN: &[R] = &[m(20)];
        const RESYN: &[R] = &[m(2), m(18), o(29)];
        const ACK_RESYN: &[R] = &[m(18)];
        const IDT: &[R] = &[m(2), o(19), o(29)];
        const TRANS_END: &[R] = &[o(27), o(28), o(81)];
        const ACK_TRANS_END: &[R] = &[m(2), o(27), o(28), o(29), o(81)];
        const MSG: &[R] = &[
            m(9),
            m(13),
            o(14),
            o(16),
            m(17),
            o(30),
            o(40),
            o(50),
            o(61),
            o(62),
            o(73),
            o(74),
            o(77),
            o(78),
            o(79),
            o(80),
            o(81),
            o(91),
        ];
        const MSG_SEGMENT: &[R] = &[o(91)];
        const ACK_MSG: &[R] = &[m(2), o(13), o(16), o(29), o(79), o(80), o(81), o(91)];
        const NONE: &[R] = &[];
        match self {
            FpduKind::Connect => CONNECT,
            FpduKind::Aconnect => ACONNECT,
            FpduKind::Rconnect | FpduKind::Release | FpduKind::Deselect | FpduKind::AckDeselect => {
                DIAG_MSG
            }
            FpduKind::Relconf => RELCONF,
            FpduKind::Abort | FpduKind::Crf | FpduKind::AckCrf | FpduKind::AckRead => DIAG_ONLY,
            FpduKind::Create => CREATE,
            FpduKind::AckCreate => ACK_CREATE,
            FpduKind::Select => SELECT,
            FpduKind::AckSelect => ACK_SELECT,
            FpduKind::Orf => ORF,
            FpduKind::AckOrf => ACK_ORF,
            FpduKind::Read => READ,
            FpduKind::Write
            | FpduKind::AckIdt
            | FpduKind::Dtf
            | FpduKind::DtfDa
            | FpduKind::DtfMa
            | FpduKind::DtfFa => NONE,
            FpduKind::AckWrite => ACK_WRITE,
            FpduKind::DtfEnd => DTF_END,
            FpduKind::Syn => SYN,
            FpduKind::AckSyn => ACK_SYN,
            FpduKind::Resyn => RESYN,
            FpduKind::AckResyn => ACK_RESYN,
            FpduKind::Idt => IDT,
            FpduKind::TransEnd => TRANS_END,
            FpduKind::AckTransEnd => ACK_TRANS_END,
            FpduKind::Msg | FpduKind::MsgDm => MSG,
            FpduKind::MsgMm | FpduKind::MsgFm => MSG_SEGMENT,
            FpduKind::AckMsg => ACK_MSG,
        }
    }
}

impl fmt::Display for FpduKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One entry of a FPDU parameter template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamRule {
    /// PI or PGI code.
    pub code: u8,
    /// Whether the parameter is mandatory.
    pub mandatory: bool,
}

/// A parameter unit: either a single PI or a PGI containing PIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    /// Single parameter.
    Pi {
        /// Identifier.
        pi: Pi,
        /// Raw value.
        value: Vec<u8>,
    },
    /// Parameter group.
    Pgi {
        /// Group identifier.
        pgi: Pgi,
        /// Contained parameters in canonical order.
        items: Vec<(Pi, Vec<u8>)>,
    },
}

impl Param {
    /// Wire code of the unit (PI or PGI code).
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            Param::Pi { pi, .. } => pi.code(),
            Param::Pgi { pgi, .. } => pgi.code(),
        }
    }
}

/// A decoded (or to-be-encoded) FPDU.
#[derive(Clone, PartialEq, Eq)]
pub struct Fpdu {
    /// Kind (phase + type).
    pub kind: FpduKind,
    /// Octet 5: connection identifier at the destination.
    pub id_dst: u8,
    /// Octet 6: connection identifier at the source, or number of articles for a multi-article DTF.
    pub id_src: u8,
    /// Parameters in canonical (ascending code) order. Empty for data FPDUs.
    pub params: Vec<Param>,
    /// Raw content of data FPDUs (file data), empty otherwise.
    pub data: Vec<u8>,
}

/// Error returned when a FPDU cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{diag}: {detail}")]
pub struct DecodeError {
    /// Diagnostic to report to the peer (318 for parameter problems, 311 for structural ones).
    pub diag: Diagnostic,
    /// Human readable detail.
    pub detail: String,
}

impl DecodeError {
    fn param(detail: impl Into<String>) -> Self {
        Self {
            diag: Diagnostic::INVALID_PARAMETER,
            detail: detail.into(),
        }
    }

    fn protocol(detail: impl Into<String>) -> Self {
        Self {
            diag: Diagnostic::REMOTE_PROTOCOL_ERROR,
            detail: detail.into(),
        }
    }
}

impl Fpdu {
    /// Create an empty FPDU of the given kind.
    #[must_use]
    pub fn new(kind: FpduKind) -> Self {
        Self {
            kind,
            id_dst: 0,
            id_src: 0,
            params: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Create a data FPDU carrying `data`.
    #[must_use]
    pub fn data(kind: FpduKind, id_dst: u8, id_src: u8, data: Vec<u8>) -> Self {
        Self {
            kind,
            id_dst,
            id_src,
            params: Vec::new(),
            data,
        }
    }

    /// Set the connection identifiers.
    #[must_use]
    pub fn with_ids(mut self, id_dst: u8, id_src: u8) -> Self {
        self.id_dst = id_dst;
        self.id_src = id_src;
        self
    }

    /// Insert or replace a top-level parameter, keeping canonical order.
    pub fn set(&mut self, pi: Pi, value: impl Into<Vec<u8>>) -> &mut Self {
        let value = value.into();
        let code = pi.code();
        match self.params.binary_search_by_key(&code, Param::code) {
            Ok(i) => self.params[i] = Param::Pi { pi, value },
            Err(i) => self.params.insert(i, Param::Pi { pi, value }),
        }
        self
    }

    /// Builder-style [`Fpdu::set`].
    #[must_use]
    pub fn with(mut self, pi: Pi, value: impl Into<Vec<u8>>) -> Self {
        self.set(pi, value);
        self
    }

    /// Insert or replace a numeric parameter (minimal big-endian encoding, at least one byte).
    pub fn set_num(&mut self, pi: Pi, value: u64) -> &mut Self {
        self.set(pi, encode_num(value))
    }

    /// Builder-style [`Fpdu::set_num`].
    #[must_use]
    pub fn with_num(mut self, pi: Pi, value: u64) -> Self {
        self.set_num(pi, value);
        self
    }

    /// Insert or replace a text parameter (ISO-8859-1, trailing blanks trimmed).
    pub fn set_text(&mut self, pi: Pi, value: &str) -> &mut Self {
        let bytes: Vec<u8> = value
            .trim_end()
            .chars()
            .map(|c| if (c as u32) < 256 { c as u8 } else { b'?' })
            .collect();
        self.set(pi, bytes)
    }

    /// Builder-style [`Fpdu::set_text`].
    #[must_use]
    pub fn with_text(mut self, pi: Pi, value: &str) -> Self {
        self.set_text(pi, value);
        self
    }

    /// Insert or replace a diagnostic (PI 2).
    pub fn set_diag(&mut self, diag: Diagnostic) -> &mut Self {
        self.set(Pi::Diag, diag.to_bytes().to_vec())
    }

    /// Builder-style [`Fpdu::set_diag`].
    #[must_use]
    pub fn with_diag(mut self, diag: Diagnostic) -> Self {
        self.set_diag(diag);
        self
    }

    /// Insert or replace a parameter group. Items are sorted into canonical order.
    pub fn set_pgi(&mut self, pgi: Pgi, mut items: Vec<(Pi, Vec<u8>)>) -> &mut Self {
        items.sort_by_key(|(pi, _)| pi.code());
        let code = pgi.code();
        match self.params.binary_search_by_key(&code, Param::code) {
            Ok(i) => self.params[i] = Param::Pgi { pgi, items },
            Err(i) => self.params.insert(i, Param::Pgi { pgi, items }),
        }
        self
    }

    /// Builder-style [`Fpdu::set_pgi`].
    #[must_use]
    pub fn with_pgi(mut self, pgi: Pgi, items: Vec<(Pi, Vec<u8>)>) -> Self {
        self.set_pgi(pgi, items);
        self
    }

    /// Remove a top-level parameter.
    pub fn remove(&mut self, pi: Pi) -> Option<Vec<u8>> {
        let i = self
            .params
            .iter()
            .position(|p| matches!(p, Param::Pi { pi: p, .. } if *p == pi))?;
        match self.params.remove(i) {
            Param::Pi { value, .. } => Some(value),
            Param::Pgi { .. } => None,
        }
    }

    /// Raw value of a parameter, looked up at top level then inside groups.
    #[must_use]
    pub fn get(&self, pi: Pi) -> Option<&[u8]> {
        for p in &self.params {
            match p {
                Param::Pi { pi: q, value } if *q == pi => return Some(value),
                Param::Pgi { items, .. } => {
                    if let Some((_, v)) = items.iter().find(|(q, _)| *q == pi) {
                        return Some(v);
                    }
                }
                Param::Pi { .. } => {}
            }
        }
        None
    }

    /// Whether the parameter is present (top level or in a group).
    #[must_use]
    pub fn has(&self, pi: Pi) -> bool {
        self.get(pi).is_some()
    }

    /// Items of a parameter group.
    #[must_use]
    pub fn pgi(&self, pgi: Pgi) -> Option<&[(Pi, Vec<u8>)]> {
        self.params.iter().find_map(|p| match p {
            Param::Pgi { pgi: g, items } if *g == pgi => Some(items.as_slice()),
            _ => None,
        })
    }

    /// Numeric value of a parameter (big-endian, up to 8 bytes).
    #[must_use]
    pub fn get_num(&self, pi: Pi) -> Option<u64> {
        self.get(pi).map(decode_num)
    }

    /// Text value of a parameter (ISO-8859-1, trailing blanks trimmed).
    #[must_use]
    pub fn get_text(&self, pi: Pi) -> Option<String> {
        self.get(pi).map(|v| {
            v.iter()
                .map(|b| char::from(*b))
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
    }

    /// Diagnostic (PI 2), if present.
    #[must_use]
    pub fn diag(&self) -> Option<Diagnostic> {
        self.get(Pi::Diag).and_then(Diagnostic::from_bytes)
    }

    /// Whether this FPDU is an acknowledgement carrying a non-zero diagnostic.
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.kind.is_ack() && self.diag().is_some_and(|d| !d.is_ok())
    }

    /// Total encoded length (header + content), without CRC.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        if self.kind.is_data() {
            return HEADER_LEN + self.data.len();
        }
        HEADER_LEN
            + self
                .params
                .iter()
                .map(|p| match p {
                    Param::Pi { value, .. } => unit_len(value.len()),
                    Param::Pgi { items, .. } => {
                        unit_len(items.iter().map(|(_, v)| unit_len(v.len())).sum())
                    }
                })
                .sum::<usize>()
    }

    /// Encode the FPDU (without CRC). Fails if the FPDU would not fit in 65535 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Append the encoded FPDU to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let total = self.encoded_len();
        if total > MAX_FPDU_LEN {
            return Err(EncodeError::TooLong(total));
        }
        let start = out.len();
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.push(self.kind.phase());
        out.push(self.kind.type_code());
        out.push(self.id_dst);
        out.push(self.id_src);
        if self.kind.is_data() {
            out.extend_from_slice(&self.data);
        } else {
            for p in &self.params {
                match p {
                    Param::Pi { pi, value } => {
                        if value.is_empty() {
                            return Err(EncodeError::EmptyValue(pi.code()));
                        }
                        push_unit(out, pi.code(), value);
                    }
                    Param::Pgi { pgi, items } => {
                        let mut inner = Vec::new();
                        for (pi, value) in items {
                            if value.is_empty() {
                                return Err(EncodeError::EmptyValue(pi.code()));
                            }
                            push_unit(&mut inner, pi.code(), value);
                        }
                        push_unit(out, pgi.code(), &inner);
                    }
                }
            }
        }
        debug_assert_eq!(out.len() - start, total);
        Ok(())
    }

    /// Decode one complete FPDU from `bytes` (exactly one FPDU, no CRC, no trailing bytes).
    /// Parameters are validated against the FPDU template (order, mandatory, known codes).
    pub fn decode(bytes: &[u8]) -> Result<Fpdu, DecodeError> {
        Self::decode_with(bytes, true)
    }

    /// Decode one FPDU without template validation (only structural checks).
    pub fn decode_lenient(bytes: &[u8]) -> Result<Fpdu, DecodeError> {
        Self::decode_with(bytes, false)
    }

    fn decode_with(bytes: &[u8], strict: bool) -> Result<Fpdu, DecodeError> {
        if bytes.len() < HEADER_LEN {
            return Err(DecodeError::protocol(format!(
                "FPDU too short ({} bytes)",
                bytes.len()
            )));
        }
        let declared = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        if declared != bytes.len() {
            return Err(DecodeError::protocol(format!(
                "FPDU length field {} does not match the {} bytes received",
                declared,
                bytes.len()
            )));
        }
        let kind = FpduKind::from_codes(bytes[2], bytes[3]).ok_or_else(|| {
            DecodeError::protocol(format!(
                "unknown FPDU phase/type {:#04x}/{:#04x}",
                bytes[2], bytes[3]
            ))
        })?;
        let mut fpdu = Fpdu {
            kind,
            id_dst: bytes[4],
            id_src: bytes[5],
            params: Vec::new(),
            data: Vec::new(),
        };
        let body = &bytes[HEADER_LEN..];
        if kind.is_data() {
            fpdu.data = body.to_vec();
            return Ok(fpdu);
        }
        let mut pos = 0;
        let mut last_code = 0u8;
        while pos < body.len() {
            let (code, value, next) = read_unit(body, pos)?;
            if code <= last_code && !fpdu.params.is_empty() {
                if strict {
                    return Err(DecodeError::param(format!(
                        "parameter {code} appears after parameter {last_code} (wrong order or duplicate)"
                    )));
                }
            } else {
                last_code = code;
            }
            if let Some(pgi) = Pgi::from_code(code) {
                let mut items = Vec::new();
                let mut ipos = 0;
                let mut last_inner = 0u8;
                while ipos < value.len() {
                    let (icode, ivalue, inext) = read_unit(value, ipos)?;
                    let pi = Pi::from_code(icode).ok_or_else(|| {
                        DecodeError::param(format!("unknown PI {icode} inside {pgi}"))
                    })?;
                    if strict {
                        if !pgi.contains(pi) {
                            return Err(DecodeError::param(format!(
                                "{pi} is not allowed inside {pgi}"
                            )));
                        }
                        if icode <= last_inner && !items.is_empty() {
                            return Err(DecodeError::param(format!(
                                "{pi} out of order inside {pgi}"
                            )));
                        }
                    }
                    last_inner = icode;
                    items.push((pi, ivalue.to_vec()));
                    ipos = inext;
                }
                fpdu.params.push(Param::Pgi { pgi, items });
            } else if let Some(pi) = Pi::from_code(code) {
                fpdu.params.push(Param::Pi {
                    pi,
                    value: value.to_vec(),
                });
            } else {
                return Err(DecodeError::param(format!("unknown parameter code {code}")));
            }
            pos = next;
        }
        if strict {
            fpdu.validate_template()?;
        }
        Ok(fpdu)
    }

    /// Check the parameters against the template of the FPDU kind.
    pub fn validate_template(&self) -> Result<(), DecodeError> {
        let template = self.kind.template();
        for p in &self.params {
            let code = p.code();
            if !template.iter().any(|r| r.code == code) {
                return Err(DecodeError::param(format!(
                    "parameter {code} not allowed in {}",
                    self.kind
                )));
            }
            if let Param::Pi { pi, value } = p {
                let max = pi.max_len();
                if max != 0 && value.len() > max {
                    return Err(DecodeError::param(format!(
                        "{pi} value too long ({} > {max})",
                        value.len()
                    )));
                }
            }
            if let Param::Pgi { pgi, items } = p {
                for (pi, mandatory) in pgi.members() {
                    if *mandatory && !items.iter().any(|(q, _)| q == pi) {
                        return Err(DecodeError::param(format!(
                            "mandatory {pi} missing inside {pgi}"
                        )));
                    }
                }
            }
        }
        for rule in template.iter().filter(|r| r.mandatory) {
            if !self.params.iter().any(|p| p.code() == rule.code) {
                return Err(DecodeError::param(format!(
                    "mandatory parameter {} missing in {}",
                    rule.code, self.kind
                )));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Fpdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} dst={} src={}",
            self.kind.name(),
            self.id_dst,
            self.id_src
        )?;
        if self.kind.is_data() {
            return write!(f, " data={} bytes", self.data.len());
        }
        for p in &self.params {
            match p {
                Param::Pi { pi, value } => write!(f, " {}", render(*pi, value))?,
                Param::Pgi { pgi, items } => {
                    write!(f, " PGI{}{{", pgi.code())?;
                    for (pi, v) in items {
                        write!(f, " {}", render(*pi, v))?;
                    }
                    write!(f, " }}")?;
                }
            }
        }
        Ok(())
    }
}

fn render(pi: Pi, value: &[u8]) -> String {
    use crate::pi::ValueKind;
    match pi.kind() {
        ValueKind::Text | ValueKind::DateTime => {
            let s: String = value.iter().map(|b| char::from(*b)).collect();
            format!("PI{}={s:?}", pi.code())
        }
        ValueKind::Number | ValueKind::Symbol | ValueKind::Mask if value.len() <= 8 => {
            format!("PI{}={}", pi.code(), decode_num(value))
        }
        _ => format!("PI{}=0x{}", pi.code(), hex(value)),
    }
}

/// Hexadecimal rendering of a byte slice.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Encoding error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// The FPDU exceeds 65535 bytes.
    #[error("FPDU too long: {0} bytes")]
    TooLong(usize),
    /// A parameter has an empty value (LI = 0 is forbidden).
    #[error("parameter {0} has an empty value")]
    EmptyValue(u8),
}

fn unit_len(value_len: usize) -> usize {
    1 + if value_len < 255 { 1 } else { 3 } + value_len
}

fn push_unit(out: &mut Vec<u8>, code: u8, value: &[u8]) {
    out.push(code);
    if value.len() < 255 {
        out.push(value.len() as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(value);
}

/// Read one PI/PGI unit at `pos`; returns `(code, value, next position)`.
fn read_unit(buf: &[u8], pos: usize) -> Result<(u8, &[u8], usize), DecodeError> {
    let code = buf[pos];
    let li_pos = pos + 1;
    let Some(&li) = buf.get(li_pos) else {
        return Err(DecodeError::param(format!(
            "parameter {code}: missing length indicator"
        )));
    };
    let (len, start) = if li == 0xFF {
        match buf.get(li_pos + 1..li_pos + 3) {
            Some(b) => (usize::from(u16::from_be_bytes([b[0], b[1]])), li_pos + 3),
            None => {
                return Err(DecodeError::param(format!(
                    "parameter {code}: truncated extended length"
                )))
            }
        }
    } else {
        (usize::from(li), li_pos + 1)
    };
    if len == 0 {
        return Err(DecodeError::param(format!(
            "parameter {code}: zero length is forbidden"
        )));
    }
    let end = start + len;
    if end > buf.len() {
        return Err(DecodeError::param(format!(
            "parameter {code}: declared length {len} exceeds the {} remaining bytes",
            buf.len() - start
        )));
    }
    Ok((code, &buf[start..end], end))
}

/// Minimal big-endian encoding of an unsigned number (at least one byte).
#[must_use]
pub fn encode_num(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
    bytes[first..].to_vec()
}

/// Big-endian decoding of an unsigned number (values longer than 8 bytes keep the low 8).
#[must_use]
pub fn decode_num(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(encode_num(0), vec![0]);
        assert_eq!(encode_num(255), vec![255]);
        assert_eq!(encode_num(256), vec![1, 0]);
        assert_eq!(encode_num(0x0102_0304), vec![1, 2, 3, 4]);
        assert_eq!(decode_num(&[1, 2, 3, 4]), 0x0102_0304);
        assert_eq!(decode_num(&[]), 0);
    }

    #[test]
    fn connect_round_trip() {
        let mut f = Fpdu::new(FpduKind::Connect).with_ids(0, 1);
        f.set_text(Pi::Requester, "CXCLIENT")
            .set_text(Pi::Server, "PESITSRV")
            .set_num(Pi::Version, 2)
            .set(Pi::SyncOption, vec![0, 32, 2])
            .set_num(Pi::AccessType, 0);
        let bytes = f.encode().unwrap_or_default();
        assert_eq!(bytes[..6], [0, bytes.len() as u8, 0x40, 0x20, 0, 1]);
        let g = Fpdu::decode(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(f, g);
        assert_eq!(g.get_text(Pi::Requester).as_deref(), Some("CXCLIENT"));
        assert_eq!(g.get_num(Pi::Version), Some(2));
        // canonical order is enforced by set()
        assert_eq!(
            g.params.iter().map(Param::code).collect::<Vec<_>>(),
            vec![3, 4, 6, 7, 22]
        );
    }

    #[test]
    fn create_with_groups() {
        let f = Fpdu::new(FpduKind::Create)
            .with_ids(0x62, 0)
            .with_pgi(
                Pgi::FileId,
                vec![(Pi::FileName, b"PWSEND".to_vec()), (Pi::FileType, vec![0])],
            )
            .with_num(Pi::TransferId, 0x1234)
            .with_num(Pi::Priority, 0)
            .with_num(Pi::MaxEntitySize, 32768)
            .with_pgi(
                Pgi::LogicalAttributes,
                vec![
                    (Pi::ArticleFormat, vec![0x80]),
                    (Pi::ArticleLength, vec![0x10, 0]),
                ],
            )
            .with_pgi(Pgi::PhysicalAttributes, vec![(Pi::MaxReservation, vec![5])])
            .with_pgi(
                Pgi::HistoricalAttributes,
                vec![(Pi::CreationDate, b"260828120000".to_vec())],
            );
        let bytes = f.encode().unwrap_or_default();
        let g = Fpdu::decode(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(f, g);
        assert_eq!(g.get_text(Pi::FileName).as_deref(), Some("PWSEND"));
        assert_eq!(g.pgi(Pgi::FileId).map(|i| i[0].0), Some(Pi::FileType));
        assert_eq!(g.get_num(Pi::ArticleLength), Some(4096));
        assert_eq!(g.get_num(Pi::MaxReservation), Some(5));
    }

    #[test]
    fn strict_validation() {
        // wrong order: PI 4 before PI 3
        let bytes = [0, 16, 0x40, 0x20, 0, 1, 4, 1, b'S', 3, 1, b'C', 6, 1, 2, 22];
        let mut v = bytes.to_vec();
        v.push(1);
        v.push(0);
        v[1] = v.len() as u8;
        let err = Fpdu::decode(&v).err().map(|e| e.diag);
        assert_eq!(err, Some(Diagnostic::INVALID_PARAMETER));
        assert!(Fpdu::decode_lenient(&v).is_ok());
        // missing mandatory PI 22
        let f = Fpdu::new(FpduKind::Connect)
            .with_text(Pi::Requester, "A")
            .with_text(Pi::Server, "B")
            .with_num(Pi::Version, 2);
        let v = f.encode().unwrap_or_default();
        assert_eq!(
            Fpdu::decode(&v).err().map(|e| e.diag),
            Some(Diagnostic::INVALID_PARAMETER)
        );
        // zero length
        let v = [0u8, 8, 0xC0, 0x02, 1, 0, 2, 0];
        assert!(Fpdu::decode(&v).is_err());
        // length mismatch
        let v = [0u8, 9, 0xC0, 0x02, 1, 0];
        assert_eq!(
            Fpdu::decode(&v).err().map(|e| e.diag),
            Some(Diagnostic::REMOTE_PROTOCOL_ERROR)
        );
    }

    #[test]
    fn extended_length() {
        let msg = vec![b'x'; 300];
        let f = Fpdu::new(FpduKind::MsgMm)
            .with_ids(5, 0)
            .with(Pi::Message, msg.clone());
        let v = f.encode().unwrap_or_default();
        assert_eq!(v[6], 91);
        assert_eq!(v[7], 0xFF);
        assert_eq!(u16::from_be_bytes([v[8], v[9]]), 300);
        let g = Fpdu::decode(&v).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(g.get(Pi::Message), Some(msg.as_slice()));
    }

    #[test]
    fn data_fpdu() {
        let f = Fpdu::data(FpduKind::Dtf, 0x62, 0, vec![1, 2, 3]);
        let v = f.encode().unwrap_or_default();
        assert_eq!(v, vec![0, 9, 0, 0, 0x62, 0, 1, 2, 3]);
        assert_eq!(Fpdu::decode(&v).unwrap_or_else(|e| panic!("{e}")), f);
    }

    #[test]
    fn kinds_round_trip() {
        for k in FpduKind::ALL {
            assert_eq!(FpduKind::from_codes(k.phase(), k.type_code()), Some(*k));
            // templates are in ascending order
            let t = k.template();
            assert!(t.windows(2).all(|w| w[0].code < w[1].code), "{k}");
        }
        assert_eq!(FpduKind::Create.ack(), Some(FpduKind::AckCreate));
        assert!(FpduKind::AckSyn.is_ack());
    }
}
