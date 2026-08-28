//! Convenience constructors for the FPDUs of the Hors-SIT profile.

use crate::diag::Diagnostic;
use crate::fpdu::{Fpdu, FpduKind};
use crate::params::{
    AccessType, ArticleFormat, Compression, EndCode, RequestedAttributes, SyncOption, Version,
};
use crate::pi::{Pgi, Pi};

/// Parameters of a CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectParams {
    /// PI 3.
    pub requester: String,
    /// PI 4.
    pub server: String,
    /// PI 5 (optional password, at most 8 characters, plus optional new password).
    pub password: Option<String>,
    /// PI 6.
    pub version: Version,
    /// PI 7 (omitted when disabled).
    pub sync: SyncOption,
    /// PI 22.
    pub access: AccessType,
    /// PI 23.
    pub resync: bool,
    /// PI 1.
    pub crc: bool,
    /// PI 26 (seconds).
    pub timeout: Option<u16>,
    /// PI 99.
    pub free_message: Option<String>,
}

impl ConnectParams {
    /// Build the CONNECT FPDU with the requester connection id `id_src`.
    #[must_use]
    pub fn build(&self, id_src: u8) -> Fpdu {
        let mut f = Fpdu::new(FpduKind::Connect).with_ids(0, id_src);
        if self.crc {
            f.set_num(Pi::Crc, 1);
        }
        f.set_text(Pi::Requester, &self.requester)
            .set_text(Pi::Server, &self.server);
        if let Some(p) = self.password.as_deref().filter(|p| !p.is_empty()) {
            f.set_text(Pi::AccessControl, p);
        }
        f.set_num(Pi::Version, self.version.code());
        if self.sync.enabled() {
            f.set(Pi::SyncOption, self.sync.to_bytes());
        }
        f.set_num(Pi::AccessType, self.access.code());
        if self.resync {
            f.set_num(Pi::Resync, 1);
        }
        if let Some(t) = self.timeout {
            f.set_num(Pi::Timeout, u64::from(t));
        }
        if let Some(m) = self.free_message.as_deref().filter(|m| !m.is_empty()) {
            f.set_text(Pi::FreeMessage, m);
        }
        f
    }
}

/// Build an ACONNECT.
#[must_use]
pub fn aconnect(
    id_dst: u8,
    id_src: u8,
    version: Version,
    sync: SyncOption,
    resync: bool,
    free_message: Option<&str>,
) -> Fpdu {
    let mut f = Fpdu::new(FpduKind::Aconnect)
        .with_ids(id_dst, id_src)
        .with_num(Pi::Version, version.code());
    if sync.enabled() {
        f.set(Pi::SyncOption, sync.to_bytes());
    }
    if resync {
        f.set_num(Pi::Resync, 1);
    }
    if let Some(m) = free_message.filter(|m| !m.is_empty()) {
        f.set_text(Pi::FreeMessage, m);
    }
    f
}

/// Build an RCONNECT (connection refused).
#[must_use]
pub fn rconnect(id_dst: u8, diag: Diagnostic, free_message: Option<&str>) -> Fpdu {
    let mut f = Fpdu::new(FpduKind::Rconnect)
        .with_ids(id_dst, 0)
        .with_diag(diag);
    if let Some(m) = free_message.filter(|m| !m.is_empty()) {
        f.set_text(Pi::FreeMessage, m);
    }
    f
}

/// Build a RELEASE.
#[must_use]
pub fn release(id_dst: u8, id_src: u8, diag: Diagnostic) -> Fpdu {
    Fpdu::new(FpduKind::Release)
        .with_ids(id_dst, id_src)
        .with_diag(diag)
}

/// Build a RELCONF.
#[must_use]
pub fn relconf(id_dst: u8, id_src: u8) -> Fpdu {
    Fpdu::new(FpduKind::Relconf).with_ids(id_dst, id_src)
}

/// Build an ABORT.
#[must_use]
pub fn abort(id_dst: u8, id_src: u8, diag: Diagnostic) -> Fpdu {
    Fpdu::new(FpduKind::Abort)
        .with_ids(id_dst, id_src)
        .with_diag(diag)
}

/// Description of a file for CREATE / SELECT / ACK(SELECT).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileSpec {
    /// PI 3 inside PGI 9 (optional).
    pub requester: Option<String>,
    /// PI 4 inside PGI 9 (optional).
    pub server: Option<String>,
    /// PI 11.
    pub file_type: u64,
    /// PI 12.
    pub file_name: String,
    /// PI 13.
    pub transfer_id: u32,
    /// PI 15.
    pub restarted: bool,
    /// PI 16 (0 ASCII, 1 EBCDIC, 2 binary).
    pub data_code: Option<u8>,
    /// PI 17.
    pub priority: u8,
    /// PI 25.
    pub max_entity_size: u16,
    /// PI 31.
    pub article_format: ArticleFormat,
    /// PI 32.
    pub article_length: u16,
    /// PI 33.
    pub organisation: Option<u8>,
    /// PI 37.
    pub label: Option<String>,
    /// PI 41 (0 KB, 1 articles).
    pub reservation_unit: Option<u8>,
    /// PI 42.
    pub max_reservation: u64,
    /// PI 51 (`AAMMJJhhmmss`).
    pub creation_date: Option<String>,
    /// PI 52.
    pub extraction_date: Option<String>,
    /// PI 61.
    pub client_id: Option<String>,
    /// PI 62.
    pub bank_id: Option<String>,
    /// PI 63.
    pub file_access_control: Option<String>,
    /// PI 99.
    pub free_message: Option<String>,
}

impl FileSpec {
    fn file_id_group(&self) -> Vec<(Pi, Vec<u8>)> {
        let mut items = Vec::new();
        if let Some(r) = &self.requester {
            items.push((Pi::Requester, text(r)));
        }
        if let Some(s) = &self.server {
            items.push((Pi::Server, text(s)));
        }
        items.push((Pi::FileType, crate::fpdu::encode_num(self.file_type)));
        items.push((Pi::FileName, text(&self.file_name)));
        items
    }

    fn logical_group(&self) -> Vec<(Pi, Vec<u8>)> {
        let mut items = vec![
            (Pi::ArticleFormat, vec![self.article_format.code()]),
            (
                Pi::ArticleLength,
                crate::fpdu::encode_num(u64::from(self.article_length)),
            ),
        ];
        if let Some(o) = self.organisation {
            items.push((Pi::FileOrganisation, vec![o]));
        }
        if let Some(l) = self.label.as_deref().filter(|l| !l.is_empty()) {
            items.push((Pi::FileLabel, text(l)));
        }
        items
    }

    fn physical_group(&self) -> Vec<(Pi, Vec<u8>)> {
        let mut items = Vec::new();
        if let Some(u) = self.reservation_unit {
            items.push((Pi::ReservationUnit, vec![u]));
        }
        items.push((
            Pi::MaxReservation,
            crate::fpdu::encode_num(self.max_reservation),
        ));
        items
    }

    fn historical_group(&self) -> Option<Vec<(Pi, Vec<u8>)>> {
        let created = self.creation_date.as_deref()?;
        let mut items = vec![(Pi::CreationDate, text(created))];
        if let Some(e) = &self.extraction_date {
            items.push((Pi::ExtractionDate, text(e)));
        }
        Some(items)
    }

    fn common_tail(&self, f: &mut Fpdu) {
        if let Some(c) = &self.client_id {
            f.set_text(Pi::ClientId, c);
        }
        if let Some(b) = &self.bank_id {
            f.set_text(Pi::BankId, b);
        }
        if let Some(a) = &self.file_access_control {
            f.set_text(Pi::FileAccessControl, a);
        }
        if let Some(m) = self.free_message.as_deref().filter(|m| !m.is_empty()) {
            f.set_text(Pi::FreeMessage, m);
        }
    }

    /// Build a CREATE addressed to the server connection `id_dst`.
    #[must_use]
    pub fn create(&self, id_dst: u8) -> Fpdu {
        let mut f = Fpdu::new(FpduKind::Create).with_ids(id_dst, 0);
        f.set_pgi(Pgi::FileId, self.file_id_group())
            .set_num(Pi::TransferId, u64::from(self.transfer_id));
        if self.restarted {
            f.set_num(Pi::Restarted, 1);
        }
        if let Some(c) = self.data_code {
            f.set(Pi::DataCode, vec![c]);
        }
        f.set(Pi::Priority, vec![self.priority])
            .set_num(Pi::MaxEntitySize, u64::from(self.max_entity_size));
        f.set_pgi(Pgi::LogicalAttributes, self.logical_group())
            .set_pgi(Pgi::PhysicalAttributes, self.physical_group());
        if let Some(h) = self.historical_group() {
            f.set_pgi(Pgi::HistoricalAttributes, h);
        }
        self.common_tail(&mut f);
        f
    }

    /// Build a SELECT addressed to the server connection `id_dst`.
    #[must_use]
    pub fn select(&self, id_dst: u8, attributes: RequestedAttributes) -> Fpdu {
        let mut f = Fpdu::new(FpduKind::Select).with_ids(id_dst, 0);
        f.set_pgi(Pgi::FileId, self.file_id_group())
            .set_num(Pi::TransferId, u64::from(self.transfer_id));
        if attributes.code() != 0 {
            f.set(Pi::RequestedAttributes, vec![attributes.code()]);
        }
        if self.restarted {
            f.set_num(Pi::Restarted, 1);
        }
        f.set(Pi::Priority, vec![self.priority])
            .set_num(Pi::MaxEntitySize, u64::from(self.max_entity_size));
        self.common_tail(&mut f);
        f
    }

    /// Build a positive ACK(SELECT) describing the selected file.
    #[must_use]
    pub fn ack_select(&self, id_dst: u8, attributes: RequestedAttributes) -> Fpdu {
        let mut f = Fpdu::new(FpduKind::AckSelect)
            .with_ids(id_dst, 0)
            .with_diag(Diagnostic::OK);
        f.set_pgi(Pgi::FileId, self.file_id_group())
            .set_num(Pi::TransferId, u64::from(self.transfer_id));
        if let Some(c) = self.data_code {
            f.set(Pi::DataCode, vec![c]);
        }
        f.set_num(Pi::MaxEntitySize, u64::from(self.max_entity_size));
        if attributes.logical {
            f.set_pgi(Pgi::LogicalAttributes, self.logical_group());
        }
        if attributes.physical {
            f.set_pgi(Pgi::PhysicalAttributes, self.physical_group());
        }
        if attributes.historical {
            if let Some(h) = self.historical_group() {
                f.set_pgi(Pgi::HistoricalAttributes, h);
            }
        }
        if let Some(c) = &self.client_id {
            f.set_text(Pi::ClientId, c);
        }
        if let Some(b) = &self.bank_id {
            f.set_text(Pi::BankId, b);
        }
        if let Some(m) = self.free_message.as_deref().filter(|m| !m.is_empty()) {
            f.set_text(Pi::FreeMessage, m);
        }
        f
    }

    /// Extract a file specification from a CREATE, SELECT or ACK(SELECT).
    #[must_use]
    pub fn from_fpdu(f: &Fpdu) -> Self {
        use crate::params::FpduExt;
        Self {
            requester: f
                .pgi(Pgi::FileId)
                .and_then(|g| g.iter().find(|(p, _)| *p == Pi::Requester))
                .map(|(_, v)| text_of(v)),
            server: f
                .pgi(Pgi::FileId)
                .and_then(|g| g.iter().find(|(p, _)| *p == Pi::Server))
                .map(|(_, v)| text_of(v)),
            file_type: f.get_num(Pi::FileType).unwrap_or(0),
            file_name: f.get_text(Pi::FileName).unwrap_or_default(),
            transfer_id: f.transfer_id().unwrap_or(0),
            restarted: f.get_num(Pi::Restarted) == Some(1),
            data_code: f.get(Pi::DataCode).and_then(|v| v.first().copied()),
            priority: f
                .get(Pi::Priority)
                .and_then(|v| v.first().copied())
                .unwrap_or(0),
            max_entity_size: f.max_entity_size().unwrap_or(0),
            article_format: f
                .get(Pi::ArticleFormat)
                .map(ArticleFormat::from_bytes)
                .unwrap_or_default(),
            article_length: f.get_num(Pi::ArticleLength).unwrap_or(0).min(0xFFFF) as u16,
            organisation: f.get(Pi::FileOrganisation).and_then(|v| v.first().copied()),
            label: f.get_text(Pi::FileLabel),
            reservation_unit: f.get(Pi::ReservationUnit).and_then(|v| v.first().copied()),
            max_reservation: f.get_num(Pi::MaxReservation).unwrap_or(0),
            creation_date: f.get_text(Pi::CreationDate),
            extraction_date: f.get_text(Pi::ExtractionDate),
            client_id: f.get_text(Pi::ClientId),
            bank_id: f.get_text(Pi::BankId),
            file_access_control: f.get_text(Pi::FileAccessControl),
            free_message: f.get_text(Pi::FreeMessage),
        }
    }
}

fn text(s: &str) -> Vec<u8> {
    s.trim_end()
        .chars()
        .map(|c| if (c as u32) < 256 { c as u8 } else { b'?' })
        .collect()
}

fn text_of(v: &[u8]) -> String {
    v.iter()
        .map(|b| char::from(*b))
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// Build an ACK(CREATE).
#[must_use]
pub fn ack_create(
    id_dst: u8,
    diag: Diagnostic,
    transfer_id: Option<u32>,
    max_entity_size: u16,
    free_message: Option<&str>,
) -> Fpdu {
    let mut f = Fpdu::new(FpduKind::AckCreate)
        .with_ids(id_dst, 0)
        .with_diag(diag);
    if let Some(t) = transfer_id {
        f.set_num(Pi::TransferId, u64::from(t));
    }
    f.set_num(Pi::MaxEntitySize, u64::from(max_entity_size));
    if let Some(m) = free_message.filter(|m| !m.is_empty()) {
        f.set_text(Pi::FreeMessage, m);
    }
    f
}

/// Build a negative ACK(SELECT).
#[must_use]
pub fn nack_select(id_dst: u8, diag: Diagnostic, free_message: Option<&str>) -> Fpdu {
    let mut f = Fpdu::new(FpduKind::AckSelect)
        .with_ids(id_dst, 0)
        .with_diag(diag);
    if let Some(m) = free_message.filter(|m| !m.is_empty()) {
        f.set_text(Pi::FreeMessage, m);
    }
    f
}

/// Build a DESELECT.
#[must_use]
pub fn deselect(id_dst: u8, diag: Diagnostic) -> Fpdu {
    Fpdu::new(FpduKind::Deselect)
        .with_ids(id_dst, 0)
        .with_diag(diag)
}

/// Build an ACK(DESELECT).
#[must_use]
pub fn ack_deselect(id_dst: u8, diag: Diagnostic) -> Fpdu {
    Fpdu::new(FpduKind::AckDeselect)
        .with_ids(id_dst, 0)
        .with_diag(diag)
}

/// Build an ORF (open) proposing a compression.
#[must_use]
pub fn orf(id_dst: u8, compression: Compression) -> Fpdu {
    let mut f = Fpdu::new(FpduKind::Orf).with_ids(id_dst, 0);
    if compression != Compression::None {
        f.set(Pi::Compression, compression.to_bytes().to_vec());
    }
    f
}

/// Build an ACK(ORF).
#[must_use]
pub fn ack_orf(id_dst: u8, diag: Diagnostic, compression: Compression) -> Fpdu {
    let mut f = Fpdu::new(FpduKind::AckOrf)
        .with_ids(id_dst, 0)
        .with_diag(diag);
    if compression != Compression::None {
        f.set(Pi::Compression, compression.to_bytes().to_vec());
    }
    f
}

/// Build a CRF (close).
#[must_use]
pub fn crf(id_dst: u8, diag: Diagnostic) -> Fpdu {
    Fpdu::new(FpduKind::Crf).with_ids(id_dst, 0).with_diag(diag)
}

/// Build an ACK(CRF).
#[must_use]
pub fn ack_crf(id_dst: u8, diag: Diagnostic) -> Fpdu {
    Fpdu::new(FpduKind::AckCrf)
        .with_ids(id_dst, 0)
        .with_diag(diag)
}

/// Build a READ with the restart point (sync point number, 0 = beginning).
#[must_use]
pub fn read(id_dst: u8, restart_point: u32) -> Fpdu {
    Fpdu::new(FpduKind::Read)
        .with_ids(id_dst, 0)
        .with_num(Pi::RestartPoint, u64::from(restart_point))
}

/// Build an ACK(READ).
#[must_use]
pub fn ack_read(id_dst: u8, diag: Diagnostic) -> Fpdu {
    Fpdu::new(FpduKind::AckRead)
        .with_ids(id_dst, 0)
        .with_diag(diag)
}

/// Build a WRITE.
#[must_use]
pub fn write(id_dst: u8) -> Fpdu {
    Fpdu::new(FpduKind::Write).with_ids(id_dst, 0)
}

/// Build an ACK(WRITE) with the restart point chosen by the receiver.
#[must_use]
pub fn ack_write(id_dst: u8, diag: Diagnostic, restart_point: u32) -> Fpdu {
    Fpdu::new(FpduKind::AckWrite)
        .with_ids(id_dst, 0)
        .with_diag(diag)
        .with_num(Pi::RestartPoint, u64::from(restart_point))
}

/// Build a DTF.END.
#[must_use]
pub fn dtf_end(id_dst: u8, diag: Diagnostic) -> Fpdu {
    Fpdu::new(FpduKind::DtfEnd)
        .with_ids(id_dst, 0)
        .with_diag(diag)
}

/// Build a SYN.
#[must_use]
pub fn syn(id_dst: u8, number: u32) -> Fpdu {
    Fpdu::new(FpduKind::Syn)
        .with_ids(id_dst, 0)
        .with_num(Pi::SyncNumber, u64::from(number))
}

/// Build an ACK(SYN).
#[must_use]
pub fn ack_syn(id_dst: u8, number: u32) -> Fpdu {
    Fpdu::new(FpduKind::AckSyn)
        .with_ids(id_dst, 0)
        .with_num(Pi::SyncNumber, u64::from(number))
}

/// Build a RESYN.
#[must_use]
pub fn resyn(id_dst: u8, diag: Diagnostic, restart_point: u32) -> Fpdu {
    Fpdu::new(FpduKind::Resyn)
        .with_ids(id_dst, 0)
        .with_diag(diag)
        .with_num(Pi::RestartPoint, u64::from(restart_point))
}

/// Build an ACK(RESYN).
#[must_use]
pub fn ack_resyn(id_dst: u8, restart_point: u32) -> Fpdu {
    Fpdu::new(FpduKind::AckResyn)
        .with_ids(id_dst, 0)
        .with_num(Pi::RestartPoint, u64::from(restart_point))
}

/// Build an IDT (interrupt).
#[must_use]
pub fn idt(id_dst: u8, diag: Diagnostic, code: EndCode) -> Fpdu {
    Fpdu::new(FpduKind::Idt)
        .with_ids(id_dst, 0)
        .with_diag(diag)
        .with(Pi::EndCode, vec![code.code()])
}

/// Build an ACK(IDT).
#[must_use]
pub fn ack_idt(id_dst: u8) -> Fpdu {
    Fpdu::new(FpduKind::AckIdt).with_ids(id_dst, 0)
}

/// Build a TRANS.END with the optional counters.
#[must_use]
pub fn trans_end(id_dst: u8, byte_count: Option<u64>, article_count: Option<u64>) -> Fpdu {
    let mut f = Fpdu::new(FpduKind::TransEnd).with_ids(id_dst, 0);
    if let Some(b) = byte_count {
        f.set_num(Pi::ByteCount, b);
    }
    if let Some(a) = article_count {
        f.set_num(Pi::ArticleCount, a);
    }
    f
}

/// Build an ACK(TRANS.END).
#[must_use]
pub fn ack_trans_end(
    id_dst: u8,
    diag: Diagnostic,
    byte_count: Option<u64>,
    article_count: Option<u64>,
) -> Fpdu {
    let mut f = Fpdu::new(FpduKind::AckTransEnd)
        .with_ids(id_dst, 0)
        .with_diag(diag);
    if let Some(b) = byte_count {
        f.set_num(Pi::ByteCount, b);
    }
    if let Some(a) = article_count {
        f.set_num(Pi::ArticleCount, a);
    }
    f
}

/// Build a MSG (or MSGDM when `kind` is given) carrying `message` (PI 91).
#[must_use]
pub fn msg(
    kind: FpduKind,
    id_dst: u8,
    spec: &FileSpec,
    expects_reply: bool,
    message: Option<&[u8]>,
) -> Fpdu {
    let mut f = Fpdu::new(kind).with_ids(id_dst, 0);
    f.set_pgi(Pgi::FileId, spec.file_id_group())
        .set_num(Pi::TransferId, u64::from(spec.transfer_id));
    if expects_reply {
        f.set(Pi::RequestedAttributes, vec![1]);
    }
    if let Some(c) = spec.data_code {
        f.set(Pi::DataCode, vec![c]);
    }
    f.set(Pi::Priority, vec![spec.priority]);
    if let Some(h) = spec.historical_group() {
        f.set_pgi(Pgi::HistoricalAttributes, h);
    }
    if let Some(c) = &spec.client_id {
        f.set_text(Pi::ClientId, c);
    }
    if let Some(b) = &spec.bank_id {
        f.set_text(Pi::BankId, b);
    }
    if let Some(m) = message.filter(|m| !m.is_empty()) {
        f.set(Pi::Message, m.to_vec());
    }
    f
}

/// Build a MSGMM / MSGFM segment.
#[must_use]
pub fn msg_segment(kind: FpduKind, id_dst: u8, segment: &[u8]) -> Fpdu {
    let mut f = Fpdu::new(kind).with_ids(id_dst, 0);
    if !segment.is_empty() {
        f.set(Pi::Message, segment.to_vec());
    }
    f
}

/// Build an ACK(MSG).
#[must_use]
pub fn ack_msg(
    id_dst: u8,
    diag: Diagnostic,
    transfer_id: Option<u32>,
    reply: Option<&[u8]>,
) -> Fpdu {
    let mut f = Fpdu::new(FpduKind::AckMsg)
        .with_ids(id_dst, 0)
        .with_diag(diag);
    if let Some(t) = transfer_id {
        f.set_num(Pi::TransferId, u64::from(t));
    }
    if let Some(r) = reply.filter(|r| !r.is_empty()) {
        f.set(Pi::Message, r.to_vec());
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_and_create_validate() {
        let c = ConnectParams {
            requester: "PWSRV01".into(),
            server: "CETOM1".into(),
            password: Some("secret".into()),
            version: Version::E,
            sync: SyncOption {
                interval_kb: 256,
                window: 2,
            },
            access: AccessType::Write,
            resync: true,
            crc: true,
            timeout: None,
            free_message: None,
        }
        .build(7);
        let bytes = c.encode().unwrap_or_default();
        let d = Fpdu::decode(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.get_num(Pi::Crc), Some(1));
        assert_eq!(d.get_text(Pi::AccessControl).as_deref(), Some("secret"));
        assert_eq!(d.id_src, 7);

        let spec = FileSpec {
            file_name: "PWSEND".into(),
            transfer_id: 42,
            max_entity_size: 32768,
            article_format: ArticleFormat::Variable,
            article_length: 4096,
            max_reservation: 12,
            creation_date: Some("260828120000".into()),
            ..FileSpec::default()
        };
        let create = spec.create(0x62);
        let d =
            Fpdu::decode(&create.encode().unwrap_or_default()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(FileSpec::from_fpdu(&d), spec);
        let sel = spec.select(0x62, RequestedAttributes::ALL);
        let d = Fpdu::decode(&sel.encode().unwrap_or_default()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.get(Pi::RequestedAttributes), Some(&[7u8][..]));
        let ack = spec.ack_select(1, RequestedAttributes::ALL);
        let d = Fpdu::decode(&ack.encode().unwrap_or_default()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.get_num(Pi::ArticleLength), Some(4096));
        assert!(d.pgi(Pgi::HistoricalAttributes).is_some());
    }

    #[test]
    fn all_builders_validate() {
        let fpdus = vec![
            aconnect(
                1,
                2,
                Version::E,
                SyncOption {
                    interval_kb: 32,
                    window: 1,
                },
                true,
                Some("hi"),
            ),
            rconnect(1, Diagnostic::CALLER_UNKNOWN, Some("unknown")),
            release(2, 1, Diagnostic::OK),
            relconf(1, 2),
            abort(2, 1, Diagnostic::TIMEOUT),
            ack_create(1, Diagnostic::OK, Some(5), 4096, None),
            nack_select(1, Diagnostic::FILE_NOT_FOUND, Some("no")),
            deselect(2, Diagnostic::OK),
            ack_deselect(1, Diagnostic::OK),
            orf(2, Compression::Mixed),
            ack_orf(1, Diagnostic::OK, Compression::Horizontal),
            crf(2, Diagnostic::OK),
            ack_crf(1, Diagnostic::OK),
            read(2, 3),
            ack_read(1, Diagnostic::OK),
            write(2),
            ack_write(1, Diagnostic::OK, 0),
            dtf_end(2, Diagnostic::OK),
            syn(2, 12),
            ack_syn(1, 12),
            resyn(2, Diagnostic::TRANSMISSION_ERROR, 11),
            ack_resyn(1, 11),
            idt(2, Diagnostic::VOLUNTARY_STOP, EndCode::CancelByRequester),
            ack_idt(1),
            trans_end(2, Some(1_000_000), Some(245)),
            ack_trans_end(1, Diagnostic::OK, Some(1_000_000), Some(245)),
            msg(
                FpduKind::Msg,
                2,
                &FileSpec {
                    file_name: "MSG".into(),
                    transfer_id: 1,
                    ..FileSpec::default()
                },
                true,
                Some(b"hello"),
            ),
            msg_segment(FpduKind::MsgFm, 2, b"tail"),
            ack_msg(1, Diagnostic::OK, Some(1), Some(b"ok")),
        ];
        for f in fpdus {
            let bytes = f.encode().unwrap_or_else(|e| panic!("{e}"));
            let d = Fpdu::decode(&bytes).unwrap_or_else(|e| panic!("{e} for {f:?}"));
            assert_eq!(d, f);
        }
    }
}
