//! X.509 certificate inspection.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Human-readable summary of a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number (hex).
    pub serial: String,
    /// Not-before (RFC 3339).
    pub not_before: String,
    /// Not-after (RFC 3339).
    pub not_after: String,
    /// Whether the certificate is currently within its validity window.
    pub valid: bool,
    /// Whether it is a CA certificate.
    pub is_ca: bool,
    /// Subject alternative names.
    pub sans: Vec<String>,
    /// SHA-256 fingerprint (hex, colon-separated).
    pub fingerprint: String,
}

/// Certificate parsing error.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// No PEM certificate found.
    #[error("no certificate found in the PEM input")]
    NoCert,
    /// Malformed certificate.
    #[error("invalid certificate: {0}")]
    Parse(String),
}

fn sha256_hex(data: &[u8]) -> String {
    // Small self-contained SHA-256 (fingerprints only; not security-critical).
    let h = Sha256::digest(data);
    h.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Inspect the first certificate in a PEM bundle.
pub fn inspect_pem(pem_bytes: &[u8]) -> Result<CertInfo, CertError> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(pem_bytes).map_err(|e| CertError::Parse(e.to_string()))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| CertError::Parse(e.to_string()))?;
    Ok(inspect(&cert, &pem.contents))
}

/// Inspect every certificate in a PEM bundle.
pub fn inspect_all(pem_bytes: &[u8]) -> Result<Vec<CertInfo>, CertError> {
    let mut out = Vec::new();
    for pem in x509_parser::pem::Pem::iter_from_buffer(pem_bytes).flatten() {
        if let Ok(cert) = pem.parse_x509() {
            out.push(inspect(&cert, &pem.contents));
        }
    }
    if out.is_empty() {
        return Err(CertError::NoCert);
    }
    Ok(out)
}

fn inspect(cert: &X509Certificate<'_>, der: &[u8]) -> CertInfo {
    let nb = cert.validity().not_before;
    let na = cert.validity().not_after;
    let now = ASN1Time::now();
    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .map(|g| match g {
                    GeneralName::DNSName(s) => format!("DNS:{s}"),
                    GeneralName::IPAddress(b) => format!(
                        "IP:{}",
                        b.iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(".")
                    ),
                    GeneralName::RFC822Name(s) => format!("email:{s}"),
                    GeneralName::URI(s) => format!("URI:{s}"),
                    other => format!("{other:?}"),
                })
                .collect()
        })
        .unwrap_or_default();
    CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before: nb.to_rfc2822().unwrap_or_else(|_| nb.to_string()),
        not_after: na.to_rfc2822().unwrap_or_else(|_| na.to_string()),
        valid: nb <= now && now <= na,
        is_ca: cert.is_ca(),
        sans,
        fingerprint: sha256_hex(der),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_a_generated_certificate() {
        let ca = crate::ca::LocalCa::generate("Root CA", Some("Org"), 3650)
            .unwrap_or_else(|e| panic!("{e}"));
        let info = inspect_pem(ca.cert_pem().as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert!(info.is_ca);
        assert!(info.subject.contains("Root CA"));
        assert_eq!(
            info.issuer, info.subject,
            "a self-signed CA is its own issuer"
        );
        assert_eq!(
            info.fingerprint.len(),
            32 * 3 - 1,
            "SHA-256 fingerprint is 32 hex-pairs joined by colons"
        );
        assert!(info
            .fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':'));
    }

    #[test]
    fn rejects_non_certificate_input() {
        assert!(matches!(
            inspect_pem(b"not a certificate"),
            Err(CertError::Parse(_) | CertError::NoCert)
        ));
    }

    #[test]
    fn known_sha256_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let fp = sha256_hex(b"abc");
        assert!(
            fp.to_lowercase().starts_with("ba:78:16:bf:8f:01:cf:ea"),
            "{fp}"
        );
    }
}
