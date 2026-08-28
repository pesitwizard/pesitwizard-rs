//! Common types for certificate issuance and the provider backends.

use serde::{Deserialize, Serialize};

fn default_ttl() -> u32 {
    365
}
fn default_true() -> bool {
    true
}

/// A request to issue a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertRequest {
    /// Common name (CN).
    pub common_name: String,
    /// Subject alternative names (`DNS:host`, `IP:1.2.3.4`, or bare host / address).
    #[serde(default)]
    pub sans: Vec<String>,
    /// Validity in days.
    #[serde(default = "default_ttl")]
    pub ttl_days: u32,
    /// Issue a CA certificate.
    #[serde(default)]
    pub is_ca: bool,
    /// Include the TLS server-authentication extended key usage.
    #[serde(default = "default_true")]
    pub server_auth: bool,
    /// Include the TLS client-authentication extended key usage.
    #[serde(default = "default_true")]
    pub client_auth: bool,
    /// Organization (O).
    #[serde(default)]
    pub organization: Option<String>,
}

impl CertRequest {
    /// DNS-style SANs (without the `DNS:` prefix), plus the CN.
    #[must_use]
    pub fn dns_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .sans
            .iter()
            .filter_map(|s| {
                let s = s.trim();
                if let Some(d) = s.strip_prefix("DNS:") {
                    Some(d.to_owned())
                } else if s.starts_with("IP:") || s.parse::<std::net::IpAddr>().is_ok() {
                    None
                } else {
                    Some(s.to_owned())
                }
            })
            .collect();
        if !v.iter().any(|d| d.eq_ignore_ascii_case(&self.common_name)) {
            v.insert(0, self.common_name.clone());
        }
        v
    }

    /// IP SANs.
    #[must_use]
    pub fn ip_names(&self) -> Vec<String> {
        self.sans
            .iter()
            .filter_map(|s| {
                let s = s.trim().strip_prefix("IP:").unwrap_or(s.trim());
                s.parse::<std::net::IpAddr>().ok().map(|_| s.to_owned())
            })
            .collect()
    }
}

/// An issued certificate (PEM).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Issued {
    /// The leaf certificate (PEM).
    pub certificate: String,
    /// The private key (PEM), when the backend returns one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// The issuing CA chain (PEM), leaf-issuer first.
    #[serde(default)]
    pub ca_chain: Vec<String>,
    /// Serial number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
}

/// PKI error.
#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    /// Local generation failure.
    #[error("certificate generation: {0}")]
    Gen(String),
    /// Vault backend failure.
    #[error("vault: {0}")]
    Vault(String),
    /// No CA is configured.
    #[error("no local CA configured")]
    NoCa,
    /// I/O error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// A certificate-issuing backend.
pub enum Backend {
    /// A local certificate authority.
    Local(crate::ca::LocalCa),
    /// A HashiCorp Vault PKI secrets engine.
    Vault(Box<crate::vault::VaultPki>),
}

impl Backend {
    /// Issue a certificate.
    pub async fn issue(&self, req: &CertRequest) -> Result<Issued, PkiError> {
        match self {
            Backend::Local(ca) => ca.issue(req),
            Backend::Vault(v) => v.issue(req).await,
        }
    }

    /// The issuing CA chain (PEM).
    pub async fn ca_chain(&self) -> Result<Vec<String>, PkiError> {
        match self {
            Backend::Local(ca) => Ok(vec![ca.cert_pem().to_owned()]),
            Backend::Vault(v) => v.ca_chain().await,
        }
    }

    /// Backend kind (`"local"` / `"vault"`).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Backend::Local(_) => "local",
            Backend::Vault(_) => "vault",
        }
    }
}
