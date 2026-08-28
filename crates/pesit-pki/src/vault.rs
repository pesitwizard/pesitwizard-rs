//! A native HashiCorp Vault PKI backend.
//!
//! Issues and signs certificates through Vault's PKI secrets engine
//! (`{address}/v1/{mount}/issue/{role}`), with token or AppRole authentication.

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::provider::{CertRequest, Issued, PkiError};

/// Vault authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "camelCase")]
pub enum VaultAuth {
    /// A fixed Vault token.
    Token {
        /// The token.
        token: String,
    },
    /// AppRole login (a token is fetched and cached).
    AppRole {
        /// Role identifier.
        role_id: String,
        /// Secret identifier.
        secret_id: String,
        /// AppRole auth mount (default `approle`).
        #[serde(default)]
        mount: Option<String>,
    },
}

/// Vault PKI configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    /// Vault base address, e.g. `https://vault.example.com:8200`.
    pub address: String,
    /// PKI secrets-engine mount (default `pki`).
    #[serde(default)]
    pub mount: Option<String>,
    /// PKI role used to issue certificates.
    pub role: String,
    /// Authentication.
    pub auth: VaultAuth,
    /// Vault namespace (Vault Enterprise).
    #[serde(default)]
    pub namespace: Option<String>,
    /// CA certificate (PEM) trusted for the TLS connection to Vault.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Skip TLS verification when connecting to Vault (testing only).
    #[serde(default)]
    pub insecure: bool,
}

impl VaultConfig {
    fn pki_mount(&self) -> &str {
        self.mount.as_deref().unwrap_or("pki")
    }
}

/// A Vault PKI client.
pub struct VaultPki {
    cfg: VaultConfig,
    client: reqwest::Client,
    token: Mutex<Option<String>>,
}

impl std::fmt::Debug for VaultPki {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultPki")
            .field("address", &self.cfg.address)
            .field("mount", &self.cfg.pki_mount())
            .field("role", &self.cfg.role)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct IssueResponse {
    data: IssueData,
}
#[derive(Deserialize)]
struct IssueData {
    certificate: String,
    #[serde(default)]
    issuing_ca: Option<String>,
    #[serde(default)]
    ca_chain: Vec<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    serial_number: Option<String>,
}

impl VaultPki {
    /// Build a Vault client from its configuration.
    pub fn new(cfg: VaultConfig) -> Result<Self, PkiError> {
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
        if cfg.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(pem) = &cfg.ca_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| PkiError::Vault(format!("invalid Vault CA: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|e| PkiError::Vault(e.to_string()))?;
        Ok(Self {
            cfg,
            client,
            token: Mutex::new(None),
        })
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}",
            self.cfg.address.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn with_headers(
        &self,
        rb: reqwest::RequestBuilder,
        token: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut rb = rb;
        if let Some(t) = token {
            rb = rb.header("X-Vault-Token", t);
        }
        if let Some(ns) = &self.cfg.namespace {
            rb = rb.header("X-Vault-Namespace", ns);
        }
        rb
    }

    /// Obtain a usable token (logging in via AppRole and caching it when needed).
    async fn token(&self) -> Result<String, PkiError> {
        match &self.cfg.auth {
            VaultAuth::Token { token } => Ok(token.clone()),
            VaultAuth::AppRole {
                role_id,
                secret_id,
                mount,
            } => {
                if let Some(t) = self.token.lock().await.clone() {
                    return Ok(t);
                }
                let mount = mount.as_deref().unwrap_or("approle");
                let body = serde_json::json!({ "role_id": role_id, "secret_id": secret_id });
                let resp = self
                    .with_headers(
                        self.client.post(self.url(&format!("auth/{mount}/login"))),
                        None,
                    )
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| PkiError::Vault(e.to_string()))?;
                let value = Self::json(resp).await?;
                let token = value
                    .get("auth")
                    .and_then(|a| a.get("client_token"))
                    .and_then(|t| t.as_str())
                    .ok_or_else(|| PkiError::Vault("AppRole login returned no token".into()))?
                    .to_owned();
                *self.token.lock().await = Some(token.clone());
                Ok(token)
            }
        }
    }

    async fn json(resp: reqwest::Response) -> Result<serde_json::Value, PkiError> {
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| PkiError::Vault(e.to_string()))?;
        if !status.is_success() {
            let msg = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| {
                    v.get("errors").and_then(|e| {
                        e.as_array().map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join("; ")
                        })
                    })
                })
                .filter(|s| !s.is_empty())
                .unwrap_or(text);
            return Err(PkiError::Vault(format!("HTTP {status}: {msg}")));
        }
        serde_json::from_str(&text).map_err(|e| PkiError::Vault(e.to_string()))
    }

    /// Issue a certificate through Vault.
    pub async fn issue(&self, req: &CertRequest) -> Result<Issued, PkiError> {
        let token = self.token().await?;
        let path = format!("{}/issue/{}", self.cfg.pki_mount(), self.cfg.role);
        let body = serde_json::json!({
            "common_name": req.common_name,
            "alt_names": req.dns_names().join(","),
            "ip_sans": req.ip_names().join(","),
            "ttl": format!("{}h", u64::from(req.ttl_days) * 24),
        });
        let resp = self
            .with_headers(self.client.post(self.url(&path)), Some(&token))
            .json(&body)
            .send()
            .await
            .map_err(|e| PkiError::Vault(e.to_string()))?;
        let value = Self::json(resp).await?;
        let parsed: IssueResponse =
            serde_json::from_value(value).map_err(|e| PkiError::Vault(e.to_string()))?;
        let mut chain = parsed.data.ca_chain;
        if chain.is_empty() {
            if let Some(ca) = parsed.data.issuing_ca {
                chain.push(ca);
            }
        }
        Ok(Issued {
            certificate: parsed.data.certificate,
            private_key: parsed.data.private_key,
            ca_chain: chain,
            serial: parsed.data.serial_number,
        })
    }

    /// The CA chain of the PKI mount (PEM certificates).
    pub async fn ca_chain(&self) -> Result<Vec<String>, PkiError> {
        let url = self.url(&format!("{}/ca_chain", self.cfg.pki_mount()));
        let resp = self
            .with_headers(self.client.get(url), None)
            .send()
            .await
            .map_err(|e| PkiError::Vault(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| PkiError::Vault(e.to_string()))?;
        if !status.is_success() || text.trim().is_empty() {
            // fall back to the single issuing certificate
            let url = self.url(&format!("{}/ca/pem", self.cfg.pki_mount()));
            let resp = self
                .with_headers(self.client.get(url), None)
                .send()
                .await
                .map_err(|e| PkiError::Vault(e.to_string()))?;
            let text = resp
                .text()
                .await
                .map_err(|e| PkiError::Vault(e.to_string()))?;
            return Ok(split_pem(&text));
        }
        Ok(split_pem(&text))
    }

    /// Check that Vault is reachable and the PKI mount responds; returns the Vault version.
    pub async fn health(&self) -> Result<String, PkiError> {
        let resp = self
            .with_headers(self.client.get(self.url("sys/health")), None)
            .send()
            .await
            .map_err(|e| PkiError::Vault(e.to_string()))?;
        let value = Self::json(resp).await?;
        Ok(value
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned())
    }
}

fn split_pem(bundle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in bundle.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            cur = String::new();
        }
        if !cur.is_empty() || line.contains("BEGIN CERTIFICATE") {
            cur.push_str(line);
            cur.push('\n');
        }
        if line.contains("END CERTIFICATE") {
            out.push(std::mem::take(&mut cur));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::CertRequest;

    #[test]
    fn splits_a_pem_bundle_into_certificates() {
        let bundle = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let parts = split_pem(bundle);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("AAA") && parts[1].contains("BBB"));
        assert!(split_pem("nothing here").is_empty());
    }

    #[test]
    fn request_splits_dns_and_ip_sans() {
        let req = CertRequest {
            common_name: "a.example".into(),
            sans: vec![
                "DNS:a.example".into(),
                "b.example".into(),
                "IP:10.0.0.1".into(),
                "192.168.0.1".into(),
            ],
            ttl_days: 30,
            is_ca: false,
            server_auth: true,
            client_auth: true,
            organization: None,
        };
        assert_eq!(
            req.dns_names(),
            vec!["a.example".to_owned(), "b.example".to_owned()],
            "CN kept once, IPs excluded"
        );
        assert_eq!(
            req.ip_names(),
            vec!["10.0.0.1".to_owned(), "192.168.0.1".to_owned()]
        );
    }

    #[test]
    fn parses_a_realistic_vault_issue_response() {
        let json = serde_json::json!({
            "request_id": "abc",
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
                "issuing_ca": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----",
                "serial_number": "1a:2b:3c"
            }
        });
        let parsed: IssueResponse = serde_json::from_value(json).unwrap_or_else(|e| panic!("{e}"));
        assert!(parsed.data.certificate.contains("LEAF"));
        assert_eq!(parsed.data.serial_number.as_deref(), Some("1a:2b:3c"));
        assert!(parsed.data.private_key.is_some());
    }

    #[test]
    fn builds_urls_and_config_defaults() {
        let cfg = VaultConfig {
            address: "https://vault.local:8200/".into(),
            mount: None,
            role: "pesit".into(),
            auth: VaultAuth::Token { token: "t".into() },
            namespace: None,
            ca_pem: None,
            insecure: true,
        };
        assert_eq!(cfg.pki_mount(), "pki");
        let v = VaultPki::new(cfg).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            v.url("pki/issue/pesit"),
            "https://vault.local:8200/v1/pki/issue/pesit"
        );
    }
}
