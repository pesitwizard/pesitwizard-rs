//! On-disk store of keystores (certificate + private key) and truststores (CA bundles).

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cert::{self, CertInfo};

/// Store error.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// I/O error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Certificate parsing error.
    #[error("{0}")]
    Cert(#[from] cert::CertError),
    /// Invalid name.
    #[error("invalid name '{0}'")]
    Name(String),
    /// A keystore must contain a certificate and a private key.
    #[error("a keystore needs both a certificate and a private key")]
    MissingKey,
}

/// Metadata of a keystore.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeystoreMeta {
    /// Name.
    pub name: String,
    /// Leaf certificate details.
    pub info: CertInfo,
    /// Absolute path of the certificate (PEM).
    pub cert_path: String,
    /// Absolute path of the private key (PEM).
    pub key_path: String,
}

/// Metadata of a truststore.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TruststoreMeta {
    /// Name.
    pub name: String,
    /// Certificates in the bundle.
    pub certs: Vec<CertInfo>,
    /// Absolute path of the bundle (PEM).
    pub path: String,
}

fn sanitize(name: &str) -> Result<String, StoreError> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if ok && name != "." && name != ".." {
        Ok(name.to_owned())
    } else {
        Err(StoreError::Name(name.to_owned()))
    }
}

/// A certificate store rooted at a directory.
#[derive(Debug, Clone)]
pub struct CertStore {
    keystores: PathBuf,
    truststores: PathBuf,
}

impl CertStore {
    /// Open (or create) a store under `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        let keystores = dir.join("keystores");
        let truststores = dir.join("truststores");
        std::fs::create_dir_all(&keystores)?;
        std::fs::create_dir_all(&truststores)?;
        Ok(Self {
            keystores,
            truststores,
        })
    }

    fn key_cert(&self, name: &str) -> PathBuf {
        self.keystores.join(format!("{name}.crt.pem"))
    }
    fn key_key(&self, name: &str) -> PathBuf {
        self.keystores.join(format!("{name}.key.pem"))
    }
    fn trust_path(&self, name: &str) -> PathBuf {
        self.truststores.join(format!("{name}.pem"))
    }

    /// Store a keystore (certificate + private key), replacing any existing one.
    pub fn put_keystore(
        &self,
        name: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<KeystoreMeta, StoreError> {
        let name = sanitize(name)?;
        if !key_pem.contains("PRIVATE KEY") {
            return Err(StoreError::MissingKey);
        }
        let info = cert::inspect_pem(cert_pem.as_bytes())?;
        std::fs::write(self.key_cert(&name), cert_pem)?;
        write_private(&self.key_key(&name), key_pem)?;
        Ok(KeystoreMeta {
            name: name.clone(),
            info,
            cert_path: self.key_cert(&name).to_string_lossy().into_owned(),
            key_path: self.key_key(&name).to_string_lossy().into_owned(),
        })
    }

    /// Store a truststore (one or more CA certificates), replacing any existing one.
    pub fn put_truststore(
        &self,
        name: &str,
        bundle_pem: &str,
    ) -> Result<TruststoreMeta, StoreError> {
        let name = sanitize(name)?;
        let certs = cert::inspect_all(bundle_pem.as_bytes())?;
        std::fs::write(self.trust_path(&name), bundle_pem)?;
        Ok(TruststoreMeta {
            name: name.clone(),
            certs,
            path: self.trust_path(&name).to_string_lossy().into_owned(),
        })
    }

    /// Read a keystore's metadata.
    #[must_use]
    pub fn keystore(&self, name: &str) -> Option<KeystoreMeta> {
        let name = sanitize(name).ok()?;
        let cert = std::fs::read(self.key_cert(&name)).ok()?;
        let info = cert::inspect_pem(&cert).ok()?;
        Some(KeystoreMeta {
            name: name.clone(),
            info,
            cert_path: self.key_cert(&name).to_string_lossy().into_owned(),
            key_path: self.key_key(&name).to_string_lossy().into_owned(),
        })
    }

    /// Read a truststore's metadata.
    #[must_use]
    pub fn truststore(&self, name: &str) -> Option<TruststoreMeta> {
        let name = sanitize(name).ok()?;
        let data = std::fs::read(self.trust_path(&name)).ok()?;
        let certs = cert::inspect_all(&data).ok()?;
        Some(TruststoreMeta {
            name: name.clone(),
            certs,
            path: self.trust_path(&name).to_string_lossy().into_owned(),
        })
    }

    /// List all keystores (in name order).
    #[must_use]
    pub fn list_keystores(&self) -> Vec<KeystoreMeta> {
        list_names(&self.keystores, ".crt.pem")
            .into_iter()
            .filter_map(|n| self.keystore(&n))
            .collect()
    }

    /// List all truststores (in name order).
    #[must_use]
    pub fn list_truststores(&self) -> Vec<TruststoreMeta> {
        list_names(&self.truststores, ".pem")
            .into_iter()
            .filter_map(|n| self.truststore(&n))
            .collect()
    }

    /// Certificate and key file paths of a keystore, if it exists.
    #[must_use]
    pub fn keystore_files(&self, name: &str) -> Option<(PathBuf, PathBuf)> {
        let name = sanitize(name).ok()?;
        let (c, k) = (self.key_cert(&name), self.key_key(&name));
        (c.exists() && k.exists()).then_some((c, k))
    }

    /// Bundle file path of a truststore, if it exists.
    #[must_use]
    pub fn truststore_file(&self, name: &str) -> Option<PathBuf> {
        let name = sanitize(name).ok()?;
        let p = self.trust_path(&name);
        p.exists().then_some(p)
    }

    /// Delete a keystore; returns whether it existed.
    pub fn delete_keystore(&self, name: &str) -> Result<bool, StoreError> {
        let name = sanitize(name)?;
        let existed = self.key_cert(&name).exists();
        remove_if(&self.key_cert(&name))?;
        remove_if(&self.key_key(&name))?;
        Ok(existed)
    }

    /// Delete a truststore; returns whether it existed.
    pub fn delete_truststore(&self, name: &str) -> Result<bool, StoreError> {
        let name = sanitize(name)?;
        let existed = self.trust_path(&name).exists();
        remove_if(&self.trust_path(&name))?;
        Ok(existed)
    }
}

fn list_names(dir: &Path, suffix: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.strip_suffix(suffix).map(str::to_owned)
        })
        .collect();
    names.sort();
    names
}

fn remove_if(p: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::LocalCa;
    use crate::provider::CertRequest;

    fn material() -> (String, String, String) {
        let ca = LocalCa::generate("Test CA", None, 3650).unwrap_or_else(|e| panic!("{e}"));
        let req = CertRequest {
            common_name: "svc".into(),
            sans: vec!["DNS:svc".into()],
            ttl_days: 365,
            is_ca: false,
            server_auth: true,
            client_auth: true,
            organization: None,
        };
        let issued = ca.issue(&req).unwrap_or_else(|e| panic!("{e}"));
        (
            issued.certificate,
            issued.private_key.unwrap_or_default(),
            ca.cert_pem().to_owned(),
        )
    }

    #[test]
    fn keystore_round_trip() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let store = CertStore::open(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        let (cert, key, _) = material();
        let meta = store
            .put_keystore("node-tls", &cert, &key)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(meta.name, "node-tls");
        assert!(meta.info.subject.contains("svc"));
        // files exist and are usable for TLS wiring
        let (cp, kp) = store
            .keystore_files("node-tls")
            .unwrap_or_else(|| panic!("keystore files missing"));
        assert!(cp.exists() && kp.exists());
        assert_eq!(store.list_keystores().len(), 1);
        assert_eq!(
            store.keystore("node-tls").map(|m| m.name),
            Some("node-tls".into())
        );
        // key file is not world-readable on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&kp)
                .unwrap_or_else(|e| panic!("{e}"))
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "private key must not be group/other readable"
            );
        }
        assert!(store
            .delete_keystore("node-tls")
            .unwrap_or_else(|e| panic!("{e}")));
        assert!(!store
            .delete_keystore("node-tls")
            .unwrap_or_else(|e| panic!("{e}")));
        assert!(store.list_keystores().is_empty());
    }

    #[test]
    fn truststore_round_trip_and_multi_cert() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let store = CertStore::open(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        let (_, _, ca1) = material();
        let (_, _, ca2) = material();
        let bundle = format!("{ca1}{ca2}");
        let meta = store
            .put_truststore("roots", &bundle)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(meta.certs.len(), 2, "the bundle has two CA certificates");
        assert!(meta.certs.iter().all(|c| c.is_ca));
        assert!(store.truststore_file("roots").is_some());
        assert_eq!(store.list_truststores().len(), 1);
    }

    #[test]
    fn rejects_keystore_without_key_and_bad_names() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let store = CertStore::open(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        let (cert, _, _) = material();
        assert!(matches!(
            store.put_keystore("x", &cert, "no key here"),
            Err(StoreError::MissingKey)
        ));
        assert!(matches!(
            store.put_truststore("../evil", &cert),
            Err(StoreError::Name(_))
        ));
        assert!(matches!(
            store.put_truststore("a/b", &cert),
            Err(StoreError::Name(_))
        ));
    }
}
