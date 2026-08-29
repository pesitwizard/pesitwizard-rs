//! Certificate and CA management for PeSIT Wizard: X.509 inspection, a local certificate authority
//! (`rcgen`), a native HashiCorp Vault PKI backend, and an on-disk certificate store.

pub mod ca;
pub mod cert;
pub mod ocsp;
pub mod provider;
pub mod sign;
pub mod store;
pub mod vault;

pub use ca::LocalCa;
pub use cert::{inspect_all, inspect_pem, CertInfo};
pub use provider::{Backend, CertRequest, Issued, PkiError};
pub use store::{CertStore, KeystoreMeta, TruststoreMeta};
pub use vault::{VaultAuth, VaultConfig, VaultPki};
