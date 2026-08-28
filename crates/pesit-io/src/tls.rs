//! rustls configuration helpers for PeSIT over TLS.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
pub use tokio_rustls::{TlsAcceptor, TlsConnector};

/// TLS protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2.
    #[serde(rename = "1.2")]
    V1_2,
    /// TLS 1.3.
    #[serde(rename = "1.3")]
    V1_3,
}

/// TLS client (requester side) settings.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TlsClientSettings {
    /// PEM file with the CA certificates used to verify the server (system roots when absent).
    pub ca_file: Option<String>,
    /// PEM file with the client certificate chain (mutual TLS).
    pub cert_file: Option<String>,
    /// PEM file with the client private key (mutual TLS).
    pub key_file: Option<String>,
    /// Verify that the server certificate matches the host name (default true).
    pub verify_hostname: Option<bool>,
    /// Skip certificate verification altogether (testing only).
    #[serde(default)]
    pub insecure: bool,
    /// Minimum TLS version (default 1.2).
    pub min_version: Option<TlsVersion>,
}

/// TLS server (responder side) settings.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TlsServerSettings {
    /// PEM file with the server certificate chain.
    pub cert_file: String,
    /// PEM file with the server private key.
    pub key_file: String,
    /// PEM file with the CA certificates used to verify client certificates.
    pub ca_file: Option<String>,
    /// Require a client certificate (mutual TLS).
    #[serde(default)]
    pub require_client_cert: bool,
    /// Minimum TLS version (default 1.2).
    pub min_version: Option<TlsVersion>,
}

/// TLS setup error.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// File access error.
    #[error("cannot read {0}: {1}")]
    Io(String, std::io::Error),
    /// PEM parsing error.
    #[error("invalid PEM in {0}")]
    Pem(String),
    /// rustls configuration error.
    #[error("TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
    /// Certificate verifier construction error.
    #[error("TLS verifier: {0}")]
    Verifier(#[from] rustls::client::VerifierBuilderError),
    /// Invalid server name.
    #[error("invalid server name {0}")]
    ServerName(String),
}

static TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
static TLS12_UP: [&rustls::SupportedProtocolVersion; 2] =
    [&rustls::version::TLS12, &rustls::version::TLS13];

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let data = std::fs::read(path).map_err(|e| TlsError::Io(path.to_owned(), e))?;
    rustls_pemfile::certs(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::Pem(path.to_owned()))
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let data = std::fs::read(path).map_err(|e| TlsError::Io(path.to_owned(), e))?;
    rustls_pemfile::private_key(&mut data.as_slice())
        .map_err(|_| TlsError::Pem(path.to_owned()))?
        .ok_or_else(|| TlsError::Pem(path.to_owned()))
}

fn versions(min: Option<TlsVersion>) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match min {
        Some(TlsVersion::V1_3) => &TLS13_ONLY,
        _ => &TLS12_UP,
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build a TLS connector.
pub fn connector(settings: &TlsClientSettings) -> Result<TlsConnector, TlsError> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(settings.min_version))?;
    let builder = if settings.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider())))
    } else {
        let mut roots = RootCertStore::empty();
        match &settings.ca_file {
            Some(ca) => {
                for c in load_certs(ca)? {
                    roots.add(c)?;
                }
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        if settings.verify_hostname.unwrap_or(true) {
            builder.with_root_certificates(roots)
        } else {
            let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                provider(),
            )
            .build()?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(IgnoreHostname(inner)))
        }
    };
    let config = match (&settings.cert_file, &settings.key_file) {
        (Some(c), Some(k)) => builder.with_client_auth_cert(load_certs(c)?, load_key(k)?)?,
        _ => builder.with_no_client_auth(),
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Build a TLS acceptor.
pub fn acceptor(settings: &TlsServerSettings) -> Result<TlsAcceptor, TlsError> {
    let builder = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions(settings.min_version))?;
    let builder = match &settings.ca_file {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in load_certs(ca)? {
                roots.add(c)?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider(),
            );
            let verifier = if settings.require_client_cert {
                verifier
            } else {
                verifier.allow_unauthenticated()
            };
            builder.with_client_cert_verifier(
                verifier
                    .build()
                    .map_err(|e| TlsError::Rustls(rustls::Error::General(e.to_string())))?,
            )
        }
        None => builder.with_no_client_auth(),
    };
    let config = builder.with_single_cert(
        load_certs(&settings.cert_file)?,
        load_key(&settings.key_file)?,
    )?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Parse a server name for SNI / verification.
pub fn server_name(host: &str) -> Result<ServerName<'static>, TlsError> {
    ServerName::try_from(host.to_owned()).map_err(|_| TlsError::ServerName(host.to_owned()))
}

/// Whether a path looks like a PEM file (used by configuration validation).
#[must_use]
pub fn is_pem(path: &str) -> bool {
    Path::new(path).extension().is_some_and(|e| {
        e.eq_ignore_ascii_case("pem")
            || e.eq_ignore_ascii_case("crt")
            || e.eq_ignore_ascii_case("key")
    })
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Verifies the chain against the configured roots but ignores host name mismatches.
#[derive(Debug)]
struct IgnoreHostname(Arc<rustls::client::WebPkiServerVerifier>);

impl rustls::client::danger::ServerCertVerifier for IgnoreHostname {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self
            .0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. },
            )) => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
