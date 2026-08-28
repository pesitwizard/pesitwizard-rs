//! A local certificate authority based on `rcgen`.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

use crate::provider::{CertRequest, Issued, PkiError};

/// A local CA: a self-signed CA certificate and its private key (PEM).
#[derive(Debug, Clone)]
pub struct LocalCa {
    cert_pem: String,
    key_pem: String,
}

fn dn(cn: &str, org: Option<&str>) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    if let Some(o) = org {
        d.push(DnType::OrganizationName, o);
    }
    d
}

fn err(e: impl std::fmt::Display) -> PkiError {
    PkiError::Gen(e.to_string())
}

impl LocalCa {
    /// Load a CA from its certificate and key (PEM).
    #[must_use]
    pub fn from_pem(cert_pem: String, key_pem: String) -> Self {
        Self { cert_pem, key_pem }
    }

    /// The CA certificate (PEM).
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA private key (PEM).
    #[must_use]
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Generate a new CA certificate.
    pub fn generate(
        common_name: &str,
        organization: Option<&str>,
        ttl_days: u32,
    ) -> Result<Self, PkiError> {
        let key = KeyPair::generate().map_err(err)?;
        let mut params = CertificateParams::new(Vec::new()).map_err(err)?;
        params.distinguished_name = dn(common_name, organization);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(i64::from(ttl_days));
        let cert = params.self_signed(&key).map_err(err)?;
        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    /// Issue a leaf (or sub-CA) certificate signed by this CA.
    pub fn issue(&self, req: &CertRequest) -> Result<Issued, PkiError> {
        let ca_key = KeyPair::from_pem(&self.key_pem).map_err(err)?;
        let ca_params = CertificateParams::from_ca_cert_pem(&self.cert_pem).map_err(err)?;
        let ca_cert = ca_params.self_signed(&ca_key).map_err(err)?;

        let leaf_key = KeyPair::generate().map_err(err)?;
        let mut params = CertificateParams::new(req.dns_names()).map_err(err)?;
        for ip in req.ip_names() {
            if let Ok(addr) = ip.parse() {
                params
                    .subject_alt_names
                    .push(rcgen::SanType::IpAddress(addr));
            }
        }
        params.distinguished_name = dn(&req.common_name, req.organization.as_deref());
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(i64::from(req.ttl_days));
        if req.is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
        } else {
            params.is_ca = IsCa::ExplicitNoCa;
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            if req.server_auth {
                params
                    .extended_key_usages
                    .push(ExtendedKeyUsagePurpose::ServerAuth);
            }
            if req.client_auth {
                params
                    .extended_key_usages
                    .push(ExtendedKeyUsagePurpose::ClientAuth);
            }
        }
        let leaf = params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .map_err(err)?;
        Ok(Issued {
            certificate: leaf.pem(),
            private_key: Some(leaf_key.serialize_pem()),
            ca_chain: vec![self.cert_pem.clone()],
            serial: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    fn ca() -> LocalCa {
        LocalCa::generate("PeSIT Wizard Test CA", Some("PeSIT Wizard"), 3650)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn generated_ca_is_a_ca() {
        let info =
            crate::cert::inspect_pem(ca().cert_pem().as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert!(info.is_ca, "the CA certificate must carry CA:TRUE");
        assert!(info.subject.contains("PeSIT Wizard Test CA"));
        assert!(info.valid);
    }

    #[test]
    fn issued_leaf_is_cryptographically_signed_by_the_ca() {
        let ca = ca();
        let req = CertRequest {
            common_name: "node.example.com".into(),
            sans: vec![
                "DNS:node.example.com".into(),
                "DNS:alt.example.com".into(),
                "IP:127.0.0.1".into(),
            ],
            ttl_days: 365,
            is_ca: false,
            server_auth: true,
            client_auth: true,
            organization: None,
        };
        let issued = ca.issue(&req).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            issued.private_key.is_some(),
            "a local CA returns the leaf private key"
        );
        assert_eq!(issued.ca_chain.len(), 1);

        let ca_pem = parse_x509_pem(ca.cert_pem().as_bytes())
            .unwrap_or_else(|e| panic!("{e}"))
            .1;
        let ca_cert = ca_pem.parse_x509().unwrap_or_else(|e| panic!("{e}"));
        let leaf_pem = parse_x509_pem(issued.certificate.as_bytes())
            .unwrap_or_else(|e| panic!("{e}"))
            .1;
        let leaf = leaf_pem.parse_x509().unwrap_or_else(|e| panic!("{e}"));

        // the strongest check: the leaf signature verifies against the CA public key.
        assert!(
            leaf.verify_signature(Some(ca_cert.public_key())).is_ok(),
            "leaf must verify against the CA public key"
        );
        assert_eq!(
            leaf.issuer().to_string(),
            ca_cert.subject().to_string(),
            "issuer must be the CA subject"
        );
        assert!(!leaf.is_ca(), "a leaf must not be a CA");

        let info = crate::cert::inspect_pem(issued.certificate.as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            info.sans.iter().any(|s| s == "DNS:node.example.com"),
            "SANs: {:?}",
            info.sans
        );
        assert!(info.sans.iter().any(|s| s == "DNS:alt.example.com"));
        assert!(
            info.sans.iter().any(|s| s.starts_with("IP:127.0.0.1")),
            "SANs: {:?}",
            info.sans
        );
        assert!(info.valid);
    }

    #[test]
    fn a_leaf_from_another_ca_does_not_verify() {
        let a = ca();
        let b = LocalCa::generate("Other CA", None, 3650).unwrap_or_else(|e| panic!("{e}"));
        let req = CertRequest {
            common_name: "x".into(),
            sans: vec![],
            ttl_days: 30,
            is_ca: false,
            server_auth: true,
            client_auth: false,
            organization: None,
        };
        let issued = a.issue(&req).unwrap_or_else(|e| panic!("{e}"));
        let b_pem = parse_x509_pem(b.cert_pem().as_bytes())
            .unwrap_or_else(|e| panic!("{e}"))
            .1;
        let b_cert = b_pem.parse_x509().unwrap_or_else(|e| panic!("{e}"));
        let leaf_pem = parse_x509_pem(issued.certificate.as_bytes())
            .unwrap_or_else(|e| panic!("{e}"))
            .1;
        let leaf = leaf_pem.parse_x509().unwrap_or_else(|e| panic!("{e}"));
        assert!(
            leaf.verify_signature(Some(b_cert.public_key())).is_err(),
            "a leaf must not verify against an unrelated CA"
        );
    }
}
