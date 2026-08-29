//! Online Certificate Status Protocol responder (RFC 6960).
//!
//! Answers OCSP requests about certificates issued by the [local CA](crate::ca::LocalCa): the
//! request's `CertID` is echoed back and its serial number is looked up in the revoked list to
//! decide `good` / `revoked`. The response is signed by the CA key (ECDSA P-256).

use std::time::Duration;

use der::{Decode, DecodePem, Encode};
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use x509_cert::Certificate;
use x509_ocsp::builder::OcspResponseBuilder;
use x509_ocsp::{CertStatus, OcspGeneralizedTime, OcspRequest, ResponderId, RevokedInfo};

use crate::ca::LocalCa;
use crate::PkiError;

/// A revoked certificate: its serial (hex, no separators) and revocation time (Unix seconds).
#[derive(Debug, Clone)]
pub struct Revoked {
    /// Serial number as an uppercase hex string with no separators.
    pub serial_hex: String,
    /// Revocation time, Unix seconds.
    pub revoked_at_unix: i64,
}

fn gen(e: impl std::fmt::Display) -> PkiError {
    PkiError::Gen(e.to_string())
}

fn ocsp_time(unix: i64) -> Result<OcspGeneralizedTime, PkiError> {
    let secs = u64::try_from(unix.max(0)).unwrap_or(0);
    let dt = der::DateTime::from_unix_duration(Duration::from_secs(secs)).map_err(gen)?;
    Ok(OcspGeneralizedTime::from(dt))
}

/// Normalise a serial to uppercase hex with no separators or leading zeroes.
fn norm_serial(hex: &str) -> String {
    let cleaned: String = hex
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_uppercase();
    let trimmed = cleaned.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// Answer an OCSP request (DER) about certificates issued by `ca`. `now_unix` is the current time
/// in Unix seconds. Returns the DER-encoded OCSP response, signed by the CA key.
pub fn respond(
    ca: &LocalCa,
    revoked: &[Revoked],
    request_der: &[u8],
    now_unix: i64,
) -> Result<Vec<u8>, PkiError> {
    let request = OcspRequest::from_der(request_der)
        .map_err(|e| PkiError::Gen(format!("invalid OCSP request: {e}")))?;

    // Signer derived from the CA private key (ECDSA P-256).
    let key = rcgen::KeyPair::from_pem(ca.key_pem()).map_err(gen)?;
    let mut signer = SigningKey::from_pkcs8_der(&key.serialize_der())
        .map_err(|e| PkiError::Gen(format!("CA key is not an ECDSA P-256 key: {e}")))?;

    // Responder identified by the CA subject name; the CA certificate is attached to the response.
    let ca_cert = Certificate::from_pem(ca.cert_pem()).map_err(gen)?;
    let responder = ResponderId::ByName(ca_cert.tbs_certificate.subject.clone());

    let this_update = ocsp_time(now_unix)?;
    let next_update = ocsp_time(now_unix + 86_400)?;

    let mut builder = OcspResponseBuilder::new(responder);
    for entry in request.tbs_request.request_list {
        let serial = norm_serial(&bytes_to_hex(entry.req_cert.serial_number.as_bytes()));
        let status = match revoked
            .iter()
            .find(|r| norm_serial(&r.serial_hex) == serial)
        {
            Some(r) => CertStatus::revoked(RevokedInfo {
                revocation_time: ocsp_time(r.revoked_at_unix)?,
                revocation_reason: None,
            }),
            None => CertStatus::good(),
        };
        let single = x509_ocsp::SingleResponse::new(entry.req_cert, status, this_update)
            .with_next_update(next_update);
        builder = builder.with_single_response(single);
    }

    let response = builder
        .sign::<_, DerSignature>(&mut signer, Some(vec![ca_cert]), this_update)
        .map_err(|e| PkiError::Gen(format!("cannot sign OCSP response: {e}")))?;
    response.to_der().map_err(gen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::LocalCa;
    use crate::provider::CertRequest;

    fn ca() -> LocalCa {
        LocalCa::generate("PeSIT OCSP Test CA", Some("PeSIT"), 3650)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn leaf_request() -> CertRequest {
        CertRequest {
            common_name: "leaf.example.com".into(),
            sans: vec!["DNS:leaf.example.com".into()],
            ttl_days: 365,
            is_ca: false,
            server_auth: true,
            client_auth: false,
            organization: None,
        }
    }

    /// Build a minimal OCSP request DER for the given serial via the request builder.
    fn request_for(ca: &LocalCa, leaf: &x509_cert::Certificate) -> Vec<u8> {
        use x509_ocsp::builder::OcspRequestBuilder;
        use x509_ocsp::CertId;
        let ca_cert =
            x509_cert::Certificate::from_pem(ca.cert_pem()).unwrap_or_else(|e| panic!("{e}"));
        let cert_id =
            CertId::from_issuer::<sha1::Sha1>(&ca_cert, leaf.tbs_certificate.serial_number.clone())
                .unwrap_or_else(|e| panic!("{e}"));
        OcspRequestBuilder::new(x509_ocsp::Version::V1)
            .with_request(x509_ocsp::Request::new(cert_id))
            .build()
            .to_der()
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn good_and_revoked_status() {
        let ca = ca();
        let issued = ca.issue(&leaf_request()).unwrap_or_else(|e| panic!("{e}"));
        let leaf =
            x509_cert::Certificate::from_pem(&issued.certificate).unwrap_or_else(|e| panic!("{e}"));
        let serial_hex = bytes_to_hex(leaf.tbs_certificate.serial_number.as_bytes());
        let req = request_for(&ca, &leaf);

        // Not revoked -> the response parses and reports good.
        let der = respond(&ca, &[], &req, 1_700_000_000).unwrap_or_else(|e| panic!("{e}"));
        let resp = x509_ocsp::OcspResponse::from_der(&der).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            resp.response_status,
            x509_ocsp::OcspResponseStatus::Successful
        );
        let basic = resp
            .response_bytes
            .and_then(|b| x509_ocsp::BasicOcspResponse::from_der(b.response.as_bytes()).ok())
            .unwrap_or_else(|| panic!("no basic response"));
        assert!(matches!(
            basic.tbs_response_data.responses[0].cert_status,
            CertStatus::Good(_)
        ));

        // Revoked -> the response reports revoked for the same serial.
        let revoked = [Revoked {
            serial_hex,
            revoked_at_unix: 1_699_000_000,
        }];
        let der = respond(&ca, &revoked, &req, 1_700_000_000).unwrap_or_else(|e| panic!("{e}"));
        let resp = x509_ocsp::OcspResponse::from_der(&der).unwrap_or_else(|e| panic!("{e}"));
        let basic = resp
            .response_bytes
            .and_then(|b| x509_ocsp::BasicOcspResponse::from_der(b.response.as_bytes()).ok())
            .unwrap_or_else(|| panic!("no basic response"));
        assert!(matches!(
            basic.tbs_response_data.responses[0].cert_status,
            CertStatus::Revoked(_)
        ));
    }
}
