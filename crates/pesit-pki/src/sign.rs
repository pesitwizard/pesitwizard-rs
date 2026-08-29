//! Detached ECDSA-P256/SHA-256 signatures over arbitrary bytes, using the local CA key. Used to
//! sign configuration backup bundles so their integrity and provenance can be checked on import.

use der::{DecodePem, Encode};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use x509_cert::Certificate;

use crate::ca::LocalCa;
use crate::PkiError;

/// Signature algorithm identifier recorded alongside a signature.
pub const ALGORITHM: &str = "ecdsa-p256-sha256";

fn gen(e: impl std::fmt::Display) -> PkiError {
    PkiError::Gen(e.to_string())
}

/// Sign `data` with the CA private key (ECDSA P-256 / SHA-256); returns the DER signature.
pub fn sign_bytes(ca: &LocalCa, data: &[u8]) -> Result<Vec<u8>, PkiError> {
    let key = rcgen::KeyPair::from_pem(ca.key_pem()).map_err(gen)?;
    let signer = SigningKey::from_pkcs8_der(&key.serialize_der())
        .map_err(|e| PkiError::Gen(format!("CA key is not an ECDSA P-256 key: {e}")))?;
    let sig: DerSignature = signer.sign(data);
    Ok(sig.as_bytes().to_vec())
}

/// Verify a DER signature over `data` against the public key in `cert_pem` (a PEM certificate).
pub fn verify_bytes(cert_pem: &str, data: &[u8], sig_der: &[u8]) -> Result<bool, PkiError> {
    let cert = Certificate::from_pem(cert_pem).map_err(gen)?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(gen)?;
    let vk = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|e| PkiError::Gen(format!("certificate is not an ECDSA P-256 key: {e}")))?;
    let Ok(sig) = DerSignature::try_from(sig_der) else {
        return Ok(false);
    };
    Ok(vk.verify(data, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::LocalCa;

    #[test]
    fn sign_and_verify_round_trip() {
        let ca =
            LocalCa::generate("Sign Test CA", Some("PW"), 3650).unwrap_or_else(|e| panic!("{e}"));
        let data = b"the quick brown fox";
        let sig = sign_bytes(&ca, data).unwrap_or_else(|e| panic!("{e}"));

        // Valid signature verifies against the CA certificate.
        assert!(verify_bytes(ca.cert_pem(), data, &sig).unwrap_or_else(|e| panic!("{e}")));
        // Tampered data does not.
        assert!(!verify_bytes(ca.cert_pem(), b"the quick brown FOX", &sig)
            .unwrap_or_else(|e| panic!("{e}")));
        // A different CA does not.
        let other =
            LocalCa::generate("Other CA", Some("PW"), 3650).unwrap_or_else(|e| panic!("{e}"));
        assert!(!verify_bytes(other.cert_pem(), data, &sig).unwrap_or_else(|e| panic!("{e}")));
    }
}
