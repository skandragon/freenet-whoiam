//! Connect proof: a persona signs "I consent to identify to this app"
//! for the bounce-through flow. Domain-separated from slot/destroy signing
//! so a connect proof can never be replayed as a state write.
//!
//! The proof binds to the callback's origin+path (`return_base`), not just
//! its origin: apps hosted on the same Freenet node share the node's HTTP
//! origin, and the path (contract key) is what tells them apart.
//!
//! The proof carries no profile data — a verifier that wants name/bio/avatar
//! fetches the identity contract for the proven key (docs/resources.md).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

const CONNECT_DOMAIN: &[u8] = b"whoiam-connect-v1";

/// domain ‖ pk(32) ‖ u32le len ‖ return_base ‖ u32le len ‖ challenge ‖ u64le time_ms
fn connect_message(pk: &VerifyingKey, return_base: &str, challenge: &str, time_ms: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        CONNECT_DOMAIN.len() + 32 + 8 + return_base.len() + challenge.len() + 8,
    );
    m.extend_from_slice(CONNECT_DOMAIN);
    m.extend_from_slice(pk.as_bytes());
    for f in [return_base, challenge] {
        m.extend_from_slice(&(f.len() as u32).to_le_bytes());
        m.extend_from_slice(f.as_bytes());
    }
    m.extend_from_slice(&time_ms.to_le_bytes());
    m
}

pub fn sign_connect(sk: &SigningKey, return_base: &str, challenge: &str, time_ms: u64) -> Signature {
    sk.sign(&connect_message(&sk.verifying_key(), return_base, challenge, time_ms))
}

pub fn check_connect(
    pk: &VerifyingKey,
    return_base: &str,
    challenge: &str,
    time_ms: u64,
    sig: &Signature,
) -> Result<(), String> {
    pk.verify(&connect_message(pk, return_base, challenge, time_ms), sig)
        .map_err(|_| "bad connect signature".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://example.com/app";

    fn key() -> SigningKey {
        use rand::rngs::OsRng;
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn round_trip() {
        let sk = key();
        let sig = sign_connect(&sk, BASE, "abc123", 1000);
        assert!(check_connect(&sk.verifying_key(), BASE, "abc123", 1000, &sig).is_ok());
    }

    #[test]
    fn any_field_change_rejected() {
        let sk = key();
        let pk = sk.verifying_key();
        let sig = sign_connect(&sk, BASE, "abc123", 1000);
        assert!(check_connect(&pk, "https://example.com/evil", "abc123", 1000, &sig).is_err());
        assert!(check_connect(&pk, BASE, "abc124", 1000, &sig).is_err());
        assert!(check_connect(&pk, BASE, "abc123", 1001, &sig).is_err());
        assert!(check_connect(&key().verifying_key(), BASE, "abc123", 1000, &sig).is_err());
    }

    /// Length prefixes: shifting bytes between adjacent fields must not
    /// produce the same message.
    #[test]
    fn field_boundary_ambiguity_rejected() {
        let sk = key();
        let pk = sk.verifying_key();
        let sig = sign_connect(&sk, BASE, "abc", 1000);
        assert!(check_connect(&pk, &format!("{BASE}a"), "bc", 1000, &sig).is_err());
    }

    /// Wire-frozen: a format change here invalidates proofs against every
    /// deployed verifier. Deliberate migrations only.
    #[test]
    fn golden_connect_signature() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let sig = sign_connect(&sk, "https://example.com/app", "abc123", 12345);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&sig.to_bytes()),
            "122b675bdbc8772f52631524ac2b500dec76721bff7c0b299025df04e18e8e8ddf2b8d0a232a5785e68d5738be4f5111ae7b58106f5458b966b9b365fff5ac09",
        );
    }
}
