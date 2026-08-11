//! Identity key derivation: one master seed, unlinkable per-index ed25519
//! keypairs. Deterministic forever — this is the backup format.

use ed25519_dalek::SigningKey;

const CONTEXT: &str = "whoiam identity v1";

pub fn identity_signing_key(seed: &[u8; 32], index: u32) -> SigningKey {
    let mut ikm = [0u8; 36];
    ikm[..32].copy_from_slice(seed);
    ikm[32..].copy_from_slice(&index.to_le_bytes());
    SigningKey::from_bytes(&blake3::derive_key(CONTEXT, &ikm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let seed = [7u8; 32];
        assert_eq!(
            identity_signing_key(&seed, 0).to_bytes(),
            identity_signing_key(&seed, 0).to_bytes()
        );
    }

    #[test]
    fn distinct_per_index_and_seed() {
        let seed = [7u8; 32];
        let other = [8u8; 32];
        let k0 = identity_signing_key(&seed, 0).verifying_key();
        let k1 = identity_signing_key(&seed, 1).verifying_key();
        let o0 = identity_signing_key(&other, 0).verifying_key();
        assert_ne!(k0, k1);
        assert_ne!(k0, o0);
    }
}
