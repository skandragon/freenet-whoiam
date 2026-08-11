//! Identity contract state: named slots, each independently signed and
//! timestamped by the identity key, plus an optional destruction marker.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Hard cap on one slot's content bytes.
pub const MAX_SLOT_BYTES: usize = 128 * 1024;
/// Hard cap on the whole serialized state.
pub const MAX_STATE_BYTES: usize = 512 * 1024;
/// Timestamps further than this ahead of the host clock are rejected — a
/// poisoned far-future timestamp must not win LWW forever.
pub const MAX_FUTURE_MS: u64 = 10 * 60 * 1000;

const SLOT_DOMAIN: &[u8] = b"whoiam-slot-v1";
const DESTROY_DOMAIN: &[u8] = b"whoiam-destroy-v1";

/// Contract parameters: the identity's public key. The contract address is
/// hash(wasm + these params), so it is derivable offline from the pubkey.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IdentityParamsV1 {
    pub version: u32,
    pub pubkey: VerifyingKey,
}

/// One named resource: content bytes signed by the identity key. Empty
/// bytes = tombstone (slot deleted; kept so the deletion propagates).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SignedSlot {
    pub time_ms: u64,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
    pub sig: Signature,
}

/// Signed "this identity is dead forever" marker. Once merged, all slots
/// drop and no further content is accepted.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DestroyedMarker {
    pub time_ms: u64,
    pub sig: Signature,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct IdentityStateV1 {
    pub slots: BTreeMap<String, SignedSlot>,
    pub destroyed: Option<DestroyedMarker>,
}

fn slot_message(pk: &VerifyingKey, name: &str, time_ms: u64, content_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SLOT_DOMAIN.len() + 32 + 4 + name.len() + 8 + 32);
    m.extend_from_slice(SLOT_DOMAIN);
    m.extend_from_slice(pk.as_bytes());
    m.extend_from_slice(&(name.len() as u32).to_le_bytes());
    m.extend_from_slice(name.as_bytes());
    m.extend_from_slice(&time_ms.to_le_bytes());
    m.extend_from_slice(content_hash);
    m
}

fn destroy_message(pk: &VerifyingKey, time_ms: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(DESTROY_DOMAIN.len() + 32 + 8);
    m.extend_from_slice(DESTROY_DOMAIN);
    m.extend_from_slice(pk.as_bytes());
    m.extend_from_slice(&time_ms.to_le_bytes());
    m
}

pub fn sign_slot(sk: &SigningKey, name: &str, time_ms: u64, bytes: Vec<u8>) -> SignedSlot {
    let hash = blake3::hash(&bytes);
    let msg = slot_message(&sk.verifying_key(), name, time_ms, hash.as_bytes());
    SignedSlot {
        time_ms,
        bytes,
        sig: sk.sign(&msg),
    }
}

pub fn check_slot(slot: &SignedSlot, name: &str, pk: &VerifyingKey) -> Result<(), String> {
    if slot.bytes.len() > MAX_SLOT_BYTES {
        return Err(format!("slot {name:?} exceeds {MAX_SLOT_BYTES} bytes"));
    }
    let hash = blake3::hash(&slot.bytes);
    let msg = slot_message(pk, name, slot.time_ms, hash.as_bytes());
    pk.verify(&msg, &slot.sig)
        .map_err(|_| format!("bad signature on slot {name:?}"))
}

pub fn sign_destroy(sk: &SigningKey, time_ms: u64) -> DestroyedMarker {
    let msg = destroy_message(&sk.verifying_key(), time_ms);
    DestroyedMarker {
        time_ms,
        sig: sk.sign(&msg),
    }
}

pub fn check_destroy(m: &DestroyedMarker, pk: &VerifyingKey) -> Result<(), String> {
    pk.verify(&destroy_message(pk, m.time_ms), &m.sig)
        .map_err(|_| "bad signature on destruction marker".into())
}

/// LWW order for a slot: newer time wins, content hash breaks ties so
/// concurrent same-millisecond writes converge identically everywhere.
pub fn slot_order_key(s: &SignedSlot) -> (u64, [u8; 32]) {
    (s.time_ms, *blake3::hash(&s.bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn slot_sign_verify_round_trip() {
        let sk = key();
        let slot = sign_slot(&sk, "profile", 1000, b"hello".to_vec());
        assert!(check_slot(&slot, "profile", &sk.verifying_key()).is_ok());
    }

    #[test]
    fn tampered_bytes_rejected() {
        let sk = key();
        let mut slot = sign_slot(&sk, "profile", 1000, b"hello".to_vec());
        slot.bytes = b"evil!".to_vec();
        assert!(check_slot(&slot, "profile", &sk.verifying_key()).is_err());
    }

    #[test]
    fn wrong_slot_name_rejected() {
        let sk = key();
        let slot = sign_slot(&sk, "profile", 1000, b"hello".to_vec());
        assert!(check_slot(&slot, "avatar", &sk.verifying_key()).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let slot = sign_slot(&key(), "profile", 1000, b"hello".to_vec());
        assert!(check_slot(&slot, "profile", &key().verifying_key()).is_err());
    }

    #[test]
    fn tombstone_signs_fine() {
        let sk = key();
        let slot = sign_slot(&sk, "avatar", 1000, vec![]);
        assert!(check_slot(&slot, "avatar", &sk.verifying_key()).is_ok());
        assert!(slot.bytes.is_empty());
    }

    #[test]
    fn oversized_slot_rejected() {
        let sk = key();
        let slot = sign_slot(&sk, "avatar", 1000, vec![0u8; MAX_SLOT_BYTES + 1]);
        assert!(check_slot(&slot, "avatar", &sk.verifying_key()).is_err());
    }

    #[test]
    fn destroy_round_trip() {
        let sk = key();
        let m = sign_destroy(&sk, 5000);
        assert!(check_destroy(&m, &sk.verifying_key()).is_ok());
        assert!(check_destroy(&m, &key().verifying_key()).is_err());
    }

    #[test]
    fn order_key_ties_break_on_hash() {
        let sk = key();
        let a = sign_slot(&sk, "x", 1000, b"a".to_vec());
        let b = sign_slot(&sk, "x", 1000, b"b".to_vec());
        assert_ne!(slot_order_key(&a), slot_order_key(&b));
        assert!(slot_order_key(&a) < slot_order_key(&b) || slot_order_key(&b) < slot_order_key(&a));
    }

    #[test]
    fn params_cbor_round_trip() {
        let pk = key().verifying_key();
        let params = IdentityParamsV1 { version: 1, pubkey: pk };
        let bytes = crate::to_cbor(&params).unwrap();
        let back: IdentityParamsV1 = crate::from_cbor(&bytes).unwrap();
        assert_eq!(params, back);
    }
}
