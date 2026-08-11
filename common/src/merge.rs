//! Pure merge for identity state: per-slot LWW with a destroy-forever
//! marker. The contract shell calls these with the host clock; tests call
//! them with a fixed clock.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::state::{
    check_destroy, check_slot, slot_order_key, IdentityStateV1, SignedSlot, MAX_FUTURE_MS,
    MAX_STATE_BYTES,
};

/// Compact summary for delta sync: per-slot order keys + destroy time.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SummaryV1 {
    pub slots: BTreeMap<String, (u64, [u8; 32])>,
    pub destroyed_ms: Option<u64>,
}

fn check_incoming_slot(
    name: &str,
    slot: &SignedSlot,
    pk: &VerifyingKey,
    now_ms: u64,
) -> Result<(), String> {
    if slot.time_ms > now_ms.saturating_add(MAX_FUTURE_MS) {
        return Err(format!("slot {name:?} timestamp too far in the future"));
    }
    check_slot(slot, name, pk)
}

/// Validate a full state (used by the contract's validate_state and by the
/// toolkit before trusting a fetched state).
pub fn validate_full(
    state: &IdentityStateV1,
    pk: &VerifyingKey,
    now_ms: u64,
) -> Result<(), String> {
    if let Some(m) = &state.destroyed {
        check_destroy(m, pk)?;
        if !state.slots.is_empty() {
            return Err("destroyed state must carry no slots".into());
        }
        return Ok(());
    }
    for (name, slot) in &state.slots {
        check_incoming_slot(name, slot, pk, now_ms)?;
    }
    if crate::to_cbor(state)?.len() > MAX_STATE_BYTES {
        return Err(format!("state exceeds {MAX_STATE_BYTES} bytes"));
    }
    Ok(())
}

/// Fold `incoming` into `current`. Returns Ok(true) if `current` changed.
/// Anything invalid in `incoming` rejects the whole update.
pub fn merge_state(
    current: &mut IdentityStateV1,
    incoming: &IdentityStateV1,
    pk: &VerifyingKey,
    now_ms: u64,
) -> Result<bool, String> {
    // A destruction marker anywhere ends the identity: verify, then collapse.
    if let Some(m) = &incoming.destroyed {
        check_destroy(m, pk)?;
        match &current.destroyed {
            Some(held) if held.time_ms >= m.time_ms => return Ok(false),
            _ => {
                current.slots.clear();
                current.destroyed = Some(*m);
                return Ok(true);
            }
        }
    }
    if current.destroyed.is_some() {
        // Dead identities accept nothing but (redundant) markers.
        return if incoming.slots.is_empty() {
            Ok(false)
        } else {
            Err("identity destroyed".into())
        };
    }

    let mut changed = false;
    for (name, slot) in &incoming.slots {
        check_incoming_slot(name, slot, pk, now_ms)?;
        let newer = current
            .slots
            .get(name)
            .is_none_or(|held| slot_order_key(slot) > slot_order_key(held));
        if newer {
            current.slots.insert(name.clone(), slot.clone());
            changed = true;
        }
    }
    if changed && crate::to_cbor(current)?.len() > MAX_STATE_BYTES {
        return Err(format!("merged state exceeds {MAX_STATE_BYTES} bytes"));
    }
    Ok(changed)
}

pub fn summarize(state: &IdentityStateV1) -> SummaryV1 {
    SummaryV1 {
        slots: state
            .slots
            .iter()
            .map(|(k, v)| (k.clone(), slot_order_key(v)))
            .collect(),
        destroyed_ms: state.destroyed.as_ref().map(|m| m.time_ms),
    }
}

/// Everything the summary's holder is missing: slots newer than (or absent
/// from) the summary, and the destroy marker if they lack it.
pub fn delta_since(state: &IdentityStateV1, summary: &SummaryV1) -> IdentityStateV1 {
    if state.destroyed.is_some() {
        return state.clone();
    }
    IdentityStateV1 {
        slots: state
            .slots
            .iter()
            .filter(|(k, v)| {
                summary
                    .slots
                    .get(*k)
                    .is_none_or(|held| slot_order_key(v) > *held)
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        destroyed: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{sign_destroy, sign_slot, MAX_SLOT_BYTES};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    const NOW: u64 = 1_000_000;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn state_with(sk: &SigningKey, name: &str, time: u64, content: &[u8]) -> IdentityStateV1 {
        let mut s = IdentityStateV1::default();
        s.slots
            .insert(name.into(), sign_slot(sk, name, time, content.to_vec()));
        s
    }

    #[test]
    fn newer_slot_wins() {
        let sk = key();
        let pk = sk.verifying_key();
        let mut cur = state_with(&sk, "profile", 100, b"old");
        let inc = state_with(&sk, "profile", 200, b"new");
        assert!(merge_state(&mut cur, &inc, &pk, NOW).unwrap());
        assert_eq!(cur.slots["profile"].bytes, b"new");
    }

    #[test]
    fn older_and_equal_ignored() {
        let sk = key();
        let pk = sk.verifying_key();
        let newer = state_with(&sk, "profile", 200, b"new");
        let mut cur = newer.clone();
        let older = state_with(&sk, "profile", 100, b"old");
        assert!(!merge_state(&mut cur, &older, &pk, NOW).unwrap());
        assert!(!merge_state(&mut cur, &newer.clone(), &pk, NOW).unwrap());
        assert_eq!(cur.slots["profile"].bytes, b"new");
    }

    #[test]
    fn bad_signature_rejects_update() {
        let sk = key();
        let pk = sk.verifying_key();
        let mut cur = IdentityStateV1::default();
        let mut inc = state_with(&sk, "profile", 100, b"x");
        inc.slots.get_mut("profile").unwrap().bytes = b"forged".to_vec();
        assert!(merge_state(&mut cur, &inc, &pk, NOW).is_err());
    }

    #[test]
    fn far_future_rejected() {
        let sk = key();
        let pk = sk.verifying_key();
        let mut cur = IdentityStateV1::default();
        let inc = state_with(&sk, "profile", NOW + MAX_FUTURE_MS + 1, b"x");
        assert!(merge_state(&mut cur, &inc, &pk, NOW).is_err());
        let ok = state_with(&sk, "profile", NOW + MAX_FUTURE_MS - 1, b"x");
        assert!(merge_state(&mut cur, &ok, &pk, NOW).is_ok());
    }

    #[test]
    fn oversized_slot_rejected() {
        let sk = key();
        let pk = sk.verifying_key();
        let mut cur = IdentityStateV1::default();
        let inc = state_with(&sk, "avatar", 100, &vec![0u8; MAX_SLOT_BYTES + 1]);
        assert!(merge_state(&mut cur, &inc, &pk, NOW).is_err());
    }

    #[test]
    fn destroy_collapses_and_locks() {
        let sk = key();
        let pk = sk.verifying_key();
        let mut cur = state_with(&sk, "profile", 100, b"x");
        let mut inc = IdentityStateV1::default();
        inc.destroyed = Some(sign_destroy(&sk, 200));
        assert!(merge_state(&mut cur, &inc, &pk, NOW).unwrap());
        assert!(cur.slots.is_empty());
        assert!(cur.destroyed.is_some());
        // Further content is refused.
        let late = state_with(&sk, "profile", 300, b"zombie");
        assert!(merge_state(&mut cur, &late, &pk, NOW).is_err());
        // Redundant older marker: no change, no error.
        let mut older = IdentityStateV1::default();
        older.destroyed = Some(sign_destroy(&sk, 150));
        assert!(!merge_state(&mut cur, &older, &pk, NOW).unwrap());
    }

    #[test]
    fn forged_destroy_rejected() {
        let sk = key();
        let pk = sk.verifying_key();
        let mut cur = state_with(&sk, "profile", 100, b"x");
        let mut inc = IdentityStateV1::default();
        inc.destroyed = Some(sign_destroy(&key(), 200));
        assert!(merge_state(&mut cur, &inc, &pk, NOW).is_err());
        assert!(!cur.slots.is_empty());
    }

    #[test]
    fn tombstone_slot_propagates() {
        let sk = key();
        let pk = sk.verifying_key();
        let mut cur = state_with(&sk, "avatar", 100, b"img");
        let inc = state_with(&sk, "avatar", 200, b"");
        assert!(merge_state(&mut cur, &inc, &pk, NOW).unwrap());
        assert!(cur.slots["avatar"].bytes.is_empty());
    }

    #[test]
    fn validate_full_checks_everything() {
        let sk = key();
        let pk = sk.verifying_key();
        let good = state_with(&sk, "profile", 100, b"x");
        assert!(validate_full(&good, &pk, NOW).is_ok());
        let mut destroyed = IdentityStateV1::default();
        destroyed.destroyed = Some(sign_destroy(&sk, 200));
        assert!(validate_full(&destroyed, &pk, NOW).is_ok());
        // Destroyed + slots is malformed.
        let mut both = state_with(&sk, "profile", 100, b"x");
        both.destroyed = Some(sign_destroy(&sk, 200));
        assert!(validate_full(&both, &pk, NOW).is_err());
    }

    #[test]
    fn summary_and_delta() {
        let sk = key();
        let pk = sk.verifying_key();
        let mut cur = state_with(&sk, "profile", 100, b"a");
        let sum_old = summarize(&cur);
        let newer = state_with(&sk, "avatar", 200, b"img");
        merge_state(&mut cur, &newer, &pk, NOW).unwrap();
        let delta = delta_since(&cur, &sum_old);
        assert!(delta.slots.contains_key("avatar"));
        assert!(!delta.slots.contains_key("profile"));
        // Delta applies cleanly onto the summarized holder's state.
        let mut holder = state_with(&sk, "profile", 100, b"a");
        assert!(merge_state(&mut holder, &delta, &pk, NOW).unwrap());
        assert_eq!(holder, cur);
    }
}
