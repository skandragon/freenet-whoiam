//! Request/response messages between the whoiam UI and its KV delegate.
//! Mirrors Freebird's delegate API: the delegate is a dumb origin-isolated
//! secret store; all meaning lives in the caller.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum WhoiamDelegateRequest {
    Store { key: String, value: ByteBuf },
    Get { key: String },
    Delete { key: String },
    List,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum WhoiamDelegateResponse {
    Stored { key: String },
    Value { key: String, value: Option<ByteBuf> },
    Deleted { key: String },
    KeyList { keys: Vec<String> },
    Error { message: String },
}

/// Delegate keys the UI uses. The seed is the crown jewels; meta is a small
/// CBOR record describing which identity indices exist.
pub const KEY_SEED: &str = "seed";
pub const KEY_META: &str = "meta";

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct IdentityMeta {
    pub identities: Vec<IdentityEntry>,
    /// Monotonic allocation watermark. Indices derive keypairs, so a
    /// destroyed identity's index must NEVER be handed out again (the new
    /// identity would inherit the destroyed contract). Allocate from here,
    /// bump on create, never decrement. `default` keeps pre-field stored
    /// meta decodable; [`IdentityMeta::alloc_index`] covers the 0 it decodes to.
    #[serde(default)]
    pub next_index: u32,
}

impl IdentityMeta {
    /// Next index to create under. The max-over-live fallback covers meta
    /// stored before `next_index` existed (deserialized as 0).
    pub fn alloc_index(&self) -> u32 {
        self.identities
            .iter()
            .map(|e| e.index + 1)
            .max()
            .unwrap_or(0)
            .max(self.next_index)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IdentityEntry {
    pub index: u32,
    pub label: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_cbor_round_trip() {
        let req = WhoiamDelegateRequest::Store {
            key: "seed".into(),
            value: ByteBuf::from(vec![1, 2, 3]),
        };
        let bytes = crate::to_cbor(&req).unwrap();
        let back: WhoiamDelegateRequest = crate::from_cbor(&bytes).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn meta_cbor_round_trip() {
        let meta = IdentityMeta {
            identities: vec![IdentityEntry {
                index: 0,
                label: "main".into(),
            }],
            next_index: 1,
        };
        let bytes = crate::to_cbor(&meta).unwrap();
        let back: IdentityMeta = crate::from_cbor(&bytes).unwrap();
        assert_eq!(meta, back);
    }

    /// A destroyed identity's index must never be reallocated: the watermark
    /// stays high even after the entry is removed from the live list.
    #[test]
    fn alloc_never_reuses_destroyed_index() {
        let mut meta = IdentityMeta::default();
        assert_eq!(meta.alloc_index(), 0);
        meta.identities.push(IdentityEntry { index: 0, label: "a".into() });
        meta.next_index = 1;
        meta.identities.push(IdentityEntry { index: 1, label: "b".into() });
        meta.next_index = 2;
        // Destroy the highest-index identity.
        meta.identities.retain(|e| e.index != 1);
        assert_eq!(meta.alloc_index(), 2, "index 1 must stay retired");
    }

    /// Meta stored before `next_index` existed must still decode, and
    /// alloc_index must cover the 0 it decodes to.
    #[test]
    fn pre_next_index_meta_decodes() {
        // Encode the old shape by hand: a map with only `identities`.
        #[derive(serde::Serialize)]
        struct OldMeta {
            identities: Vec<IdentityEntry>,
        }
        let old = OldMeta {
            identities: vec![IdentityEntry { index: 3, label: "x".into() }],
        };
        let bytes = crate::to_cbor(&old).unwrap();
        let meta: IdentityMeta = crate::from_cbor(&bytes).unwrap();
        assert_eq!(meta.next_index, 0);
        assert_eq!(meta.alloc_index(), 4);
    }
}
