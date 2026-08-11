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
        };
        let bytes = crate::to_cbor(&meta).unwrap();
        let back: IdentityMeta = crate::from_cbor(&bytes).unwrap();
        assert_eq!(meta, back);
    }
}
