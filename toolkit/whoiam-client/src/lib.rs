//! Consumer toolkit for whoiam identities.
//!
//! Given an identity's public key, derives its contract address offline
//! (pinned wasm bytes + params), fetches the state from a Freenet node's
//! websocket API, verifies every signature client-side (never trust the
//! serving node), and returns typed resources.
//!
//! ```no_run
//! # async fn demo() -> Result<(), whoiam_client::FetchError> {
//! let pk = whoiam_client::parse_pubkey("6Yo3...").unwrap();
//! let id = whoiam_client::fetch("ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native", &pk).await?;
//! println!("{:?} {} bytes of avatar", id.profile, id.avatar.map_or(0, |a| a.len()));
//! # Ok(()) }
//! ```

use std::collections::BTreeMap;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::{
    ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi,
};
use freenet_stdlib::prelude::*;

use whoiam_core::merge::validate_full;
use whoiam_core::resources::{ProfileV1, SLOT_AVATAR, SLOT_PROFILE};
use whoiam_core::state::{IdentityParamsV1, IdentityStateV1};

/// The exact contract bytes every canonical whoiam build publishes with.
/// Addresses are hash(wasm + params); changing these bytes rotates every
/// identity's address, so they are vendored and pinned (scripts/wasm-hashes.txt).
pub const IDENTITY_CONTRACT_WASM: &[u8] =
    include_bytes!("../../../ui/contracts/identity_contract.wasm");

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("identity contract not found on the network")]
    NotFound,
    #[error("identity destroyed at {since_ms} ms")]
    Destroyed { since_ms: u64 },
    #[error("bad signature: {0}")]
    BadSignature(String),
    #[error("malformed state: {0}")]
    Malformed(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("timed out waiting for the node")]
    Timeout,
}

/// A fetched, signature-verified identity. `raw_slots` carries every
/// non-tombstoned slot (including ones this build doesn't recognize) so
/// forward-compatible consumers can reach new resource types.
#[derive(Debug, Clone)]
pub struct Identity {
    pub pubkey: VerifyingKey,
    pub profile: Option<ProfileV1>,
    pub avatar: Option<Vec<u8>>,
    pub raw_slots: BTreeMap<String, Vec<u8>>,
}

pub fn identity_params(pk: &VerifyingKey) -> IdentityParamsV1 {
    IdentityParamsV1 {
        version: 1,
        pubkey: *pk,
    }
}

/// The identity's contract key, derived offline.
pub fn contract_key(pk: &VerifyingKey) -> ContractKey {
    let params = whoiam_core::to_cbor(&identity_params(pk)).expect("params serialize");
    ContractKey::from_params_and_code(
        Parameters::from(params),
        &ContractCode::from(IDENTITY_CONTRACT_WASM.to_vec()),
    )
}

/// bs58 (preferred) or lowercase hex.
pub fn parse_pubkey(s: &str) -> Result<VerifyingKey, String> {
    let bytes: Vec<u8> = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .map_err(|e| e.to_string())?
    } else {
        bs58::decode(s).into_vec().map_err(|e| e.to_string())?
    };
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
}

pub fn format_pubkey(pk: &VerifyingKey) -> String {
    bs58::encode(pk.as_bytes()).into_string()
}

fn wall_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Convert verified state into the typed Identity. `pub(crate)` on purpose:
/// the only public path to an `Identity` is `fetch`, which verifies first —
/// this function assumes its input already passed `validate_full`.
///
/// Well-known slots get their schema enforced here too: signatures prove
/// authorship, not honesty, and a hostile identity can self-sign anything.
/// A schema-violating `profile`/`avatar` fails the fetch as Malformed
/// rather than reaching consumers unchecked.
pub(crate) fn identity_from_state(
    pk: &VerifyingKey,
    state: &IdentityStateV1,
) -> Result<Identity, FetchError> {
    if let Some(m) = &state.destroyed {
        return Err(FetchError::Destroyed { since_ms: m.time_ms });
    }
    let mut raw_slots = BTreeMap::new();
    for (name, slot) in &state.slots {
        if slot.bytes.is_empty() {
            continue; // tombstone
        }
        raw_slots.insert(name.clone(), slot.bytes.clone());
    }
    let profile = raw_slots
        .get(SLOT_PROFILE)
        .map(|b| {
            let p: ProfileV1 = whoiam_core::from_cbor(b).map_err(FetchError::Malformed)?;
            whoiam_core::resources::check_profile(&p).map_err(FetchError::Malformed)?;
            Ok(p)
        })
        .transpose()?;
    let avatar = raw_slots
        .get(SLOT_AVATAR)
        .map(|b| {
            whoiam_core::resources::check_avatar_bytes(b).map_err(FetchError::Malformed)?;
            Ok(b.clone())
        })
        .transpose()?;
    Ok(Identity {
        pubkey: *pk,
        profile,
        avatar,
        raw_slots,
    })
}

/// Fetch and verify an identity from a node.
pub async fn fetch(node_url: &str, pk: &VerifyingKey) -> Result<Identity, FetchError> {
    let (stream, _) = tokio_tungstenite::connect_async(node_url)
        .await
        .map_err(|e| FetchError::Transport(format!("connect {node_url}: {e}")))?;
    let mut api = WebApi::start(stream);

    let key = contract_key(pk);
    api.send(ClientRequest::ContractOp(ContractRequest::Get {
        key: *key.id(),
        return_contract_code: false,
        subscribe: false,
        blocking_subscribe: false,
    }))
    .await
    .map_err(|e| FetchError::Transport(e.to_string()))?;

    let state = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match api.recv().await {
                Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                    state, ..
                })) => return Ok(state),
                Ok(_) => continue,
                Err(e) => {
                    // Fragile by necessity: the client error type exposes no
                    // structured not-found variant, so this string-matches
                    // the node's wording. A node release rewording the
                    // message degrades NotFound to Transport (not unsafe,
                    // just less precise).
                    let msg = e.to_string();
                    return Err(if msg.contains("not found") {
                        FetchError::NotFound
                    } else {
                        FetchError::Transport(msg)
                    });
                }
            }
        }
    })
    .await
    .map_err(|_| FetchError::Timeout)??;

    if state.as_ref().is_empty() {
        // Contract exists but has no content yet.
        return identity_from_state(pk, &IdentityStateV1::default());
    }
    let state: IdentityStateV1 =
        whoiam_core::from_cbor(state.as_ref()).map_err(FetchError::Malformed)?;
    // Full client-side verification — the serving node is untrusted.
    validate_full(&state, pk, wall_now_ms()).map_err(FetchError::BadSignature)?;
    identity_from_state(pk, &state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use whoiam_core::state::{sign_destroy, sign_slot};

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn contract_key_deterministic_and_distinct() {
        let a = key().verifying_key();
        let b = key().verifying_key();
        assert_eq!(contract_key(&a), contract_key(&a));
        assert_ne!(contract_key(&a), contract_key(&b));
    }

    #[test]
    fn pubkey_parse_both_encodings() {
        let pk = key().verifying_key();
        let b58 = format_pubkey(&pk);
        let hex = data_encoding::HEXLOWER.encode(pk.as_bytes());
        assert_eq!(parse_pubkey(&b58).unwrap(), pk);
        assert_eq!(parse_pubkey(&hex).unwrap(), pk);
        assert!(parse_pubkey("nope!").is_err());
    }

    #[test]
    fn state_conversion_hides_tombstones_surfaces_destroyed() {
        let sk = key();
        let pk = sk.verifying_key();
        let mut state = IdentityStateV1::default();
        let profile = whoiam_core::to_cbor(&ProfileV1 {
            name: "graff".into(),
            bio: "hi".into(),
        })
        .unwrap();
        state
            .slots
            .insert("profile".into(), sign_slot(&sk, "profile", 100, profile));
        state
            .slots
            .insert("avatar".into(), sign_slot(&sk, "avatar", 200, vec![]));

        let id = identity_from_state(&pk, &state).unwrap();
        assert_eq!(id.profile.unwrap().name, "graff");
        assert!(id.avatar.is_none(), "tombstoned avatar must be hidden");
        assert!(!id.raw_slots.contains_key("avatar"));

        let mut dead = IdentityStateV1::default();
        dead.destroyed = Some(sign_destroy(&sk, 300));
        assert!(matches!(
            identity_from_state(&pk, &dead),
            Err(FetchError::Destroyed { since_ms: 300 })
        ));
    }

    /// Signatures prove authorship, not honesty: schema-violating well-known
    /// slots from a hostile identity must not reach consumers.
    #[test]
    fn hostile_well_known_slots_rejected() {
        let sk = key();
        let pk = sk.verifying_key();

        let mut state = IdentityStateV1::default();
        let big_bio = whoiam_core::to_cbor(&ProfileV1 {
            name: "x".into(),
            bio: "b".repeat(100_000),
        })
        .unwrap();
        state
            .slots
            .insert("profile".into(), sign_slot(&sk, "profile", 100, big_bio));
        assert!(matches!(
            identity_from_state(&pk, &state),
            Err(FetchError::Malformed(_))
        ));

        let mut state = IdentityStateV1::default();
        state
            .slots
            .insert("avatar".into(), sign_slot(&sk, "avatar", 100, b"GIF89a not a png".to_vec()));
        assert!(matches!(
            identity_from_state(&pk, &state),
            Err(FetchError::Malformed(_))
        ));
    }
}
