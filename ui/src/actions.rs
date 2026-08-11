//! User-intent actions: onboard, edit, backup, destroy. Every action signs
//! locally with a key derived on demand from the delegate-held seed.

use dioxus::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_bytes::ByteBuf;
use whoiam_core::delegate_api::{
    IdentityEntry, IdentityMeta, WhoiamDelegateRequest, KEY_META, KEY_SEED,
};
use whoiam_core::derive::identity_signing_key;
use whoiam_core::merge::merge_state;
use whoiam_core::resources::{check_avatar_bytes, check_profile, ProfileV1, SLOT_AVATAR, SLOT_PROFILE};
use whoiam_core::state::{sign_destroy, sign_slot, IdentityStateV1};

use crate::api;
use crate::keys;
use crate::state::*;

pub fn identity_pubkey(index: u32) -> Option<VerifyingKey> {
    seed().map(|s| identity_signing_key(&s, index).verifying_key())
}

fn signing_key(index: u32) -> Result<SigningKey, String> {
    seed()
        .map(|s| identity_signing_key(&s, index))
        .ok_or_else(|| "seed not loaded".to_string())
}

async fn store_meta(meta: &IdentityMeta) -> Result<(), String> {
    api::kv_request(WhoiamDelegateRequest::Store {
        key: KEY_META.into(),
        value: ByteBuf::from(whoiam_core::to_cbor(meta)?),
    })
    .await?;
    *META.write() = meta.clone();
    Ok(())
}

/// First run: generate the master seed and persist it in the delegate.
pub async fn create_seed() -> Result<(), String> {
    use rand::RngCore;
    let mut s = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut s);
    api::kv_request(WhoiamDelegateRequest::Store {
        key: KEY_SEED.into(),
        value: ByteBuf::from(s.to_vec()),
    })
    .await?;
    *SEED_LOADED.write() = Some(Some(s));
    store_meta(&IdentityMeta::default()).await
}

/// Parse a backup: 64 hex chars or a BIP39 24-word phrase.
pub fn parse_backup(input: &str) -> Result<[u8; 32], String> {
    let trimmed = input.trim();
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() == 64 && compact.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(compact.to_lowercase().as_bytes())
            .map_err(|e| e.to_string())?;
        return <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "not 32 bytes".into());
    }
    let mnemonic = bip39::Mnemonic::parse_normalized(&trimmed.to_lowercase())
        .map_err(|e| format!("not hex and not a valid recovery phrase: {e}"))?;
    let (entropy, len) = mnemonic.to_entropy_array();
    <[u8; 32]>::try_from(&entropy[..len]).map_err(|_| "phrase must encode 32 bytes (24 words)".into())
}

/// The backup file contents for the current seed.
pub fn backup_text() -> Result<String, String> {
    let s = seed().ok_or("seed not loaded")?;
    let hex = data_encoding::HEXLOWER.encode(&s);
    let words = bip39::Mnemonic::from_entropy(&s).map_err(|e| e.to_string())?;
    Ok(format!(
        "whoiam master seed — KEEP THIS SECRET, KEEP THIS SAFE\n\
         Anyone with this seed controls every identity derived from it,\n\
         including ones you create in the future.\n\n\
         hex:\n{hex}\n\nrecovery phrase (24 words):\n{words}\n"
    ))
}

/// Restore: store the seed, then probe derived addresses for existing
/// identities. Probing GETs indices 0..PROBE_LIMIT and simply waits a fixed
/// window for states to arrive; anything found lands in meta.
/// ponytail: fixed 8s window + 16-index cap instead of true gap detection —
/// add response-driven probing if identities beyond 16 become real.
pub async fn restore_seed(input: String) -> Result<(), String> {
    const PROBE_LIMIT: u32 = 16;
    let s = parse_backup(&input)?;
    api::kv_request(WhoiamDelegateRequest::Store {
        key: KEY_SEED.into(),
        value: ByteBuf::from(s.to_vec()),
    })
    .await?;
    *SEED_LOADED.write() = Some(Some(s));

    for index in 0..PROBE_LIMIT {
        let pk = identity_signing_key(&s, index).verifying_key();
        let _ = api::fetch_identity(&pk).await;
    }
    crate::sleep_ms(8000).await;

    let mut meta = IdentityMeta::default();
    {
        let states = IDENTITY_STATES.read();
        for index in 0..PROBE_LIMIT {
            let pk = identity_signing_key(&s, index).verifying_key();
            if let Some(Some(state)) = states.get(&pk.to_bytes()) {
                if state.destroyed.is_none() {
                    meta.identities.push(IdentityEntry {
                        index,
                        label: format!("identity {index}"),
                    });
                }
            }
        }
    }
    store_meta(&meta).await
}

/// Manually re-attach one index restore probing missed (e.g. the contract
/// rotted off the network). Re-PUTs an empty state to revive the address.
pub async fn readd_index(index: u32) -> Result<(), String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let mut meta = META.read().clone();
    if meta.identities.iter().any(|e| e.index == index) {
        return Err(format!("index {index} is already attached"));
    }
    api::put_identity(&pk, &IdentityStateV1::default()).await?;
    meta.identities.push(IdentityEntry {
        index,
        label: format!("identity {index}"),
    });
    meta.identities.sort_by_key(|e| e.index);
    store_meta(&meta).await
}

/// Create the next identity: derive the next unused index, PUT its (empty)
/// contract, record it in meta.
pub async fn create_identity(label: String) -> Result<u32, String> {
    let meta = META.read().clone();
    let index = meta
        .identities
        .iter()
        .map(|e| e.index + 1)
        .max()
        .unwrap_or(0);
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    api::put_identity(&pk, &IdentityStateV1::default()).await?;
    IDENTITY_STATES
        .write()
        .insert(pk.to_bytes(), Some(IdentityStateV1::default()));
    let mut meta = meta;
    let label = if label.trim().is_empty() {
        format!("identity {index}")
    } else {
        label.trim().to_string()
    };
    meta.identities.push(IdentityEntry { index, label });
    store_meta(&meta).await?;
    Ok(index)
}

pub async fn rename_identity(index: u32, label: String) -> Result<(), String> {
    let mut meta = META.read().clone();
    let entry = meta
        .identities
        .iter_mut()
        .find(|e| e.index == index)
        .ok_or("no such identity")?;
    entry.label = label.trim().to_string();
    store_meta(&meta).await
}

/// Sign one slot and push it; optimistic local apply so the UI updates
/// immediately (the contract runs the same merge).
async fn publish_slot(index: u32, name: &str, bytes: Vec<u8>) -> Result<(), String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let slot = sign_slot(&sk, name, keys::now_ms(), bytes);
    let mut delta = IdentityStateV1::default();
    delta.slots.insert(name.to_string(), slot);
    api::update_identity(&pk, &delta).await?;
    let mut states = IDENTITY_STATES.write();
    let entry = states.entry(pk.to_bytes()).or_insert(None);
    let current = entry.get_or_insert_with(IdentityStateV1::default);
    merge_state(current, &delta, &pk, keys::now_ms())?;
    Ok(())
}

pub async fn save_profile(index: u32, name: String, bio: String) -> Result<(), String> {
    let profile = ProfileV1 {
        name: name.trim().to_string(),
        bio: bio.trim().to_string(),
    };
    check_profile(&profile)?;
    publish_slot(index, SLOT_PROFILE, whoiam_core::to_cbor(&profile)?).await
}

pub async fn publish_avatar(index: u32, png: Vec<u8>) -> Result<(), String> {
    check_avatar_bytes(&png)?;
    publish_slot(index, SLOT_AVATAR, png).await
}

pub async fn remove_avatar(index: u32) -> Result<(), String> {
    publish_slot(index, SLOT_AVATAR, vec![]).await
}

/// Destroy the PUBLIC identity first (signed permanent marker), and only
/// then forget it locally. The seed stays; the index is never reused.
pub async fn destroy_identity(index: u32) -> Result<(), String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let mut delta = IdentityStateV1::default();
    delta.destroyed = Some(sign_destroy(&sk, keys::now_ms()));
    api::update_identity(&pk, &delta).await?;

    let mut meta = META.read().clone();
    meta.identities.retain(|e| e.index != index);
    store_meta(&meta).await?;
    IDENTITY_STATES.write().remove(&pk.to_bytes());
    *VIEW.write() = View::Home;
    Ok(())
}

/// Fetch (and subscribe to) every identity in meta — boot and post-restore.
pub async fn fetch_all_identities() {
    let entries = META.read().identities.clone();
    for e in entries {
        if let Some(pk) = identity_pubkey(e.index) {
            let _ = api::fetch_identity(&pk).await;
        }
    }
}
