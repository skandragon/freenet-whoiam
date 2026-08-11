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

/// How long to wait for the delegate's Stored ack. The node answers
/// delegate requests locally, so honest failures surface fast.
const KV_ACK_TIMEOUT_MS: u32 = 10_000;
/// How long to wait for a contract Put/Update confirmation.
const CONTRACT_ACK_TIMEOUT_MS: u32 = 30_000;

/// Poll until `done()` or timeout. The protocol has no request ids, so
/// "done" is a caller-chosen observation (an ack counter passing its
/// pre-send baseline, or state reflecting the write).
async fn wait_until(mut done: impl FnMut() -> bool, timeout_ms: u32, what: &str) -> Result<(), String> {
    let mut waited = 0u32;
    while waited < timeout_ms {
        if done() {
            return Ok(());
        }
        crate::sleep_ms(100).await;
        waited += 100;
    }
    Err(format!("{what} was not confirmed — nothing was changed remotely. Reload and try again."))
}

/// Store a delegate value and wait for its Stored ack. Send success only
/// means the frame left the browser; a swallowed delegate error would
/// otherwise masquerade as persistence.
async fn kv_store_confirmed(key: &str, value: Vec<u8>) -> Result<(), String> {
    let baseline = api::kv_acks(key);
    api::kv_request(WhoiamDelegateRequest::Store {
        key: key.into(),
        value: ByteBuf::from(value),
    })
    .await?;
    wait_until(
        || api::kv_acks(key) > baseline,
        KV_ACK_TIMEOUT_MS,
        &format!("storing {key:?} in the key store"),
    )
    .await
}

/// PUT an empty contract and wait for the node's PutResponse. Same reason
/// as `kv_store_confirmed`: a resolved `send()` is not an accepted write.
async fn put_identity_confirmed(pk: &VerifyingKey, what: &str) -> Result<(), String> {
    let baseline = api::contract_acks(pk);
    api::put_identity(pk, &IdentityStateV1::default()).await?;
    wait_until(
        || api::contract_acks(pk) > baseline,
        CONTRACT_ACK_TIMEOUT_MS,
        what,
    )
    .await
}

/// Persist meta, then mirror it locally — only after the delegate confirms,
/// so the UI never shows identities the store doesn't hold.
async fn store_meta(meta: &IdentityMeta) -> Result<(), String> {
    kv_store_confirmed(KEY_META, whoiam_core::to_cbor(meta)?).await?;
    *META.write() = meta.clone();
    Ok(())
}

/// First run: generate the master seed and persist it in the delegate.
/// SEED_LOADED flips only after the Stored ack — an optimistic write here
/// would both fake onboarding on a failed store AND disarm the
/// empty-delegate-response detector (it only fires while the seed is
/// unloaded).
pub async fn create_seed() -> Result<(), String> {
    use rand::RngCore;
    let mut s = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut s);
    kv_store_confirmed(KEY_SEED, s.to_vec()).await?;
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

/// The backup file contents for a seed. Pure so the round-trip with
/// [`parse_backup`] is testable without a browser.
pub fn backup_text_for(s: &[u8; 32]) -> Result<String, String> {
    let hex = data_encoding::HEXLOWER.encode(s);
    let words = bip39::Mnemonic::from_entropy(s).map_err(|e| e.to_string())?;
    Ok(format!(
        "whoiam master seed — KEEP THIS SECRET, KEEP THIS SAFE\n\
         Anyone with this seed controls every persona derived from it,\n\
         including ones you create in the future.\n\n\
         hex:\n{hex}\n\nrecovery phrase (24 words):\n{words}\n"
    ))
}

/// The backup file contents for the current seed.
pub fn backup_text() -> Result<String, String> {
    backup_text_for(&seed().ok_or("seed not loaded")?)
}

/// Restore: store the seed, then probe derived addresses for existing
/// identities. Probing GETs indices 0..PROBE_LIMIT and simply waits a fixed
/// window for states to arrive; anything found lands in meta.
/// ponytail: fixed 8s window + 16-index cap instead of true gap detection —
/// add response-driven probing if identities beyond 16 become real.
pub async fn restore_seed(input: String) -> Result<(), String> {
    const PROBE_LIMIT: u32 = 16;
    let s = parse_backup(&input)?;
    kv_store_confirmed(KEY_SEED, s.to_vec()).await?;
    *SEED_LOADED.write() = Some(Some(s));

    let mut send_failures = 0u32;
    for index in 0..PROBE_LIMIT {
        let pk = identity_signing_key(&s, index).verifying_key();
        if let Err(e) = api::fetch_identity(&pk).await {
            api::log(&format!("restore probe {index} failed to send: {e}"));
            send_failures += 1;
        }
    }
    // Every probe failing to SEND is not "searched and found nothing" —
    // it's "couldn't search". Empty-meta success here would read as a bad
    // backup phrase and invite recreating identity 0 over a live one.
    if send_failures == PROBE_LIMIT {
        return Err("couldn't reach the network to search for your personas — reload and try again".into());
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
                        label: format!("persona {index}"),
                    });
                }
                // Destroyed identities stay out of the list but still push
                // the watermark: their indices are retired forever.
                meta.next_index = meta.next_index.max(index + 1);
            }
        }
    }
    store_meta(&meta).await
}

/// Manually re-attach one index restore probing missed (e.g. the contract
/// rotted off the network). Re-PUTs an empty state to revive the address.
/// No UI affordance yet — callable surface for the restore-miss case.
pub async fn readd_index(index: u32) -> Result<(), String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let mut meta = META.read().clone();
    if meta.identities.iter().any(|e| e.index == index) {
        return Err(format!("index {index} is already attached"));
    }
    put_identity_confirmed(&pk, "reviving the persona contract").await?;
    meta.identities.push(IdentityEntry {
        index,
        label: format!("persona {index}"),
    });
    meta.identities.sort_by_key(|e| e.index);
    meta.next_index = meta.next_index.max(index + 1);
    store_meta(&meta).await
}

/// Create the next identity: allocate from the monotonic watermark (a
/// destroyed identity's index must never be reused — the rederived key
/// would inherit its permanently-destroyed contract), PUT its (empty)
/// contract, and record it in meta only after the node confirms the Put.
pub async fn create_identity(label: String) -> Result<u32, String> {
    let mut meta = META.read().clone();
    let index = meta.alloc_index();
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    put_identity_confirmed(&pk, "creating the persona contract").await?;
    // Confirmed by the PutResponse — this entry is no longer speculative.
    IDENTITY_STATES
        .write()
        .insert(pk.to_bytes(), Some(IdentityStateV1::default()));
    let label = if label.trim().is_empty() {
        format!("persona {index}")
    } else {
        label.trim().to_string()
    };
    meta.identities.push(IdentityEntry { index, label });
    meta.next_index = index + 1;
    store_meta(&meta).await?;
    Ok(index)
}

pub async fn rename_identity(index: u32, label: String) -> Result<(), String> {
    let mut meta = META.read().clone();
    let entry = meta
        .identities
        .iter_mut()
        .find(|e| e.index == index)
        .ok_or("no such persona")?;
    entry.label = label.trim().to_string();
    store_meta(&meta).await
}

/// Sign one slot, push it, and wait for confirmation: either an
/// UpdateResponse ack or the subscription echo landing the slot in local
/// state (dispatch merges notifications for tracked contracts). No
/// optimistic apply — "published ✓" must mean the node accepted it.
async fn publish_slot(index: u32, name: &str, bytes: Vec<u8>) -> Result<(), String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let time_ms = keys::now_ms();
    let slot = sign_slot(&sk, name, time_ms, bytes);
    let mut delta = IdentityStateV1::default();
    delta.slots.insert(name.to_string(), slot);
    let baseline = api::contract_acks(&pk);
    api::update_identity(&pk, &delta).await?;
    let slot_name = name.to_string();
    let pkb = pk.to_bytes();
    wait_until(
        move || {
            if api::contract_acks(&pk) > baseline {
                return true;
            }
            IDENTITY_STATES
                .peek()
                .get(&pkb)
                .and_then(|e| e.as_ref())
                .and_then(|s| s.slots.get(&slot_name))
                .is_some_and(|s| s.time_ms >= time_ms)
        },
        CONTRACT_ACK_TIMEOUT_MS,
        "publishing",
    )
    .await?;
    // Confirmed: mirror locally (idempotent if the echo already merged it).
    let mut states = IDENTITY_STATES.write();
    let entry = states.entry(pkb).or_insert(None);
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

/// Destroy the PUBLIC identity first (signed permanent marker), wait until
/// the node confirms the marker landed, and only then forget it locally —
/// deleting local metadata on an unconfirmed push would leave the public
/// identity alive while the user believes it destroyed. The seed stays;
/// `next_index` (untouched here) retires the index forever.
pub async fn destroy_identity(index: u32) -> Result<(), String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let mut delta = IdentityStateV1::default();
    delta.destroyed = Some(sign_destroy(&sk, keys::now_ms()));
    let baseline = api::contract_acks(&pk);
    api::update_identity(&pk, &delta).await?;
    let pkb = pk.to_bytes();
    wait_until(
        move || {
            if api::contract_acks(&pk) > baseline {
                return true;
            }
            // Subscription echo: the destroyed marker merged into local state.
            IDENTITY_STATES
                .peek()
                .get(&pkb)
                .and_then(|e| e.as_ref())
                .is_some_and(|s| s.destroyed.is_some())
        },
        CONTRACT_ACK_TIMEOUT_MS,
        "destroying the public persona",
    )
    .await
    .map_err(|e| format!("{e} The persona was NOT removed locally."))?;

    let mut meta = META.read().clone();
    meta.identities.retain(|e| e.index != index);
    store_meta(&meta).await?;
    IDENTITY_STATES.write().remove(&pk.to_bytes());
    *VIEW.write() = View::Home;
    Ok(())
}

/// Connect challenge charset: URL-safe unreserved chars only, so callback
/// URLs build by plain concatenation with no re-encoding step to get wrong.
pub fn valid_challenge(c: &str) -> bool {
    (1..=256).contains(&c.len())
        && c.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '~' | '-'))
}

fn callback_url(return_url: &str, params: &str) -> String {
    let sep = if return_url.contains('?') { '&' } else { '?' };
    format!("{return_url}{sep}{params}")
}

/// The signed approval callback URL: proof that this persona's key consented
/// to identify to `req.origin` for this challenge, at this time.
pub fn connect_ok_url(index: u32, req: &ConnectRequest, time_ms: u64) -> Result<String, String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let sig = whoiam_core::connect::sign_connect(&sk, &req.return_base, &req.challenge, time_ms);
    let hex = |b: &[u8]| data_encoding::HEXLOWER.encode(b);
    Ok(callback_url(
        &req.return_url,
        &format!(
            "whoiam=ok&pk={}&sig={}&challenge={}&ts={time_ms}",
            hex(pk.as_bytes()),
            hex(&sig.to_bytes()),
            req.challenge
        ),
    ))
}

pub fn connect_denied_url(req: &ConnectRequest) -> String {
    callback_url(&req.return_url, "whoiam=denied")
}

/// Fetch (and subscribe to) every identity in meta — boot and post-restore.
/// The empty re-PUT first is the freebird resume pattern: it creates the
/// contract if it's missing (rotted off the network, or orphaned by a
/// deliberate wasm rotation) and is a merge no-op otherwise, so our own
/// identities self-heal on every boot.
pub async fn fetch_all_identities() {
    let entries = META.read().identities.clone();
    for e in entries {
        if let Some(pk) = identity_pubkey(e.index) {
            if let Err(err) = api::put_identity(&pk, &IdentityStateV1::default()).await {
                api::log(&format!("identity {} re-put failed: {err}", e.index));
            }
            if let Err(err) = api::fetch_identity(&pk).await {
                api::log(&format!("identity {} fetch failed: {err}", e.index));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{backup_text_for, callback_url, parse_backup, valid_challenge};

    const SEED: [u8; 32] = [0x5A; 32];

    #[test]
    fn challenge_charset_enforced() {
        assert!(valid_challenge("abc123._~-"));
        assert!(!valid_challenge(""));
        assert!(!valid_challenge(&"x".repeat(257)));
        // Anything that could break URL concatenation or smuggle params.
        for bad in ["a&b", "a=b", "a b", "a#b", "a%41", "a/b", "ü"] {
            assert!(!valid_challenge(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn callback_url_separator() {
        assert_eq!(callback_url("https://x.com/cb", "whoiam=denied"), "https://x.com/cb?whoiam=denied");
        assert_eq!(callback_url("https://x.com/cb?a=1", "whoiam=denied"), "https://x.com/cb?a=1&whoiam=denied");
    }

    /// The whole point of a backup: both encodings in the file must parse
    /// back to the exact seed. This is the restore path's data-loss guard.
    #[test]
    fn backup_round_trips_both_encodings() {
        let text = backup_text_for(&SEED).unwrap();
        let hex_line = text.lines().find(|l| l.len() == 64).unwrap();
        let words_line = text.lines().last().unwrap();
        assert_eq!(words_line.split_whitespace().count(), 24);
        assert_eq!(parse_backup(hex_line).unwrap(), SEED);
        assert_eq!(parse_backup(words_line).unwrap(), SEED);
    }

    #[test]
    fn hex_forgiving_of_case_and_whitespace() {
        let hex = data_encoding::HEXLOWER.encode(&SEED);
        assert_eq!(parse_backup(&hex.to_uppercase()).unwrap(), SEED);
        // As pasted from the backup file with a stray newline/indent.
        assert_eq!(parse_backup(&format!("  {}\n", hex)).unwrap(), SEED);
        // Whitespace INSIDE the hex (line-wrapped paste).
        let (a, b) = hex.split_at(32);
        assert_eq!(parse_backup(&format!("{a}\n{b}")).unwrap(), SEED);
    }

    #[test]
    fn wrong_sizes_rejected() {
        // 12-word phrase = 16-byte entropy: valid BIP39, wrong seed size.
        let twelve = bip39::Mnemonic::from_entropy(&[7u8; 16]).unwrap().to_string();
        assert!(parse_backup(&twelve).is_err());
        // Near-miss hex lengths fall through to the mnemonic parser and fail.
        let hex = data_encoding::HEXLOWER.encode(&SEED);
        assert!(parse_backup(&hex[..63]).is_err());
        assert!(parse_backup(&format!("{hex}0")).is_err());
        assert!(parse_backup("definitely not a backup").is_err());
    }
}
