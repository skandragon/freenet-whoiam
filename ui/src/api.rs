#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code, unused_imports))]
//! Node connection + request plumbing + response dispatch.
//! Slimmed from Freebird's api layer: one WebSocket via
//! `freenet_stdlib::client_api::WebApi`, global Dioxus signals, stateless
//! response dispatch keyed by tracked contract ids.

use std::collections::BTreeMap;

use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::{
    ClientRequest, ContractRequest, ContractResponse, DelegateRequest, HostResponse,
};
#[cfg(target_arch = "wasm32")]
use freenet_stdlib::client_api::WebApi;
use freenet_stdlib::prelude::*;
use whoiam_core::delegate_api::{
    IdentityMeta, WhoiamDelegateRequest, WhoiamDelegateResponse, KEY_META, KEY_SEED,
};
use whoiam_core::merge::merge_state;
use whoiam_core::state::IdentityStateV1;

use crate::keys;
use crate::state::*;

#[cfg(target_arch = "wasm32")]
pub fn websocket_url() -> String {
    let win = web_sys::window().expect("window");
    let location = win.location();
    let proto = if location.protocol().unwrap_or_default() == "https:" {
        "wss"
    } else {
        "ws"
    };
    let host = location.host().unwrap_or_else(|_| "127.0.0.1:7509".into());
    let base = format!("{proto}://{host}/v1/contract/command?encodingProtocol=native");
    // Auth token arrives as ?authToken= on the page URL (node-served apps).
    let token = location
        .search()
        .ok()
        .and_then(|s| web_sys::UrlSearchParams::new_with_str(&s).ok())
        .and_then(|p| p.get("authToken"));
    match token {
        Some(t) => format!("{base}&authToken={t}"),
        None => base,
    }
}

#[cfg(target_arch = "wasm32")]
pub async fn connect() -> Result<(), String> {
    use futures::channel::mpsc;
    use futures::StreamExt;

    let url = websocket_url();
    let ws = web_sys::WebSocket::new(&url).map_err(|e| format!("websocket open: {e:?}"))?;

    let (tx, mut rx) = mpsc::unbounded::<Result<HostResponse, String>>();
    let tx_err = tx.clone();
    let api = WebApi::start(
        ws,
        move |result| {
            let _ = tx.unbounded_send(result.map_err(|e| e.to_string()));
        },
        move |err| {
            let _ = tx_err.unbounded_send(Err(format!("connection error: {err}")));
        },
        || {
            *SYNC_STATUS.write() = SyncStatus::Connected;
        },
    );
    *WEB_API.write() = Some(api);

    // Response pump: runs for the life of the page.
    wasm_bindgen_futures::spawn_local(async move {
        while let Some(msg) = rx.next().await {
            match msg {
                Ok(response) => dispatch(response),
                Err(e) => {
                    let connection_dead = e.contains("AUTH_TOKEN_INVALID")
                        || e.contains("WebSocket is not open")
                        || e.starts_with("connection error");
                    if connection_dead {
                        log(&format!("connection lost: {e}"));
                        *SYNC_STATUS.write() =
                            SyncStatus::Error("connection lost — reconnecting…".into());
                        schedule_reload();
                    } else if *SYNC_STATUS.read() != SyncStatus::Connected {
                        *SYNC_STATUS.write() = SyncStatus::Error(e);
                    } else {
                        // Request-level error (e.g. Get for a contract that
                        // doesn't exist yet) — the connection is fine.
                        log(&format!("request error: {e}"));
                    }
                }
            }
        }
    });
    Ok(())
}

/// Reload the page once, after a short delay — the simplest reliable
/// reconnect (fresh socket, fresh auth token, full resync). Guarded so a
/// burst of errors schedules only one.
#[cfg(target_arch = "wasm32")]
fn schedule_reload() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SCHEDULED: AtomicBool = AtomicBool::new(false);
    if SCHEDULED.swap(true, Ordering::SeqCst) {
        return;
    }
    wasm_bindgen_futures::spawn_local(async {
        crate::sleep_ms(5000).await;
        if let Some(win) = web_sys::window() {
            let _ = win.location().reload();
        }
    });
}

pub async fn send(request: ClientRequest<'static>) -> Result<(), String> {
    let mut guard = WEB_API.write();
    let api = guard.as_mut().ok_or("not connected")?;
    api.send(request).await.map_err(|e| e.to_string())
}

// ---- contract operations ----

fn identity_container(pk: &VerifyingKey) -> ContractContainer {
    let params = whoiam_core::to_cbor(&keys::identity_params(pk)).expect("params");
    ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        std::sync::Arc::new(ContractCode::from(keys::IDENTITY_CONTRACT_WASM.to_vec())),
        Parameters::from(params),
    )))
}

/// PUT an identity contract (creates on first use; the contract's merge
/// makes a re-Put a plain apply). Subscribes so update notifications flow.
pub async fn put_identity(pk: &VerifyingKey, state: &IdentityStateV1) -> Result<(), String> {
    let bytes = whoiam_core::to_cbor(state)?;
    track(pk);
    send(ClientRequest::ContractOp(ContractRequest::Put {
        contract: identity_container(pk),
        state: WrappedState::new(bytes),
        related_contracts: RelatedContracts::default(),
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
}

/// Push a partial state (delta) into our identity contract.
pub async fn update_identity(pk: &VerifyingKey, delta: &IdentityStateV1) -> Result<(), String> {
    let bytes = whoiam_core::to_cbor(delta)?;
    track(pk);
    send(ClientRequest::ContractOp(ContractRequest::Update {
        key: keys::identity_key(pk),
        data: UpdateData::Delta(StateDelta::from(bytes)),
    }))
    .await
}

/// GET + subscribe an identity's contract.
pub async fn fetch_identity(pk: &VerifyingKey) -> Result<(), String> {
    IDENTITY_STATES.write().entry(pk.to_bytes()).or_insert(None);
    track(pk);
    send(ClientRequest::ContractOp(ContractRequest::Get {
        key: keys::identity_instance_id(pk),
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    }))
    .await
}

// ---- delegate operations ----

fn whoiam_delegate_container() -> DelegateContainer {
    let code = DelegateCode::from(keys::WHOIAM_DELEGATE_WASM.to_vec());
    let params = Parameters::from(Vec::<u8>::new());
    let delegate = Delegate::from((&code, &params));
    DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate))
}

pub fn whoiam_delegate_key() -> DelegateKey {
    let code = DelegateCode::from(keys::WHOIAM_DELEGATE_WASM.to_vec());
    let params = Parameters::from(Vec::<u8>::new());
    DelegateKey::from_params(code.hash_str(), &params).expect("delegate key")
}

/// Stable-but-local cipher material, same rationale as River (river#397):
/// re-registrations must reuse identical material or the node re-keys the
/// delegate's secret store.
#[cfg(target_arch = "wasm32")]
fn delegate_cipher_material() -> ([u8; 32], [u8; 24]) {
    const CIPHER_KEY: &str = "whoiam_delegate_cipher_v1";
    const NONCE_KEY: &str = "whoiam_delegate_nonce_v1";
    let storage = web_sys::window().and_then(|w| w.local_storage().ok().flatten());
    if let Some(s) = &storage {
        if let (Ok(Some(c)), Ok(Some(n))) = (s.get_item(CIPHER_KEY), s.get_item(NONCE_KEY)) {
            if let (Ok(c), Ok(n)) = (bs58::decode(c).into_vec(), bs58::decode(n).into_vec()) {
                if c.len() == 32 && n.len() == 24 {
                    return (c.try_into().unwrap(), n.try_into().unwrap());
                }
            }
        }
    }
    use rand::RngCore;
    let mut cipher = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut cipher);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    if let Some(s) = &storage {
        let _ = s.set_item(CIPHER_KEY, &bs58::encode(cipher).into_string());
        let _ = s.set_item(NONCE_KEY, &bs58::encode(nonce).into_string());
    }
    (cipher, nonce)
}

#[cfg(target_arch = "wasm32")]
pub async fn register_delegate() -> Result<(), String> {
    let (cipher, nonce) = delegate_cipher_material();
    send(ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate {
        delegate: whoiam_delegate_container(),
        cipher,
        nonce,
    }))
    .await
}

pub async fn kv_request(request: WhoiamDelegateRequest) -> Result<(), String> {
    let payload = whoiam_core::to_cbor(&request)?;
    send(ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
        key: whoiam_delegate_key(),
        params: Parameters::from(Vec::<u8>::new()),
        inbound: vec![InboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(payload),
        )],
    }))
    .await
}

// ---- response dispatch ----

fn dispatch(response: HostResponse) {
    match response {
        HostResponse::ContractResponse(cr) => dispatch_contract(cr),
        HostResponse::DelegateResponse { key, values } => {
            if key != whoiam_delegate_key() {
                return;
            }
            if values.is_empty() {
                note_empty_delegate_response();
            }
            for out in values {
                if let OutboundDelegateMsg::ApplicationMessage(app_msg) = out {
                    dispatch_kv(app_msg.payload.as_ref());
                }
            }
        }
        _ => {}
    }
}

/// An empty delegate response is the node's tell for a swallowed delegate
/// error. Exactly one empty response is legitimate — the RegisterDelegate
/// ack — so only a SECOND one proves errors are being swallowed. (Observed
/// against the freenet1 explorer node, 2026-08-11; a node release changing
/// the RegisterDelegate ack shape invalidates this count.)
fn note_empty_delegate_response() {
    use std::sync::atomic::{AtomicU32, Ordering};
    static EMPTY: AtomicU32 = AtomicU32::new(0);
    let seen = EMPTY.fetch_add(1, Ordering::SeqCst) + 1;
    if seen >= 2 && SEED_LOADED.peek().is_none() {
        log("empty whoiam delegate response beyond the register ack — node is swallowing delegate errors");
        *KEY_STORE_UNREACHABLE.write() = true;
    }
}

fn dispatch_contract(response: ContractResponse) {
    match response {
        ContractResponse::GetResponse { key, state, .. } => {
            apply_contract_bytes(&key, state.as_ref());
        }
        ContractResponse::UpdateNotification { key, update } => match update {
            UpdateData::State(s) => apply_contract_bytes(&key, s.as_ref()),
            UpdateData::Delta(d) => apply_contract_bytes(&key, d.as_ref()),
            UpdateData::StateAndDelta { state, .. } => apply_contract_bytes(&key, state.as_ref()),
            _ => {}
        },
        // Write confirmations: actions wait on these counters before
        // reporting success or (for destroy) dropping local key metadata —
        // `send()` resolving only means the frame left the browser.
        ContractResponse::PutResponse { key } => bump_contract_ack(&key),
        ContractResponse::UpdateResponse { key, .. } => bump_contract_ack(&key),
        _ => {}
    }
}

/// Confirmed writes per contract id: incremented on PutResponse and
/// UpdateResponse. Uncorrelated with individual requests (the protocol has
/// no request ids), so waiters compare against a pre-send baseline.
/// Private: read them through `contract_acks` / `kv_acks`.
static CONTRACT_ACKS: GlobalSignal<BTreeMap<String, u64>> = Signal::global(BTreeMap::new);

/// Confirmed delegate stores per key, from the delegate's Stored acks.
static KV_ACKS: GlobalSignal<BTreeMap<String, u64>> = Signal::global(BTreeMap::new);

fn bump_contract_ack(key: &ContractKey) {
    *CONTRACT_ACKS.write().entry(key.id().to_string()).or_insert(0) += 1;
}

pub fn contract_acks(pk: &VerifyingKey) -> u64 {
    CONTRACT_ACKS
        .peek()
        .get(&keys::identity_key(pk).id().to_string())
        .copied()
        .unwrap_or(0)
}

pub fn kv_acks(key: &str) -> u64 {
    KV_ACKS.peek().get(key).copied().unwrap_or(0)
}

/// Full state and deltas are the same shape (a partial IdentityStateV1):
/// verify against the tracked identity's key, then LWW-merge into place.
fn apply_contract_bytes(key: &ContractKey, bytes: &[u8]) {
    let Some(owner) = lookup(key) else { return };
    if bytes.is_empty() {
        // An empty GetResponse is a real answer — contract exists, nothing
        // published. Mark it arrived (Some(default)) so views stop gating;
        // "pending" and "empty" must stay distinguishable.
        IDENTITY_STATES
            .write()
            .entry(owner)
            .or_insert(None)
            .get_or_insert_with(IdentityStateV1::default);
        return;
    }
    let Ok(vk) = VerifyingKey::from_bytes(&owner) else { return };
    match whoiam_core::from_cbor::<IdentityStateV1>(bytes) {
        Ok(incoming) => {
            let mut states = IDENTITY_STATES.write();
            let entry = states.entry(owner).or_insert(None);
            let current = entry.get_or_insert_with(IdentityStateV1::default);
            // The incoming bytes are untrusted: merge_state re-verifies
            // every signature before anything lands in the UI.
            if let Err(e) = merge_state(current, &incoming, &vk, keys::now_ms()) {
                log(&format!("rejected identity state for {key}: {e}"));
            }
        }
        Err(e) => log(&format!("bad identity state: {e}")),
    }
}

fn dispatch_kv(payload: &[u8]) {
    match whoiam_core::from_cbor::<WhoiamDelegateResponse>(payload) {
        Ok(WhoiamDelegateResponse::Value { key, value }) => {
            // Present-but-undecodable is NOT "absent": treating a corrupt
            // seed/meta as a fresh install would route to onboarding, whose
            // next write overwrites possibly-recoverable key material. Flag
            // unreachable instead so the user gets the error screen.
            if key == KEY_SEED {
                match value.as_deref() {
                    None => *SEED_LOADED.write() = Some(None),
                    Some(v) => match <[u8; 32]>::try_from(&v[..]) {
                        Ok(seed) => *SEED_LOADED.write() = Some(Some(seed)),
                        Err(_) => {
                            log("stored seed has wrong length — refusing to treat as absent");
                            *KEY_STORE_UNREACHABLE.write() = true;
                        }
                    },
                }
            } else if key == KEY_META {
                match value.as_deref() {
                    None => {
                        *META.write() = IdentityMeta::default();
                        *META_LOADED.write() = true;
                    }
                    Some(v) => match whoiam_core::from_cbor::<IdentityMeta>(v) {
                        Ok(meta) => {
                            *META.write() = meta;
                            *META_LOADED.write() = true;
                        }
                        Err(e) => {
                            log(&format!("stored meta undecodable ({e}) — refusing to treat as empty"));
                            *KEY_STORE_UNREACHABLE.write() = true;
                        }
                    },
                }
            }
        }
        Ok(WhoiamDelegateResponse::Stored { key }) => {
            *KV_ACKS.write().entry(key).or_insert(0) += 1;
        }
        Ok(WhoiamDelegateResponse::Deleted { .. })
        | Ok(WhoiamDelegateResponse::KeyList { .. }) => {}
        Ok(WhoiamDelegateResponse::Error { message }) => {
            log(&format!("delegate error: {message}"));
        }
        Err(e) => log(&format!("bad delegate response: {e}")),
    }
}

// ---- tracked-contract registry ----

pub static TRACKED: GlobalSignal<BTreeMap<String, [u8; 32]>> = Signal::global(BTreeMap::new);

fn track(pk: &VerifyingKey) {
    TRACKED
        .write()
        .insert(keys::identity_key(pk).id().to_string(), pk.to_bytes());
}

fn lookup(key: &ContractKey) -> Option<[u8; 32]> {
    TRACKED.read().get(&key.id().to_string()).copied()
}

pub fn log(msg: &str) {
    #[cfg(target_arch = "wasm32")]
    web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(msg));
    #[cfg(not(target_arch = "wasm32"))]
    println!("{msg}");
}
