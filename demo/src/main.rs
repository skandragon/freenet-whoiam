//! Demo Freenet app for the whoiam connect flow: the "external site" side.
//!
//! Landing: generate a one-time challenge and bounce to whoiam. Callback:
//! verify the connect proof (signature over our own origin+path, the
//! challenge, and a fresh timestamp), then fetch the identity contract from
//! the node and show the persona's profile — name, bio, avatar — verifying
//! every slot signature on the way in (`merge_state`).
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use ed25519_dalek::Signature;
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::ContractResponse;
#[cfg(target_arch = "wasm32")]
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, HostResponse, WebApi};
use freenet_stdlib::prelude::*;
use whoiam_core::merge::merge_state;
use whoiam_core::resources::{ProfileV1, SLOT_AVATAR, SLOT_PROFILE};
use whoiam_core::state::{IdentityParamsV1, IdentityStateV1};

const PROOF_MAX_AGE_MS: u64 = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS: u32 = 30_000;

// Same vendored contract bytes as the whoiam UI — the address of an
// identity's contract derives from wasm + params.
const IDENTITY_CONTRACT_WASM: &[u8] = include_bytes!("../../ui/contracts/identity_contract.wasm");

fn identity_key(pk: &VerifyingKey) -> ContractKey {
    let params = whoiam_core::to_cbor(&IdentityParamsV1 { version: 1, pubkey: *pk })
        .expect("params serialize");
    ContractKey::from_params_and_code(
        Parameters::from(params),
        &ContractCode::from(IDENTITY_CONTRACT_WASM.to_vec()),
    )
}

/// What this page is doing, decided once at boot from the URL params.
#[derive(Clone, PartialEq, Debug)]
enum Mode {
    Landing,
    Denied,
    /// Proof verified; profile fetch in progress or done.
    Verified { pk: [u8; 32] },
    Failed(String),
}

static MODE: GlobalSignal<Option<Mode>> = Signal::global(|| None);
/// The proven persona's contract state. None = fetch pending.
static PROFILE: GlobalSignal<Option<IdentityStateV1>> = Signal::global(|| None);
static FETCH_ERROR: GlobalSignal<Option<String>> = Signal::global(|| None);
#[cfg(target_arch = "wasm32")]
static WEB_API: GlobalSignal<Option<WebApi>> = Signal::global(|| None);
static WS_CONNECTED: GlobalSignal<bool> = Signal::global(|| false);

fn log(msg: &str) {
    #[cfg(target_arch = "wasm32")]
    web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(msg));
    #[cfg(not(target_arch = "wasm32"))]
    println!("{msg}");
}

// ---- boot: parse + verify the callback ----

/// This app's own origin+path — what connect proofs to us are bound to.
/// `location.origin` is useless here ("null": the shell sandboxes apps into
/// opaque-origin iframes), so derive from the full URL.
#[cfg(target_arch = "wasm32")]
fn own_base_and_params() -> Option<(String, web_sys::UrlSearchParams)> {
    let href = web_sys::window()?.location().href().ok()?;
    let url = web_sys::Url::new(&href).ok()?;
    let params = web_sys::UrlSearchParams::new_with_str(&url.search().as_str()).ok()?;
    Some((format!("{}{}", url.origin(), url.pathname()), params))
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(target_arch = "wasm32")]
fn decide_mode() -> Mode {
    let Some((base, params)) = own_base_and_params() else {
        return Mode::Landing;
    };
    match params.get("whoiam").as_deref() {
        Some("denied") => Mode::Denied,
        Some("ok") => match verify_callback(&base, &params) {
            Ok(pk) => Mode::Verified { pk: pk.to_bytes() },
            Err(why) => Mode::Failed(why),
        },
        _ => Mode::Landing,
    }
}

#[cfg(target_arch = "wasm32")]
fn verify_callback(base: &str, params: &web_sys::UrlSearchParams) -> Result<VerifyingKey, String> {
    let get = |k: &str| params.get(k).ok_or_else(|| format!("missing {k} param"));
    let challenge = get("challenge")?;
    let ts: u64 = get("ts")?.parse().map_err(|_| "bad ts".to_string())?;
    let now = now_ms();
    if now.abs_diff(ts) > PROOF_MAX_AGE_MS {
        return Err("stale proof — go back to the site and connect again".into());
    }
    let pk_bytes: [u8; 32] = hex32(&get("pk")?).ok_or("malformed pk")?;
    let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| "invalid public key")?;
    let sig_bytes = data_encoding::HEXLOWER_PERMISSIVE
        .decode(get("sig")?.as_bytes())
        .map_err(|_| "malformed sig")?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| "sig must be 64 bytes")?;
    whoiam_core::connect::check_connect(&pk, base, &challenge, ts, &Signature::from_bytes(&sig_arr))
        .map_err(|_| {
            "signature does not verify — impersonation attempt or corrupted callback".to_string()
        })?;
    Ok(pk)
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = data_encoding::HEXLOWER_PERMISSIVE.decode(s.as_bytes()).ok()?;
    v.try_into().ok()
}

// ---- node connection (slimmed from ui/src/api.rs: fetch-only) ----

#[cfg(target_arch = "wasm32")]
fn websocket_url() -> String {
    let win = web_sys::window().expect("window");
    let location = win.location();
    let proto = if location.protocol().unwrap_or_default() == "https:" { "wss" } else { "ws" };
    let host = location.host().unwrap_or_else(|_| "127.0.0.1:7509".into());
    format!("{proto}://{host}/v1/contract/command?encodingProtocol=native")
}

#[cfg(target_arch = "wasm32")]
async fn connect_ws(owner: VerifyingKey) -> Result<(), String> {
    use futures::channel::mpsc;
    use futures::StreamExt;

    let ws = web_sys::WebSocket::new(&websocket_url()).map_err(|e| format!("websocket open: {e:?}"))?;
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
            *WS_CONNECTED.write() = true;
        },
    );
    *WEB_API.write() = Some(api);

    let expected = identity_key(&owner);
    wasm_bindgen_futures::spawn_local(async move {
        while let Some(msg) = rx.next().await {
            match msg {
                Ok(HostResponse::ContractResponse(cr)) => {
                    apply_contract(&owner, &expected, cr);
                }
                Ok(_) => {}
                Err(e) => log(&format!("node error: {e}")),
            }
        }
    });
    Ok(())
}

fn apply_contract(owner: &VerifyingKey, expected: &ContractKey, response: ContractResponse) {
    let bytes = match response {
        ContractResponse::GetResponse { key, state, .. } if key.id() == expected.id() => state,
        ContractResponse::UpdateNotification { key, update } if key.id() == expected.id() => {
            match update {
                UpdateData::State(s) => WrappedState::new(s.into_bytes()),
                UpdateData::Delta(d) => WrappedState::new(d.into_bytes()),
                UpdateData::StateAndDelta { state, .. } => WrappedState::new(state.into_bytes()),
                _ => return,
            }
        }
        _ => return,
    };
    let mut current = PROFILE.peek().clone().unwrap_or_default();
    if bytes.as_ref().is_empty() {
        // Real answer: contract exists, nothing published yet.
        *PROFILE.write() = Some(current);
        return;
    }
    match whoiam_core::from_cbor::<IdentityStateV1>(bytes.as_ref()) {
        // Untrusted bytes: merge_state re-verifies every slot signature
        // against the proven key before anything is displayed.
        Ok(incoming) => match merge_state(&mut current, &incoming, owner, now_ms_native()) {
            Ok(_) => *PROFILE.write() = Some(current),
            Err(e) => log(&format!("rejected identity state: {e}")),
        },
        Err(e) => log(&format!("bad identity state: {e}")),
    }
}

fn now_ms_native() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        now_ms()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

#[cfg(target_arch = "wasm32")]
async fn fetch_profile(pk_bytes: [u8; 32]) {
    let Ok(pk) = VerifyingKey::from_bytes(&pk_bytes) else {
        *FETCH_ERROR.write() = Some("bad key".into());
        return;
    };
    if let Err(e) = connect_ws(pk).await {
        *FETCH_ERROR.write() = Some(e);
        return;
    }
    while !*WS_CONNECTED.read() {
        sleep_ms(100).await;
    }
    let request = ClientRequest::ContractOp(ContractRequest::Get {
        key: *identity_key(&pk).id(),
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    });
    let send_result = {
        let mut guard = WEB_API.write();
        match guard.as_mut() {
            Some(api) => api.send(request).await.map_err(|e| e.to_string()),
            None => Err("not connected".into()),
        }
    };
    if let Err(e) = send_result {
        *FETCH_ERROR.write() = Some(e);
        return;
    }
    // ponytail: single GET + watchdog, no retry — the proving user's node
    // just served whoiam, so the contract is warm in practice.
    sleep_ms(FETCH_TIMEOUT_MS).await;
    if PROFILE.peek().is_none() && FETCH_ERROR.peek().is_none() {
        *FETCH_ERROR.write() =
            Some("profile didn't arrive — the persona's contract may not be reachable".into());
    }
}

pub async fn sleep_ms(ms: u32) {
    #[cfg(target_arch = "wasm32")]
    {
        let promise = js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .expect("window")
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32)
                .expect("set_timeout");
        });
        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = ms;
    }
}

// ---- landing-side actions ----

#[cfg(target_arch = "wasm32")]
fn start_connect(whoiam_url: &str) -> Result<(), String> {
    use rand::RngCore;
    let whoiam_url = whoiam_url.trim();
    if whoiam_url.is_empty() {
        return Err("enter your whoiam URL first".into());
    }
    let (base, _) = own_base_and_params().ok_or("no window")?;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = data_encoding::HEXLOWER.encode(&nonce);
    let sep = if whoiam_url.contains('?') { '&' } else { '?' };
    let url = format!(
        "{whoiam_url}{sep}connect=v1&challenge={challenge}&return={}",
        js_sys::encode_uri_component(&base)
    );
    leave_to(&url)
}

/// Mirrors the shell bridge's CONTRACT_PREFIX_RE: `/^\/v[12]\/contract\/web\/[^/]+\//`
/// — the only shape its `navigate` handler will top-navigate to.
#[cfg(target_arch = "wasm32")]
fn is_contract_web_path(path: &str) -> bool {
    ["/v1/contract/web/", "/v2/contract/web/"]
        .iter()
        .filter_map(|p| path.strip_prefix(p))
        .any(|rest| rest.find('/').is_some_and(|i| i > 0))
}

/// Leave the app for `url`, staying in this tab when possible. The sandbox
/// has no allow-top-navigation, but the shell's `navigate` postMessage
/// bridge top-navigates on our behalf — it only accepts same-node
/// contract-app URLs, so anything else goes out via a popup (which escapes
/// the sandbox).
#[cfg(target_arch = "wasm32")]
fn leave_to(url: &str) -> Result<(), String> {
    let win = web_sys::window().ok_or("no window")?;
    // location.origin is "null" in the opaque-origin sandbox; take our real
    // origin from href instead.
    let href = win.location().href().map_err(|_| "no href")?;
    let own = web_sys::Url::new(&href).map_err(|_| "bad href")?;
    let target = web_sys::Url::new_with_base(url, &href).map_err(|_| "bad URL")?;
    if target.origin() != own.origin() || !is_contract_web_path(&target.pathname()) {
        return match win.open_with_url_and_target(url, "_blank") {
            Ok(_) => Ok(()),
            Err(_) => Err("couldn't open whoiam — popup blocker?".into()),
        };
    }
    if own.search_params().get("__sandbox").is_none() {
        // Not wrapped by the shell (dev serve): navigate directly.
        return win.location().assign(url).map_err(|_| "navigation failed".into());
    }
    // ponytail: assumes the node's shell has the navigate bridge (current
    // freenet-core); an older shell silently drops the message.
    let parent = win
        .parent()
        .ok()
        .flatten()
        .ok_or("sandboxed but no parent frame")?;
    let msg = js_sys::Object::new();
    for (k, v) in [
        ("__freenet_shell__", wasm_bindgen::JsValue::TRUE),
        ("type", "navigate".into()),
        ("href", url.into()),
    ] {
        js_sys::Reflect::set(&msg, &k.into(), &v).map_err(|_| "message build failed")?;
    }
    parent
        .post_message(&msg, "*")
        .map_err(|_| "shell bridge unreachable")?;
    Ok(())
}

// ---- views ----

fn short_key(pk: &[u8; 32]) -> String {
    let full = bs58::encode(pk).into_string();
    format!("{}…", full.chars().take(10).collect::<String>())
}

fn identicon_style(pk: &[u8; 32]) -> String {
    let h1 = (((pk[0] as u16) << 8 | pk[1] as u16) % 360) as u16;
    let h2 = (h1 + 40 + (pk[2] % 140) as u16) % 360;
    format!("background: linear-gradient(135deg, hsl({h1},70%,55%), hsl({h2},70%,35%))")
}

fn sniff_mime(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        "image/png"
    }
}

fn avatar_data_url(bytes: &[u8]) -> String {
    use base64::Engine;
    format!(
        "data:{};base64,{}",
        sniff_mime(bytes),
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

fn App() -> Element {
    use_effect(|| {
        #[cfg(target_arch = "wasm32")]
        {
            let mode = decide_mode();
            if let Mode::Verified { pk } = mode.clone() {
                spawn(async move {
                    fetch_profile(pk).await;
                });
            }
            *MODE.write() = Some(mode);
        }
    });

    let mode = MODE.read().clone();
    // Terminal views (verified/denied/failed) offer a way back to the start
    // without leaving the tab; state-only, the callback params stay in the
    // URL and are simply ignored until a reload.
    let show_home = !matches!(mode, None | Some(Mode::Landing));
    let body = match mode {
        None => rsx! { p { class: "muted", "…" } },
        Some(Mode::Landing) => rsx! { Landing {} },
        Some(Mode::Denied) => rsx! {
            div { class: "card center-text",
                h2 { "Declined" }
                p { "You chose not to share a persona. That's all this site ever learns." }
            }
        },
        Some(Mode::Failed(why)) => rsx! {
            div { class: "card center-text",
                h2 { class: "error", "✘ Not verified" }
                p { "{why}" }
            }
        },
        Some(Mode::Verified { pk }) => rsx! { VerifiedView { pk } },
    };

    rsx! {
        style { dangerous_inner_html: include_str!("../../ui/assets/main.css") }
        header { class: "top",
            span { class: "wordmark", "whoiam connect " span { class: "iam", "demo" } }
        }
        main {
            section { class: "wrap narrow-wrap",
                if show_home {
                    button { class: "ghost back",
                        onclick: move |_| {
                            *PROFILE.write() = None;
                            *FETCH_ERROR.write() = None;
                            *MODE.write() = Some(Mode::Landing);
                        },
                        "← home"
                    }
                }
                {body}
            }
        }
        footer { class: "foot", "a pretend app that trusts whoiam personas" }
    }
}

/// Prefill for the whoiam URL: an explicit ?whoiam_url=… link param wins, then
/// a contract id baked in at build time (WHOIAM_SITE_CONTRACT — publish-demo.sh
/// derives it from the publisher's own key store), joined to our own origin
/// so it follows whatever host/port the node is reached through.
#[cfg(target_arch = "wasm32")]
fn default_whoiam_url() -> String {
    // NOT "whoiam" — that's the callback status param (ok/denied), and this
    // runs on callback URLs too after a reset to the landing view.
    if let Some((_, params)) = own_base_and_params() {
        if let Some(u) = params.get("whoiam_url") {
            return u;
        }
    }
    if let (Some(id), Some(href)) = (
        option_env!("WHOIAM_SITE_CONTRACT"),
        web_sys::window().and_then(|w| w.location().href().ok()),
    ) {
        if let Ok(url) = web_sys::Url::new(&href) {
            return format!("{}/v1/contract/web/{id}/", url.origin());
        }
    }
    String::new()
}

#[component]
fn Landing() -> Element {
    let mut whoiam_url = use_signal(|| {
        #[cfg(target_arch = "wasm32")]
        {
            return default_whoiam_url();
        }
        #[allow(unreachable_code)]
        String::new()
    });
    let mut error = use_signal(String::new);
    // A build with the whoiam contract baked in (publish-demo.sh) needs no
    // input — the demo just knows. The field only appears as a fallback.
    let known = !whoiam_url.read().is_empty();

    rsx! {
        div { class: "card",
            h2 { "Link a whoiam persona" }
            p { class: "muted",
                "This pretend app has no accounts of its own. Prove you own a whoiam persona and it will greet you by name — profile fetched straight from the persona's contract, every signature checked."
            }
            if !known {
                label { r#for: "whoiam-url", "Your whoiam URL" }
                input {
                    id: "whoiam-url",
                    placeholder: "http://127.0.0.1:7509/v1/contract/web/…/",
                    value: "{whoiam_url}",
                    oninput: move |e| whoiam_url.set(e.value()),
                }
            }
            div { class: "row",
                button { class: "primary",
                    onclick: move |_| {
                        error.set(String::new());
                        #[cfg(target_arch = "wasm32")]
                        if let Err(e) = start_connect(&whoiam_url.read()) {
                            error.set(e);
                        }
                    },
                    "Connect a persona"
                }
            }
            p { class: "muted",
                "You'll be taken to whoiam; approving there brings you back here with the proof."
            }
            if !error.read().is_empty() { p { class: "error", "{error}" } }
        }
    }
}

#[component]
fn VerifiedView(pk: [u8; 32]) -> Element {
    let state = PROFILE.read().clone();
    let fetch_error = FETCH_ERROR.read().clone();
    let full_key = bs58::encode(&pk).into_string();

    let profile: Option<ProfileV1> = state.as_ref().and_then(|s| {
        let slot = s.slots.get(SLOT_PROFILE)?;
        if slot.bytes.is_empty() {
            return None;
        }
        whoiam_core::from_cbor(&slot.bytes).ok()
    });
    let avatar: Option<Vec<u8>> = state.as_ref().and_then(|s| {
        let slot = s.slots.get(SLOT_AVATAR)?;
        if slot.bytes.is_empty() {
            return None;
        }
        whoiam_core::resources::check_avatar_bytes(&slot.bytes).ok()?;
        Some(slot.bytes.clone())
    });
    let destroyed = state.as_ref().is_some_and(|s| s.destroyed.is_some());
    let name = profile.as_ref().map(|p| p.name.clone()).unwrap_or_default();
    let bio = profile.as_ref().map(|p| p.bio.clone()).unwrap_or_default();
    let display = if name.is_empty() { short_key(&pk) } else { name.clone() };

    rsx! {
        div { class: "card",
            h2 { class: "ok", "✔ Persona verified" }
            p { class: "muted",
                "The signature proves the owner of this key consented to identify to this app, just now. Profile below is loaded from the persona's contract on Freenet."
            }
        }
        if destroyed {
            div { class: "card center-text",
                p { class: "error", "This persona has been destroyed by its owner." }
            }
        } else if let Some(_) = state {
            div { class: "card",
                div { class: "id-head lg",
                    match avatar {
                        Some(bytes) => rsx! { img { class: "avatar lg", src: avatar_data_url(&bytes), alt: "" } },
                        None => rsx! { span { class: "avatar lg", style: identicon_style(&pk) } },
                    }
                    div { class: "id-title",
                        h2 { "Welcome, {display}" }
                        code { class: "muted small", "{short_key(&pk)}" }
                    }
                }
                if !bio.is_empty() { p { class: "bio", "{bio}" } }
                if profile.is_none() { p { class: "muted", "No profile published yet — just a proven key." } }
            }
        } else if let Some(e) = fetch_error {
            div { class: "card", p { class: "error", "{e}" } }
        } else {
            div { class: "card center-text",
                div { class: "spinner" }
                p { class: "muted", "Loading the persona's profile from Freenet…" }
            }
        }
        div { class: "card",
            label { "Proven public key" }
            div { class: "keyrow", code { "{full_key}" } }
            p { class: "muted",
                "A real app would now attach this key to its own account record. Remembering the one-time challenge across the bounce is the app's job — server-side, or in its delegate."
            }
        }
    }
}

fn main() {
    dioxus::launch(App);
}
