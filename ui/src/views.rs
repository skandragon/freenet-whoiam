//! UI components. One file — the phase-1 surface is small.

use dioxus::prelude::*;
use whoiam_core::resources::{ProfileV1, MAX_AVATAR_BYTES, MAX_BIO_CHARS, MAX_NAME_CHARS, SLOT_AVATAR, SLOT_PROFILE};

use crate::actions;
use crate::api;
use crate::state::*;

const KEY_STORE_TIMEOUT_MS: u32 = 12_000;

pub fn short_key(pk: &[u8; 32]) -> String {
    let full = bs58::encode(pk).into_string();
    format!("{}…", full.chars().take(10).collect::<String>())
}

fn full_key(pk: &[u8; 32]) -> String {
    bs58::encode(pk).into_string()
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

/// This identity's published state, if it has arrived.
fn published(index: u32) -> Option<whoiam_core::state::IdentityStateV1> {
    let pk = actions::identity_pubkey(index)?;
    IDENTITY_STATES.read().get(&pk.to_bytes())?.clone()
}

fn published_profile(index: u32) -> Option<ProfileV1> {
    let state = published(index)?;
    let slot = state.slots.get(SLOT_PROFILE)?;
    if slot.bytes.is_empty() {
        return None;
    }
    whoiam_core::from_cbor(&slot.bytes).ok()
}

fn published_avatar(index: u32) -> Option<Vec<u8>> {
    let state = published(index)?;
    let slot = state.slots.get(SLOT_AVATAR)?;
    if slot.bytes.is_empty() {
        return None;
    }
    // Signed ≠ well-formed: schema-check before the bytes reach an <img>.
    whoiam_core::resources::check_avatar_bytes(&slot.bytes).ok()?;
    Some(slot.bytes.clone())
}

fn avatar_data_url(bytes: &[u8]) -> String {
    use base64::Engine;
    format!(
        "data:{};base64,{}",
        sniff_mime(bytes),
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

/// Parse a `?connect=v1&challenge=…&return=…` bounce-through request from
/// the iframe URL (the shell forwards external query params through).
/// Trust boundary: a malformed request is logged and ignored — the app just
/// boots normally.
#[cfg(target_arch = "wasm32")]
fn connect_request_from_location() -> Option<ConnectRequest> {
    let search = web_sys::window()?.location().search().ok()?;
    let params = web_sys::UrlSearchParams::new_with_str(&search).ok()?;
    if params.get("connect")? != "v1" {
        api::log("connect request ignored: unknown version");
        return None;
    }
    let challenge = params.get("challenge")?;
    let return_url = params.get("return")?;
    if !actions::valid_challenge(&challenge) {
        api::log("connect request ignored: bad challenge");
        return None;
    }
    // Absolute http(s) URL, no fragment (a fragment would swallow the
    // params we append).
    let Ok(url) = web_sys::Url::new(&return_url) else {
        api::log("connect request ignored: unparseable return URL");
        return None;
    };
    if !matches!(url.protocol().as_str(), "http:" | "https:") || !url.hash().is_empty() {
        api::log("connect request ignored: return URL must be http(s) with no fragment");
        return None;
    }
    Some(ConnectRequest {
        origin: url.origin(),
        return_base: format!("{}{}", url.origin(), url.pathname()),
        return_url,
        challenge,
    })
}

/// Mirrors the shell bridge's CONTRACT_PREFIX_RE: `/^\/v[12]\/contract\/web\/[^/]+\//`
/// — the only shape its `navigate` handler will top-navigate to.
fn is_contract_web_path(path: &str) -> bool {
    ["/v1/contract/web/", "/v2/contract/web/"]
        .iter()
        .filter_map(|p| path.strip_prefix(p))
        .any(|rest| rest.find('/').is_some_and(|i| i > 0))
}

/// Leave the app for `url`, staying in this tab when possible. The sandbox
/// has no allow-top-navigation, but the shell's `navigate` postMessage
/// bridge top-navigates on our behalf — it only accepts same-node
/// contract-app URLs, so anything else still goes out via a popup (which
/// escapes the sandbox). Returns true if navigation happens in this tab.
#[cfg(target_arch = "wasm32")]
fn leave_to(url: &str) -> Result<bool, String> {
    let win = web_sys::window().ok_or("no window")?;
    // location.origin is "null" in the opaque-origin sandbox; take our real
    // origin from href instead.
    let href = win.location().href().map_err(|_| "no href")?;
    let own = web_sys::Url::new(&href).map_err(|_| "bad href")?;
    let target = web_sys::Url::new_with_base(url, &href).map_err(|_| "bad URL")?;
    if target.origin() != own.origin() || !is_contract_web_path(&target.pathname()) {
        return open_tab(url).map(|()| false);
    }
    if own.search_params().get("__sandbox").is_none() {
        // Not wrapped by the shell (dev serve): navigate directly.
        return win
            .location()
            .assign(url)
            .map(|()| true)
            .map_err(|_| "navigation failed".into());
    }
    // ponytail: assumes the node's shell has the navigate bridge (current
    // freenet-core); an older shell silently drops the message. Add a
    // timeout fallback to open_tab if old nodes matter.
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
    Ok(true)
}

#[cfg(not(target_arch = "wasm32"))]
fn leave_to(_url: &str) -> Result<bool, String> {
    Err("unavailable".into())
}

#[cfg(test)]
mod leave_tests {
    #[test]
    fn contract_web_path_shape() {
        for ok in ["/v1/contract/web/KEY/", "/v2/contract/web/KEY/index.html"] {
            assert!(super::is_contract_web_path(ok), "{ok}");
        }
        for bad in ["/v1/contract/web/KEY", "/v1/contract/web//x", "/v1/node/KEY/", "/v3/contract/web/KEY/"] {
            assert!(!super::is_contract_web_path(bad), "{bad}");
        }
    }
}

/// New-tab fallback for callbacks the shell won't navigate to (foreign
/// origins) — a popup escapes the sandbox.
#[cfg(target_arch = "wasm32")]
fn open_tab(url: &str) -> Result<(), String> {
    // `noopener` makes window.open return null even on success, so a None
    // here is NOT a popup-blocker signal — only a thrown error is.
    match web_sys::window()
        .ok_or("no window")?
        .open_with_url_and_target_and_features(url, "_blank", "noopener,noreferrer")
    {
        Ok(_) => Ok(()),
        Err(_) => Err("couldn't open the return tab — is a popup blocker interfering?".into()),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn open_tab(_url: &str) -> Result<(), String> {
    Err("unavailable".into())
}

#[cfg(target_arch = "wasm32")]
async fn copy_to_clipboard(text: String) -> Result<(), String> {
    let nav = web_sys::window().ok_or("no window")?.navigator();
    wasm_bindgen_futures::JsFuture::from(nav.clipboard().write_text(&text))
        .await
        .map(|_| ())
        .map_err(|_| "clipboard write failed".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn copy_to_clipboard(_text: String) -> Result<(), String> {
    Err("clipboard unavailable".to_string())
}

#[component]
fn CopyButton(text: String, label: String) -> Element {
    let mut state = use_signal(|| None::<bool>);
    rsx! {
        button { class: "ghost",
            onclick: move |_| {
                let value = text.clone();
                spawn(async move {
                    let ok = copy_to_clipboard(value).await.is_ok();
                    state.set(Some(ok));
                    crate::sleep_ms(1500).await;
                    state.set(None);
                });
            },
            match *state.read() {
                Some(true) => "copied ✓".to_string(),
                Some(false) => "copy failed".to_string(),
                None => label.clone(),
            }
        }
    }
}

/// Center-crop square, downscale, re-encode PNG, shrinking until it fits
/// the avatar slot cap (photos at 512px PNG can exceed it).
#[cfg(target_arch = "wasm32")]
async fn shrink_to_avatar(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    use base64::Engine;
    use wasm_bindgen::JsCast;
    let b64 = &base64::engine::general_purpose::STANDARD;
    let document = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("no document")?;
    let img: web_sys::HtmlImageElement = document
        .create_element("img")
        .map_err(|_| "create img")?
        .dyn_into()
        .map_err(|_| "img cast")?;
    // Browsers sniff the container from the bytes, so one generic-mime
    // decode attempt suffices: if it fails, it isn't an image.
    img.set_src(&format!("data:image/png;base64,{}", b64.encode(&bytes)));
    if wasm_bindgen_futures::JsFuture::from(img.decode()).await.is_err() {
        return Err("that file doesn't decode as an image".into());
    }
    let (w, h) = (img.natural_width(), img.natural_height());
    if w == 0 || h == 0 {
        return Err("empty image".into());
    }
    let side = w.min(h);
    // Descend from the schema's max dimension until the PNG fits the byte
    // cap (photos at 512² routinely exceed it); never below the schema min.
    use whoiam_core::resources::{MAX_AVATAR_DIM, MIN_AVATAR_DIM};
    for out in [MAX_AVATAR_DIM, 384, 256, 192, 128, 96, MIN_AVATAR_DIM] {
        let out = out.min(side.max(MIN_AVATAR_DIM));
        let canvas: web_sys::HtmlCanvasElement = document
            .create_element("canvas")
            .map_err(|_| "create canvas")?
            .dyn_into()
            .map_err(|_| "canvas cast")?;
        canvas.set_width(out);
        canvas.set_height(out);
        let ctx: web_sys::CanvasRenderingContext2d = canvas
            .get_context("2d")
            .ok()
            .flatten()
            .ok_or("no 2d context")?
            .dyn_into()
            .map_err(|_| "context cast")?;
        ctx.draw_image_with_html_image_element_and_sw_and_sh_and_dx_and_dy_and_dw_and_dh(
            &img,
            ((w - side) / 2) as f64,
            ((h - side) / 2) as f64,
            side as f64,
            side as f64,
            0.0,
            0.0,
            out as f64,
            out as f64,
        )
        .map_err(|_| "draw failed")?;
        let url = canvas.to_data_url_with_type("image/png").map_err(|_| "encode failed")?;
        let data = b64
            .decode(url.strip_prefix("data:image/png;base64,").ok_or("unexpected canvas output")?)
            .map_err(|e| format!("decode canvas output: {e}"))?;
        if data.len() <= MAX_AVATAR_BYTES {
            return Ok(data);
        }
    }
    Err("image too large even at 64×64 — try a simpler image".into())
}

#[cfg(not(target_arch = "wasm32"))]
async fn shrink_to_avatar(_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    Err("image processing unavailable".into())
}

// ---- screens ----

pub fn App() -> Element {
    use_effect(|| {
        spawn(async {
            #[cfg(target_arch = "wasm32")]
            {
                if let Some(req) = connect_request_from_location() {
                    *CONNECT.write() = Some(req);
                }
                if let Err(e) = api::connect().await {
                    *SYNC_STATUS.write() = SyncStatus::Error(e);
                    return;
                }
                while *SYNC_STATUS.read() == SyncStatus::Connecting {
                    crate::sleep_ms(100).await;
                }
                match api::register_delegate() {
                    r => match r.await {
                        Ok(()) => api::log("sent RegisterDelegate"),
                        Err(e) => api::log(&format!("delegate registration failed: {e}")),
                    },
                }
                use whoiam_core::delegate_api::{WhoiamDelegateRequest, KEY_META, KEY_SEED};
                for key in [KEY_SEED, KEY_META] {
                    if let Err(e) = api::kv_request(WhoiamDelegateRequest::Get { key: key.into() }).await {
                        api::log(&format!("{key} get failed: {e}"));
                    }
                }
                // Watchdog: a swallowed delegate error means the seed OR
                // meta answer never arrives — flip to an explanatory
                // screen, not an eternal spinner. (Both Gets go out
                // together; either can be the one the node swallows.)
                spawn(async {
                    crate::sleep_ms(KEY_STORE_TIMEOUT_MS).await;
                    if SEED_LOADED.peek().is_none() || !*META_LOADED.peek() {
                        api::log("seed/meta answer never arrived — key store unreachable");
                        *KEY_STORE_UNREACHABLE.write() = true;
                    }
                });
            }
        });
    });

    // Once the seed and meta are both in, pull every persona's contract.
    use_effect(move || {
        let ready = seed().is_some() && *META_LOADED.read();
        if ready {
            spawn(async {
                actions::fetch_all_identities().await;
            });
        }
    });

    // Unreachable wins whenever the boot answers are incomplete — a loaded
    // seed with swallowed meta must not spin forever on "Loading…".
    let boot_complete = seed().is_some() && *META_LOADED.read();
    let body = if *KEY_STORE_UNREACHABLE.read() && !boot_complete {
        rsx! { Unreachable {} }
    } else {
        match SEED_LOADED.read().clone() {
            None => rsx! { Loading { message: "Reaching your key store…" } },
            Some(None) => rsx! { Onboarding {} },
            Some(Some(_)) if !*META_LOADED.read() => {
                rsx! { Loading { message: "Loading your personas…" } }
            }
            Some(Some(_)) if CONNECT.read().is_some() => rsx! { ConnectView {} },
            Some(Some(_)) => match *VIEW.read() {
                View::Home => rsx! { Home {} },
                View::Identity(index) => rsx! { Detail { index } },
                View::Backup => rsx! { BackupView {} },
            },
        }
    };

    rsx! {
        // Inlined: the site is served under /v1/contract/web/<id>/ with no
        // server-side routing, so linked asset paths 404 (freebird pattern).
        style { dangerous_inner_html: include_str!("../assets/main.css") }
        header { class: "top",
            button { class: "wordmark", onclick: move |_| *VIEW.write() = View::Home,
                span { class: "who", "who" }
                span { class: "iam", "iam" }
            }
            StatusDot {}
        }
        main { {body} }
        footer { class: "foot",
            "your persona, everywhere · "
            button { onclick: move |_| *VIEW.write() = View::Backup, "backup" }
            " · "
            a { href: "https://github.com/skandragon/freenet-whoiam", target: "_blank", "source" }
        }
    }
}

#[component]
fn StatusDot() -> Element {
    let (class, title) = match &*SYNC_STATUS.read() {
        SyncStatus::Connecting => ("dot connecting", "connecting to your node".to_string()),
        SyncStatus::Connected => ("dot ok", "connected to your node".to_string()),
        SyncStatus::Error(e) => ("dot err", e.clone()),
    };
    rsx! { span { class: class, title: title } }
}

#[component]
fn Loading(message: String) -> Element {
    rsx! {
        section { class: "center",
            div { class: "spinner" }
            p { class: "muted", "{message}" }
        }
    }
}

#[component]
fn Unreachable() -> Element {
    rsx! {
        section { class: "center",
            div { class: "card narrow",
                h2 { "Key store unreachable" }
                p { "Your node didn't answer the request for your master seed. This usually means the delegate hit an error the node swallowed." }
                p { class: "muted", "Reloading the page usually fixes it. Your keys are safe — nothing is lost." }
                button { class: "primary",
                    onclick: move |_| {
                        #[cfg(target_arch = "wasm32")]
                        if let Some(w) = web_sys::window() { let _ = w.location().reload(); }
                    },
                    "Reload"
                }
            }
        }
    }
}

#[component]
fn Onboarding() -> Element {
    let mut restoring = use_signal(|| false);
    let mut backup_input = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);

    rsx! {
        section { class: "hero",
            h1 {
                "One persona. "
                span { class: "grad", "Every app." }
            }
            p { class: "sub",
                "whoiam keeps your avatar, name, and bio in one place on Freenet. Apps that know you pull them from here — update once, it updates everywhere. No account, no server, no tracking. Just a key that's yours."
            }
            if !*restoring.read() {
                div { class: "hero-actions",
                    button { class: "primary big", disabled: *busy.read(),
                        onclick: move |_| {
                            busy.set(true);
                            error.set(String::new());
                            spawn(async move {
                                if let Err(e) = actions::create_seed().await {
                                    error.set(e);
                                }
                                busy.set(false);
                            });
                        },
                        if *busy.read() { "Creating your key…" } else { "Get started" }
                    }
                    button { class: "ghost", onclick: move |_| restoring.set(true),
                        "I have a backup"
                    }
                }
            } else {
                div { class: "card narrow left",
                    h3 { "Restore from backup" }
                    p { class: "muted", "Paste your 24-word recovery phrase or the 64-character hex seed." }
                    textarea {
                        rows: 3,
                        placeholder: "witch collapse practice feed shame open despair…",
                        value: "{backup_input}",
                        oninput: move |e| backup_input.set(e.value()),
                    }
                    div { class: "row",
                        button { class: "primary", disabled: *busy.read(),
                            onclick: move |_| {
                                busy.set(true);
                                error.set(String::new());
                                spawn(async move {
                                    if let Err(e) = actions::restore_seed(backup_input.read().clone()).await {
                                        error.set(e);
                                    }
                                    busy.set(false);
                                });
                            },
                            if *busy.read() { "Searching the network…" } else { "Restore" }
                        }
                        button { class: "ghost", onclick: move |_| restoring.set(false), "Back" }
                    }
                    if *busy.read() { p { class: "muted", "Probing your persona addresses — this takes about ten seconds." } }
                }
            }
            if !error.read().is_empty() { p { class: "error", "{error}" } }
        }
    }
}

#[component]
fn Home() -> Element {
    let mut new_label = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let entries = META.read().identities.clone();

    rsx! {
        section { class: "wrap",
            if entries.is_empty() {
                div { class: "card narrow center-text",
                    h2 { "Your key is ready" }
                    p { class: "muted", "Create your first persona — a public page other Freenet apps can read your avatar and profile from. You can make more than one; they're not linkable to each other." }
                }
            }
            div { class: "grid",
                for entry in entries {
                    IdentityCard { index: entry.index, label: entry.label.clone() }
                }
                div { class: "card new-card",
                    h3 { "New persona" }
                    input {
                        placeholder: "label (only you see this)",
                        value: "{new_label}",
                        oninput: move |e| new_label.set(e.value()),
                    }
                    button { class: "primary", disabled: *busy.read(),
                        onclick: move |_| {
                            busy.set(true);
                            error.set(String::new());
                            spawn(async move {
                                let label = new_label.read().clone();
                                match actions::create_identity(label).await {
                                    Ok(index) => {
                                        new_label.set(String::new());
                                        *VIEW.write() = View::Identity(index);
                                    }
                                    Err(e) => error.set(e),
                                }
                                busy.set(false);
                            });
                        },
                        if *busy.read() { "Creating…" } else { "Create" }
                    }
                    if !error.read().is_empty() { p { class: "error", "{error}" } }
                }
            }
        }
    }
}

/// Bounce-through persona picker: an external site asked who the user is.
/// Approve signs a connect proof with the chosen persona's key and returns
/// to the callback (same tab for same-node apps, new tab otherwise);
/// refuse returns with `whoiam=denied`.
#[component]
fn ConnectView() -> Element {
    let Some(req) = CONNECT.read().clone() else {
        return rsx! {};
    };
    let entries = META.read().identities.clone();
    let mut sent = use_signal(|| None::<(String, bool)>);
    let mut error = use_signal(String::new);
    let origin = req.origin.clone();
    let deny_req = req.clone();

    if let Some((msg, in_tab)) = sent.read().clone() {
        let hint = if in_tab { "Taking you back to the site…" } else { "You can close this tab now." };
        return rsx! {
            section { class: "wrap narrow-wrap",
                div { class: "card center-text",
                    h2 { "{msg}" }
                    p { class: "muted", "{hint}" }
                    button { class: "ghost", onclick: move |_| *CONNECT.write() = None, "back to whoiam" }
                }
            }
        };
    }

    rsx! {
        section { class: "wrap narrow-wrap",
            div { class: "card",
                h2 { "Share a persona?" }
                p {
                    strong { "{origin}" }
                    " wants to know who you are."
                }
                p { class: "muted",
                    "Sharing sends a signed proof that you own the persona. The site learns its public key (and can read its public profile) — nothing else."
                }
            }
            if entries.is_empty() {
                div { class: "card center-text",
                    p { class: "muted", "You don't have any personas yet. Set one up first, then start over from the site." }
                    button { class: "ghost", onclick: move |_| *CONNECT.write() = None, "open whoiam" }
                }
            }
            div { class: "grid",
                for entry in entries {
                    ConnectCard {
                        index: entry.index,
                        label: entry.label.clone(),
                        req: req.clone(),
                        on_done: move |result: Result<(String, bool), String>| match result {
                            Ok(msg) => sent.set(Some(msg)),
                            Err(e) => error.set(e),
                        },
                    }
                }
            }
            div { class: "row",
                button { class: "ghost",
                    onclick: move |_| {
                        match leave_to(&actions::connect_denied_url(&deny_req)) {
                            Ok(in_tab) => sent.set(Some(("Declined".into(), in_tab))),
                            Err(e) => error.set(e),
                        }
                    },
                    "Don't share"
                }
            }
            if !error.read().is_empty() { p { class: "error", "{error}" } }
        }
    }
}

#[component]
fn ConnectCard(
    index: u32,
    label: String,
    req: ConnectRequest,
    on_done: EventHandler<Result<(String, bool), String>>,
) -> Element {
    let Some(pk) = actions::identity_pubkey(index) else {
        return rsx! {};
    };
    let pkb = pk.to_bytes();
    let profile = published_profile(index);
    let avatar = published_avatar(index);
    let display = profile
        .as_ref()
        .map(|p| p.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| label.clone());

    rsx! {
        button { class: "card id-card",
            onclick: move |_| {
                // Sign at click time so the timestamp is fresh; the click on
                // this card IS the consent.
                let result = actions::connect_ok_url(index, &req, crate::keys::now_ms())
                    .and_then(|url| leave_to(&url))
                    .map(|in_tab| (format!("Shared as “{display}”"), in_tab));
                on_done.call(result);
            },
            div { class: "id-head",
                match avatar {
                    Some(bytes) => rsx! { img { class: "avatar", src: avatar_data_url(&bytes), alt: "" } },
                    None => rsx! { span { class: "avatar", style: identicon_style(&pkb) } },
                }
                div {
                    h3 { "{label}" }
                    code { class: "muted", "{short_key(&pkb)}" }
                }
            }
        }
    }
}

#[component]
fn BackupView() -> Element {
    rsx! {
        section { class: "wrap narrow-wrap",
            button { class: "ghost back", onclick: move |_| *VIEW.write() = View::Home, "← all personas" }
            BackupCard {}
        }
    }
}

#[component]
fn IdentityCard(index: u32, label: String) -> Element {
    let Some(pk) = actions::identity_pubkey(index) else {
        return rsx! {};
    };
    let pkb = pk.to_bytes();
    let profile = published_profile(index);
    let avatar = published_avatar(index);
    let display = profile
        .as_ref()
        .map(|p| p.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| label.clone());
    let bio = profile.map(|p| p.bio).unwrap_or_default();

    rsx! {
        button { class: "card id-card", onclick: move |_| *VIEW.write() = View::Identity(index),
            div { class: "id-head",
                match avatar {
                    Some(bytes) => rsx! { img { class: "avatar", src: avatar_data_url(&bytes), alt: "" } },
                    None => rsx! { span { class: "avatar", style: identicon_style(&pkb) } },
                }
                div {
                    h3 { "{display}" }
                    code { class: "muted", "{short_key(&pkb)}" }
                }
            }
            if !bio.is_empty() { p { class: "bio", "{bio}" } }
        }
    }
}

#[component]
fn BackupCard() -> Element {
    // The host page's CSP (frame-src 'self') blocks blob:/data: downloads
    // from this sandboxed iframe, so a file download is impossible here —
    // reveal the backup text and let the user copy/save it themselves.
    let mut error = use_signal(String::new);
    let mut revealed = use_signal(|| None::<String>);
    rsx! {
        div { class: "card backup",
            div {
                h3 { "Back up your master seed" }
                p { class: "muted",
                    "One backup covers every persona — even ones you create later. Anyone holding it controls them all, so store it somewhere safe."
                }
            }
            match revealed.read().clone() {
                None => rsx! {
                    div { class: "row",
                        button { class: "primary",
                            onclick: move |_| {
                                match actions::backup_text() {
                                    Ok(t) => revealed.set(Some(t)),
                                    Err(e) => error.set(e),
                                }
                            },
                            "Show backup"
                        }
                    }
                },
                Some(text) => rsx! {
                    textarea { class: "backup-text", readonly: true, rows: 10, value: "{text}" }
                    div { class: "row",
                        CopyButton { text: text.clone(), label: "copy".to_string() }
                        button { class: "ghost", onclick: move |_| revealed.set(None), "hide" }
                    }
                },
            }
            if !error.read().is_empty() { p { class: "error", "{error}" } }
        }
    }
}

#[component]
fn Detail(index: u32) -> Element {
    let Some(pk) = actions::identity_pubkey(index) else {
        return rsx! { Loading { message: "Deriving key…" } };
    };
    let pkb = pk.to_bytes();
    let entry_label = META
        .read()
        .identities
        .iter()
        .find(|e| e.index == index)
        .map(|e| e.label.clone())
        .unwrap_or_default();

    // Has the state ARRIVED (vs requested/pending)? "No profile yet" and
    // "state not here yet" must not be conflated: seeding the edit form from
    // a pending state would let Publish LWW-overwrite the real profile.
    let arrived = published(index).is_some();
    let profile = published_profile(index);
    let avatar = published_avatar(index);

    let mut name = use_signal(String::new);
    let mut bio = use_signal(String::new);
    let mut form_seeded = use_signal(|| false);
    // Seed the form only once the state has ARRIVED: seeding blank while
    // the fetch is pending would let Publish LWW-erase the live profile.
    if arrived && !*form_seeded.read() {
        if let Some(p) = &profile {
            name.set(p.name.clone());
            bio.set(p.bio.clone());
        }
        form_seeded.set(true);
    }

    let mut editing = use_signal(|| false);
    let mut save_busy = use_signal(|| false);
    let mut save_msg = use_signal(String::new);
    let mut save_err = use_signal(String::new);
    let mut pic_busy = use_signal(|| false);
    let mut pic_err = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut destroy_busy = use_signal(|| false);
    let mut destroy_err = use_signal(String::new);

    // After every hook (Dioxus hook order must not vary between renders):
    // wait for the contract state before showing editable surfaces.
    if !arrived {
        return rsx! {
            section { class: "wrap narrow-wrap",
                button { class: "ghost back", onclick: move |_| *VIEW.write() = View::Home, "← all personas" }
                Loading { message: "Fetching this persona from the network…" }
            }
        };
    }

    let addr = full_key(&pkb);
    let contract_id = crate::keys::identity_key(&pk).id().to_string();

    let pub_name = profile.as_ref().map(|p| p.name.clone()).unwrap_or_default();
    let pub_bio = profile.as_ref().map(|p| p.bio.clone()).unwrap_or_default();
    // save_profile trims before publishing, so compare trimmed.
    let dirty = name.read().trim() != pub_name || bio.read().trim() != pub_bio;
    let show_name = if pub_name.is_empty() { "—".to_string() } else { pub_name.clone() };
    let show_bio = if pub_bio.is_empty() { "—".to_string() } else { pub_bio.clone() };

    rsx! {
        section { class: "wrap narrow-wrap",
            button { class: "ghost back", onclick: move |_| *VIEW.write() = View::Home, "← all personas" }

            div { class: "card",
                div { class: "id-head lg",
                    match avatar.clone() {
                        Some(bytes) => rsx! { img { class: "avatar lg", src: avatar_data_url(&bytes), alt: "" } },
                        None => rsx! { span { class: "avatar lg", style: identicon_style(&pkb) } },
                    }
                    div { class: "id-title",
                        h2 { "{entry_label}" }
                        code { class: "muted small", "{short_key(&pkb)}" }
                    }
                }
                p { class: "muted", "Profile picture — auto-cropped square, published as PNG:" }
                div { class: "row",
                    // Hidden input; the label below is the visible control.
                    input {
                        id: "avatar-file",
                        r#type: "file",
                        style: "display:none",
                        accept: "image/png,image/jpeg,image/webp,image/gif",
                        disabled: *pic_busy.read(),
                        onchange: move |e| {
                            let Some(file) = e.files().into_iter().next() else { return };
                            pic_err.set(String::new());
                            pic_busy.set(true);
                            spawn(async move {
                                let result = async {
                                    let bytes = file.read_bytes().await.map_err(|e| format!("read failed: {e}"))?;
                                    let png = shrink_to_avatar(bytes.to_vec()).await?;
                                    actions::publish_avatar(index, png).await
                                }
                                .await;
                                if let Err(e) = result { pic_err.set(e); }
                                pic_busy.set(false);
                            });
                        },
                    }
                    label { class: "ghost", r#for: "avatar-file",
                        if avatar.is_some() { "change" } else { "choose file" }
                    }
                    if avatar.is_some() {
                        button { class: "ghost", disabled: *pic_busy.read(),
                            onclick: move |_| {
                                pic_busy.set(true);
                                spawn(async move {
                                    if let Err(e) = actions::remove_avatar(index).await { pic_err.set(e); }
                                    pic_busy.set(false);
                                });
                            },
                            "remove"
                        }
                    }
                }
                if *pic_busy.read() { p { class: "muted", "Publishing picture…" } }
                if !pic_err.read().is_empty() { p { class: "error", "{pic_err}" } }
            }

            div { class: "card",
                h3 { "Public profile" }
                if *editing.read() {
                    label { "Name" }
                    input {
                        value: "{name}",
                        maxlength: "{MAX_NAME_CHARS}",
                        placeholder: "shown in apps",
                        oninput: move |e| name.set(e.value()),
                    }
                    label { "Bio" }
                    textarea {
                        rows: 3,
                        value: "{bio}",
                        maxlength: "{MAX_BIO_CHARS}",
                        placeholder: "a line about you ({MAX_BIO_CHARS} chars max)",
                        oninput: move |e| bio.set(e.value()),
                    }
                    div { class: "row",
                        if dirty {
                            button { class: "primary", disabled: *save_busy.read(),
                                onclick: move |_| {
                                    save_busy.set(true);
                                    save_err.set(String::new());
                                    save_msg.set(String::new());
                                    spawn(async move {
                                        match actions::save_profile(index, name.read().clone(), bio.read().clone()).await {
                                            Ok(()) => {
                                                editing.set(false);
                                                save_msg.set("published ✓".into());
                                                spawn(async move { crate::sleep_ms(2500).await; save_msg.set(String::new()); });
                                            }
                                            Err(e) => save_err.set(e),
                                        }
                                        save_busy.set(false);
                                    });
                                },
                                if *save_busy.read() { "Publishing…" } else { "Publish" }
                            }
                        }
                        button { class: "ghost", disabled: *save_busy.read(),
                            onclick: move |_| {
                                name.set(pub_name.clone());
                                bio.set(pub_bio.clone());
                                editing.set(false);
                            },
                            "cancel"
                        }
                    }
                } else {
                    label { "Name" }
                    p { "{show_name}" }
                    label { "Bio" }
                    p { "{show_bio}" }
                    div { class: "row",
                        button { class: "ghost", onclick: move |_| editing.set(true), "change" }
                        if !save_msg.read().is_empty() { span { class: "ok", "{save_msg}" } }
                    }
                }
                if !save_err.read().is_empty() { p { class: "error", "{save_err}" } }
            }

            div { class: "card",
                h3 { "Share with apps" }
                p { class: "muted", "Apps fetch this persona with your public key (they derive the contract from it):" }
                label { "Public key" }
                div { class: "keyrow" ,
                    code { "{addr}" }
                    CopyButton { text: addr.clone(), label: "copy".to_string() }
                }
                label { "Contract" }
                div { class: "keyrow",
                    code { "{contract_id}" }
                    CopyButton { text: contract_id.clone(), label: "copy".to_string() }
                }
            }

            details { class: "card danger",
                summary { h3 { "Danger zone" } }
                p { class: "muted",
                    "Destroying publishes a signed, permanent “this persona is gone” marker, then forgets the key material. Apps that check will stop showing you. This cannot be undone."
                }
                label { "Type the label (“{entry_label}”) to confirm" }
                input {
                    value: "{confirm}",
                    placeholder: "{entry_label}",
                    oninput: move |e| confirm.set(e.value()),
                }
                button { class: "destructive",
                    disabled: *destroy_busy.read() || confirm.read().trim() != entry_label,
                    onclick: move |_| {
                        destroy_busy.set(true);
                        destroy_err.set(String::new());
                        spawn(async move {
                            if let Err(e) = actions::destroy_identity(index).await {
                                destroy_err.set(e);
                            }
                            destroy_busy.set(false);
                        });
                    },
                    if *destroy_busy.read() { "Destroying…" } else { "Destroy this persona forever" }
                }
                if !destroy_err.read().is_empty() { p { class: "error", "{destroy_err}" } }
            }
        }
    }
}

