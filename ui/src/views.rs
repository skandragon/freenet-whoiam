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
    (!slot.bytes.is_empty()).then(|| slot.bytes.clone())
}

fn avatar_data_url(bytes: &[u8]) -> String {
    use base64::Engine;
    format!(
        "data:{};base64,{}",
        sniff_mime(bytes),
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
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
    // Browsers sniff the container from the bytes; a generic mime is fine.
    img.set_src(&format!("data:image/png;base64,{}", b64.encode(&bytes)));
    if wasm_bindgen_futures::JsFuture::from(img.decode()).await.is_err() {
        // Retry as jpeg-ish data; most browsers already sniffed, so a second
        // failure means it's not an image at all.
        return Err("that file doesn't decode as an image".into());
    }
    let (w, h) = (img.natural_width(), img.natural_height());
    if w == 0 || h == 0 {
        return Err("empty image".into());
    }
    let side = w.min(h);
    for out in [512u32, 384, 256, 192, 128, 96, 64] {
        let out = out.min(side.max(64));
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

/// Save `text` as a downloaded file.
#[cfg(target_arch = "wasm32")]
fn download_text(filename: &str, text: &str) -> Result<(), String> {
    use wasm_bindgen::JsCast;
    let document = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("no document")?;
    let array = js_sys::Array::new();
    array.push(&wasm_bindgen::JsValue::from_str(text));
    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type("text/plain");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&array, &opts)
        .map_err(|_| "blob create failed")?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(|_| "object url failed")?;
    let a: web_sys::HtmlAnchorElement = document
        .create_element("a")
        .map_err(|_| "create anchor")?
        .dyn_into()
        .map_err(|_| "anchor cast")?;
    a.set_href(&url);
    a.set_download(filename);
    a.click();
    let _ = web_sys::Url::revoke_object_url(&url);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn download_text(_filename: &str, _text: &str) -> Result<(), String> {
    Err("download unavailable".into())
}

// ---- screens ----

pub fn App() -> Element {
    use_effect(|| {
        spawn(async {
            #[cfg(target_arch = "wasm32")]
            {
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
                // Watchdog: a swallowed delegate error means the seed answer
                // never arrives — flip to an explanatory screen, not an
                // eternal spinner.
                spawn(async {
                    crate::sleep_ms(KEY_STORE_TIMEOUT_MS).await;
                    if SEED_LOADED.peek().is_none() {
                        api::log("seed answer never arrived — key store unreachable");
                        *KEY_STORE_UNREACHABLE.write() = true;
                    }
                });
            }
        });
    });

    // Once the seed and meta are both in, pull every identity's contract.
    use_effect(move || {
        let ready = seed().is_some() && *META_LOADED.read();
        if ready {
            spawn(async {
                actions::fetch_all_identities().await;
            });
        }
    });

    let body = if *KEY_STORE_UNREACHABLE.read() && seed().is_none() {
        rsx! { Unreachable {} }
    } else {
        match SEED_LOADED.read().clone() {
            None => rsx! { Loading { message: "Reaching your key store…" } },
            Some(None) => rsx! { Onboarding {} },
            Some(Some(_)) if !*META_LOADED.read() => {
                rsx! { Loading { message: "Loading your identities…" } }
            }
            Some(Some(_)) => match *VIEW.read() {
                View::Home => rsx! { Home {} },
                View::Identity(index) => rsx! { Detail { index } },
            },
        }
    };

    rsx! {
        document::Stylesheet { href: asset!("/assets/main.css") }
        header { class: "top",
            button { class: "wordmark", onclick: move |_| *VIEW.write() = View::Home,
                span { class: "who", "who" }
                span { class: "iam", "iam" }
            }
            StatusDot {}
        }
        main { {body} }
        footer { class: "foot",
            "your identity, everywhere · "
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
                "One identity. "
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
                    if *busy.read() { p { class: "muted", "Probing your identity addresses — this takes about ten seconds." } }
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
                    p { class: "muted", "Create your first identity — a public page other Freenet apps can read your avatar and profile from. You can make more than one; they're not linkable to each other." }
                }
            }
            div { class: "grid",
                for entry in entries {
                    IdentityCard { index: entry.index, label: entry.label.clone() }
                }
                div { class: "card new-card",
                    h3 { "New identity" }
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
    let mut error = use_signal(String::new);
    let mut done = use_signal(|| false);
    rsx! {
        div { class: "card backup",
            div {
                h3 { "Back up your master seed" }
                p { class: "muted",
                    "One file covers every identity — even ones you create later. Anyone holding it controls them all, so store it somewhere safe."
                }
            }
            div { class: "row",
                button { class: "primary",
                    onclick: move |_| {
                        error.set(String::new());
                        match actions::backup_text().and_then(|t| download_text("whoiam-seed.txt", &t)) {
                            Ok(()) => {
                                done.set(true);
                                spawn(async move { crate::sleep_ms(3000).await; done.set(false); });
                            }
                            Err(e) => error.set(e),
                        }
                    },
                    if *done.read() { "Saved ✓" } else { "Download backup" }
                }
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

    let profile = published_profile(index);
    let avatar = published_avatar(index);

    let mut name = use_signal(String::new);
    let mut bio = use_signal(String::new);
    let mut form_seeded = use_signal(|| false);
    if !*form_seeded.read() {
        if let Some(p) = &profile {
            name.set(p.name.clone());
            bio.set(p.bio.clone());
        }
        form_seeded.set(true);
    }

    let mut save_busy = use_signal(|| false);
    let mut save_msg = use_signal(String::new);
    let mut save_err = use_signal(String::new);
    let mut pic_busy = use_signal(|| false);
    let mut pic_err = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut destroy_busy = use_signal(|| false);
    let mut destroy_err = use_signal(String::new);

    let addr = full_key(&pkb);
    let contract_id = crate::keys::identity_key(&pk).id().to_string();

    rsx! {
        section { class: "wrap narrow-wrap",
            button { class: "ghost back", onclick: move |_| *VIEW.write() = View::Home, "← all identities" }

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
                    input {
                        r#type: "file",
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
                    button { class: "primary", disabled: *save_busy.read(),
                        onclick: move |_| {
                            save_busy.set(true);
                            save_err.set(String::new());
                            save_msg.set(String::new());
                            spawn(async move {
                                match actions::save_profile(index, name.read().clone(), bio.read().clone()).await {
                                    Ok(()) => {
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
                    if !save_msg.read().is_empty() { span { class: "ok", "{save_msg}" } }
                }
                if !save_err.read().is_empty() { p { class: "error", "{save_err}" } }
            }

            div { class: "card",
                h3 { "Share with apps" }
                p { class: "muted", "Apps fetch this identity with your public key (they derive the contract from it):" }
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

            div { class: "card danger",
                h3 { "Danger zone" }
                p { class: "muted",
                    "Destroying publishes a signed, permanent “this identity is gone” marker, then forgets the key material. Apps that check will stop showing you. This cannot be undone."
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
                    if *destroy_busy.read() { "Destroying…" } else { "Destroy this identity forever" }
                }
                if !destroy_err.read().is_empty() { p { class: "error", "{destroy_err}" } }
            }
        }
    }
}
