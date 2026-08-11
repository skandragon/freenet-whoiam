//! Global UI state (Dioxus signals).

use std::collections::BTreeMap;

use dioxus::prelude::*;
use freenet_stdlib::client_api::WebApi;
use whoiam_core::delegate_api::IdentityMeta;
use whoiam_core::state::IdentityStateV1;

#[derive(Clone, PartialEq, Debug, Default)]
pub enum SyncStatus {
    #[default]
    Connecting,
    Connected,
    Error(String),
}

pub static WEB_API: GlobalSignal<Option<WebApi>> = Signal::global(|| None);
pub static SYNC_STATUS: GlobalSignal<SyncStatus> = Signal::global(SyncStatus::default);

/// Delegate's answer for the master seed:
/// None = not answered yet; Some(None) = no seed stored (onboard);
/// Some(Some(seed)) = ready.
pub static SEED_LOADED: GlobalSignal<Option<Option<[u8; 32]>>> = Signal::global(|| None);

/// Identity metadata (indices + labels), delegate-persisted.
pub static META: GlobalSignal<IdentityMeta> = Signal::global(IdentityMeta::default);
/// The delegate answered the meta Get (even if empty) — gate on this so we
/// never overwrite stored meta with an empty default.
pub static META_LOADED: GlobalSignal<bool> = Signal::global(|| false);

/// Published contract state per identity pubkey. None = requested, not yet
/// arrived (or the contract doesn't exist on the network yet).
pub static IDENTITY_STATES: GlobalSignal<BTreeMap<[u8; 32], Option<IdentityStateV1>>> =
    Signal::global(BTreeMap::new);

/// The seed answer will never arrive (watchdog timeout or the node is
/// swallowing delegate errors). Drives an explanatory error screen instead
/// of an eternal spinner.
pub static KEY_STORE_UNREACHABLE: GlobalSignal<bool> = Signal::global(|| false);

/// A validated `?connect=v1` bounce-through request from an external site
/// (parsed from the iframe URL at boot). While present, the app shows the
/// persona picker instead of the normal views.
#[derive(Clone, PartialEq, Debug)]
pub struct ConnectRequest {
    /// Origin of the callback URL — what the user is shown.
    pub origin: String,
    /// origin+path of the callback URL — what the proof is bound to (apps on
    /// the same Freenet node share an origin; the path tells them apart).
    pub return_base: String,
    pub return_url: String,
    pub challenge: String,
}

pub static CONNECT: GlobalSignal<Option<ConnectRequest>> = Signal::global(|| None);

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum View {
    #[default]
    Home,
    Identity(u32),
    Backup,
}

pub static VIEW: GlobalSignal<View> = Signal::global(View::default);

pub fn seed() -> Option<[u8; 32]> {
    SEED_LOADED.read().clone().flatten()
}
