# whoiam Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build phase 1 of whoiam end to end: core crate, identity contract, key-store delegate, Rust toolkit, Dioxus UI, docs, published to the live node and verified in a browser.

**Architecture:** Cargo workspace pattern-copied from `~/git/github/skandragon/freenet-freebird`. Pure logic in `whoiam-core`; thin wasm shells for contract and delegate; native toolkit crate over `freenet-stdlib` `WebApi`; Dioxus 0.7 web UI that vendors the wasm bytes and signs everything browser-side.

**Tech Stack:** Rust 2021, freenet-stdlib 0.8.5, ed25519-dalek 2.1.1, ciborium, serde_bytes, blake3, bs58, data-encoding, dioxus 0.7 (web), tokio + tokio-tungstenite 0.27 (toolkit), Playwright (e2e), fdev (site publish).

## Global Constraints

- Contract/delegate wasm compile with `getrandom = { version = "0.2", features = ["custom"] }`, NEVER a backend feature ("js") at workspace level (freenet/river#241).
- Wasm bytes are vendored into `ui/contracts/` and pinned by sha256 in `scripts/wasm-hashes.txt`; `make check-addresses` must pass before any UI build or publish. Address rotation is a deliberate act.
- Contract address = `ContractKey::from_params_and_code(params_cbor, wasm)`; params CBOR = `{version: 1, pubkey}`.
- Per-slot cap 128 KiB (`MAX_SLOT_BYTES`), total state cap 512 KiB (`MAX_STATE_BYTES`), far-future clamp `MAX_FUTURE_MS = 10 * 60 * 1000`.
- Slot signature: ed25519 over `"whoiam-slot-v1" ‖ pubkey ‖ slot_name_len_le32 ‖ slot_name ‖ time_ms_le64 ‖ blake3(content)`. Destruction signature over `"whoiam-destroy-v1" ‖ pubkey ‖ time_ms_le64`.
- Identity derivation: `blake3::derive_key("whoiam identity v1", seed ‖ index_le32)` → ed25519 seed. (Spec said HKDF-SHA256; blake3 `derive_key` has identical properties and is already a dependency — spec amended.)
- All CBOR via ciborium; avatar/content byte fields use `serde_bytes`.
- Delegate stores only: `seed` (32 bytes) and `meta` (CBOR `IdentityMeta { identities: Vec<{index: u32, label: String}> }`), origin-prefixed like freebird-delegate.
- Node for manual testing: `ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native` (ssh tunnel to explorer@10.46.101.1; publish via `fdev`, site key name `whoiam`).
- Commits: short messages, frequent.

---

### Task 1: Workspace scaffold + whoiam-core types & signing

**Files:**
- Create: `Cargo.toml` (workspace: common, contracts/identity-contract, delegates/whoiam-delegate, toolkit/whoiam-client, ui), `rust-toolchain.toml` (copy freebird), `.gitignore`, `LICENSE` (AGPL-3.0, copy freebird)
- Create: `common/Cargo.toml` (name `whoiam-core`; deps: ciborium, serde, serde_bytes, ed25519-dalek, blake3, bs58, data-encoding, freenet-stdlib)
- Create: `common/src/lib.rs` (modules + `to_cbor`/`from_cbor` helpers, copy freebird-core's)
- Create: `common/src/state.rs`
- Test: unit tests in `state.rs`

**Interfaces (produces):**
```rust
pub struct IdentityParamsV1 { pub version: u32, pub pubkey: VerifyingKey }
pub struct SignedSlot { pub time_ms: u64, #[serde(with="serde_bytes")] pub bytes: Vec<u8>, pub sig: Signature }
pub struct DestroyedMarker { pub time_ms: u64, pub sig: Signature }
pub struct IdentityStateV1 { pub slots: BTreeMap<String, SignedSlot>, pub destroyed: Option<DestroyedMarker> }
pub fn sign_slot(sk: &SigningKey, name: &str, time_ms: u64, bytes: Vec<u8>) -> SignedSlot
pub fn check_slot(slot: &SignedSlot, name: &str, pk: &VerifyingKey) -> Result<(), String>
pub fn sign_destroy(sk: &SigningKey, time_ms: u64) -> DestroyedMarker
pub fn check_destroy(m: &DestroyedMarker, pk: &VerifyingKey) -> Result<(), String>
pub fn slot_order_key(s: &SignedSlot) -> (u64, [u8; 32])   // (time, blake3(bytes))
pub const MAX_SLOT_BYTES: usize = 128 * 1024;
pub const MAX_STATE_BYTES: usize = 512 * 1024;
pub const MAX_FUTURE_MS: u64 = 600_000;
```

- [ ] Write failing tests: sign/verify round-trip, tampered bytes rejected, wrong slot name rejected, wrong key rejected, empty-bytes tombstone signs fine, destroy round-trip.
- [ ] Implement; `cargo test -p whoiam-core` passes.
- [ ] Commit "core types and slot signing".

### Task 2: whoiam-core merge

**Files:**
- Create: `common/src/merge.rs`
- Test: unit tests in `merge.rs` + proptest optional (skip if time)

**Interfaces (produces):**
```rust
/// Pure merge: fold `incoming` into `current`. `now_ms` supplied by caller
/// (host clock in contract, wall clock in tests). Invalid incoming pieces are
/// REJECTED with Err (contract turns this into update rejection).
pub fn merge_state(current: &mut IdentityStateV1, incoming: &IdentityStateV1,
                   pk: &VerifyingKey, now_ms: u64) -> Result<bool, String> // true = changed
pub fn validate_full(state: &IdentityStateV1, pk: &VerifyingKey, now_ms: u64) -> Result<(), String>
pub fn summarize(state: &IdentityStateV1) -> SummaryV1 // map name -> (time, hash) + destroyed time
pub fn delta_since(state: &IdentityStateV1, summary: &SummaryV1) -> IdentityStateV1
```

Merge rules (each is a test):
- newer `(time, hash)` wins per slot; older/equal incoming ignored (no change)
- bad signature anywhere in incoming → Err
- slot > MAX_SLOT_BYTES or serialized state > MAX_STATE_BYTES → Err
- `time_ms > now + MAX_FUTURE_MS` → Err
- valid destroyed marker: clears all slots, sets destroyed; further slot merges rejected ("identity destroyed"); a second older marker ignored, newer replaces
- empty-bytes slot acts as tombstone (kept in map so it propagates; toolkit hides it)

- [ ] Write failing tests per rule above, then implement until green.
- [ ] Commit "per-slot LWW merge with destruction".

### Task 3: whoiam-core derivation, profile schema, delegate API

**Files:**
- Create: `common/src/derive.rs`, `common/src/resources.rs`, `common/src/delegate_api.rs`

**Interfaces (produces):**
```rust
// derive.rs
pub fn identity_signing_key(seed: &[u8; 32], index: u32) -> SigningKey
// resources.rs
pub const SLOT_PROFILE: &str = "profile"; pub const SLOT_AVATAR: &str = "avatar";
pub struct ProfileV1 { pub name: String, pub bio: String }
pub const MAX_NAME_CHARS: usize = 64; pub const MAX_BIO_CHARS: usize = 280;
pub const MAX_AVATAR_BYTES: usize = 128 * 1024;
pub const MIN_AVATAR_DIM: u32 = 64; pub const MAX_AVATAR_DIM: u32 = 512;
pub fn check_profile(p: &ProfileV1) -> Result<(), String>
// image magic sniff only (PNG 89 50 4E 47 / WebP RIFF....WEBP); dimensions are UI's job
pub fn check_avatar_bytes(b: &[u8]) -> Result<(), String>
// delegate_api.rs — mirror freebird's FreebirdDelegateRequest/Response verbatim
pub enum WhoiamDelegateRequest { Store{key: String, value: serde_bytes::ByteBuf}, Get{key: String}, Delete{key: String}, List }
pub enum WhoiamDelegateResponse { Stored{key}, Value{key, value: Option<ByteBuf>}, Deleted{key}, KeyList{keys: Vec<String>}, Error{message} }
```

- [ ] Tests: same seed+index → same key; different index/seed → different; profile over-limit rejected; PNG/WebP magic accepted, GIF rejected.
- [ ] Commit "derivation, resource schemas, delegate api".

### Task 4: identity-contract wasm shell

**Files:**
- Create: `contracts/identity-contract/Cargo.toml` (crate-type cdylib+rlib, feature `freenet-main-contract` default, getrandom custom — copy avatar-contract manifest)
- Create: `contracts/identity-contract/src/lib.rs`

Pattern: `freenet-freebird/contracts/avatar-contract/src/lib.rs`. Implement all four `ContractInterface` methods over core:
- `validate_state`: empty ok; else `validate_full(&state, &params.pubkey, now_ms())`
- `update_state`: fold each `UpdateData::State/Delta` (both decode as `IdentityStateV1`) via `merge_state`; reject on Err; return full state
- `summarize_state`: CBOR `summarize()`
- `get_state_delta`: CBOR `delta_since()`

- [ ] Native unit tests: valid state accepted, update merges, bad sig rejected, destroy collapses.
- [ ] Commit "identity contract".

### Task 5: whoiam-delegate

**Files:**
- Create: `delegates/whoiam-delegate/Cargo.toml`, `delegates/whoiam-delegate/src/lib.rs`

Clone `freebird-delegate/src/lib.rs` mechanically: same Kv trait seam, origin prefix, `#[delegate]` impl; swap request/response types for `Whoiam*`.

- [ ] Tests (in-memory Kv): store/get/delete/list round-trip, origin isolation (two origins don't see each other's keys).
- [ ] Commit "kv delegate".

### Task 6: build tooling — wasm, import check, hash pin

**Files:**
- Create: `Makefile` (adapt freebird's: targets `all contracts delegate ui test check-imports check-addresses pin-hashes publish clean`; contracts = identity-contract only)
- Create: `scripts/publish-ui.sh` (adapt freebird's; KEY_NAME whoiam, SITE_DIR `target/dx/whoiam-ui/release/web/public`)
- Create: `ui/contracts/` vendored `identity_contract.wasm`, `whoiam_delegate.wasm`; `scripts/wasm-hashes.txt` via `make pin-hashes`

- [ ] `make contracts delegate` builds, `check-imports` clean, `pin-hashes`, commit "build tooling + vendored wasm".

### Task 7: whoiam-client toolkit

**Files:**
- Create: `toolkit/whoiam-client/Cargo.toml` (deps: whoiam-core, freenet-stdlib features net, tokio, tokio-tungstenite 0.27, ciborium, ed25519-dalek, data-encoding, bs58, thiserror)
- Create: `toolkit/whoiam-client/src/lib.rs`, `toolkit/whoiam-client/examples/whoiam-fetch.rs`

**Interfaces (produces):**
```rust
pub const IDENTITY_CONTRACT_WASM: &[u8] = include_bytes!("../../../ui/contracts/identity_contract.wasm");
pub fn identity_params(pk: &VerifyingKey) -> IdentityParamsV1
pub fn contract_key(pk: &VerifyingKey) -> ContractKey       // derive offline
pub enum FetchError { NotFound, Destroyed{since_ms: u64}, BadSignature(String), Malformed(String), Oversized, Transport(String), Timeout }
pub struct Identity { pub pubkey: VerifyingKey, pub profile: Option<ProfileV1>, pub avatar: Option<Vec<u8>>, pub raw_slots: BTreeMap<String, Vec<u8>> }
pub async fn fetch(node_url: &str, pk: &VerifyingKey) -> Result<Identity, FetchError>
pub fn parse_pubkey(s: &str) -> Result<VerifyingKey, String> // bs58 or hex
```
`fetch`: connect (freebird-ctl `connect`/`wait_for` pattern, 60s timeout), Get by instance id, decode `IdentityStateV1`, `validate_full` client-side (never trust the node), map tombstoned/unknown slots away, decode profile CBOR.

Example binary: `whoiam-fetch --node URL --key <bs58 pubkey> [--avatar-out f.png]` prints profile, writes avatar.

- [ ] Unit tests: `contract_key` deterministic/distinct per key; state→Identity conversion hides tombstones, surfaces Destroyed; parse_pubkey both encodings.
- [ ] Commit "rust toolkit".

### Task 8: docs/resources.md + README.md

Write the consumer-facing schema doc per spec (avatar + profile rules, unknown-slot rule, address derivation recipe with pinned wasm hash) and a README (what whoiam is, workspace map, build/publish/test commands, toolkit usage snippet).

- [ ] Commit "docs".

### Task 9: UI scaffold — connection, keys, delegate persistence

**Files:**
- Create: `ui/Cargo.toml` (crib freebird-ui: dioxus 0.7 web, getrandom js HERE ONLY, web-sys features incl. HtmlInputElement, FileReader, Blob, Url, HtmlAnchorElement, HtmlImageElement, HtmlCanvasElement, CanvasRenderingContext2d)
- Create: `ui/Dioxus.toml` (title "whoiam"), `ui/src/main.rs`, `ui/src/api.rs`, `ui/src/keys.rs`, `ui/src/state.rs`
- Vendored wasm consumed via `include_bytes!("../contracts/identity_contract.wasm")` etc.

Crib from freebird-ui: `websocket_url()`, `connect()` + dispatch pump, `register_delegate` with localStorage cipher material (`whoiam_delegate_cipher_v1`), `kv_request`, TRACKED registry (kinds: `Identity([u8;32])` only), signals: `SEED: Option<[u8;32]>`, `IDENTITIES: Vec<IdentityEntry{index,label,pubkey}>`, `PUBLISHED: BTreeMap<[u8;32], IdentityStateV1>`, `SYNC_STATUS`, `BUSY/TOAST`.
Boot flow: connect → register delegate → Get `seed` + `meta` → populate signals (no seed = onboarding screen).

- [ ] `cargo check -p whoiam-ui --target wasm32-unknown-unknown` clean; commit "ui scaffold".

### Task 10: UI features + polish

**Files:**
- Create: `ui/src/views.rs`, `ui/src/actions.rs`, `ui/assets/main.css`

Features: onboarding (generate seed / restore from backup), identity list + create (derive next index, PUT empty contract, store meta), profile editor (name/bio, schema-checked), avatar upload (file input → img decode → canvas re-encode PNG ≤512² center-crop square → size check → sign slot → Update/Put), backup download (hex seed file via Blob+anchor; show words if bip39 fits, else hex only — decide inline), identity detail with contract address (bs58 id + copy button), destroy flow (type-to-confirm → push marker → verify → drop meta), restore probing (indices 0.. with gap-of-5, manual re-add field).
Polish: single hand-written CSS file, dark-first with light support, gradient identicon fallback avatar from pubkey bytes, responsive card layout. Make it genuinely pretty — this is a deliverable, not an afterthought.

- [ ] `dx build --release` succeeds; commit "ui".

### Task 11: publish + live manual verification (Playwright MCP)

- [ ] Ensure tunnel: `nc -z localhost 7509` else `ssh -f -L 7509:localhost:7509 explorer@10.46.101.1 sleep 3600`.
- [ ] `scripts/publish-ui.sh` (fdev website init whoiam + publish).
- [ ] Playwright MCP against `http://127.0.0.1:7509/v1/contract/web/<key>/`: create identity, set profile, upload avatar (generate a test PNG), download backup, reload page → state persists, fetch same identity with `whoiam-fetch` example against the node, screenshot the pretty UI.
- [ ] Fix what breaks; commit fixes.

### Task 12: Playwright e2e suite (for a test node)

**Files:**
- Create: `e2e/package.json`, `e2e/playwright.config.ts` (`baseURL` from `WHOIAM_URL` env), `e2e/tests/identity.spec.ts`, `e2e/README.md`

Specs: onboarding creates identity; profile save survives reload; avatar upload renders; backup file downloads and contains 64 hex chars; destroy removes identity from list. Documented as "run against a throwaway test node, not production".

- [ ] `npx playwright test --list` parses; run full suite only if a test node is available this session (else document).
- [ ] Commit "e2e suite".

### Task 13: wrap-up

- [ ] `make test` green, `make check-addresses` green, push, update brain project knowledge (new projects/freenet-whoiam/ index), file follow-up issues for anything deferred.

## Self-review notes

- Spec coverage: every spec section maps to a task (keys→1/3/9, contract→2/4, schemas→3/8, toolkit→7, flows→9/10, errors→2/4/7, testing→all + 11/12). Ghostkeys stays an open question (issue-tracked).
- Deviation from spec, deliberate: blake3 `derive_key` replaces HKDF-SHA256 (equivalent KDF properties, dependency already present) — spec amended in same commit.
- Types referenced across tasks checked for name consistency (`IdentityStateV1`, `SignedSlot`, `merge_state`, `WhoiamDelegateRequest`).
