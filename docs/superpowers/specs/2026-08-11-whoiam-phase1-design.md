# whoiam phase 1: core identity — design

2026-08-11. Status: approved.

whoiam is an identity platform for Freenet apps. A user holds one or more
identities; each identity is an ed25519 keypair whose public half determines
a public identity contract holding that identity's public resources (avatar,
profile). Any Freenet app can fetch those resources through a toolkit crate,
so updating an avatar in whoiam updates it everywhere.

Phase 1 (this spec): delegate key store, identity contract, resource
schemas, Rust toolkit, Dioxus management UI. Phase 2 (app association
handshake) and phase 3 (cross-app delegation grants) are sketched at the end
and tracked as GitHub issues.

## Workspace

Cargo workspace, pattern-copied from freenet-freebird:

| crate | role |
|---|---|
| `common/` (`whoiam-core`) | types, signing, per-slot LWW merge; pure, no wasm deps; shared by contract, UI, toolkit |
| `contracts/identity-contract` | thin `ContractInterface` shell over core merge (avatar-contract pattern) |
| `delegates/whoiam-delegate` | dumb origin-isolated KV secret store (freebird-delegate clone); holds master seed + identity metadata; no signing, no derivation |
| `toolkit/whoiam-client` | consumer crate: derive address from pubkey (pinned wasm hash), fetch via node websocket, verify sigs, return typed resources; TS port later |
| `ui/` | Dioxus 0.7 webapp, published as a Freenet site contract; all key generation and signing happens here (delegate runtime has no RNG) |

Makefile includes a `check-addresses` target pinning the contract/delegate
wasm sha256 from day 1 (guard from Freebird's 2026-08-10 address-rotation
incident: any wasm byte change rotates every derived address).

## Keys, backup, restore

- Master seed: 32 random bytes, generated in the UI, stored only in the
  delegate.
- Identity *i* keypair: ed25519 seed = HKDF-SHA256(ikm = master seed,
  info = `"whoiam-identity"` ‖ u32 index). Identities share no public
  linkage; derivation is invisible without the seed.
- Delegate stores: the seed, plus a metadata record (used indices, labels).
  The UI pulls the seed into memory to derive and sign; it never persists it
  outside the delegate.
- Backup: download the seed as one file (hex + BIP39-style word encoding).
  A single backup covers all identities, including ones created later.
- Restore: user supplies seed; UI re-derives indices 0, 1, 2… and probes
  each derived contract address, stopping after a gap of 5 unused indices
  (HD-wallet style); rebuilds delegate metadata from what it finds. Caveat:
  an unhosted contract can rot off the network (subscription is a short
  lease), so restore may miss dormant identities; the UI lets the user
  manually re-add an index, and a re-PUT at the derived address revives it.
- Slot signature: ed25519 over
  `"whoiam-slot-v1" ‖ pubkey ‖ slot_name ‖ time_ms ‖ blake3(content)`.

## Identity contract

- Params (CBOR): `{ version: 1, pubkey: [u8; 32] }`. Address =
  hash(wasm + params), so consumers derive it offline from the pubkey.
- State (CBOR): `map<slot_name: String, SignedSlot>` plus optional
  destruction marker. `SignedSlot { time_ms: u64, bytes: Vec<u8>, sig }`.
- Merge: per-slot LWW ordered by `(time_ms, blake3(bytes))`. Timestamps more
  than `MAX_FUTURE_MS` ahead of the host clock are rejected (poisoned
  far-future timestamps must not win LWW forever).
- Slot deletion: signed empty-content tombstone with a newer time.
- Destruction marker: a signed `Destroyed { time_ms, sig }` record. Once a
  valid marker lands, all slots drop, updates are rejected, and only the
  marker survives merges — the identity is publicly dead forever. The UI
  destroys the public identity first, then removes local key material.
- Caps: per-slot ≤ 128 KiB, total state ≤ 512 KiB (practical PUT limit is
  low single MB).
- Unknown slot names are valid if correctly signed; the toolkit ignores
  ones it doesn't recognize (forward compatibility — phase 3 grant slots
  ride on this).

## Resource schemas (`docs/resources.md`)

Consumer-facing contract for each well-known slot:

- `avatar` — PNG or WebP; square; ≥64×64, ≤512×512; ≤128 KiB. Consumers
  should assume square rendering and may round corners.
- `profile` — CBOR `{ name: String ≤64 chars, bio: String ≤280 chars }`,
  UTF-8, plain text (no markup).

New resource types get documented here before apps consume them.

## Flows

- **Create identity**: UI generates (or already has) the seed → derives the
  next index's keypair → PUTs an empty identity contract → records
  index/label in delegate metadata.
- **Update resource**: UI validates against the schema (dimensions, size),
  signs the slot, sends UPDATE over the node websocket.
- **Consume** (any app): `whoiam_client::fetch(pubkey)` → derives address →
  GETs state → verifies every slot signature client-side (never trust the
  serving node) → returns typed `Identity { profile, avatar, … }`.
- **Destroy**: UI signs and pushes the destruction marker, confirms it took,
  then deletes that identity's metadata (seed remains; the index is simply
  never reused).
- **Backup / restore**: as in the keys section.

## Errors

- Contract: bad signature, oversize, far-future time, post-destruction
  update → update rejected / `ValidateResult::Invalid`; malformed CBOR →
  `ContractError::Deser`.
- Toolkit: typed errors — `NotFound`, `BadSignature`, `Destroyed`,
  `Oversized`, `Malformed`, transport errors passed through.
- UI: schema violations (wrong image size/format) rejected before signing.

## Testing

- `whoiam-core`: pure unit tests for merge (LWW order, tombstones,
  destruction, far-future clamp) and sign/verify round-trips.
- Delegate: Kv trait seam with in-memory impl (freebird pattern), since the
  native `DelegateCtx` is a stub.
- Integration: make target that stands up the local test network, publishes
  a demo identity, and fetches it with a `whoiam-client` example binary.

## Phase 2 sketch (issue): app association

An app (e.g. Freebird) opens whoiam with a nonce; whoiam asks the user
"associate this identity with Freebird?"; on yes, whoiam generates its own
nonce, signs `H(app_nonce, whoiam_nonce, app_id)` with the identity key, and
returns the user to the app with pubkey + both nonces + signature. The app
verifies, then durably remembers the identity's pubkey (and thus contract
address). Details (URI scheme, replay protection, callback transport) to be
specced when built.

## Phase 3 sketch (issue): cross-app delegation

OAuth-like grants with whoiam as the trusted third party: user asks in app A
"let A post to app B as me"; B mints a scoped token; the token is stored in
the whoiam identity contract as a grant slot encrypted to A's key. Grants
are inspectable and revocable from whoiam (slot tombstone). Rotation plan
documented even if not implemented. Where the request/mint flow lives (whoiam
vs B) is an open design question for that spec.

## Open questions

- Ghostkeys interaction: unknown. Possibly an optional attestation slot
  (Freebird check-mark style) binding a ghostkey to an identity. Not in
  phase 1.
- BIP39 wordlist vs plain hex for the backup file format: decide during
  implementation (both encodings in one file is the current plan).
