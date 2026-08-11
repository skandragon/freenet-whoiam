# whoiam public resources

The contract every consumer reads. An identity is an ed25519 public key;
its contract address derives offline from that key (see "Addressing"). The
state is a map of named **slots**, each independently signed by the
identity key. Slots this document doesn't list are valid if correctly
signed — ignore ones you don't understand.

Verify before trusting: the serving node is untrusted. `whoiam-client`
(Rust) does full signature verification on fetch; if you decode state by
hand you must verify each slot's signature yourself (domain-separated
ed25519, see `common/src/state.rs`).

## Addressing

```
params  = CBOR { version: 1, pubkey: <32-byte ed25519 key> }
address = ContractKey::from_params_and_code(params, identity_contract.wasm)
```

The canonical `identity_contract.wasm` bytes are vendored in
`ui/contracts/` and pinned in `scripts/wasm-hashes.txt`. Consumers should
use `whoiam_client::contract_key(&pubkey)` and never compile the wasm
themselves — a byte-different wasm derives the wrong address.

## Slot: `profile`

CBOR `{ name: String, bio: String }`.

| rule | value |
|---|---|
| `name` | ≤ 64 characters, UTF-8, plain text (no markup) |
| `bio` | ≤ 280 characters, UTF-8, plain text (no markup) |

Render as text; never interpret as HTML/markdown. `name` may be empty —
fall back to an abbreviated pubkey.

## Slot: `avatar`

Raw image bytes (the slot content IS the file).

| rule | value |
|---|---|
| container | PNG or WebP |
| shape | square |
| dimensions | ≥ 64×64, ≤ 512×512 |
| size | ≤ 128 KiB |

Consumers should assume square rendering (rounding corners is fine) and
scale down freely. The whoiam UI re-encodes uploads to a square PNG within
these bounds, but treat dimensions as advisory — a hand-rolled publisher
may lie, so cap what you render.

## Lifecycle

- **Tombstoned slot** (empty content, newer timestamp): the resource was
  deleted. `whoiam-client` hides these; treat as absent.
- **Destroyed identity**: the state carries only a signed destruction
  marker. This is permanent. Drop cached resources and stop rendering the
  identity (`whoiam-client` returns `FetchError::Destroyed`).

## Connect flow ("sign in with whoiam")

An app can ask the user to prove they own a persona. Open the whoiam site
URL with:

```
?connect=v1&challenge=<nonce>&return=<url-encoded callback URL>
```

- `challenge`: random, one-time, URL-safe (`[A-Za-z0-9._~-]`, ≤ 256 chars).
  Store it; you must recognize it on the callback.
- `return`: absolute http(s) URL, no fragment. whoiam shows its origin to
  the user and binds the proof to its **origin+path** (`return_base`) —
  path included because apps on the same Freenet node share the node's
  HTTP origin.

whoiam returns to the callback — in the same tab when it is a contract app
on the same node (via the shell's `navigate` postMessage bridge), in a new
tab otherwise (the sandboxed app cannot top-navigate to a foreign origin) —
with either `whoiam=denied`, or:

```
whoiam=ok&pk=<hex 32B>&sig=<hex 64B>&challenge=<echo>&ts=<unix ms>
```

Verify (reference: `common/src/connect.rs`, exercised by `demo/`):

1. `challenge` is one you issued — then burn it (one-time). A pure
   client-side page inside the Freenet sandbox has no storage that
   survives the bounce, so this bookkeeping belongs to your backend or
   your app's delegate.
2. `ts` is fresh (whoiam signs at click time; ±10 min is reasonable).
3. ed25519-verify `sig` with `pk` over
   `"whoiam-connect-v1" ‖ pk ‖ u32le len ‖ return_base ‖ u32le len ‖ challenge ‖ u64le ts`
   where `return_base` is your own origin+path.

The binding makes a proof issued for another app useless to a replaying
attacker; the challenge makes each proof single-use. The proof carries no
profile data: a verified `pk` is the persona's identity key — fetch its
contract per this document for name/bio/avatar. The `demo/` app does
exactly that (verify, then fetch and render, checking every slot
signature); publish it to a node with `scripts/publish-demo.sh`.

## Adding a resource type

New well-known slots get documented here (format, caps, rendering hints)
before apps consume them. Namespace experimental slots with an app prefix
(e.g. `freebird:banner`) to avoid collisions.
