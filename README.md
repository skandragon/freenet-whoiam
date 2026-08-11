# whoiam

Identity for Freenet apps. One place for your avatar and profile; every
app that knows your public key can fetch them, and an update here shows up
everywhere.

- Each **identity** is an ed25519 keypair derived from one master seed
  (back up the seed once, every identity — even future ones — is
  recoverable). Identities are unlinkable in public.
- Each identity has a **public contract** (address derived from its
  pubkey) holding signed resource slots: `avatar`, `profile`, more later.
  See [docs/resources.md](docs/resources.md) for the consumer contract.
- The **delegate** is a dumb origin-isolated secret store on your node
  holding the seed; all key derivation and signing happen in the UI.
- **Destroying** an identity publishes a signed permanent marker first,
  then forgets the local keys.

## Workspace

| dir | what |
|---|---|
| `common/` | `whoiam-core`: types, signing, LWW merge, derivation — pure, tested |
| `contracts/identity-contract/` | the public identity contract (wasm) |
| `delegates/whoiam-delegate/` | seed store delegate (wasm) |
| `toolkit/whoiam-client/` | Rust consumer crate + `whoiam-fetch` example |
| `ui/` | Dioxus web UI, published to Freenet as a site contract |
| `demo/` | connect-flow demo app (verify proof, fetch profile), its own site contract |
| `e2e/` | Playwright suite (run against a throwaway test node) |

## Consuming an identity (Rust)

```rust
let pk = whoiam_client::parse_pubkey("…bs58 or hex…")?;
let id = whoiam_client::fetch(
    "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native", &pk).await?;
// id.profile: Option<ProfileV1 { name, bio }>, id.avatar: Option<Vec<u8>>
```

Signatures are verified client-side; the serving node is untrusted.

Apps can also ask the user to prove persona ownership ("sign in with
whoiam"): open the whoiam site with `?connect=v1&challenge=…&return=…`,
verify the signed callback, then fetch the proven key's contract — see the
connect-flow section of [docs/resources.md](docs/resources.md) and the
demo app in [demo/](demo/) (`make publish-demo`).

Or from a shell:

```sh
cargo run -p whoiam-client --example whoiam-fetch -- --key <pubkey> --avatar-out avatar.png
```

## Building

```sh
make test           # workspace unit tests
make contracts      # build + vendor identity_contract.wasm (guarded)
make delegate       # build + vendor whoiam_delegate.wasm (guarded)
make ui             # dx build --release
make publish        # publish the UI site via fdev (needs node tunnel)
```

**Wasm bytes are pinned** (`scripts/wasm-hashes.txt`): contract addresses
are content-derived, so changed bytes rotate every identity's address.
`make check-addresses` fails the build if bytes drift; re-pin only as a
deliberate migration (`make pin-hashes`).

## Roadmap

- Phase 2: app association handshake (#1)
- Phase 3: OAuth-like cross-app delegation grants (#2)
- TS toolkit; Ghostkeys interaction is an open question.
