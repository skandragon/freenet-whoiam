# whoiam connect flow ("sign in with whoiam")

2026-08-11. Approved in-session. Revised same day: demo moved into Freenet
(Dioxus app, own site contract) and the proof binds to the callback's
origin+path; the callback carries no profile — the verifier fetches the
identity contract for name/bio/avatar. docs/resources.md holds the
authoritative protocol; details below are historical where they differ.

## Goal

An external site can ask the user to associate a persona with their account
there, and receive a cryptographic proof that the user controls that
persona's key — no impersonation possible.

## Flow

1. Site generates a random `challenge` (URL-safe string, ≤256 chars), stores
   it locally, and opens the whoiam site URL with
   `?connect=v1&challenge=<c>&return=<url-encoded callback URL>`.
2. The Freenet shell forwards those params into the sandboxed app iframe
   (only `__sandbox*`/`authToken*` are stripped). whoiam parses them at boot;
   if valid, after seed+meta load it shows a picker instead of Home:
   "**{callback origin}** wants to know who you are", one button per persona,
   plus "Don't share".
3. Clicking a persona signs, with that persona's key:
   `"whoiam-connect-v1" ‖ pk(32) ‖ u32le len ‖ origin ‖ u32le len ‖ challenge ‖ u64le time_ms`
   and opens (new tab — the sandbox forbids top navigation) the return URL
   with `whoiam=ok&pk=<hex>&sig=<hex>&challenge=<c>&ts=<ms>` appended.
   "Don't share" opens it with `whoiam=denied`.
4. The callback page verifies: the challenge is one it issued (one-time),
   `ts` is fresh (±10 min), and the ed25519 signature checks against `pk`
   using **its own origin** in the message. Origin binding prevents
   cross-site replay; the one-time challenge prevents same-site replay.

## Validation (trust boundary, in whoiam)

- `challenge`: 1..=256 chars, charset `[A-Za-z0-9._~-]` (keeps callback URL
  building pure string concat, no re-encoding).
- `return`: parses as a URL, scheme http/https, no fragment. Origin is
  derived from it and shown to the user. Invalid request → logged, ignored,
  app behaves normally.

## Pieces

- `common/src/connect.rs`: `sign_connect` / `check_connect`, domain-separated
  like slot/destroy signing. Unit tests + golden vector (wire-frozen).
- `ui`: `CONNECT` static parsed at boot; `ConnectView` picker; signing +
  `window.open` on click. No contract or delegate changes.
- `demo/index.html`: single static zero-dependency page (WebCrypto Ed25519)
  that is both the connect button and its own callback/verifier.
- `e2e/tests/connect.spec.ts`: full round trip against a test node, demo page
  served via Playwright route interception on a `localhost` origin (secure
  context for WebCrypto).

## Out of scope (later if wanted)

- Site-side fetch of profile/avatar after connect (already possible via
  `whoiam-client` given the proven pk).
- Session persistence in whoiam ("remember this site").
