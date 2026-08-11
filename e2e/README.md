# whoiam e2e suite

Playwright tests for the published whoiam UI. **Run against a throwaway
test node only** — the suite onboards (creates a seed) and creates/destroys
identities in that node's delegate store.

```sh
cd e2e
npm install
npx playwright install chromium
WHOIAM_URL="http://127.0.0.1:50509/v1/contract/web/<site-key>/" npm test
```

Getting a test node + site:

1. Start a local node (see freenet-core, or the local-network setup in the
   Griffinbrain freenet notes).
2. `WHOIAM_SITE_KEY=whoiam-test scripts/publish-ui.sh` with the tunnel/port
   pointed at the test node.
3. Point `WHOIAM_URL` at the printed site URL.

The avatar-upload path isn't covered here (Playwright can't exercise the
canvas re-encode deterministically across engines); it's covered by the
manual session checklist instead.
