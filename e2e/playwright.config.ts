import { defineConfig } from "@playwright/test";

// WHOIAM_URL must point at the whoiam site on a THROWAWAY test node, e.g.
//   http://127.0.0.1:50509/v1/contract/web/<site-key>/
// The suite creates and destroys identities — never aim it at a node whose
// delegate holds a seed you care about.
export default defineConfig({
  testDir: "./tests",
  timeout: 120_000,
  // One worker, sequential: every test shares the node's single delegate
  // seed store, so parallel onboarding races.
  workers: 1,
  use: {
    baseURL: process.env.WHOIAM_URL,
    screenshot: "only-on-failure",
  },
});
