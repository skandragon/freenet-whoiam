import { test, expect, Page, FrameLocator } from "@playwright/test";
import { app, createIdentity, ensureOnboarded } from "./helpers";

// The demo app published on the SAME test node (scripts/publish-demo.sh):
//   WHOIAM_DEMO_URL="http://127.0.0.1:50509/v1/contract/web/<demo-key>/"
const DEMO_URL = process.env.WHOIAM_DEMO_URL;

// Publish name+bio on the identity the picker will share (from Detail view).
async function publishProfile(page: Page, name: string, bio: string) {
  const a = app(page);
  await a.getByRole("button", { name: "change", exact: true }).click();
  await a.getByPlaceholder("shown in apps").fill(name);
  await a.getByPlaceholder(/a line about you/).fill(bio);
  await a.getByRole("button", { name: "Publish" }).click();
  await expect(a.getByText("published ✓")).toBeVisible({ timeout: 60_000 });
}

// Land on the whoiam picker via the demo app. Demo and whoiam live on the
// same node, so every hop is a same-tab navigation through the shell's
// `navigate` bridge — no new tabs anywhere in the flow.
async function startConnect(page: Page, label: string): Promise<FrameLocator> {
  expect(DEMO_URL, "set WHOIAM_DEMO_URL to the demo app on the test node").toBeTruthy();
  // The demo build knows where whoiam runs (WHOIAM_SITE_CONTRACT baked in);
  // only unbaked builds show a URL field. ?whoiam_url= overrides the baked
  // value so the suite is explicit about which whoiam it drives.
  await page.goto(`${DEMO_URL!}?whoiam_url=${encodeURIComponent(process.env.WHOIAM_URL!)}`);
  await app(page).getByRole("button", { name: "Connect a persona" }).click();
  const w = app(page);
  await expect(w.getByRole("heading", { name: "Share a persona?" })).toBeVisible({ timeout: 60_000 });
  await expect(w.getByRole("heading", { name: label })).toBeVisible();
  return w;
}

test("connect: approve, verify, and load the profile from the contract", async ({ page }) => {
  const label = `connect-${Date.now()}`;
  const bio = "verified by the connect e2e";
  await ensureOnboarded(page);
  await createIdentity(page, label);
  await publishProfile(page, label, bio);

  const w = await startConnect(page, label);
  await w.getByRole("heading", { name: label }).click();
  const c = app(page);
  await expect(c.getByText("✔ Persona verified")).toBeVisible({ timeout: 60_000 });
  // Profile is fetched from the identity contract, not passed in the URL.
  await expect(c.getByRole("heading", { name: `Welcome, ${label}` })).toBeVisible({ timeout: 60_000 });
  await expect(c.getByText(bio)).toBeVisible();
});

test("connect: refuse reports denied", async ({ page }) => {
  const label = `deny-${Date.now()}`;
  await ensureOnboarded(page);
  await createIdentity(page, label);

  const w = await startConnect(page, label);
  await w.getByRole("button", { name: "Don't share" }).click();
  const c = app(page);
  await expect(c.getByRole("heading", { name: "Declined" })).toBeVisible({ timeout: 60_000 });

  // "← home" resets the callback view to the landing view.
  await c.getByRole("button", { name: "← home" }).click();
  await expect(c.getByRole("heading", { name: "Link a whoiam persona" })).toBeVisible();
});

test("connect: a tampered callback fails verification", async ({ page }) => {
  const label = `tamper-${Date.now()}`;
  await ensureOnboarded(page);
  await createIdentity(page, label);

  const w = await startConnect(page, label);
  await w.getByRole("heading", { name: label }).click();
  await expect(app(page).getByText("✔ Persona verified")).toBeVisible({ timeout: 60_000 });

  // Flip one hex digit of the challenge: the signature must stop verifying.
  const url = new URL(page.url());
  const challenge = url.searchParams.get("challenge")!;
  url.searchParams.set("challenge", (challenge[0] === "0" ? "1" : "0") + challenge.slice(1));
  await page.goto(url.toString());
  await expect(app(page).getByText("✘ Not verified")).toBeVisible({ timeout: 60_000 });
});
