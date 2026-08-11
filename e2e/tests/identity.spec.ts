import { test, expect, FrameLocator, Page } from "@playwright/test";

// The node serves the webapp inside a sandboxed shell iframe.
function app(page: Page): FrameLocator {
  return page.frameLocator("iframe");
}

async function open(page: Page) {
  expect(process.env.WHOIAM_URL, "set WHOIAM_URL to the whoiam site on a test node").toBeTruthy();
  await page.goto("/");
}

// Onboard if this node's delegate has no seed yet; land on Home either way.
async function ensureOnboarded(page: Page) {
  await open(page);
  const a = app(page);
  const getStarted = a.getByRole("button", { name: "Get started" });
  const backup = a.getByRole("button", { name: "Download backup" });
  await expect(getStarted.or(backup).first()).toBeVisible({ timeout: 60_000 });
  if (await getStarted.isVisible()) {
    await getStarted.click();
    await expect(backup).toBeVisible({ timeout: 30_000 });
  }
}

async function createIdentity(page: Page, label: string) {
  const a = app(page);
  await a.getByPlaceholder("label (only you see this)").fill(label);
  await a.getByRole("button", { name: "Create", exact: true }).click();
  // Landing on the detail view proves the PUT went out.
  await expect(a.getByRole("heading", { name: label })).toBeVisible({ timeout: 60_000 });
}

test("onboarding creates the key store", async ({ page }) => {
  await ensureOnboarded(page);
  await expect(app(page).getByRole("button", { name: "Download backup" })).toBeVisible();
});

test("create identity, publish profile, survives reload", async ({ page }) => {
  await ensureOnboarded(page);
  const label = `e2e-${Date.now()}`;
  await createIdentity(page, label);

  const a = app(page);
  await a.getByPlaceholder("shown in apps").fill(label);
  await a.getByPlaceholder(/a line about you/).fill("published by the e2e suite");
  await a.getByRole("button", { name: "Publish" }).click();
  await expect(a.getByText("published ✓")).toBeVisible({ timeout: 60_000 });

  await page.reload();
  const after = app(page);
  // The card shows the published name and bio after a full reload
  // (seed from delegate, state re-fetched from the network).
  await expect(after.getByRole("heading", { name: label })).toBeVisible({ timeout: 60_000 });
  await expect(after.getByText("published by the e2e suite")).toBeVisible({ timeout: 60_000 });
});

test("backup downloads the seed file", async ({ page }) => {
  await ensureOnboarded(page);
  const downloadPromise = page.waitForEvent("download");
  await app(page).getByRole("button", { name: "Download backup" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("whoiam-seed.txt");
  const path = await download.path();
  const fs = await import("node:fs/promises");
  const text = await fs.readFile(path!, "utf8");
  expect(text).toMatch(/hex:\n[0-9a-f]{64}\n/);
  expect(text.split("recovery phrase")[1]?.trim().split(/\s+/).length).toBeGreaterThanOrEqual(24);
});

test("destroy removes the identity from the list", async ({ page }) => {
  await ensureOnboarded(page);
  const label = `doomed-${Date.now()}`;
  await createIdentity(page, label);

  const a = app(page);
  await a.getByPlaceholder(label).fill(label); // type-to-confirm input
  await a.getByRole("button", { name: "Destroy this identity forever" }).click();
  // Back on Home without the destroyed identity's card.
  await expect(a.getByRole("heading", { name: "New identity" })).toBeVisible({ timeout: 60_000 });
  await expect(a.getByRole("heading", { name: label })).toHaveCount(0);
});
