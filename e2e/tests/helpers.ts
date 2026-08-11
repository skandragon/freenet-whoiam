import { expect, FrameLocator, Page } from "@playwright/test";

// The node serves the webapp inside a sandboxed shell iframe.
export function app(page: Page): FrameLocator {
  return page.frameLocator("iframe");
}

export async function open(page: Page) {
  expect(process.env.WHOIAM_URL, "set WHOIAM_URL to the whoiam site on a test node").toBeTruthy();
  // Not goto("/"): that resolves against the ORIGIN and lands on the node
  // dashboard, dropping the /v1/contract/web/<key>/ path.
  await page.goto(process.env.WHOIAM_URL!);
}

// Onboard if this node's delegate has no seed yet; land on Home either way.
export async function ensureOnboarded(page: Page) {
  await open(page);
  const a = app(page);
  const getStarted = a.getByRole("button", { name: "Get started" });
  const home = a.getByRole("heading", { name: "New persona" });
  await expect(getStarted.or(home).first()).toBeVisible({ timeout: 60_000 });
  if (await getStarted.isVisible()) {
    await getStarted.click();
    await expect(home).toBeVisible({ timeout: 30_000 });
  }
}

export async function createIdentity(page: Page, label: string) {
  const a = app(page);
  await a.getByPlaceholder("label (only you see this)").fill(label);
  await a.getByRole("button", { name: "Create", exact: true }).click();
  // Landing on the detail view proves the PUT went out.
  await expect(a.getByRole("heading", { name: label })).toBeVisible({ timeout: 60_000 });
}
