import { test, expect } from "@playwright/test";
import { app, createIdentity, ensureOnboarded } from "./helpers";

test("onboarding creates the key store", async ({ page }) => {
  await ensureOnboarded(page);
  await expect(app(page).getByRole("heading", { name: "New persona" })).toBeVisible();
});

test("create identity, publish profile, survives reload", async ({ page }) => {
  await ensureOnboarded(page);
  const label = `e2e-${Date.now()}`;
  await createIdentity(page, label);

  const a = app(page);
  await a.getByRole("button", { name: "change", exact: true }).click();
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

test("backup reveals the seed text", async ({ page }) => {
  await ensureOnboarded(page);
  const a = app(page);
  await a.getByRole("button", { name: "backup", exact: true }).click(); // footer link
  await a.getByRole("button", { name: "Show backup" }).click();
  const text = await a.locator("textarea.backup-text").inputValue();
  expect(text).toMatch(/hex:\n[0-9a-f]{64}\n/);
  expect(text.split("recovery phrase")[1]?.trim().split(/\s+/).length).toBeGreaterThanOrEqual(24);
  await a.getByRole("button", { name: "hide" }).click();
  await expect(a.locator("textarea.backup-text")).toHaveCount(0);
});

test("destroy removes the identity from the list", async ({ page }) => {
  await ensureOnboarded(page);
  const label = `doomed-${Date.now()}`;
  await createIdentity(page, label);

  const a = app(page);
  await a.getByText("Danger zone").click(); // expand the collapsed <details>
  await a.getByPlaceholder(label).fill(label); // type-to-confirm input
  await a.getByRole("button", { name: "Destroy this persona forever" }).click();
  // Back on Home without the destroyed identity's card.
  await expect(a.getByRole("heading", { name: "New persona" })).toBeVisible({ timeout: 60_000 });
  await expect(a.getByRole("heading", { name: label })).toHaveCount(0);
});
