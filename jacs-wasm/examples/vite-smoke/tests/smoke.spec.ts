import { expect, test } from "@playwright/test";

// Load the built page (Playwright's webServer config in
// `playwright.config.ts` starts `vite preview --port 4173` first) and
// wait until the smoke script reports either `SMOKE OK` or
// `SMOKE FAILED`. Fail if not OK.
test("vite smoke signs and verifies via @jacs/wasm", async ({ page }) => {
  await page.goto("/");
  const output = page.getByTestId("output");
  await expect(output).toContainText(/SMOKE OK|SMOKE FAILED/, { timeout: 15_000 });
  const text = (await output.textContent()) ?? "";
  expect(text, "smoke output should contain SMOKE OK").toContain("SMOKE OK");
});
