import { expect, test } from "@playwright/test";

// Load the built page (Playwright's webServer config in
// `playwright.config.ts` starts `vite preview --port 4173` first) and
// wait until the smoke script reports either `SMOKE OK` or
// `SMOKE FAILED`. Fail if not OK.
test("chromium browser uses @jacs/wasm to sign and verify", async (
  { page },
  testInfo,
) => {
  expect(testInfo.project.name).toBe("chromium");

  await page.goto("/");
  const output = page.getByTestId("output");
  await expect(output).toContainText(/SMOKE OK|SMOKE FAILED/, {
    timeout: 15_000,
  });
  const text = (await output.textContent()) ?? "";

  expect(text, "smoke output should contain SMOKE OK").toContain("SMOKE OK");
  expect(text, "smoke output should not contain SMOKE FAILED").not.toContain(
    "SMOKE FAILED",
  );
  expect(text, "smoke output should include public key generation").toMatch(
    /pk len: \d+/,
  );
  expect(text, "smoke output should include signed document length").toMatch(
    /signed length: \d+/,
  );
  expect(text, "smoke output should include successful verification").toContain(
    "verify.valid = true",
  );
});
