// SPDX-License-Identifier: MIT
import { test, expect, type Page } from "@playwright/test";

/**
 * E2E run of the full pk-auth ceremony + admin surface, driven through the demo's
 * SPA. Uses Chrome's CDP virtual WebAuthn authenticator so passkeys work without a
 * physical security key. Each test installs a fresh authenticator scoped to the
 * page, so tests don't share credential state.
 */

interface VirtualAuthenticator {
  authenticatorId: string;
}

async function installVirtualAuthenticator(
  page: Page,
  transport: "internal" | "usb" = "internal",
): Promise<VirtualAuthenticator> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const result = (await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport,
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  })) as { authenticatorId: string };
  return { authenticatorId: result.authenticatorId };
}

test.describe("pk-auth Spring Boot demo — full flow", () => {
  test.beforeEach(async ({ page }) => {
    await installVirtualAuthenticator(page);
    await page.goto("/");
  });

  test("register then login mints a JWT", async ({ page }) => {
    await page.fill("#reg-username", `alice-${Date.now()}`);
    await page.click("#btn-register");

    await expect(page.locator("#register-out")).toContainText("credentialId", { timeout: 15_000 });

    const username = await page.inputValue("#reg-username");
    await page.fill("#login-username", username);
    await page.click("#btn-login");

    await expect(page.locator("#login-out")).toContainText("token", { timeout: 15_000 });
    await expect(page.locator("#jwt-out")).toContainText("sub", { timeout: 5_000 });
  });

  test("list, rename, and delete a passkey", async ({ page }) => {
    const username = `bob-${Date.now()}`;
    await page.fill("#reg-username", username);
    await page.fill("#reg-label", "first key");
    await page.click("#btn-register");
    await expect(page.locator("#register-out")).toContainText("credentialId");

    await page.fill("#login-username", username);
    await page.click("#btn-login");
    await expect(page.locator("#login-out")).toContainText("token");

    // Add a second passkey so we can exercise delete: the admin API blocks deletion
    // of a user's last credential (409 Conflict), which is the right policy but
    // would make a single-key delete test unrealistic. The server-issued
    // excludeCredentials would make the original virtual authenticator refuse a
    // second registration (per spec InvalidStateError) — install a *second*
    // virtual authenticator so the fresh one accepts the create() call. Chrome
    // only permits one "internal" authenticator at a time, so use USB transport
    // for the second.
    await installVirtualAuthenticator(page, "usb");
    await page.fill("#reg-label", "second key");
    const [secondFinish] = await Promise.all([
      page.waitForResponse(
        (r) =>
          r.url().includes("/auth/passkeys/registration/finish") && r.request().method() === "POST",
      ),
      page.click("#btn-register-again"),
    ]);
    expect(secondFinish.status()).toBe(200);

    await page.click("#btn-creds");
    const credList = page.locator("#cred-list li");
    await expect(credList).toHaveCount(2);

    // Rename — accept the prompt and wait for the PATCH to land before re-asserting.
    page.once("dialog", (dialog) => {
      expect(dialog.type()).toBe("prompt");
      dialog.accept("renamed key");
    });
    const [renameResp] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes("/auth/admin/credentials/") && r.request().method() === "PATCH",
      ),
      page.locator('#cred-list button[data-action="rename"]').first().click(),
    ]);
    expect(renameResp.status()).toBe(200);
    await expect(credList.first()).toContainText("renamed key");

    // Delete — accept the confirm and wait for the DELETE to land.
    page.once("dialog", (dialog) => {
      expect(dialog.type()).toBe("confirm");
      dialog.accept();
    });
    const [deleteResp] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes("/auth/admin/credentials/") && r.request().method() === "DELETE",
      ),
      page.locator('#cred-list button[data-action="delete"]').first().click(),
    ]);
    expect(deleteResp.status()).toBeLessThan(300);
    await expect(credList).toHaveCount(1, { timeout: 10_000 });
  });

  test("regenerate backup codes and check remaining count", async ({ page }) => {
    const username = `carol-${Date.now()}`;
    await page.fill("#reg-username", username);
    await page.click("#btn-register");
    await expect(page.locator("#register-out")).toContainText("credentialId");

    await page.fill("#login-username", username);
    await page.click("#btn-login");
    await expect(page.locator("#login-out")).toContainText("token");

    const [regenResp] = await Promise.all([
      page.waitForResponse(
        (r) =>
          r.url().includes("/auth/admin/backup-codes/regenerate") &&
          r.request().method() === "POST",
      ),
      page.click("#btn-backup-regen"),
    ]);
    expect(regenResp.status()).toBe(200);
    const regenJson = (await regenResp.json()) as { codes: string[] };
    expect(regenJson.codes.length).toBeGreaterThan(0);

    // The remaining-count endpoint returns either `{"remaining":N}` (spring/micronaut)
    // or a bare integer (dropwizard); both render as digits in the output.
    await page.click("#btn-backup-count");
    await expect(page.locator("#backup-out")).toContainText(/[0-9]+/, { timeout: 5_000 });
  });

  test("start email verification dispatches a magic link", async ({ page }) => {
    const username = `dave-${Date.now()}`;
    await page.fill("#reg-username", username);
    await page.click("#btn-register");
    await expect(page.locator("#register-out")).toContainText("credentialId");

    await page.fill("#login-username", username);
    await page.click("#btn-login");
    await expect(page.locator("#login-out")).toContainText("token");

    await page.fill("#email", "dave@example.com");
    await page.click("#btn-email-start");
    // Logging dispatcher returns no plaintext token (it logs it). The demo just shows
    // the empty/dispatched response. So we assert the call did not error out.
    await expect(page.locator("#email-out")).not.toHaveClass(/err/, { timeout: 5_000 });
  });

  test("start phone verification dispatches an OTP", async ({ page }) => {
    const username = `eve-${Date.now()}`;
    await page.fill("#reg-username", username);
    await page.click("#btn-register");
    await expect(page.locator("#register-out")).toContainText("credentialId");

    await page.fill("#login-username", username);
    await page.click("#btn-login");
    await expect(page.locator("#login-out")).toContainText("token");

    await page.fill("#phone", "+15551234567");
    await page.click("#btn-phone-start");
    await expect(page.locator("#phone-out")).not.toHaveClass(/err/, { timeout: 5_000 });
  });
});
