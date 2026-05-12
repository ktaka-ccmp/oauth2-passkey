import { test, expect } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import {
  addPasskeyFromAccount,
  registerPasskeyFromLogin,
} from '../helpers/auth-flows';

test('account page: add a second passkey, then delete the first one', async ({
  page,
}) => {
  if (process.env.E2E_BROWSER_LOG) {
    page.on('console', (m) =>
      console.log(`[browser:${m.type()}]`, m.text()),
    );
    page.on('pageerror', (e) => console.log('[pageerror]', e.message));
    page.on('requestfailed', (r) =>
      console.log('[reqfail]', r.url(), r.failure()?.errorText),
    );
  }

  await page.goto('/o2p/user/login');
  // First virtual authenticator: stands in for the user's primary device.
  const authenticator1 = await addVirtualAuthenticator(page);

  // --- Initial registration (logs in) ---
  await registerPasskeyFromLogin(page, 'e2e-acct-user', 'E2E Account User');

  // --- Land on account page ---
  await page.goto('/o2p/user/account');
  await expect(page.locator('.item.passkey')).toHaveCount(1);
  const firstCredId = await page
    .locator('.item.passkey')
    .first()
    .getAttribute('data-credential-id');
  expect(firstCredId).toBeTruthy();

  // --- Add a second passkey ---
  // A second virtual authenticator simulates registering on a different
  // device. Without this, the only attached authenticator already holds the
  // credential for this user_handle and rejects the create() with
  // InvalidStateError (per WebAuthn excludeCredentials handling).
  // Use `usb` transport because Chrome only allows one `internal` (platform)
  // authenticator per browser context.
  const authenticator2 = await addVirtualAuthenticator(page, {
    transport: 'usb',
  });
  await addPasskeyFromAccount(page, 'e2e-acct-second', 'E2E Second');
  await expect(page.locator('.item.passkey')).toHaveCount(2);

  // --- Delete the first passkey ---
  // The Delete button triggers a window.confirm; auto-accept it.
  page.on('dialog', (d) => d.accept());

  const deleteFinish = page.waitForResponse(
    (r) =>
      r.url().includes(`/o2p/passkey/credentials/${firstCredId}`) &&
      r.request().method() === 'DELETE' &&
      r.status() === 200,
  );
  await page
    .locator(`.item.passkey[data-credential-id="${firstCredId}"]`)
    .locator('.delete-button')
    .click();
  await deleteFinish;
  await page.waitForLoadState('networkidle');

  await expect(page.locator('.item.passkey')).toHaveCount(1);
  // The remaining credential is the second one we just added.
  await expect(
    page.locator(`.item.passkey[data-credential-id="${firstCredId}"]`),
  ).toHaveCount(0);

  await authenticator2.remove();
  await authenticator1.remove();
});
