import { test, expect } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';

test('register passkey, log out, sign back in with passkey', async ({
  page,
}) => {
  if (process.env.E2E_BROWSER_LOG) {
    page.on('console', (msg) =>
      console.log(`[browser:${msg.type()}]`, msg.text()),
    );
    page.on('pageerror', (err) => console.log('[pageerror]', err.message));
  }

  await page.goto('/o2p/user/login');
  const authenticator = await addVirtualAuthenticator(page);

  // --- Register ---
  await page
    .getByRole('button', { name: /Register with Passkey/i })
    .click();
  const modal = page.locator('#registration-modal');
  await expect(modal).toBeVisible();
  await modal.locator('#reg-username').fill('e2e-user');
  await modal.locator('#reg-displayname').fill('E2E User');

  // Match on the URL only and check the status below, so a failed finish
  // request is reported as such rather than as a missing reload.
  const registrationFinish = page.waitForResponse((resp) =>
    resp.url().endsWith('/o2p/passkey/register/finish'),
  );
  // The frontend calls `location.reload()` after /register/finish succeeds.
  // Start waiting for that load before clicking, otherwise page.goto below
  // races with the reload (networkidle returns at once on an idle page).
  const reloadedAfterRegister = page.waitForEvent('load', { timeout: 20_000 });
  await modal.getByRole('button', { name: 'Register', exact: true }).click();
  expect((await registrationFinish).status()).toBe(200);
  await reloadedAfterRegister;

  // Verify auth by visiting a protected route.
  await page.goto('/');
  await expect(page.locator('body')).toContainText(/protected page/i);

  // --- Logout ---
  // The logout handler only redirects when the `redirect` query is supplied;
  // without it the response is just header-clearing with no body.
  await page.goto('/o2p/user/logout?redirect=/o2p/user/login');
  await expect(page).toHaveURL(/\/o2p\/user\/login/);

  // --- Sign back in ---
  const authFinish = page.waitForResponse((resp) =>
    resp.url().endsWith('/o2p/passkey/auth/finish'),
  );
  const reloadedAfterAuth = page.waitForEvent('load', { timeout: 20_000 });
  await page.getByRole('button', { name: /Sign in with Passkey/i }).click();
  expect((await authFinish).status()).toBe(200);
  await reloadedAfterAuth;

  await page.goto('/');
  await expect(page.locator('body')).toContainText(/protected page/i);

  await authenticator.remove();
});
