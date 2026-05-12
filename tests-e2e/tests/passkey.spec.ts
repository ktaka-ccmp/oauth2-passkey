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

  const registrationFinish = page.waitForResponse(
    (resp) =>
      resp.url().endsWith('/o2p/passkey/register/finish') &&
      resp.status() === 200,
  );
  await modal.getByRole('button', { name: 'Register', exact: true }).click();
  await registrationFinish;
  // The frontend calls `location.reload()` after /register/finish succeeds.
  // Wait for that reload to settle before our next navigation, otherwise
  // page.goto races with the reload.
  await page.waitForLoadState('networkidle');

  // Verify auth by visiting a protected route.
  await page.goto('/');
  await expect(page.locator('body')).toContainText(/protected page/i);

  // --- Logout ---
  // The logout handler only redirects when the `redirect` query is supplied;
  // without it the response is just header-clearing with no body.
  await page.goto('/o2p/user/logout?redirect=/o2p/user/login');
  await expect(page).toHaveURL(/\/o2p\/user\/login/);

  // --- Sign back in ---
  const authFinish = page.waitForResponse(
    (resp) =>
      resp.url().endsWith('/o2p/passkey/auth/finish') && resp.status() === 200,
  );
  await page.getByRole('button', { name: /Sign in with Passkey/i }).click();
  await authFinish;
  await page.waitForLoadState('networkidle');

  await page.goto('/');
  await expect(page.locator('body')).toContainText(/protected page/i);

  await authenticator.remove();
});
