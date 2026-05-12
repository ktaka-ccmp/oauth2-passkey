import { test, expect } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { registerPasskeyFromLogin } from '../helpers/auth-flows';
import { resetDb } from '../helpers/db';

test('register passkey, log out, sign back in with passkey', async ({
  page,
}) => {
  if (process.env.E2E_BROWSER_LOG) {
    page.on('console', (msg) =>
      console.log(`[browser:${msg.type()}]`, msg.text()),
    );
    page.on('pageerror', (err) => console.log('[pageerror]', err.message));
  }

  await resetDb();
  await page.goto('/o2p/user/login');
  const authenticator = await addVirtualAuthenticator(page);

  // --- Register ---
  await registerPasskeyFromLogin(page, 'e2e-user', 'E2E User');

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
  await page.getByTestId('login-passkey-signin').click();
  await authFinish;
  await page.waitForLoadState('networkidle');

  await page.goto('/');
  await expect(page.locator('body')).toContainText(/protected page/i);

  await authenticator.remove();
});
