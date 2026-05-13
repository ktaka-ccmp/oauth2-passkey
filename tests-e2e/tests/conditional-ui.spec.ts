import { test, expect } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { registerPasskeyFromLogin } from '../helpers/auth-flows';
import { resetDb } from '../helpers/db';

test('conditional UI: existing passkey auto-resolves on the conditional UI page', async ({
  page,
}) => {
  if (process.env.E2E_BROWSER_LOG) {
    page.on('console', (m) =>
      console.log(`[browser:${m.type()}]`, m.text()),
    );
    page.on('pageerror', (e) => console.log('[pageerror]', e.message));
  }

  await resetDb();

  // --- Register a passkey we can later auto-resolve against.
  await page.goto('/o2p/user/login');
  const authenticator = await addVirtualAuthenticator(page);
  await registerPasskeyFromLogin(page, 'e2e-cond-user', 'E2E Cond UI');

  // --- Log out so the conditional UI page exercises a fresh login.
  await page.goto('/o2p/user/logout?redirect=/o2p/user/login');
  await expect(page).toHaveURL(/\/o2p\/user\/login/);

  // --- Go to the conditional UI page. On page load the JS issues
  //     `navigator.credentials.get({ mediation: 'conditional' })`. With the
  //     virtual authenticator's `automaticPresenceSimulation` enabled, CDP
  //     resolves the get() with the existing credential, the page POSTs to
  //     `/passkey/auth/finish`, and JS sets `window.location.href = '/'`.
  //     The whole chain happens fast enough that asserting the
  //     intermediate URL would race against the redirect — instead we
  //     listen for the auth/finish response and the final URL.
  const authFinish = page.waitForResponse(
    (r) =>
      r.url().endsWith('/o2p/passkey/auth/finish') && r.status() === 200,
    { timeout: 15_000 },
  );

  await page.goto('/o2p/passkey/conditional_ui', {
    waitUntil: 'domcontentloaded',
  });

  await authFinish;
  await page.waitForURL(/\/$/, { timeout: 10_000 });
  await expect(page.locator('body')).toContainText(/protected page/i);

  await authenticator.remove();
});
