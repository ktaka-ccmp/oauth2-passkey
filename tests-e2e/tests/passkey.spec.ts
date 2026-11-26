import { test, expect, type Response } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';

// Fails with the server's error body when the status is not 200. The body is
// read only on failure: on success the page reloads at once and the browser
// discards the response body.
async function expectOk(resp: Response): Promise<void> {
  if (resp.status() !== 200) {
    const body = await resp.text().catch(() => '<body unavailable>');
    expect(resp.status(), body).toBe(200);
  }
}

test('register passkey, log out, sign back in with passkey', async ({
  page,
}) => {
  // Room for the bounded waits below (two finish responses, two reloads)
  // plus the navigations and assertions.
  test.setTimeout(60_000);
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
  // Bounded below the reload wait, so a finish request that is never sent is
  // reported here and not as a missing reload.
  const registrationFinish = page.waitForResponse(
    (resp) => resp.url().endsWith('/o2p/passkey/register/finish'),
    { timeout: 15_000 },
  );
  // Avoid an unhandled rejection if an earlier step fails; awaiting the
  // original promise below still reports its own failure.
  registrationFinish.catch(() => {});
  // The frontend calls `location.reload()` after /register/finish succeeds.
  // Start waiting for that load before clicking, otherwise page.goto below
  // races with the reload (networkidle returns at once on an idle page).
  const reloadedAfterRegister = page.waitForEvent('load', { timeout: 20_000 });
  reloadedAfterRegister.catch(() => {});
  await modal.getByRole('button', { name: 'Register', exact: true }).click();
  await expectOk(await registrationFinish);
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
  const authFinish = page.waitForResponse(
    (resp) => resp.url().endsWith('/o2p/passkey/auth/finish'),
    { timeout: 15_000 },
  );
  authFinish.catch(() => {});
  const reloadedAfterAuth = page.waitForEvent('load', { timeout: 20_000 });
  reloadedAfterAuth.catch(() => {});
  await page.getByRole('button', { name: /Sign in with Passkey/i }).click();
  await expectOk(await authFinish);
  await reloadedAfterAuth;

  await page.goto('/');
  await expect(page.locator('body')).toContainText(/protected page/i);

  await authenticator.remove();
});
