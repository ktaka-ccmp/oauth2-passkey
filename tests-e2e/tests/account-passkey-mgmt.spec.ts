import { test, expect } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import {
  addPasskeyFromAccount,
  registerPasskeyFromLogin,
} from '../helpers/auth-flows';
import { resetDb } from '../helpers/db';
import { DEMO_BASE_URL } from '../helpers/endpoints';

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

  await resetDb();
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
    .getByTestId('passkey-delete-btn')
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

test('account page: logout via Logout button clears the session', async ({
  page,
  context,
}) => {
  await resetDb();
  await page.goto('/o2p/user/login');
  const authenticator = await addVirtualAuthenticator(page);
  await registerPasskeyFromLogin(page, 'e2e-logout-user', 'E2E Logout User');

  await page.goto('/o2p/user/account');
  // The button navigates to /o2p/user/logout?redirect=... and the server
  // clears the cookie + redirects to the default page. Wait for the
  // navigation chain to settle.
  await Promise.all([
    page.waitForURL((url) => !url.pathname.includes('/user/account'), {
      timeout: 10_000,
    }),
    page.getByTestId('account-logout-btn').click(),
  ]);

  // Protected route now redirects unauth users to login.
  const protectedReq = await context.request.get(`${DEMO_BASE_URL}/`, {
    maxRedirects: 0,
    failOnStatusCode: false,
  });
  expect([302, 303, 307]).toContain(protectedReq.status());
  expect(protectedReq.headers()['location'] ?? '').toMatch(
    /\/o2p\/user\/login/,
  );

  await authenticator.remove();
});

test('account page: Delete Account removes the user and ends the session', async ({
  browser,
}) => {
  await resetDb();

  // First user becomes the bootstrap admin (sequence_number == 1). The
  // server refuses to delete the last admin, so we register a throwaway
  // admin first and then a second user who is the actual target.
  const adminCtx = await browser.newContext();
  const adminPage = await adminCtx.newPage();
  await adminPage.goto('/o2p/user/login');
  const adminAuth = await addVirtualAuthenticator(adminPage);
  await registerPasskeyFromLogin(adminPage, 'e2e-keepalive-admin', 'Admin');

  const userCtx = await browser.newContext();
  const userPage = await userCtx.newPage();
  await userPage.goto('/o2p/user/login');
  const userAuth = await addVirtualAuthenticator(userPage);
  await registerPasskeyFromLogin(userPage, 'e2e-delete-user', 'E2E Delete User');

  await userPage.goto('/o2p/user/account');

  // The DeleteAccount() handler raises confirm() then alert() on success
  // before reloading the page. Auto-accept both.
  userPage.on('dialog', (d) => d.accept());

  const deleteResp = userPage.waitForResponse(
    (r) =>
      r.url().endsWith('/o2p/user/delete') &&
      r.request().method() === 'DELETE' &&
      r.status() === 200,
  );
  await userPage.getByTestId('account-delete-btn').click();
  await deleteResp;

  // The page reloads after the alert; once the user record is gone the
  // account page can no longer render and the request is redirected to
  // login. Wait for that landing state.
  await userPage.waitForURL(/\/o2p\/user\/login/, { timeout: 10_000 });

  // Protected route is rejected: server-side session was destroyed even if
  // the cookie survives client-side.
  const protectedReq = await userCtx.request.get(`${DEMO_BASE_URL}/`, {
    maxRedirects: 0,
    failOnStatusCode: false,
  });
  expect([302, 303, 307]).toContain(protectedReq.status());
  expect(protectedReq.headers()['location'] ?? '').toMatch(
    /\/o2p\/user\/login/,
  );

  await userAuth.remove();
  await adminAuth.remove();
  await userCtx.close();
  await adminCtx.close();
});
