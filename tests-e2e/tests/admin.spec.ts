import { test, expect } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { registerPasskeyFromLogin } from '../helpers/auth-flows';
import { resetDb } from '../helpers/db';
import { DEMO_BASE_URL, MOCK_OIDC_URL } from '../helpers/endpoints';

test('admin: list users and force-logout a second user', async ({
  browser,
}) => {
  if (process.env.E2E_BROWSER_LOG) {
    console.log('[admin spec] starting');
  }

  await resetDb();

  // --- 1) Admin user (passkey) — first registration => sequence_number = 1
  //         and is_admin = true.
  const adminCtx = await browser.newContext();
  const adminPage = await adminCtx.newPage();
  await adminPage.goto('/o2p/user/login');
  const adminAuth = await addVirtualAuthenticator(adminPage);
  await registerPasskeyFromLogin(adminPage, 'e2e-admin', 'E2E Admin');

  // Admin link is only rendered on the account page when is_admin is true.
  await adminPage.goto('/o2p/user/account');
  await expect(adminPage.getByTestId('account-admin-link')).toBeVisible();

  // --- 2) Second user via OAuth2. Use mock-oidc /test/config to give them
  //        a distinct identity so they don't collide with the admin.
  const adminApi = await adminCtx.request;
  await adminApi.post(`${MOCK_OIDC_URL}/test/config`, {
    data: {
      email: 'second@example.com',
      sub: 'google_second-user',
      name: 'Second User',
      given_name: 'Second',
      family_name: 'User',
    },
  });

  const userCtx = await browser.newContext();
  const userPage = await userCtx.newPage();
  await userPage.goto('/o2p/user/login');
  // The OAuth2 button opens a popup that drives the auth-code flow against
  // mock-oidc. Promotion popup is enabled (`O2P_PASSKEY_PROMOTION=ask`); we
  // dismiss it to leave the second user without a passkey.
  const popupPromise = userCtx.waitForEvent('page');
  await userPage.getByTestId('login-oauth2-google').click();
  const popup = await popupPromise;
  await popup.waitForURL(/\/o2p\/passkey\/promotion\/popup/, {
    timeout: 15_000,
  });
  await popup.locator('#passkey-promo-dismiss').click();
  await popup.waitForEvent('close', { timeout: 10_000 });
  await userPage.waitForLoadState('networkidle');

  // Confirm the second user has an active session by hitting a protected
  // route.
  await userPage.goto('/');
  await expect(userPage.locator('body')).toContainText(/protected page/i);

  // --- 3) Admin views the user list — both users should appear, and the
  //        second user's session indicator should be active.
  await adminPage.goto('/o2p/admin/index');
  await expect(adminPage.getByTestId('admin-user-row')).toHaveCount(2);
  await expect(
    adminPage.locator('tr[data-user-id]').filter({ hasText: 'e2e-admin' }),
  ).toHaveCount(1);
  await expect(
    adminPage
      .locator('tr[data-user-id]')
      .filter({ hasText: 'second@example.com' }),
  ).toHaveCount(1);

  const secondRow = adminPage
    .locator('tr[data-user-id]')
    .filter({ hasText: 'second@example.com' });
  const secondUserId = await secondRow.getAttribute('data-user-id');
  expect(secondUserId).toBeTruthy();

  // Session status is filled in asynchronously by client-side JS; wait for
  // the active indicator to render.
  await expect(
    adminPage.locator(`#session-status-${secondUserId} .status-active`),
  ).toBeVisible({ timeout: 5_000 });

  // --- 4) Force logout the second user via the admin user-detail page.
  await adminPage.goto(`/o2p/admin/user/${secondUserId}`);
  await expect(adminPage.getByTestId('admin-user-session-count')).toHaveText(
    /^[1-9]\d*$/,
    { timeout: 5_000 },
  );

  // Auto-accept the JS confirm() dialog the button raises.
  adminPage.on('dialog', (d) => d.accept());
  const logoutResp = adminPage.waitForResponse(
    (r) =>
      r.url().endsWith(`/o2p/admin/user/${secondUserId}/logout`) &&
      r.request().method() === 'POST' &&
      r.status() === 200,
  );
  await adminPage.getByTestId('admin-force-logout-btn').click();
  await logoutResp;

  // Session count drops to 0; the button is hidden by the page JS.
  await expect(adminPage.getByTestId('admin-user-session-count')).toHaveText(
    '0',
    { timeout: 5_000 },
  );

  // --- 5) Verify the second user is actually logged out — a protected
  //        route should now redirect to login (no body text).
  const protectedReq = await userCtx.request.get(`${DEMO_BASE_URL}/`, {
    maxRedirects: 0,
    failOnStatusCode: false,
  });
  expect([302, 303, 307]).toContain(protectedReq.status());
  const location = protectedReq.headers()['location'] ?? '';
  expect(location).toMatch(/\/o2p\/user\/login/);

  await adminAuth.remove();
  await adminCtx.close();
  await userCtx.close();
});

test('admin: toggle a second user\'s admin status, then delete them', async ({
  browser,
}) => {
  await resetDb();

  // --- 1) Admin via passkey (first user => sequence_number == 1 => is_admin)
  const adminCtx = await browser.newContext();
  const adminPage = await adminCtx.newPage();
  await adminPage.goto('/o2p/user/login');
  const adminAuth = await addVirtualAuthenticator(adminPage);
  await registerPasskeyFromLogin(adminPage, 'e2e-admin', 'E2E Admin');

  // --- 2) Second user via OAuth2 (distinct identity via mock-oidc /test/config)
  await adminCtx.request.post(`${MOCK_OIDC_URL}/test/config`, {
    data: {
      email: 'second@example.com',
      sub: 'google_second-user',
      name: 'Second User',
      given_name: 'Second',
      family_name: 'User',
    },
  });

  const userCtx = await browser.newContext();
  const userPage = await userCtx.newPage();
  await userPage.goto('/o2p/user/login');
  const popupPromise = userCtx.waitForEvent('page');
  await userPage.getByTestId('login-oauth2-google').click();
  const popup = await popupPromise;
  await popup.waitForURL(/\/o2p\/passkey\/promotion\/popup/, {
    timeout: 15_000,
  });
  await popup.locator('#passkey-promo-dismiss').click();
  await popup.waitForEvent('close', { timeout: 10_000 });
  await userPage.waitForLoadState('networkidle');

  // --- 3) Locate the second user's row on the admin index. Bootstrap admin
  //         (sequence_number == 1) has no toggle/delete button; non-bootstrap
  //         rows do, so the test naturally operates on the second user.
  await adminPage.goto('/o2p/admin/index');
  await expect(adminPage.getByTestId('admin-user-row')).toHaveCount(2);
  const secondRow = adminPage
    .locator('tr[data-user-id]')
    .filter({ hasText: 'second@example.com' });
  const secondUserId = await secondRow.getAttribute('data-user-id');
  expect(secondUserId).toBeTruthy();

  // Auto-accept confirm() + the success alert() the JS handlers raise.
  adminPage.on('dialog', (d) => d.accept());

  // --- 4) Toggle admin off->on. The UI shows is_admin as a string; assert
  //         on the inline status span the JS updates.
  const statusSpan = adminPage.locator(`#admin-status-${secondUserId}`);
  await expect(statusSpan).toHaveText('false');

  const toggleOnResp = adminPage.waitForResponse(
    (r) =>
      r.url().endsWith('/o2p/admin/update_admin_status') &&
      r.request().method() === 'PUT' &&
      r.status() === 200,
  );
  await secondRow.getByTestId('admin-toggle-admin-btn').click();
  await toggleOnResp;
  await expect(statusSpan).toHaveText('true');

  // Toggle back off — verifies the button's onclick was rewired with the
  // new status by the client-side handler.
  const toggleOffResp = adminPage.waitForResponse(
    (r) =>
      r.url().endsWith('/o2p/admin/update_admin_status') &&
      r.request().method() === 'PUT' &&
      r.status() === 200,
  );
  await secondRow.getByTestId('admin-toggle-admin-btn').click();
  await toggleOffResp;
  await expect(statusSpan).toHaveText('false');

  // --- 5) Delete the second user from the admin index. The handler
  //         returns 204 No Content on success.
  const deleteResp = adminPage.waitForResponse(
    (r) =>
      r.url().endsWith('/o2p/admin/delete_user') &&
      r.request().method() === 'DELETE' &&
      r.status() === 204,
  );
  await secondRow.getByTestId('admin-delete-user-btn').click();
  await deleteResp;
  // The JS calls window.location.reload(); wait for the row count to drop.
  await expect(adminPage.getByTestId('admin-user-row')).toHaveCount(1, {
    timeout: 5_000,
  });

  // --- 6) The deleted user's protected-route access must now redirect to
  //         login (account + cascaded session are gone).
  const protectedReq = await userCtx.request.get(`${DEMO_BASE_URL}/`, {
    maxRedirects: 0,
    failOnStatusCode: false,
  });
  expect([302, 303, 307]).toContain(protectedReq.status());
  expect(protectedReq.headers()['location'] ?? '').toMatch(
    /\/o2p\/user\/login/,
  );

  await adminAuth.remove();
  await adminCtx.close();
  await userCtx.close();
});
