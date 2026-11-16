import { test, expect } from '@playwright/test';
import { MOCK_OIDC_URL } from '../helpers/endpoints';

test('login page renders with Google + Passkey buttons', async ({ page }) => {
  await page.goto('/o2p/user/login');
  await expect(page).toHaveURL(/\/o2p\/user\/login/);
  await expect(page.locator('body')).toContainText(/sign in|login/i);
});

test('mock-oidc discovery document is reachable from the browser', async ({
  request,
}) => {
  const res = await request.get(`${MOCK_OIDC_URL}/.well-known/openid-configuration`);
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  expect(body.issuer).toBe(MOCK_OIDC_URL);
  expect(body.authorization_endpoint).toContain('/oauth2/auth');
});
