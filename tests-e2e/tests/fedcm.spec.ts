import { test, expect } from '@playwright/test';
import { resetDb } from '../helpers/db';
import { DEMO_BASE_URL, MOCK_OIDC_URL } from '../helpers/endpoints';

/**
 * FedCM is exercised at the API level rather than via the browser's
 * `navigator.credentials.get({ identity: ... })` dialog. The dialog
 * requires a real IdP config endpoint (Google's `gsi/fedcm.json`) that we
 * can't reach from localhost in CI, and Chrome's FedCM dialog automation
 * via CDP is brittle. The library code path under test is the same:
 *
 *   1. GET  /o2p/oauth2/fedcm/nonce      -> { nonce, nonce_id }
 *   2. POST /o2p/oauth2/fedcm/callback   -> { credential, nonce_id, mode }
 *
 * We mint the JWT via mock-oidc's `/test/issue_token`, which signs with
 * the same key the JWKS endpoint advertises, so the library validates
 * the token end-to-end (signature, issuer, audience, nonce, expiry).
 */
test('FedCM: API-level nonce + callback creates a session', async ({
  request,
  browser,
}) => {
  await resetDb();

  // --- 1) Get a nonce from the SUT.
  const nonceResp = await request.get(
    `${DEMO_BASE_URL}/o2p/oauth2/fedcm/nonce`,
  );
  expect(nonceResp.ok()).toBeTruthy();
  const { nonce, nonce_id } = await nonceResp.json();
  expect(nonce).toBeTruthy();
  expect(nonce_id).toBeTruthy();

  // --- 2) Have mock-oidc mint a JWT with that nonce. The default audience
  //         matches the configured Google client_id, which is what
  //         oauth2-passkey expects.
  const tokenResp = await request.post(
    `${MOCK_OIDC_URL}/test/issue_token`,
    { data: { nonce } },
  );
  expect(tokenResp.ok()).toBeTruthy();
  const { id_token } = await tokenResp.json();
  expect(id_token).toBeTruthy();

  // --- 3) Hit the callback inside a browser context so the Set-Cookie
  //         lands in a cookie jar we can reuse for the protected-route
  //         check.
  const ctx = await browser.newContext();
  try {
    const callbackResp = await ctx.request.post(
      `${DEMO_BASE_URL}/o2p/oauth2/fedcm/callback`,
      {
        data: {
          credential: id_token,
          nonce_id,
          mode: 'create_user_or_login',
        },
      },
    );
    expect(callbackResp.ok()).toBeTruthy();

    // --- 4) The cookie jar should now hold a session; protected route
    //         returns the page body instead of redirecting to login.
    const page = await ctx.newPage();
    await page.goto('/');
    await expect(page.locator('body')).toContainText(/protected page/i);
  } finally {
    await ctx.close();
  }
});

test('FedCM: callback rejects token with wrong nonce', async ({ request }) => {
  await resetDb();

  // Fetch a valid nonce_id but mint the token with a different nonce.
  const nonceResp = await request.get(
    `${DEMO_BASE_URL}/o2p/oauth2/fedcm/nonce`,
  );
  expect(nonceResp.ok()).toBeTruthy();
  const { nonce_id } = await nonceResp.json();

  const tokenResp = await request.post(
    `${MOCK_OIDC_URL}/test/issue_token`,
    { data: { nonce: 'wrong-nonce-value' } },
  );
  const { id_token } = await tokenResp.json();

  const callbackResp = await request.post(
    `${DEMO_BASE_URL}/o2p/oauth2/fedcm/callback`,
    {
      data: { credential: id_token, nonce_id, mode: 'create_user_or_login' },
      failOnStatusCode: false,
    },
  );
  expect(callbackResp.ok()).toBeFalsy();
});
