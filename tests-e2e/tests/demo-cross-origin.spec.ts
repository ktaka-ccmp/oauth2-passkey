import { test, expect, request as pwRequest } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { resetDb } from '../helpers/db';
import {
  DEMO_CROSS_ORIGIN_API_URL,
  DEMO_CROSS_ORIGIN_AUTH_URL,
} from '../helpers/endpoints';

/**
 * E2E regression coverage for `demo-cross-origin` (Pattern 2: auth
 * server + separate API server sharing a session cookie).
 *
 * Topology matches the README's "localhost (Easiest)" setup:
 *   Auth: http://localhost:13010
 *   API:  http://localhost:13011
 * Both hosts are `localhost` so the session cookie set by the auth
 * server is automatically sent to the API server by the browser (the
 * cookie spec scopes by host, not port). No SESSION_COOKIE_DOMAIN
 * tweak, no /etc/hosts changes.
 *
 * What this spec guards against silently breaking:
 *  - cross-origin cookie scope of the library's `__Host-SessionId`
 *  - the `is_authenticated_user_401` middleware behaviour on a
 *    separate API server
 *  - the CORS layer permitting credentials from the auth origin
 */

const SESSION_COOKIE = '__Host-SessionId';
const AUTH = DEMO_CROSS_ORIGIN_AUTH_URL;
const API = DEMO_CROSS_ORIGIN_API_URL;

test.describe('demo-cross-origin', () => {
  test.beforeEach(async () => {
    await resetDb(AUTH);
  });

  test('API: anonymous /api/info returns authenticated=false, /api/protected returns 401', async ({
    request,
  }) => {
    const info = await request.get(`${API}/api/info`);
    expect(info.ok()).toBeTruthy();
    const infoBody = await info.json();
    expect(infoBody.authenticated).toBe(false);
    expect(infoBody.server).toBe('API');

    const protectedResp = await request.get(`${API}/api/protected`, {
      failOnStatusCode: false,
    });
    expect(protectedResp.status()).toBe(401);
  });

  test('API: with auth cookie /api/info reflects user, /api/protected returns 200 with user info', async ({
    browser,
  }) => {
    // Register a user via the auth server's built-in passkey flow.
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      await page.goto(`${AUTH}/o2p/user/login`);
      const authenticator = await addVirtualAuthenticator(page);
      await page
        .getByRole('button', { name: /Register with Passkey/i })
        .click();
      const modal = page.getByTestId('passkey-reg-modal');
      await expect(modal).toBeVisible();
      await modal.getByTestId('passkey-reg-username').fill('e2e-xo');
      await modal.getByTestId('passkey-reg-displayname').fill('XO User');
      const finish = page.waitForResponse(
        (r) =>
          r.url().endsWith('/o2p/passkey/register/finish') &&
          r.status() === 200,
      );
      await modal.getByTestId('passkey-reg-submit').click();
      await finish;
      await page.waitForLoadState('networkidle');

      const sessionId = (await ctx.cookies(AUTH)).find(
        (c) => c.name === SESSION_COOKIE,
      )?.value;
      expect(sessionId).toBeTruthy();

      // The cookie was set on `localhost` by the auth server; verify it
      // is sent to the API server (different port, same host).
      const apiCookies = await ctx.cookies(API);
      expect(
        apiCookies.find((c) => c.name === SESSION_COOKIE)?.value,
        'session cookie should be in scope for the API server too',
      ).toBe(sessionId);

      // Hit the API server's /api/info — cookie auto-included by the
      // browser context.
      const apiCtx = await pwRequest.newContext({
        extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
      });
      try {
        const info = await apiCtx.get(`${API}/api/info`);
        expect(info.ok()).toBeTruthy();
        const infoBody = await info.json();
        expect(infoBody.authenticated).toBe(true);
        expect(infoBody.user?.account).toBe('e2e-xo');

        const protectedResp = await apiCtx.get(`${API}/api/protected`);
        expect(protectedResp.ok()).toBeTruthy();
        const protBody = await protectedResp.json();
        expect(protBody.authenticated).toBe(true);
        expect(protBody.user?.account).toBe('e2e-xo');
        expect(protBody.message).toMatch(/cookie sharing works/i);
      } finally {
        await apiCtx.dispose();
      }

      await authenticator.remove();
    } finally {
      await ctx.close();
    }
  });

  test('CORS preflight from auth origin is permitted with credentials', async ({
    request,
  }) => {
    const resp = await request.fetch(`${API}/api/protected`, {
      method: 'OPTIONS',
      headers: {
        Origin: AUTH,
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'cookie',
      },
      failOnStatusCode: false,
    });
    // Some middlewares answer preflight with 200, others 204 — both OK.
    expect(resp.status()).toBeLessThan(300);
    expect(resp.headers()['access-control-allow-origin']).toBe(AUTH);
    expect(resp.headers()['access-control-allow-credentials']).toBe('true');
  });

  test('CORS rejects unknown origin', async ({ request }) => {
    const resp = await request.fetch(`${API}/api/protected`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://evil.example.com',
        'Access-Control-Request-Method': 'GET',
      },
      failOnStatusCode: false,
    });
    // tower-http CORS returns 200 with NO Access-Control-Allow-Origin
    // header for disallowed origins (the browser is what blocks the
    // request — server doesn't have to 4xx).
    expect(
      resp.headers()['access-control-allow-origin'],
      'unknown origin must not be echoed back',
    ).toBeUndefined();
  });
});
