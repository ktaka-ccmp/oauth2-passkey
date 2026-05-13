import { test, expect, request as pwRequest } from '@playwright/test';
import type { Page } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { resetDb } from '../helpers/db';
import { DEMO_CUSTOM_LOGIN_BASE_URL } from '../helpers/endpoints';

/**
 * Drive the consumer's `/login` "Create account with Passkey" flow. The
 * custom page wires that button to `showRegistrationModal('create_user')`,
 * which is the same JS the library ships — so the modal markup carries
 * the data-testid attributes added in 4cded7a/b1e27d3.
 */
async function registerCustomLoginPasskey(
  page: Page,
  username: string,
  displayName: string,
): Promise<void> {
  await page
    .getByRole('button', { name: /Create account with Passkey/i })
    .click();
  const modal = page.getByTestId('passkey-reg-modal');
  await expect(modal).toBeVisible();
  await modal.getByTestId('passkey-reg-username').fill(username);
  await modal.getByTestId('passkey-reg-displayname').fill(displayName);
  const finish = page.waitForResponse(
    (r) => r.url().endsWith('/o2p/passkey/register/finish') && r.status() === 200,
  );
  await modal.getByTestId('passkey-reg-submit').click();
  await finish;
  await page.waitForLoadState('networkidle');
}

/**
 * E2E regression coverage for `demo-custom-login`. The demo's headline
 * feature is the `O2P_LOGIN_URL=/login` redirect contract: anonymous
 * users hitting a protected route should land on the consumer's own
 * `/login` page, not the library's built-in `/o2p/user/login`. The demo
 * also wires custom `/account` and `/admin` pages on top of the
 * library's `AuthUser` extractor / admin coordination functions.
 *
 * This spec runs against an isolated `demo-custom-login` Playwright
 * webServer entry (port 13002 by default) so the demo's auth gates are
 * exercised end-to-end without any of the library's default pages
 * showing up.
 */

const SESSION_COOKIE = '__Host-SessionId';
const BASE = DEMO_CUSTOM_LOGIN_BASE_URL;

test.describe('demo-custom-login', () => {
  test.beforeEach(async () => {
    await resetDb(BASE);
  });

  test('anonymous: protected routes redirect to /login, not /o2p/user/login', async ({
    request,
  }) => {
    for (const path of ['/protected', '/account', '/admin']) {
      const resp = await request.get(`${BASE}${path}`, {
        maxRedirects: 0,
        failOnStatusCode: false,
      });
      expect(resp.status(), `${path} should redirect when anonymous`).toBe(307);
      const location = resp.headers()['location'] ?? '';
      expect(location, `${path} → ${location}`).toBe('/login');
    }
  });

  test('anonymous: /login renders the custom page (200, not a redirect)', async ({
    request,
  }) => {
    const resp = await request.get(`${BASE}/login`, {
      maxRedirects: 0,
      failOnStatusCode: false,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.text();
    // Custom page should reference the library's auth endpoints — that
    // is the integration point the demo is meant to illustrate.
    expect(body).toMatch(/oauth2|passkey/i);
  });

  test('authed: /login redirects logged-in users to /', async ({ browser }) => {
    const ctx = await browser.newContext();
    try {
      // demo-custom-login uses `default-features = false` on the
      // library so `/o2p/user/login` does NOT render — registration
      // must go through the consumer's `/login` page, which embeds
      // passkey.js and exposes `showRegistrationModal('create_user')`.
      const page = await ctx.newPage();
      await page.goto(`${BASE}/login`);
      const authenticator = await addVirtualAuthenticator(page);
      await registerCustomLoginPasskey(page, 'e2e-custom-a', 'Custom Login A');

      const sessionId = (await ctx.cookies(BASE)).find(
        (c) => c.name === SESSION_COOKIE,
      )?.value;
      expect(sessionId).toBeTruthy();

      // Authed → /login → 303/307 to /.
      const api = await pwRequest.newContext({
        extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
      });
      try {
        const resp = await api.get(`${BASE}/login`, {
          maxRedirects: 0,
          failOnStatusCode: false,
        });
        expect(resp.status()).toBeGreaterThanOrEqual(300);
        expect(resp.status()).toBeLessThan(400);
        expect(resp.headers()['location']).toBe('/');
      } finally {
        await api.dispose();
      }

      await authenticator.remove();
    } finally {
      await ctx.close();
    }
  });

  test('authed: /, /protected, /account render with user info; /admin granted to first user', async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    try {
      const page = await ctx.newPage();
      await page.goto(`${BASE}/login`);
      const authenticator = await addVirtualAuthenticator(page);
      await registerCustomLoginPasskey(page, 'e2e-custom-admin', 'Custom Admin');

      const sessionId = (await ctx.cookies(BASE)).find(
        (c) => c.name === SESSION_COOKIE,
      )?.value;
      expect(sessionId).toBeTruthy();
      const api = await pwRequest.newContext({
        extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
      });
      try {
        // Index (anon vs authed branch) — authed renders the user
        // template that includes the label.
        const idx = await api.get(`${BASE}/`);
        expect(idx.ok()).toBeTruthy();
        expect(await idx.text()).toContain('Custom Admin');

        // /protected — AuthUser extractor must succeed and surface
        // user.account.
        const prot = await api.get(`${BASE}/protected`);
        expect(prot.ok()).toBeTruthy();
        expect(await prot.text()).toContain('e2e-custom-admin');

        // /account — custom account page assembles credentials +
        // OAuth2 accounts via library functions; the first user has 1
        // passkey, 0 OAuth2.
        const acct = await api.get(`${BASE}/account`);
        expect(acct.ok()).toBeTruthy();
        const acctBody = await acct.text();
        expect(acctBody).toContain('e2e-custom-admin');

        // /admin — first user (sequence_number=1) has admin rights.
        const adm = await api.get(`${BASE}/admin`);
        expect(adm.ok()).toBeTruthy();
        const admBody = await adm.text();
        expect(admBody).toContain('e2e-custom-admin');
      } finally {
        await api.dispose();
      }

      await authenticator.remove();
    } finally {
      await ctx.close();
    }
  });
});
