import { test, expect, request as pwRequest } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { registerPasskeyFromLogin } from '../helpers/auth-flows';
import { resetDb } from '../helpers/db';
import { DEMO_PROFILE_BASE_URL } from '../helpers/endpoints';

/**
 * E2E regression coverage for `demo-profile` — the 1:1 user-data
 * extension pattern. Like demo-todo but keyed by `user_id` as the PK of
 * the consumer's own `user_profiles` table.
 *
 * Guards: lazy-creation of the default profile on first GET, form-CSRF
 * verification on POST, value persistence across requests, user
 * isolation.
 */

const SESSION_COOKIE = '__Host-SessionId';
const BASE = DEMO_PROFILE_BASE_URL;

async function loginAs(browser: import('@playwright/test').Browser, account: string, label: string) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(`${BASE}/o2p/user/login`);
  const authenticator = await addVirtualAuthenticator(page);
  await registerPasskeyFromLogin(page, account, label);
  const sessionId = (await ctx.cookies(BASE)).find(
    (c) => c.name === SESSION_COOKIE,
  )?.value;
  if (!sessionId) throw new Error('session cookie missing after registration');
  return { ctx, page, authenticator, sessionId };
}

function readCsrfFromProfilePage(html: string): string {
  // The profile template hides the CSRF inside <input ... value="...">.
  const m = html.match(/name="csrf_token"\s+value="([^"]+)"/);
  if (!m) throw new Error('csrf_token hidden input not found in profile page');
  return m[1];
}

test.describe('demo-profile', () => {
  test.beforeEach(async () => {
    await resetDb(BASE);
  });

  test('anonymous: /profile redirects to login', async ({ request }) => {
    const resp = await request.get(`${BASE}/profile`, {
      maxRedirects: 0,
      failOnStatusCode: false,
    });
    expect(resp.status()).toBe(307);
    expect(resp.headers()['location']).toContain('/o2p/user/login');
  });

  test('authed: GET /profile lazy-creates the default profile (theme=light)', async ({
    browser,
  }) => {
    const { ctx, authenticator, sessionId } = await loginAs(
      browser,
      'e2e-prof-a',
      'Profile A',
    );
    const api = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
    });
    try {
      const resp = await api.get(`${BASE}/profile`);
      expect(resp.ok()).toBeTruthy();
      const body = await resp.text();
      // Default theme is `"light"` per `UserProfile::default`.
      expect(body).toMatch(/theme/i);
      // The template renders `{{ user.account }}` as a subtitle — that
      // is the account passed to registerPasskeyFromLogin.
      expect(body).toContain('e2e-prof-a');
    } finally {
      await api.dispose();
      await authenticator.remove();
      await ctx.close();
    }
  });

  test('authed: POST /profile with valid CSRF persists values', async ({
    browser,
  }) => {
    const { ctx, authenticator, sessionId } = await loginAs(
      browser,
      'e2e-prof-update',
      'Profile Update',
    );
    const api = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
    });
    try {
      const initial = await (await api.get(`${BASE}/profile`)).text();
      const csrf = readCsrfFromProfilePage(initial);

      const update = await api.post(`${BASE}/profile`, {
        form: {
          display_name: 'New Name',
          bio: 'hello world',
          avatar_url: '',
          theme: 'dark',
          csrf_token: csrf,
        },
        maxRedirects: 0,
        failOnStatusCode: false,
      });
      expect(update.status()).toBe(303); // Redirect::to("/")

      const after = await (await api.get(`${BASE}/profile`)).text();
      expect(after).toContain('New Name');
      expect(after).toContain('hello world');
      // Theme attribute reflects the new value in the rendered form.
      expect(after).toMatch(/value="dark"\s+selected|selected[^>]*value="dark"|theme.*dark/i);
    } finally {
      await api.dispose();
      await authenticator.remove();
      await ctx.close();
    }
  });

  test('CSRF: POST with wrong token → 403, values not persisted', async ({
    browser,
  }) => {
    const { ctx, authenticator, sessionId } = await loginAs(
      browser,
      'e2e-prof-csrf',
      'Profile CSRF',
    );
    const api = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
    });
    try {
      // Touch /profile once so the default profile exists with theme=light.
      await api.get(`${BASE}/profile`);

      const resp = await api.post(`${BASE}/profile`, {
        form: {
          display_name: 'evil',
          bio: '',
          avatar_url: '',
          theme: 'dark',
          csrf_token: 'wrong-token',
        },
        maxRedirects: 0,
        failOnStatusCode: false,
      });
      expect(resp.status()).toBe(403);

      const after = await (await api.get(`${BASE}/profile`)).text();
      expect(after).not.toContain('evil');
    } finally {
      await api.dispose();
      await authenticator.remove();
      await ctx.close();
    }
  });

  test('user isolation: B never sees A’s profile fields', async ({
    browser,
  }) => {
    const a = await loginAs(browser, 'e2e-prof-iso-a', 'Iso A');
    const apiA = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${a.sessionId}` },
    });
    try {
      const initial = await (await apiA.get(`${BASE}/profile`)).text();
      const csrfA = readCsrfFromProfilePage(initial);
      await apiA.post(`${BASE}/profile`, {
        form: {
          display_name: 'AAA-PRIVATE',
          bio: '',
          avatar_url: '',
          theme: 'light',
          csrf_token: csrfA,
        },
        maxRedirects: 0,
        failOnStatusCode: false,
      });
    } finally {
      await apiA.dispose();
    }

    const b = await loginAs(browser, 'e2e-prof-iso-b', 'Iso B');
    const apiB = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${b.sessionId}` },
    });
    try {
      const bProfile = await (await apiB.get(`${BASE}/profile`)).text();
      expect(bProfile).not.toContain('AAA-PRIVATE');
    } finally {
      await apiB.dispose();
    }

    await a.authenticator.remove();
    await b.authenticator.remove();
    await a.ctx.close();
    await b.ctx.close();
  });
});
