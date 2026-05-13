import { test, expect, request as pwRequest } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { registerPasskeyFromLogin } from '../helpers/auth-flows';
import { resetDb } from '../helpers/db';
import { DEMO_BASE_URL } from '../helpers/endpoints';

/**
 * E2E smoke tests for `demo-both/src/protected.rs` (the p1–p6 demo
 * pages). These pages illustrate the protection primitives library
 * consumers are expected to copy: `AuthUser` / `Option<AuthUser>`
 * extractors, `is_authenticated_redirect` / `is_authenticated_user_redirect`
 * middleware, CSRF token delivery via header / template / form.
 *
 * The mechanisms themselves are unit-tested in `oauth2_passkey_axum`. The
 * value of this spec is **regression detection at the integrator's
 * surface**: if a future library refactor breaks how middleware injects
 * `Extension<AuthUser>` / `Extension<CsrfToken>`, or how the CSRF header
 * is emitted on response, the library tests may still pass while the
 * consumer-facing usage silently breaks. This spec catches that without
 * needing a manual click-through before each release.
 */

const SESSION_COOKIE = '__Host-SessionId';

test.describe('demo-both p1-p6 protected routes', () => {
  test.beforeEach(async () => {
    await resetDb();
  });

  test('anonymous: protected pages redirect to login (except p2)', async ({
    request,
  }) => {
    for (const path of ['/p1', '/p3', '/p4', '/p5', '/p6', '/nested/p3']) {
      const resp = await request.get(`${DEMO_BASE_URL}${path}`, {
        maxRedirects: 0,
        failOnStatusCode: false,
      });
      expect(resp.status(), `${path} should redirect when anonymous`).toBe(307);
      expect(resp.headers()['location']).toMatch(/\/o2p\/user\/login/);
    }
  });

  test('anonymous: p2 renders without user info', async ({ request }) => {
    const resp = await request.get(`${DEMO_BASE_URL}/p2`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.text();
    expect(body).toContain('p2');
    // The template branches on `Option<AuthUser>` — the user-info section
    // simply isn't rendered when None.
    expect(body).not.toMatch(/account.*@/i);
  });

  test('authed: p1 emits X-CSRF-Token response header and shows account', async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('/o2p/user/login');
    const authenticator = await addVirtualAuthenticator(page);
    await registerPasskeyFromLogin(page, 'e2e-p1', 'p1 User');

    const sessionId = (await ctx.cookies(DEMO_BASE_URL)).find(
      (c) => c.name === SESSION_COOKIE,
    )?.value;
    expect(sessionId).toBeTruthy();

    const api = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
    });
    try {
      const resp = await api.get(`${DEMO_BASE_URL}/p1`);
      expect(resp.ok()).toBeTruthy();
      expect(resp.headers()['x-csrf-token']).toBeTruthy();
      const body = await resp.text();
      expect(body).toContain('e2e-p1');
    } finally {
      await api.dispose();
    }

    await authenticator.remove();
    await ctx.close();
  });

  test('authed: p2 renders WITH user info', async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('/o2p/user/login');
    const authenticator = await addVirtualAuthenticator(page);
    await registerPasskeyFromLogin(page, 'e2e-p2', 'p2 User');

    await page.goto('/p2');
    await expect(page.locator('body')).toContainText('e2e-p2');

    await authenticator.remove();
    await ctx.close();
  });

  test('p3 AJAX POST: with CSRF → 200; without CSRF → 403', async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('/o2p/user/login');
    const authenticator = await addVirtualAuthenticator(page);
    await registerPasskeyFromLogin(page, 'e2e-p3', 'p3 User');

    const sessionId = (await ctx.cookies(DEMO_BASE_URL)).find(
      (c) => c.name === SESSION_COOKIE,
    )?.value;
    expect(sessionId).toBeTruthy();

    // Fetch the page first to learn the CSRF token (middleware sets it as
    // a response header on every protected response).
    const apiWithCookie = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
    });
    try {
      const getResp = await apiWithCookie.get(`${DEMO_BASE_URL}/p3`);
      expect(getResp.ok()).toBeTruthy();
      const csrf = getResp.headers()['x-csrf-token'];
      expect(csrf).toBeTruthy();

      // POST with the matching header → handler runs.
      const okPost = await apiWithCookie.post(`${DEMO_BASE_URL}/p3`, {
        headers: {
          'X-CSRF-Token': csrf,
          'Content-Type': 'application/json',
        },
        data: { test: 'data' },
        failOnStatusCode: false,
      });
      expect(okPost.status()).toBe(200);
      expect(await okPost.text()).toBe('POST request received');

      // POST without the header → middleware rejects with 403 for the
      // CSRF-error branch (the auth check itself passed; only CSRF failed).
      const badPost = await apiWithCookie.post(`${DEMO_BASE_URL}/p3`, {
        headers: { 'Content-Type': 'application/json' },
        data: { test: 'data' },
        failOnStatusCode: false,
      });
      expect(badPost.status()).toBe(403);
    } finally {
      await apiWithCookie.dispose();
    }

    await authenticator.remove();
    await ctx.close();
  });

  test('authed: p4 renders user from Extension<AuthUser>', async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('/o2p/user/login');
    const authenticator = await addVirtualAuthenticator(page);
    await registerPasskeyFromLogin(page, 'e2e-p4', 'p4 User');

    await page.goto('/p4');
    await expect(page.locator('body')).toContainText('e2e-p4');

    await authenticator.remove();
    await ctx.close();
  });

  test('authed: p5 embeds CSRF token in the rendered page body', async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('/o2p/user/login');
    const authenticator = await addVirtualAuthenticator(page);
    await registerPasskeyFromLogin(page, 'e2e-p5', 'p5 User');

    const sessionId = (await ctx.cookies(DEMO_BASE_URL)).find(
      (c) => c.name === SESSION_COOKIE,
    )?.value;
    expect(sessionId).toBeTruthy();

    const api = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
    });
    try {
      const resp = await api.get(`${DEMO_BASE_URL}/p5`);
      expect(resp.ok()).toBeTruthy();
      const headerCsrf = resp.headers()['x-csrf-token'];
      const body = await resp.text();
      // The middleware sets the header AND the template embeds the same
      // value — the page renders it in a `.token-display` element.
      expect(headerCsrf).toBeTruthy();
      expect(body).toContain(headerCsrf!);
    } finally {
      await api.dispose();
    }

    await authenticator.remove();
    await ctx.close();
  });

  test('p6 form POST: valid form CSRF / mismatch / missing — three branches', async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('/o2p/user/login');
    const authenticator = await addVirtualAuthenticator(page);
    await registerPasskeyFromLogin(page, 'e2e-p6', 'p6 User');

    const sessionId = (await ctx.cookies(DEMO_BASE_URL)).find(
      (c) => c.name === SESSION_COOKIE,
    )?.value;
    expect(sessionId).toBeTruthy();

    const api = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
    });
    try {
      // Fetch p6 GET to learn the CSRF token (form-rendered + header).
      const getResp = await api.get(`${DEMO_BASE_URL}/p6`);
      const csrf = getResp.headers()['x-csrf-token'];
      expect(csrf).toBeTruthy();

      // Branch 1: valid form CSRF token → "POST successful".
      // Note: form POSTs go through CSRF middleware too — the
      // AuthUser-extractor side of the middleware permits form-like
      // Content-Types to skip the header check (because the handler is
      // expected to do its own form-field check), which is exactly what
      // `p6_post` does.
      const okResp = await api.post(`${DEMO_BASE_URL}/p6`, {
        form: { message: 'hello', csrf_token: csrf! },
        failOnStatusCode: false,
      });
      expect(okResp.ok()).toBeTruthy();
      const okBody = await okResp.text();
      expect(okBody).toContain('POST successful');

      // Branch 2: form CSRF token present but mismatched → renders an
      // error message in the page body, but still returns 200.
      const mismatchResp = await api.post(`${DEMO_BASE_URL}/p6`, {
        form: { message: 'hello', csrf_token: 'not-the-real-token' },
        failOnStatusCode: false,
      });
      expect(mismatchResp.ok()).toBeTruthy();
      const mismatchBody = await mismatchResp.text();
      expect(mismatchBody).toMatch(/CSRF token mismatch/i);

      // Branch 3: form CSRF token missing → renders a "missing" message.
      const missingResp = await api.post(`${DEMO_BASE_URL}/p6`, {
        form: { message: 'hello' },
        failOnStatusCode: false,
      });
      expect(missingResp.ok()).toBeTruthy();
      const missingBody = await missingResp.text();
      expect(missingBody).toMatch(/CSRF token missing/i);

      // Branch 4 (bonus): X-CSRF-Token header path — middleware verifies
      // before the handler runs, the handler sees
      // `csrf_via_header_verified.0 == true` and skips the form check.
      const headerResp = await api.post(`${DEMO_BASE_URL}/p6`, {
        headers: { 'X-CSRF-Token': csrf! },
        form: { message: 'hello' },
        failOnStatusCode: false,
      });
      expect(headerResp.ok()).toBeTruthy();
      const headerBody = await headerResp.text();
      expect(headerBody).toContain('verified via X-CSRF-Token header');
    } finally {
      await api.dispose();
    }

    await authenticator.remove();
    await ctx.close();
  });
});
