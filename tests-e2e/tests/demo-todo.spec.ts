import { test, expect, request as pwRequest } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { registerPasskeyFromLogin } from '../helpers/auth-flows';
import { resetDb } from '../helpers/db';
import { DEMO_TODO_BASE_URL } from '../helpers/endpoints';

/**
 * E2E regression coverage for `demo-todo` — the canonical "extend user
 * data via FK to user_id, CSRF-protected form CRUD" pattern that
 * integrators copy. Backed by Postgres (`todos` table) and the
 * library's session/CSRF middleware.
 *
 * What this guards against silently breaking:
 *  - `AuthUser` extractor + `is_authenticated_redirect` middleware in
 *    consumer code
 *  - `Extension<CsrfToken>` / `Extension<CsrfHeaderVerified>` injection
 *  - the consumer's form-CSRF verification path (constant-time compare)
 *  - user isolation via `user_id` keying (no cross-user leakage)
 */

const SESSION_COOKIE = '__Host-SessionId';
const BASE = DEMO_TODO_BASE_URL;

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

async function getCsrf(sessionId: string): Promise<string> {
  const ctx = await pwRequest.newContext({
    extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
  });
  try {
    const r = await ctx.get(`${BASE}/o2p/user/csrf_token`);
    expect(r.ok()).toBeTruthy();
    const j = (await r.json()) as { csrf_token: string };
    return j.csrf_token;
  } finally {
    await ctx.dispose();
  }
}

test.describe('demo-todo', () => {
  test.beforeEach(async () => {
    await resetDb(BASE);
  });

  test('anonymous: GET / shows the login prompt, no todos visible', async ({
    request,
  }) => {
    const resp = await request.get(`${BASE}/`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.text();
    // The template renders "todos: []" branch when user is None.
    expect(body).toMatch(/sign in|login/i);
  });

  test('authed: create / toggle / delete via the form CSRF path', async ({
    browser,
  }) => {
    const { ctx, authenticator, sessionId } = await loginAs(
      browser,
      'e2e-todo-a',
      'Todo A',
    );
    const csrf = await getCsrf(sessionId);
    const api = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
    });
    try {
      // Create (form CSRF required by handler)
      const create = await api.post(`${BASE}/todos`, {
        form: { title: 'first task', csrf_token: csrf },
        maxRedirects: 0,
        failOnStatusCode: false,
      });
      expect(create.status()).toBe(303); // Redirect::to("/")

      // Index now lists the todo
      let body = await (await api.get(`${BASE}/`)).text();
      expect(body).toContain('first task');
      const idMatch = body.match(/\/todos\/(\d+)\/toggle/);
      expect(idMatch, 'todo id should appear in toggle URL').toBeTruthy();
      const todoId = idMatch![1];

      // Toggle
      const toggle = await api.post(`${BASE}/todos/${todoId}/toggle`, {
        form: { csrf_token: csrf },
        maxRedirects: 0,
        failOnStatusCode: false,
      });
      expect(toggle.status()).toBe(303);
      body = await (await api.get(`${BASE}/`)).text();
      // Template renders "{{ completed_count }} of {{ todos.len() }} completed"
      // → "1 of 1 completed" after the toggle.
      expect(body).toMatch(/1 of 1 completed/i);

      // Delete
      const del = await api.post(`${BASE}/todos/${todoId}/delete`, {
        form: { csrf_token: csrf },
        maxRedirects: 0,
        failOnStatusCode: false,
      });
      expect(del.status()).toBe(303);
      body = await (await api.get(`${BASE}/`)).text();
      expect(body).not.toContain('first task');
    } finally {
      await api.dispose();
      await authenticator.remove();
      await ctx.close();
    }
  });

  test('CSRF: POST without csrf_token → 403, no row created', async ({
    browser,
  }) => {
    const { ctx, authenticator, sessionId } = await loginAs(
      browser,
      'e2e-todo-csrf',
      'Todo CSRF',
    );
    const api = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
    });
    try {
      const resp = await api.post(`${BASE}/todos`, {
        form: { title: 'should not appear', csrf_token: 'wrong-token' },
        maxRedirects: 0,
        failOnStatusCode: false,
      });
      expect(resp.status()).toBe(403);
      const idx = await (await api.get(`${BASE}/`)).text();
      expect(idx).not.toContain('should not appear');
    } finally {
      await api.dispose();
      await authenticator.remove();
      await ctx.close();
    }
  });

  test('user isolation: B never sees A’s todos', async ({ browser }) => {
    // User A creates a todo
    const a = await loginAs(browser, 'e2e-todo-a2', 'A2');
    const csrfA = await getCsrf(a.sessionId);
    const apiA = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${a.sessionId}` },
    });
    try {
      await apiA.post(`${BASE}/todos`, {
        form: { title: 'private to A', csrf_token: csrfA },
        maxRedirects: 0,
        failOnStatusCode: false,
      });
    } finally {
      await apiA.dispose();
    }

    // User B registers in their own context, hits /, must NOT see A's todo
    const b = await loginAs(browser, 'e2e-todo-b', 'B');
    const apiB = await pwRequest.newContext({
      extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${b.sessionId}` },
    });
    try {
      const idxB = await (await apiB.get(`${BASE}/`)).text();
      expect(idxB).not.toContain('private to A');
    } finally {
      await apiB.dispose();
    }

    await a.authenticator.remove();
    await b.authenticator.remove();
    await a.ctx.close();
    await b.ctx.close();
  });
});
