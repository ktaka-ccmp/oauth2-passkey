import { test, expect, request as pwRequest } from '@playwright/test';
import type { BrowserContext, Page } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { registerPasskeyFromLogin } from '../helpers/auth-flows';
import { resetDb } from '../helpers/db';
import { DEMO_BASE_URL, MOCK_OIDC_URL } from '../helpers/endpoints';

/**
 * Covers the two phases of OAuth2 Linking Session Protection documented at
 * `docs/src/security/oauth2-linking-protection.md`.
 *
 * Phase 1 — page session token: when `mode=add_to_user`, the
 *   `/o2p/oauth2/<provider>` initiate endpoint must reject the request
 *   unless the `context=` parameter matches `generate_page_session_token`
 *   for the *current* session's CSRF.
 *
 * Phase 2 — `misc_session`: the OAuth2 callback must link the new account
 *   to the user who *initiated* the flow, even if the session cookie has
 *   been replaced by the time the callback runs.
 */

const SESSION_COOKIE = '__Host-SessionId';

async function readPageSessionToken(page: Page): Promise<string> {
  await page.goto('/o2p/user/account');
  // The template inlines `const PAGE_SESSION_TOKEN = "..."` in a classic
  // <script> block; `const` in classic scripts does NOT attach to
  // globalThis, so we scrape the literal directly out of the page source.
  const html = await page.content();
  const m = html.match(/const PAGE_SESSION_TOKEN\s*=\s*"([^"]+)"/);
  if (!m) throw new Error('PAGE_SESSION_TOKEN literal missing from account page');
  return m[1];
}

async function getSessionCookie(ctx: BrowserContext): Promise<string> {
  const cookies = await ctx.cookies(DEMO_BASE_URL);
  const c = cookies.find((c) => c.name === SESSION_COOKIE);
  if (!c) throw new Error(`no ${SESSION_COOKIE} cookie in context`);
  return c.value;
}

async function apiCtxWithCookie(sessionId: string | null) {
  if (sessionId === null) {
    return pwRequest.newContext();
  }
  return pwRequest.newContext({
    extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
  });
}

test('Phase 1: page session token guards add_to_user initiate', async ({
  browser,
}) => {
  await resetDb();

  // --- Register user A via passkey and capture their page_session_token.
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/o2p/user/login');
  const authenticator = await addVirtualAuthenticator(page);
  await registerPasskeyFromLogin(page, 'e2e-linkprot-a', 'Link Protection A');

  const aToken = await readPageSessionToken(page);
  const aSession = await getSessionCookie(ctx);

  // --- Negative #1: unauthenticated request (no session cookie) ---------
  {
    const api = await apiCtxWithCookie(null);
    try {
      const resp = await api.get(
        `${DEMO_BASE_URL}/o2p/oauth2/google?mode=add_to_user&context=${aToken}`,
        { maxRedirects: 0, failOnStatusCode: false },
      );
      expect(resp.status()).toBe(400);
      expect(await resp.text()).toMatch(/Missing Session/i);
    } finally {
      await api.dispose();
    }
  }

  // --- Negative #2: A's session but no `context` param ------------------
  {
    const api = await apiCtxWithCookie(aSession);
    try {
      const resp = await api.get(
        `${DEMO_BASE_URL}/o2p/oauth2/google?mode=add_to_user`,
        { maxRedirects: 0, failOnStatusCode: false },
      );
      expect(resp.status()).toBe(400);
      expect(await resp.text()).toMatch(/Missing Context/i);
    } finally {
      await api.dispose();
    }
  }

  // --- Negative #3: A's session with a garbage `context` value ----------
  {
    const api = await apiCtxWithCookie(aSession);
    try {
      const resp = await api.get(
        `${DEMO_BASE_URL}/o2p/oauth2/google?mode=add_to_user&context=garbage`,
        { maxRedirects: 0, failOnStatusCode: false },
      );
      expect(resp.status()).toBe(400);
      // SessionError::PageSessionToken wraps "Page session token does not
      // match session user".
      expect(await resp.text()).toMatch(/page session token/i);
    } finally {
      await api.dispose();
    }
  }

  // --- Negative #4: session rotation invalidates the previously-rendered
  //     token. Logging back in as the same user mints a new CSRF, so the
  //     old `aToken` no longer matches.
  await page.goto('/o2p/user/logout?redirect=/o2p/user/login');
  const signinFinish = page.waitForResponse(
    (r) => r.url().endsWith('/o2p/passkey/auth/finish') && r.status() === 200,
  );
  await page.getByTestId('login-passkey-signin').click();
  await signinFinish;
  await page.waitForLoadState('networkidle');
  const aSessionRotated = await getSessionCookie(ctx);
  expect(aSessionRotated).not.toBe(aSession); // sanity: cookie did rotate

  {
    const api = await apiCtxWithCookie(aSessionRotated);
    try {
      const resp = await api.get(
        `${DEMO_BASE_URL}/o2p/oauth2/google?mode=add_to_user&context=${aToken}`,
        { maxRedirects: 0, failOnStatusCode: false },
      );
      expect(resp.status()).toBe(400);
      expect(await resp.text()).toMatch(/page session token/i);
    } finally {
      await api.dispose();
    }
  }

  // --- Positive: a freshly-rendered token does redirect to the IdP. ----
  const freshToken = await readPageSessionToken(page);
  {
    const api = await apiCtxWithCookie(aSessionRotated);
    try {
      const resp = await api.get(
        `${DEMO_BASE_URL}/o2p/oauth2/google?mode=add_to_user&context=${freshToken}`,
        { maxRedirects: 0, failOnStatusCode: false },
      );
      // Axum's Redirect::to default is 303; accept any 3xx to mock-oidc.
      expect(resp.status()).toBeGreaterThanOrEqual(300);
      expect(resp.status()).toBeLessThan(400);
      expect(resp.headers()['location']).toContain('/oauth2/auth');
    } finally {
      await api.dispose();
    }
  }

  await authenticator.remove();
  await ctx.close();
});

/**
 * Parse `code` and `state` out of mock-oidc's form_post auto-submit HTML.
 *
 * The body looks like:
 *   <form action='<redirect_uri>' method='POST'>
 *     <input type='hidden' name='code' value='<uuid>'>
 *     <input type='hidden' name='state' value='<base64url>'>
 *   </form>
 */
function parseFormPost(body: string): { code: string; state: string } {
  const codeMatch = body.match(/name='code'\s+value='([^']+)'/);
  const stateMatch = body.match(/name='state'\s+value='([^']+)'/);
  if (!codeMatch || !stateMatch) {
    throw new Error(`failed to parse form_post HTML: ${body.slice(0, 200)}`);
  }
  return { code: codeMatch[1], state: stateMatch[1] };
}

test('Phase 2: callback links to flow initiator, not the current cookie', async ({
  browser,
  request,
}) => {
  await resetDb();

  // --- User A (passkey) — the flow initiator. -------------------------
  const ctxA = await browser.newContext();
  const pageA = await ctxA.newPage();
  await pageA.goto('/o2p/user/login');
  const authA = await addVirtualAuthenticator(pageA);
  await registerPasskeyFromLogin(pageA, 'e2e-linkprot-a2', 'Link Protection A2');
  const aToken = await readPageSessionToken(pageA);
  const aSession = await getSessionCookie(ctxA);

  // --- User B (OAuth2) — exists with a distinct OIDC `sub`. The attacker
  //     model: by the time A's callback fires, B is the active session.
  await request.post(`${MOCK_OIDC_URL}/test/config`, {
    data: {
      email: 'b@example.com',
      sub: 'google_user_b',
      name: 'User B',
      given_name: 'B',
      family_name: 'User',
    },
  });
  const ctxB = await browser.newContext();
  const pageB = await ctxB.newPage();
  await pageB.goto('/o2p/user/login');
  const popupBPromise = ctxB.waitForEvent('page');
  await pageB.getByTestId('login-oauth2-google').click();
  const popupB = await popupBPromise;
  await popupB.waitForURL(/\/o2p\/passkey\/promotion\/popup/, {
    timeout: 15_000,
  });
  await popupB.locator('#passkey-promo-dismiss').click();
  await popupB.waitForEvent('close', { timeout: 10_000 });
  await pageB.waitForLoadState('networkidle');
  const bSession = await getSessionCookie(ctxB);
  expect(bSession).not.toBe(aSession);

  // --- Reconfigure mock-oidc so the link target is a *new* identity
  //     (different from both A and B). This is the OAuth2 account A is
  //     about to link.
  await request.post(`${MOCK_OIDC_URL}/test/config`, {
    data: {
      email: 'c@example.com',
      sub: 'google_to_link_with_a',
      name: 'Link Target C',
      given_name: 'C',
      family_name: 'Target',
    },
  });

  // --- Step 1: A initiates the add_to_user flow. The library stores A's
  //     session_id under `misc_session` keyed by `misc_id` and returns the
  //     redirect to mock-oidc with an OAuth2 `state` that references it.
  //     It also returns a Set-Cookie for the OAuth2 CSRF cookie
  //     (`__Host-CsrfId`); the callback in step 3 expects that cookie to
  //     be present alongside the session cookie.
  const apiA = await apiCtxWithCookie(aSession);
  let mockAuthUrl: string;
  let csrfCookieValue: string;
  try {
    const initiate = await apiA.get(
      `${DEMO_BASE_URL}/o2p/oauth2/google?mode=add_to_user&context=${aToken}`,
      { maxRedirects: 0, failOnStatusCode: false },
    );
    expect(initiate.status()).toBeGreaterThanOrEqual(300);
    expect(initiate.status()).toBeLessThan(400);
    mockAuthUrl = initiate.headers()['location'];
    expect(mockAuthUrl).toContain('/oauth2/auth');

    // Extract __Host-CsrfId from the Set-Cookie header(s).
    const setCookies = initiate
      .headersArray()
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value);
    const csrfLine = setCookies.find((c) => c.startsWith('__Host-CsrfId='));
    if (!csrfLine) {
      throw new Error(
        `initiate response missing __Host-CsrfId cookie: ${setCookies.join('|')}`,
      );
    }
    csrfCookieValue = csrfLine.split(';')[0].slice('__Host-CsrfId='.length);
  } finally {
    await apiA.dispose();
  }

  // --- Step 2: drive mock-oidc's /oauth2/auth (cookies don't matter
  //     here — the IdP doesn't authenticate via demo-both's cookie).
  const formPostResp = await request.get(mockAuthUrl, {
    maxRedirects: 0,
    failOnStatusCode: false,
  });
  expect(formPostResp.ok()).toBeTruthy();
  const { code, state } = parseFormPost(await formPostResp.text());

  // --- Step 3: submit the callback as if **B** were the active browser
  //     session. The form_post in a real attack would carry both the
  //     OAuth2 CSRF cookie (scoped to the RP's origin, so it survives the
  //     IdP round-trip) and a *session* cookie that may have rotated to
  //     B's by the time the POST happens. The library's misc_session
  //     lookup must override the session cookie's identity.
  //
  //     A side-effect of a successful callback is that A's *original*
  //     session is destroyed (delete_session_and_misc_token_from_store)
  //     and a fresh session for A is minted in the Set-Cookie of the
  //     response. We capture that new cookie to verify the linkage.
  let newSessionForA: string;
  const apiB = await pwRequest.newContext({
    extraHTTPHeaders: {
      Cookie: `${SESSION_COOKIE}=${bSession}; __Host-CsrfId=${csrfCookieValue}`,
    },
  });
  try {
    const callback = await apiB.post(
      `${DEMO_BASE_URL}/o2p/oauth2/google/authorized`,
      {
        form: { code, state },
        maxRedirects: 0,
        failOnStatusCode: false,
      },
    );
    // Successful callback returns 3xx to a success/promotion URL.
    expect(callback.status()).toBeGreaterThanOrEqual(300);
    expect(callback.status()).toBeLessThan(400);
    const setCookies = callback
      .headersArray()
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value);
    const sessionLine = setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    if (!sessionLine) {
      throw new Error(
        `callback response did not mint a fresh session cookie: ${setCookies.join('|')}`,
      );
    }
    newSessionForA = sessionLine.split(';')[0].slice(`${SESSION_COOKIE}=`.length);
    expect(newSessionForA).not.toBe(bSession);
  } finally {
    await apiB.dispose();
  }

  // --- Step 4: the freshly-issued cookie must resolve to **A** and A's
  //     account list must now include the new OAuth2 link.
  const apiAFinal = await apiCtxWithCookie(newSessionForA);
  try {
    const aAccounts = await apiAFinal.get(
      `${DEMO_BASE_URL}/o2p/oauth2/accounts`,
    );
    expect(aAccounts.ok()).toBeTruthy();
    const aList = (await aAccounts.json()) as Array<{
      provider_user_id: string;
    }>;
    // `oauth2_account_from_idinfo` stores provider_user_id as
    // `<provider>_<sub>` — see `oauth2_passkey/src/oauth2/types.rs`.
    const linked = aList.find(
      (a) => a.provider_user_id === 'google_google_to_link_with_a',
    );
    expect(linked, 'A should own the newly-linked OAuth2 account').toBeTruthy();
  } finally {
    await apiAFinal.dispose();
  }

  // --- Step 5: B's session is untouched — they still only own their
  //     original OAuth2 account; the link did NOT bleed over.
  const apiBFinal = await apiCtxWithCookie(bSession);
  try {
    const bAccounts = await apiBFinal.get(
      `${DEMO_BASE_URL}/o2p/oauth2/accounts`,
    );
    expect(bAccounts.ok()).toBeTruthy();
    const bList = (await bAccounts.json()) as Array<{
      provider_user_id: string;
    }>;
    expect(bList.map((a) => a.provider_user_id)).toEqual(['google_google_user_b']);
  } finally {
    await apiBFinal.dispose();
  }

  await authA.remove();
  await ctxA.close();
  await ctxB.close();
});
