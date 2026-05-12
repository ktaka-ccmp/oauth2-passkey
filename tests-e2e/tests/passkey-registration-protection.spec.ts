import { test, expect, request as pwRequest } from '@playwright/test';
import type { BrowserContext } from '@playwright/test';
import { addVirtualAuthenticator } from '../helpers/webauthn';
import { registerPasskeyFromLogin } from '../helpers/auth-flows';
import { resetDb } from '../helpers/db';
import { DEMO_BASE_URL, MOCK_OIDC_URL } from '../helpers/endpoints';

/**
 * Covers the two phases of Passkey Registration Session Protection
 * documented at `docs/src/security/passkey-registration-protection.md`.
 *
 * Phase 1 — X-CSRF-Token on /passkey/register/start: the AuthUser
 *   extractor's CSRF middleware rejects state-changing requests whose
 *   X-CSRF-Token header doesn't match the current session's CSRF. This
 *   guards against session rotation between page render and click.
 *
 * Phase 2 — user_handle-keyed SessionInfo: between register/start and
 *   register/finish the browser talks to the authenticator. If the
 *   session cookie changes during that window, verify_session_then_finish
 *   _registration must reject "User ID mismatch" before any credential is
 *   persisted.
 */

const SESSION_COOKIE = '__Host-SessionId';

async function getCookieValue(
  ctx: BrowserContext,
  name: string,
): Promise<string> {
  const cookies = await ctx.cookies(DEMO_BASE_URL);
  const c = cookies.find((c) => c.name === name);
  if (!c) throw new Error(`cookie ${name} missing`);
  return c.value;
}

async function fetchCsrfToken(sessionId: string): Promise<string> {
  const ctx = await pwRequest.newContext({
    extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${sessionId}` },
  });
  try {
    const resp = await ctx.get(`${DEMO_BASE_URL}/o2p/user/csrf_token`);
    expect(resp.ok()).toBeTruthy();
    const { csrf_token } = (await resp.json()) as { csrf_token: string };
    return csrf_token;
  } finally {
    await ctx.dispose();
  }
}

test('Phase 1: stale X-CSRF-Token on register/start is rejected', async ({
  browser,
}) => {
  await resetDb();

  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/o2p/user/login');
  const authenticator = await addVirtualAuthenticator(page);
  await registerPasskeyFromLogin(page, 'e2e-reg-a', 'Reg Protection A');

  const oldSession = await getCookieValue(ctx, SESSION_COOKIE);
  const oldCsrf = await fetchCsrfToken(oldSession);

  // --- Rotate the session by logging out and back in as the same user.
  //     The new session gets a fresh CSRF token; the previously-rendered
  //     `oldCsrf` is now stale.
  await page.goto('/o2p/user/logout?redirect=/o2p/user/login');
  const signinFinish = page.waitForResponse(
    (r) => r.url().endsWith('/o2p/passkey/auth/finish') && r.status() === 200,
  );
  await page.getByTestId('login-passkey-signin').click();
  await signinFinish;
  await page.waitForLoadState('networkidle');
  const newSession = await getCookieValue(ctx, SESSION_COOKIE);
  expect(newSession).not.toBe(oldSession);
  const newCsrf = await fetchCsrfToken(newSession);
  expect(newCsrf).not.toBe(oldCsrf);

  // --- Negative #1: garbage CSRF token --------------------------------
  const apiBadCsrf = await pwRequest.newContext({
    extraHTTPHeaders: {
      Cookie: `${SESSION_COOKIE}=${newSession}`,
      'X-CSRF-Token': 'garbage-not-the-real-token',
      'Content-Type': 'application/json',
    },
  });
  try {
    const resp = await apiBadCsrf.post(
      `${DEMO_BASE_URL}/o2p/passkey/register/start`,
      {
        data: { username: 'x', displayname: 'x', mode: 'add_to_user' },
        failOnStatusCode: false,
      },
    );
    expect(resp.status()).toBe(401);
  } finally {
    await apiBadCsrf.dispose();
  }

  // --- Negative #2: missing X-CSRF-Token header on JSON POST ----------
  //     CSRF middleware requires the header for non-form Content-Type.
  const apiNoCsrf = await pwRequest.newContext({
    extraHTTPHeaders: {
      Cookie: `${SESSION_COOKIE}=${newSession}`,
      'Content-Type': 'application/json',
    },
  });
  try {
    const resp = await apiNoCsrf.post(
      `${DEMO_BASE_URL}/o2p/passkey/register/start`,
      {
        data: { username: 'x', displayname: 'x', mode: 'add_to_user' },
        failOnStatusCode: false,
      },
    );
    expect(resp.status()).toBe(401);
  } finally {
    await apiNoCsrf.dispose();
  }

  // --- Negative #3: stale CSRF from a previous session (the actual
  //     attack scenario from the doc — page rendered under old session,
  //     click happens after session rotation).
  const apiStaleCsrf = await pwRequest.newContext({
    extraHTTPHeaders: {
      Cookie: `${SESSION_COOKIE}=${newSession}`,
      'X-CSRF-Token': oldCsrf,
      'Content-Type': 'application/json',
    },
  });
  try {
    const resp = await apiStaleCsrf.post(
      `${DEMO_BASE_URL}/o2p/passkey/register/start`,
      {
        data: { username: 'x', displayname: 'x', mode: 'add_to_user' },
        failOnStatusCode: false,
      },
    );
    expect(resp.status()).toBe(401);
  } finally {
    await apiStaleCsrf.dispose();
  }

  // --- Positive: matching session + CSRF accepts the request. ---------
  const apiOk = await pwRequest.newContext({
    extraHTTPHeaders: {
      Cookie: `${SESSION_COOKIE}=${newSession}`,
      'X-CSRF-Token': newCsrf,
      'Content-Type': 'application/json',
    },
  });
  try {
    const resp = await apiOk.post(
      `${DEMO_BASE_URL}/o2p/passkey/register/start`,
      {
        data: {
          username: 'e2e-reg-a-extra',
          displayname: 'Reg Protection A Extra',
          mode: 'add_to_user',
        },
        failOnStatusCode: false,
      },
    );
    expect(resp.status()).toBe(200);
  } finally {
    await apiOk.dispose();
  }

  await authenticator.remove();
  await ctx.close();
});

test('Phase 2: session swap between register/start and register/finish → User ID mismatch', async ({
  browser,
  request,
}) => {
  await resetDb();

  // --- User A: passkey-registered, holds the initial credential.
  const ctxA = await browser.newContext();
  const pageA = await ctxA.newPage();
  await pageA.goto('/o2p/user/login');
  const authA = await addVirtualAuthenticator(pageA);
  await registerPasskeyFromLogin(pageA, 'e2e-reg-swap-a', 'Reg Swap A');

  // --- User B: separate context, OAuth2-registered with a distinct sub.
  await request.post(`${MOCK_OIDC_URL}/test/config`, {
    data: {
      email: 'b@example.com',
      sub: 'google_reg_swap_b',
      name: 'Reg Swap B',
      given_name: 'B',
      family_name: 'Swap',
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
  const bSession = await getCookieValue(ctxB, SESSION_COOKIE);
  const bCsrf = await fetchCsrfToken(bSession);

  // --- The attack: bypass the browser's natural register/finish call by
  //     running register/start + navigator.credentials.create() in A's
  //     page, capturing the body that *would* have been POSTed, and then
  //     submitting it ourselves under B's session.
  //
  //     A second (cross-platform) authenticator is required because the
  //     platform authenticator already holds A's credential — WebAuthn
  //     would otherwise reject `create()` with InvalidStateError. See
  //     `account-passkey-mgmt.spec.ts` for the same workaround.
  const authA2 = await addVirtualAuthenticator(pageA, { transport: 'usb' });

  const aSession = await getCookieValue(ctxA, SESSION_COOKIE);
  const aCsrf = await fetchCsrfToken(aSession);

  const registerBody = await pageA.evaluate(async (csrfToken) => {
    const b64urlToBytes = (s: string): Uint8Array => {
      const pad = '='.repeat((4 - (s.length % 4)) % 4);
      const base64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
      const raw = atob(base64);
      const out = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
      return out;
    };
    const abToB64url = (buf: ArrayBuffer): string => {
      const bytes = new Uint8Array(buf);
      let s = '';
      for (const b of bytes) s += String.fromCharCode(b);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    };

    const startResp = await fetch('/o2p/passkey/register/start', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'X-CSRF-Token': csrfToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'would-be-evil',
        displayname: 'Would-Be Evil',
        mode: 'add_to_user',
      }),
    });
    if (!startResp.ok) {
      throw new Error(`register/start failed: ${startResp.status}`);
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const opts: any = await startResp.json();
    const userHandle: string = opts.user.user_handle;

    const publicKey: PublicKeyCredentialCreationOptions = {
      ...opts,
      challenge: b64urlToBytes(opts.challenge),
      user: { ...opts.user, id: b64urlToBytes(userHandle) },
      excludeCredentials: (opts.excludeCredentials ?? []).map(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (c: any) => ({ type: 'public-key', id: b64urlToBytes(c.id) }),
      ),
    };

    const credential = (await navigator.credentials.create({
      publicKey,
    })) as PublicKeyCredential;
    const attestation = credential.response as AuthenticatorAttestationResponse;

    return {
      id: credential.id,
      raw_id: abToB64url(credential.rawId),
      type: credential.type,
      response: {
        attestation_object: abToB64url(attestation.attestationObject),
        client_data_json: abToB64url(attestation.clientDataJSON),
      },
      user_handle: userHandle,
      mode: 'add_to_user',
    };
  }, aCsrf);

  // --- Now submit /register/finish under B's session. The handler's
  //     `Option<AuthUser>` extraction succeeds (B is logged in, B's CSRF
  //     matches B's session), so `verify_session_then_finish_registration`
  //     is the path taken. There it finds SessionInfo {user: A} under the
  //     user_handle from the body and rejects with
  //     PasskeyError::Format("User ID mismatch") → 400.
  const apiB = await pwRequest.newContext({
    extraHTTPHeaders: {
      Cookie: `${SESSION_COOKIE}=${bSession}`,
      'X-CSRF-Token': bCsrf,
      'Content-Type': 'application/json',
    },
  });
  let finishStatus: number;
  let finishBody: string;
  try {
    const resp = await apiB.post(
      `${DEMO_BASE_URL}/o2p/passkey/register/finish`,
      { data: registerBody, failOnStatusCode: false },
    );
    finishStatus = resp.status();
    finishBody = await resp.text();
  } finally {
    await apiB.dispose();
  }
  expect(finishStatus).toBe(400);
  expect(finishBody).toMatch(/user id mismatch/i);

  // --- Verify nothing was persisted: A still has exactly 1 credential
  //     (the one from registerPasskeyFromLogin), B has 0.
  const apiAVerify = await pwRequest.newContext({
    extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${aSession}` },
  });
  try {
    const aCreds = await apiAVerify.get(
      `${DEMO_BASE_URL}/o2p/passkey/credentials`,
    );
    expect(aCreds.ok()).toBeTruthy();
    const aList = (await aCreds.json()) as Array<unknown>;
    expect(aList).toHaveLength(1);
  } finally {
    await apiAVerify.dispose();
  }

  const apiBVerify = await pwRequest.newContext({
    extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${bSession}` },
  });
  try {
    const bCreds = await apiBVerify.get(
      `${DEMO_BASE_URL}/o2p/passkey/credentials`,
    );
    expect(bCreds.ok()).toBeTruthy();
    const bList = (await bCreds.json()) as Array<unknown>;
    expect(bList).toHaveLength(0);
  } finally {
    await apiBVerify.dispose();
  }

  await authA2.remove();
  await authA.remove();
  await ctxA.close();
  await ctxB.close();
});
