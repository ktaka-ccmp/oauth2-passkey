import { request } from '@playwright/test';
import { DEMO_BASE_URL, MOCK_OIDC_URL } from './endpoints';

/**
 * Wipe persistent state between tests.
 *
 * Hits `POST {targetBaseUrl}/test/reset` on the named demo (each demo
 * mounts this when its `*_TEST_RESET=1` env var is set) to clear all
 * users/passkeys/oauth2 accounts, then resets mock-oidc's `TestUser`
 * back to its default identity so the next test starts from the same
 * baseline.
 *
 * Each demo process has its own library DB (in-memory SQLite is
 * per-process even with `cache=shared`), so the DB reset only needs to
 * hit the demo under test.
 *
 * @param targetBaseUrl base URL of the demo to reset; defaults to demo-both
 */
export async function resetDb(
  targetBaseUrl: string = DEMO_BASE_URL,
): Promise<void> {
  const ctx = await request.newContext();
  try {
    const reset = await ctx.post(`${targetBaseUrl}/test/reset`);
    if (!reset.ok()) {
      throw new Error(
        `${targetBaseUrl} /test/reset failed: ${reset.status()} ${await reset.text()}`,
      );
    }
    // Reset the mock-oidc identity so subsequent OAuth2 logins create a
    // fresh user rather than reusing a sub set by a previous test.
    await ctx.post(`${MOCK_OIDC_URL}/test/config`, {
      data: {
        email: 'first-user@example.com',
        sub: 'google_first-user-test-google-id',
        name: 'First User',
        given_name: 'First',
        family_name: 'User',
      },
    });
  } finally {
    await ctx.dispose();
  }
}
