import { request } from '@playwright/test';
import { DEMO_BASE_URL, MOCK_OIDC_URL } from './endpoints';

/**
 * Wipe persistent state between tests.
 *
 * Hits the `/test/reset` route on demo-both (mounted only when
 * `DEMO_BOTH_TEST_RESET=1`) to clear all users/passkeys/oauth2 accounts,
 * then resets mock-oidc's `TestUser` back to its default identity so the
 * next test starts from the same baseline.
 *
 * The Playwright config sets the env var unconditionally, so tests can
 * always call this in `test.beforeEach` / at the top of a test.
 */
export async function resetDb(): Promise<void> {
  const ctx = await request.newContext();
  try {
    const reset = await ctx.post(`${DEMO_BASE_URL}/test/reset`);
    if (!reset.ok()) {
      throw new Error(
        `demo-both /test/reset failed: ${reset.status()} ${await reset.text()}`,
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
