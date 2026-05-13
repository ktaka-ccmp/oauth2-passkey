import { request } from '@playwright/test';
import { DEMO_BASE_URL, MOCK_OIDC_URL } from './endpoints';

/**
 * Wipe persistent state between tests.
 *
 * Hits `POST {targetBaseUrl}/o2p/test/reset`. The route lives inside
 * `oauth2-passkey-axum`, gated behind the `e2e-test` Cargo feature —
 * each demo's `Cargo.toml` declares a passthrough feature of the same
 * name, which Playwright flips on at build time via `cargo run -p
 * <demo> --features e2e-test`. Demo source code itself carries no
 * test wiring.
 *
 * Library state (users, passkeys, oauth2 accounts, login history) is
 * cascade-deleted and SQLite sequence counters are reset so the next
 * registered user lands at `sequence_number=1` again. App-side tables
 * in demo-todo / demo-profile keep their rows; rows are keyed by
 * random user_id UUIDs so they never leak into subsequent tests.
 *
 * @param targetBaseUrl base URL of the demo to reset; defaults to demo-both
 */
export async function resetDb(
  targetBaseUrl: string = DEMO_BASE_URL,
): Promise<void> {
  const ctx = await request.newContext();
  try {
    const reset = await ctx.post(`${targetBaseUrl}/o2p/test/reset`);
    if (!reset.ok()) {
      throw new Error(
        `${targetBaseUrl} /o2p/test/reset failed: ${reset.status()} ${await reset.text()}`,
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
