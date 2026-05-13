/**
 * No-op. The Postgres dependency required by demo-todo / demo-profile
 * is owned by the caller (CI's `services:` block or the developer's
 * local `docker run` / `docker compose`); Playwright should not be
 * tearing down something it didn't start.
 *
 * See `global-setup.ts` for context.
 */
export default async function globalTeardown() {}
