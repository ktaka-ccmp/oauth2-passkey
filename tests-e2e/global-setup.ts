import { createConnection } from 'net';

/**
 * Verify the Postgres dependency required by demo-todo / demo-profile
 * is reachable BEFORE Playwright's webServer entries start their Rust
 * processes. Those demos hard-code `sqlx::PgPool::connect()` which
 * fails fast on a closed port, killing the webServer before any test
 * (or even `globalSetup` orchestration) can intervene.
 *
 * Why this only checks, not starts:
 *
 * Playwright runs `globalSetup` and `webServer` entries in parallel,
 * so spawning the container from here loses the race. Pre-starting
 * Postgres is delegated to the caller:
 *
 *   - CI: `.github/workflows/e2e.yml` declares `services: postgres`
 *   - Local: run `docker compose -f db/postgresql/docker-compose.yaml up -d`
 *     (or any equivalent that publishes Postgres on `localhost:54320`
 *     with user/pass/db = `demo`)
 *
 * If the port isn't reachable, fail loudly with the remediation
 * command instead of letting demo-todo silently emit `PoolTimedOut`.
 */
const HOST = '127.0.0.1';
const PORT = 54320;

function canConnect(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    const done = (ok: boolean) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

export default async function globalSetup() {
  const ok = await canConnect(HOST, PORT, 2000);
  if (!ok) {
    // eslint-disable-next-line no-console
    console.error(
      `[global-setup] Postgres is not reachable at ${HOST}:${PORT}.\n` +
        `demo-todo and demo-profile require it.\n` +
        `\n` +
        `  Quick start: docker run -d --rm --name e2e-pg \\\n` +
        `    -p 54320:5432 \\\n` +
        `    -e POSTGRES_USER=demo -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=demo \\\n` +
        `    postgres:16-alpine\n` +
        `\n` +
        `  See tests-e2e/README.md for details.\n`,
    );
    throw new Error('Postgres not reachable; aborting Playwright run');
  }
  // eslint-disable-next-line no-console
  console.log(`[global-setup] Postgres reachable on ${HOST}:${PORT}`);
}
