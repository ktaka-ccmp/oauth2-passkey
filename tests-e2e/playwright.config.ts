import { createRequire } from 'node:module';
import { defineConfig, devices } from '@playwright/test';
import {
  APP_DATABASE_URL,
  DEMO_BASE_URL,
  DEMO_CROSS_ORIGIN_API_PORT,
  DEMO_CROSS_ORIGIN_API_URL,
  DEMO_CROSS_ORIGIN_AUTH_PORT,
  DEMO_CROSS_ORIGIN_AUTH_URL,
  DEMO_CUSTOM_LOGIN_BASE_URL,
  DEMO_CUSTOM_LOGIN_PORT,
  DEMO_PORT,
  DEMO_PROFILE_BASE_URL,
  DEMO_PROFILE_PORT,
  DEMO_TODO_BASE_URL,
  DEMO_TODO_PORT,
  MOCK_OIDC_PORT,
  MOCK_OIDC_URL,
} from './helpers/endpoints';

const require = createRequire(import.meta.url);

export default defineConfig({
  testDir: './tests',
  fullyParallel: false, // shared backend state — keep serial
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  timeout: 30_000,
  expect: { timeout: 5_000 },
  // demo-todo / demo-profile need a real Postgres; globalSetup starts
  // an ephemeral container, globalTeardown stops it. `require.resolve`
  // gives Playwright an absolute path so the loader picks it up
  // regardless of cwd. The `.ts` extension is required — Node's
  // `require.resolve` does not auto-append it.
  globalSetup: require.resolve('./global-setup.ts'),
  globalTeardown: require.resolve('./global-teardown.ts'),

  use: {
    baseURL: DEMO_BASE_URL,
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: [
    {
      command: `cargo run -p mock-oidc`,
      url: `${MOCK_OIDC_URL}/test/healthz`,
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        MOCK_OIDC_BIND: `127.0.0.1:${MOCK_OIDC_PORT}`,
        // Issuer must use the same hostname the browser sees so the discovery
        // document URLs are reachable from the SUT.
        MOCK_OIDC_ISSUER: MOCK_OIDC_URL,
        RUST_LOG: process.env.RUST_LOG ?? 'info',
      },
    },
    {
      command: `cargo run -p demo-todo`,
      url: `${DEMO_TODO_BASE_URL}/`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        DEMO_TODO_PORT: String(DEMO_TODO_PORT),
        DEMO_TODO_SKIP_DOTENV: '1',
        DEMO_TODO_TEST_RESET: '1',
        APP_DATABASE_URL,
        ORIGIN: DEMO_TODO_BASE_URL,
        OAUTH2_GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
        OAUTH2_GOOGLE_CLIENT_SECRET: 'test-client-secret',
        OAUTH2_ISSUER_URL: MOCK_OIDC_URL,
        OAUTH2_GOOGLE_PROMPT: '',
        O2P_PASSKEY_PROMOTION: 'disabled',
        GENERIC_CACHE_STORE_TYPE: 'memory',
        GENERIC_CACHE_STORE_URL: 'memory://',
        GENERIC_DATA_STORE_TYPE: 'sqlite',
        GENERIC_DATA_STORE_URL:
          'sqlite:file:e2e-todo-memdb?mode=memory&cache=shared',
        RUST_LOG: process.env.RUST_LOG ?? 'info',
      },
    },
    {
      command: `cargo run -p demo-profile`,
      url: `${DEMO_PROFILE_BASE_URL}/`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        DEMO_PROFILE_PORT: String(DEMO_PROFILE_PORT),
        DEMO_PROFILE_SKIP_DOTENV: '1',
        DEMO_PROFILE_TEST_RESET: '1',
        APP_DATABASE_URL,
        ORIGIN: DEMO_PROFILE_BASE_URL,
        OAUTH2_GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
        OAUTH2_GOOGLE_CLIENT_SECRET: 'test-client-secret',
        OAUTH2_ISSUER_URL: MOCK_OIDC_URL,
        OAUTH2_GOOGLE_PROMPT: '',
        O2P_PASSKEY_PROMOTION: 'disabled',
        GENERIC_CACHE_STORE_TYPE: 'memory',
        GENERIC_CACHE_STORE_URL: 'memory://',
        GENERIC_DATA_STORE_TYPE: 'sqlite',
        GENERIC_DATA_STORE_URL:
          'sqlite:file:e2e-profile-memdb?mode=memory&cache=shared',
        RUST_LOG: process.env.RUST_LOG ?? 'info',
      },
    },
    {
      // demo-cross-origin spawns BOTH auth (:13010) and api (:13011)
      // servers in a single process. Wait on the auth server's `/`
      // (renders even when anonymous) to know both are up.
      command: `cargo run -p demo-cross-origin`,
      url: `${DEMO_CROSS_ORIGIN_AUTH_URL}/`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        AUTH_PORT: String(DEMO_CROSS_ORIGIN_AUTH_PORT),
        API_PORT: String(DEMO_CROSS_ORIGIN_API_PORT),
        DEMO_CROSS_ORIGIN_SKIP_DOTENV: '1',
        DEMO_CROSS_ORIGIN_TEST_RESET: '1',
        ORIGIN: DEMO_CROSS_ORIGIN_AUTH_URL,
        API_ORIGIN: DEMO_CROSS_ORIGIN_API_URL,
        // Both servers run on `localhost` so the cookie is implicitly
        // shared (browsers scope cookies by host, not port). No need
        // to set SESSION_COOKIE_DOMAIN; this mirrors the README's
        // "localhost (Easiest)" topology.
        CORS_ALLOWED_ORIGINS: DEMO_CROSS_ORIGIN_AUTH_URL,
        CORS_ALLOW_CREDENTIALS: 'true',
        OAUTH2_GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
        OAUTH2_GOOGLE_CLIENT_SECRET: 'test-client-secret',
        OAUTH2_ISSUER_URL: MOCK_OIDC_URL,
        OAUTH2_GOOGLE_PROMPT: '',
        O2P_PASSKEY_PROMOTION: 'disabled',
        GENERIC_CACHE_STORE_TYPE: 'memory',
        GENERIC_CACHE_STORE_URL: 'memory://',
        GENERIC_DATA_STORE_TYPE: 'sqlite',
        GENERIC_DATA_STORE_URL:
          'sqlite:file:e2e-cross-origin-memdb?mode=memory&cache=shared',
        RUST_LOG: process.env.RUST_LOG ?? 'info',
      },
    },
    {
      command: `cargo run -p demo-custom-login`,
      url: `${DEMO_CUSTOM_LOGIN_BASE_URL}/login`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        DEMO_CUSTOM_LOGIN_PORT: String(DEMO_CUSTOM_LOGIN_PORT),
        DEMO_CUSTOM_LOGIN_SKIP_DOTENV: '1',
        DEMO_CUSTOM_LOGIN_TEST_RESET: '1',
        ORIGIN: DEMO_CUSTOM_LOGIN_BASE_URL,
        // The whole point of this demo: redirect anon users to /login,
        // not the built-in /o2p/user/login.
        O2P_LOGIN_URL: '/login',
        OAUTH2_GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
        OAUTH2_GOOGLE_CLIENT_SECRET: 'test-client-secret',
        OAUTH2_ISSUER_URL: MOCK_OIDC_URL,
        OAUTH2_GOOGLE_PROMPT: '',
        O2P_PASSKEY_PROMOTION: 'disabled',
        GENERIC_CACHE_STORE_TYPE: 'memory',
        GENERIC_CACHE_STORE_URL: 'memory://',
        GENERIC_DATA_STORE_TYPE: 'sqlite',
        GENERIC_DATA_STORE_URL:
          'sqlite:file:e2e-custom-login-memdb?mode=memory&cache=shared',
        RUST_LOG: process.env.RUST_LOG ?? 'info',
      },
    },
    {
      command: `cargo run -p demo-both`,
      url: `${DEMO_BASE_URL}/o2p/user/login`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        DEMO_BOTH_PORT: String(DEMO_PORT),
        // Block demo-both from reading the user's workspace-root `.env`,
        // which may set values (e.g. PASSKEY_AUTHENTICATOR_ATTACHMENT) that
        // break E2E assumptions.
        DEMO_BOTH_SKIP_DOTENV: '1',
        // Mount POST /test/reset so Playwright fixtures can wipe state
        // between tests. The route is only added when this var is set.
        DEMO_BOTH_TEST_RESET: '1',
        ORIGIN: DEMO_BASE_URL,
        OAUTH2_GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
        OAUTH2_GOOGLE_CLIENT_SECRET: 'test-client-secret',
        OAUTH2_ISSUER_URL: MOCK_OIDC_URL,
        OAUTH2_GOOGLE_PROMPT: '',
        // Enable passkey promotion so the post-OAuth2 popup flow is covered
        // by the E2E suite.
        O2P_PASSKEY_PROMOTION: 'ask',
        // Enable FedCM so the /oauth2/fedcm/* routes are mounted. Existing
        // OAuth2 tests still work because the JS falls back to the popup
        // flow when the browser-side FedCM dialog can't reach a real
        // identity provider config endpoint.
        O2P_FEDCM: 'enabled',
        GENERIC_CACHE_STORE_TYPE: 'memory',
        GENERIC_CACHE_STORE_URL: 'memory://',
        GENERIC_DATA_STORE_TYPE: 'sqlite',
        GENERIC_DATA_STORE_URL: 'sqlite:file:e2e-memdb?mode=memory&cache=shared',
        RUST_LOG: process.env.RUST_LOG ?? 'info,oauth2_passkey=debug',
      },
    },
  ],
});
