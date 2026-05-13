import { defineConfig, devices } from '@playwright/test';
import {
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

export default defineConfig({
  testDir: './tests',
  fullyParallel: false, // shared backend state — keep serial
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  timeout: 30_000,
  expect: { timeout: 5_000 },

  use: {
    baseURL: DEMO_BASE_URL,
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          // Disable Chrome's FedCM so `navigator.credentials.get({ identity })`
          // does not try to reach the real `accounts.google.com/gsi/fedcm.json`
          // when --headed is used. The library's client JS catches the failure
          // and falls back to the popup flow, which is what the specs assert.
          // fedcm.spec.ts exercises FedCM at the HTTP API level only, so this
          // flag does not affect it.
          args: [
            '--disable-features=FedCm,FedCmAuthz,FedCmMultipleIdentityProviders',
          ],
        },
      },
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
      // `--features e2e-test` flips the passthrough Cargo feature that
      // mounts `POST /o2p/test/reset` inside the library (used by the
      // spec helper between tests) and skips `.env` loading. Without
      // that flag the demo compiles as a clean release binary.
      command: `cargo run -p demo-todo --features e2e-test`,
      url: `${DEMO_TODO_BASE_URL}/`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        DEMO_TODO_PORT: String(DEMO_TODO_PORT),
        APP_DATABASE_URL: 'sqlite::memory:',
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
      command: `cargo run -p demo-profile --features e2e-test`,
      url: `${DEMO_PROFILE_BASE_URL}/`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        DEMO_PROFILE_PORT: String(DEMO_PROFILE_PORT),
        APP_DATABASE_URL: 'sqlite::memory:',
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
      command: `cargo run -p demo-cross-origin --features e2e-test`,
      url: `${DEMO_CROSS_ORIGIN_AUTH_URL}/`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        AUTH_PORT: String(DEMO_CROSS_ORIGIN_AUTH_PORT),
        API_PORT: String(DEMO_CROSS_ORIGIN_API_PORT),
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
      command: `cargo run -p demo-custom-login --features e2e-test`,
      url: `${DEMO_CUSTOM_LOGIN_BASE_URL}/login`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        DEMO_CUSTOM_LOGIN_PORT: String(DEMO_CUSTOM_LOGIN_PORT),
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
      command: `cargo run -p demo-both --features e2e-test`,
      url: `${DEMO_BASE_URL}/o2p/user/login`,
      timeout: 180_000,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      env: {
        DEMO_BOTH_PORT: String(DEMO_PORT),
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
