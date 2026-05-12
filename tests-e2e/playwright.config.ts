import { defineConfig, devices } from '@playwright/test';
import {
  DEMO_BASE_URL,
  DEMO_PORT,
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
      command: `cargo run -p demo-both`,
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
        // Disable the post-OAuth2 passkey promotion popup so the OAuth2 test
        // doesn't have to dismiss a second window. Promotion has its own test
        // in a later phase.
        O2P_PASSKEY_PROMOTION: 'disabled',
        GENERIC_CACHE_STORE_TYPE: 'memory',
        GENERIC_CACHE_STORE_URL: 'memory://',
        GENERIC_DATA_STORE_TYPE: 'sqlite',
        GENERIC_DATA_STORE_URL: 'sqlite:file:e2e-memdb?mode=memory&cache=shared',
        RUST_LOG: process.env.RUST_LOG ?? 'info,oauth2_passkey=debug',
      },
    },
  ],
});
