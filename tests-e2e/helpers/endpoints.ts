export const DEMO_PORT = Number(process.env.DEMO_BOTH_PORT ?? 13001);
export const DEMO_CUSTOM_LOGIN_PORT = Number(
  process.env.DEMO_CUSTOM_LOGIN_PORT ?? 13002,
);
export const DEMO_CROSS_ORIGIN_AUTH_PORT = Number(
  process.env.DEMO_CROSS_ORIGIN_AUTH_PORT ?? 13010,
);
export const DEMO_CROSS_ORIGIN_API_PORT = Number(
  process.env.DEMO_CROSS_ORIGIN_API_PORT ?? 13011,
);
export const DEMO_TODO_PORT = Number(process.env.DEMO_TODO_PORT ?? 13020);
export const DEMO_PROFILE_PORT = Number(process.env.DEMO_PROFILE_PORT ?? 13021);
export const MOCK_OIDC_PORT = Number(process.env.MOCK_OIDC_PORT ?? 19876);

// WebAuthn rejects IP-literal origins in Chrome (SecurityError: invalid domain).
// `localhost` is whitelisted as a secure context.
export const DEMO_BASE_URL = `http://localhost:${DEMO_PORT}`;
export const DEMO_CUSTOM_LOGIN_BASE_URL = `http://localhost:${DEMO_CUSTOM_LOGIN_PORT}`;
export const DEMO_CROSS_ORIGIN_AUTH_URL = `http://localhost:${DEMO_CROSS_ORIGIN_AUTH_PORT}`;
export const DEMO_CROSS_ORIGIN_API_URL = `http://localhost:${DEMO_CROSS_ORIGIN_API_PORT}`;
export const DEMO_TODO_BASE_URL = `http://localhost:${DEMO_TODO_PORT}`;
export const DEMO_PROFILE_BASE_URL = `http://localhost:${DEMO_PROFILE_PORT}`;
export const MOCK_OIDC_URL = `http://localhost:${MOCK_OIDC_PORT}`;
