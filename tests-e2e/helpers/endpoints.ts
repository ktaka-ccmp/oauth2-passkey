export const DEMO_PORT = Number(process.env.DEMO_BOTH_PORT ?? 13001);
export const MOCK_OIDC_PORT = Number(process.env.MOCK_OIDC_PORT ?? 19876);

// WebAuthn rejects IP-literal origins in Chrome (SecurityError: invalid domain).
// `localhost` is whitelisted as a secure context.
export const DEMO_BASE_URL = `http://localhost:${DEMO_PORT}`;
export const MOCK_OIDC_URL = `http://localhost:${MOCK_OIDC_PORT}`;
