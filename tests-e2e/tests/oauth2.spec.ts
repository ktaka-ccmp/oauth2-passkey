import { test, expect } from '@playwright/test';

test('OAuth2 login via mock-oidc creates session', async ({ page, context }) => {
  const logBrowser = !!process.env.E2E_BROWSER_LOG;
  if (logBrowser) {
    page.on('console', (m) => console.log(`[parent:${m.type()}]`, m.text()));
    page.on('pageerror', (e) => console.log('[parent:err]', e.message));
  }

  await page.goto('/o2p/user/login');

  // The Google button opens a popup that drives the authorization-code flow
  // against mock-oidc; the popup messages the opener and self-closes.
  const popupPromise = context.waitForEvent('page');
  await page
    .getByRole('button', { name: /Register \/ Sign in with Google/i })
    .click();
  const popup = await popupPromise;

  if (logBrowser) {
    popup.on('framenavigated', (f) => console.log('[popup:nav]', f.url()));
    popup.on('console', (m) => console.log(`[popup:${m.type()}]`, m.text()));
    popup.on('pageerror', (e) => console.log('[popup:err]', e.message));
  }

  await popup.waitForEvent('close', { timeout: 15_000 });

  // The opener listens for the auth_complete postMessage and reloads itself.
  // Wait for that reload to settle.
  await page.waitForLoadState('networkidle');

  // Verify session was established by visiting a protected route.
  await page.goto('/');
  await expect(page.locator('body')).toContainText(/protected page/i);
});
