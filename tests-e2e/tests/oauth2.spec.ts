import { test, expect } from '@playwright/test';
import { resetDb } from '../helpers/db';

test('OAuth2 login via mock-oidc, dismiss promotion popup, verify session', async ({
  page,
  context,
}) => {
  const logBrowser = !!process.env.E2E_BROWSER_LOG;
  if (logBrowser) {
    page.on('console', (m) => console.log(`[parent:${m.type()}]`, m.text()));
    page.on('pageerror', (e) => console.log('[parent:err]', e.message));
  }

  await resetDb();
  await page.goto('/o2p/user/login');

  // The Google button opens a popup that drives the authorization-code flow
  // against mock-oidc. With O2P_PASSKEY_PROMOTION=ask, the same popup then
  // navigates to the promotion page, which we dismiss explicitly.
  const popupPromise = context.waitForEvent('page');
  await page.getByTestId('login-oauth2-google').click();
  const popup = await popupPromise;

  if (logBrowser) {
    popup.on('framenavigated', (f) => console.log('[popup:nav]', f.url()));
    popup.on('console', (m) => console.log(`[popup:${m.type()}]`, m.text()));
    popup.on('pageerror', (e) => console.log('[popup:err]', e.message));
  }

  // Wait for the promotion page to load, then click "Not Now".
  await popup.waitForURL(/\/o2p\/passkey\/promotion\/popup/, {
    timeout: 15_000,
  });
  const dismissBtn = popup.locator('#passkey-promo-dismiss');
  await dismissBtn.waitFor({ timeout: 10_000 });
  await dismissBtn.click();

  await popup.waitForEvent('close', { timeout: 10_000 });
  await page.waitForLoadState('networkidle');

  // Verify session was established by visiting a protected route.
  await page.goto('/');
  await expect(page.locator('body')).toContainText(/protected page/i);
});
