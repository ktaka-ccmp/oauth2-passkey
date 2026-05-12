import type { Page } from '@playwright/test';
import { expect } from '@playwright/test';

/**
 * Drive the passkey registration UI from the login page.
 *
 * Assumes:
 * - `page` is currently on `/o2p/user/login`
 * - a virtual authenticator has already been attached
 *
 * After success the user is logged in and the login page has reloaded.
 */
export async function registerPasskeyFromLogin(
  page: Page,
  username: string,
  displayName: string,
): Promise<void> {
  await page.getByTestId('login-passkey-register').click();
  await fillAndSubmitRegistration(page, username, displayName);
}

/**
 * Drive the "Add New Passkey" flow from the account page.
 *
 * Assumes the user is logged in and the account page is loaded with a
 * virtual authenticator attached.
 */
export async function addPasskeyFromAccount(
  page: Page,
  username: string,
  displayName: string,
): Promise<void> {
  await page.getByTestId('add-passkey-btn').click();
  await fillAndSubmitRegistration(page, username, displayName);
}

async function fillAndSubmitRegistration(
  page: Page,
  username: string,
  displayName: string,
): Promise<void> {
  const modal = page.getByTestId('passkey-reg-modal');
  await expect(modal).toBeVisible();
  await modal.getByTestId('passkey-reg-username').fill(username);
  await modal.getByTestId('passkey-reg-displayname').fill(displayName);

  const finish = page.waitForResponse(
    (r) =>
      r.url().endsWith('/o2p/passkey/register/finish') && r.status() === 200,
  );
  await modal.getByTestId('passkey-reg-submit').click();
  await finish;
  await page.waitForLoadState('networkidle');
}
