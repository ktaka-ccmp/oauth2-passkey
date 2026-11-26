import type { Page } from '@playwright/test';

export interface VirtualAuthenticator {
  authenticatorId: string;
  remove: () => Promise<void>;
}

/**
 * Attach a Chrome DevTools Protocol virtual authenticator to the page so that
 * `navigator.credentials.create()` / `.get()` resolve without a real device.
 *
 * Call AFTER `page.goto(...)` so the CDP session is bound to the right target.
 * Defaults emulate a platform passkey with resident keys, automatic UV, and
 * automatic user-presence simulation.
 */
export async function addVirtualAuthenticator(
  page: Page,
): Promise<VirtualAuthenticator> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send(
    'WebAuthn.addVirtualAuthenticator',
    {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    },
  );

  return {
    authenticatorId,
    remove: async () => {
      await client.send('WebAuthn.removeVirtualAuthenticator', {
        authenticatorId,
      });
    },
  };
}
