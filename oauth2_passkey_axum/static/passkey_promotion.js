// Passkey Promotion after OAuth2 Login (experimental)
//
// This script handles passkey registration promotion after OAuth2 login.
// It listens for 'auth_complete' messages from the OAuth2 popup and sets a
// sessionStorage flag. After the page reloads, it checks the flag and shows
// a promotion modal encouraging the user to register a passkey.
//
// This file is only served when O2P_PASSKEY_PROMOTION=true.

// Listen for OAuth2 popup completion to set the promotion flag.
// This listener fires alongside the existing one in oauth2.js.
// The flag is set before the existing setTimeout(reload, 10) fires.
window.addEventListener('message', function(event) {
    if (event.data === 'auth_complete') {
        sessionStorage.setItem('oauth2_login_just_completed', 'true');
    }
});

// Base64 utility functions (duplicated to avoid dependency on passkey.js globals)
function _promotionArrayBufferToBase64URL(buffer) {
    if (!buffer) return null;
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const byte of bytes) {
        str += String.fromCharCode(byte);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function _promotionBase64URLToUint8Array(base64URL) {
    if (!base64URL) return null;
    const padding = '='.repeat((4 - base64URL.length % 4) % 4);
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/') + padding;
    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

// Check if passkey promotion should be shown
async function checkPasskeyPromotion() {
    // Check sessionStorage flag
    const justCompleted = sessionStorage.getItem('oauth2_login_just_completed');
    if (!justCompleted) return;

    // Consume the flag immediately
    sessionStorage.removeItem('oauth2_login_just_completed');

    // Check permanent opt-out
    if (localStorage.getItem('passkey_promotion_dismissed') === 'true') {
        console.log('Passkey promotion: permanently dismissed by user');
        return;
    }

    // Check WebAuthn support
    if (!window.PublicKeyCredential) {
        console.log('Passkey promotion: WebAuthn not supported');
        return;
    }

    // Check if csrfToken is available (set by the page template)
    if (typeof csrfToken === 'undefined' || !csrfToken) {
        console.log('Passkey promotion: csrfToken not available');
        return;
    }

    // Ask server if promotion is appropriate for this device (UA + AAGUID heuristic)
    try {
        const response = await fetch(O2P_ROUTE_PREFIX + '/passkey/promotion/check', {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'X-CSRF-Token': csrfToken },
        });
        if (response.ok) {
            const data = await response.json();
            if (!data.should_promote) {
                console.log('Passkey promotion: server heuristic says not needed for this platform');
                return;
            }
        }
    } catch (e) {
        // If the check fails, show the modal anyway (fail-open)
        console.log('Passkey promotion: check failed, showing modal as fallback', e);
    }

    // Show the promotion modal
    showPasskeyPromotionModal();
}

// Create and show the promotion modal
function showPasskeyPromotionModal() {
    // Remove existing modal if any
    const existing = document.getElementById('passkey-promotion-modal');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'passkey-promotion-modal';
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:10000;';

    const modal = document.createElement('div');
    modal.style.cssText = 'background:white;padding:24px;border-radius:8px;max-width:400px;width:90%;box-shadow:0 4px 20px rgba(0,0,0,0.15);';

    modal.innerHTML = `
        <h3 style="margin:0 0 12px 0;font-size:18px;">Register a Passkey?</h3>
        <p style="margin:0 0 20px 0;color:#555;font-size:14px;line-height:1.5;">
            You can register a passkey for faster, passwordless login next time.
            Passkeys use your device's biometrics (fingerprint, face) or screen lock.
        </p>
        <div style="display:flex;flex-direction:column;gap:8px;">
            <button id="passkey-promo-accept"
                style="padding:10px 16px;background:#2563eb;color:white;border:none;border-radius:6px;cursor:pointer;font-size:14px;">
                Register Passkey
            </button>
            <button id="passkey-promo-dismiss"
                style="padding:10px 16px;background:#f3f4f6;color:#374151;border:1px solid #d1d5db;border-radius:6px;cursor:pointer;font-size:14px;">
                Not Now
            </button>
            <button id="passkey-promo-never"
                style="padding:8px 16px;background:none;color:#9ca3af;border:none;cursor:pointer;font-size:12px;">
                Don't Ask Again
            </button>
        </div>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Event handlers
    document.getElementById('passkey-promo-accept').addEventListener('click', function() {
        closePasskeyPromotionModal();
        acceptPasskeyPromotion();
    });

    document.getElementById('passkey-promo-dismiss').addEventListener('click', function() {
        closePasskeyPromotionModal();
    });

    document.getElementById('passkey-promo-never').addEventListener('click', function() {
        localStorage.setItem('passkey_promotion_dismissed', 'true');
        closePasskeyPromotionModal();
    });

    // Close on overlay click
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) {
            closePasskeyPromotionModal();
        }
    });
}

function closePasskeyPromotionModal() {
    const modal = document.getElementById('passkey-promotion-modal');
    if (modal) modal.remove();
}

// Accept passkey promotion: fetch user info and start registration
async function acceptPasskeyPromotion() {
    try {
        // Fetch user info to get username and display name
        const userInfoResponse = await fetch(O2P_ROUTE_PREFIX + '/user/info', {
            method: 'GET',
            credentials: 'same-origin'
        });

        let username = 'user';
        let displayname = 'User';

        if (userInfoResponse.ok) {
            const userData = await userInfoResponse.json();
            const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
            username = userData.account ? `${userData.account}@${today}` : 'user';
            displayname = userData.label || 'User';
        }

        // Call the promotion-specific registration start endpoint
        const startResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/promotion/register/start', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': csrfToken,
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                username: username,
                displayname: displayname,
                mode: 'add_to_user',
            })
        });

        if (!startResponse.ok) {
            const errorText = await startResponse.text();
            console.error('Promotion registration start failed:', errorText);
            alert('Passkey registration failed: ' + errorText);
            return;
        }

        const options = await startResponse.json();
        console.log('Promotion registration options:', options);

        // Convert base64url strings to Uint8Array
        let userHandle = options.user.user_handle;
        options.challenge = _promotionBase64URLToUint8Array(options.challenge);
        options.user.id = _promotionBase64URLToUint8Array(userHandle);

        // Transform excludeCredentials
        if (options.excludeCredentials && Array.isArray(options.excludeCredentials)) {
            options.excludeCredentials = options.excludeCredentials.map(credential => ({
                type: 'public-key',
                id: _promotionBase64URLToUint8Array(credential.id),
            }));
        } else {
            options.excludeCredentials = [];
        }

        console.log('Processed promotion registration options:', options);

        const credential = await navigator.credentials.create({
            publicKey: options
        });

        const credentialResponse = {
            id: credential.id,
            raw_id: _promotionArrayBufferToBase64URL(credential.rawId),
            type: credential.type,
            response: {
                attestation_object: _promotionArrayBufferToBase64URL(credential.response.attestationObject),
                client_data_json: _promotionArrayBufferToBase64URL(credential.response.clientDataJSON)
            },
            user_handle: userHandle,
            mode: 'add_to_user',
        };

        console.log('Promotion registration response:', credentialResponse);

        // Reuse existing registration finish endpoint
        const finishResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/register/finish', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': csrfToken,
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin',
            body: JSON.stringify(credentialResponse)
        });

        if (finishResponse.ok) {
            alert('Passkey registered successfully! You can use it to log in next time.');
            location.reload();
        } else {
            const errorText = await finishResponse.text();
            throw new Error('Registration verification failed: ' + errorText);
        }
    } catch (error) {
        if (error.name === 'InvalidStateError') {
            // Authenticator already has a credential for this user
            console.log('Authenticator already has a credential for this user');
            alert('A passkey for this account already exists on this device.');
            return;
        }
        if (error.name === 'NotAllowedError') {
            // User cancelled the operation
            console.log('User cancelled passkey registration');
            return;
        }
        console.error('Error during promotion registration:', error);
        alert('Passkey registration failed: ' + error.message);
    }
}

// Trigger promotion check on page load
document.addEventListener('DOMContentLoaded', checkPasskeyPromotion);
