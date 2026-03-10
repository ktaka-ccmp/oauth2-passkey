// WebAuthn capabilities detection using getClientCapabilities API (Chrome 131+)
// Cached capabilities object - null means not yet fetched, undefined means not supported
let _passkeyCapabilities = null;

// Initialize and cache WebAuthn capabilities
async function initPasskeyCapabilities() {
    if (_passkeyCapabilities !== null) {
        return _passkeyCapabilities;
    }
    if (typeof PublicKeyCredential?.getClientCapabilities === 'function') {
        try {
            _passkeyCapabilities = await PublicKeyCredential.getClientCapabilities();
            console.log('WebAuthn capabilities:', _passkeyCapabilities);
            return _passkeyCapabilities;
        } catch (err) {
            console.warn('getClientCapabilities error:', err);
            _passkeyCapabilities = undefined;
            return undefined;
        }
    }
    _passkeyCapabilities = undefined;
    console.log('getClientCapabilities not supported, using fallback feature detection');
    return undefined;
}

// Check if a specific Signal API capability is supported
// Falls back to typeof check if getClientCapabilities is not available
function hasSignalCapability(capabilityName) {
    // If capabilities are cached, use them
    if (_passkeyCapabilities) {
        return _passkeyCapabilities[capabilityName] === true;
    }
    // Fallback: check if the function exists
    if (window.PublicKeyCredential) {
        return typeof window.PublicKeyCredential[capabilityName] === 'function';
    }
    return false;
}

// Initialize capabilities on page load
initPasskeyCapabilities();

// Base64 utility functions
function arrayBufferToBase64URL(buffer) {
    if (!buffer) return null;
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const byte of bytes) {
        str += String.fromCharCode(byte);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLToUint8Array(base64URL) {
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

// Authentication functions
async function startAuthentication() {
    const authStatus = document.getElementById("auth-status");
    const authActions = document.getElementById("auth-actions");

    try {
        const startResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/auth/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: "{}"
        });

        if (!startResponse.ok) {
            const errorText = await startResponse.text();
            alert('Authentication failed: ' + errorText);
            return;
        }

        const options = await startResponse.json();
        console.log('Raw Authentication options:', options);

        // Convert base64url strings
        options.challenge = base64URLToUint8Array(options.challenge);
        if (options.allowCredentials && Array.isArray(options.allowCredentials)) {
            console.log('Raw credentials:', options.allowCredentials);
            options.allowCredentials = options.allowCredentials.map(credential => ({
                type: 'public-key',  // Required by WebAuthn
                id: base64URLToUint8Array(credential.id),
                transports: credential.transports  // Optional
            }));
            console.log('Processed credentials:', options.allowCredentials);
        } else {
            options.allowCredentials = [];
        }
        console.log('Processed Authentication options:', options);

        const credential = await navigator.credentials.get({
            publicKey: options
        });

        console.log('Authentication credential:', credential);

        const authResponse = {
            auth_id: options.authId,
            id: credential.id,
            raw_id: arrayBufferToBase64URL(credential.rawId),
            type: credential.type,
            authenticator_attachment: credential.authenticatorAttachment,
            response: {
                authenticator_data: arrayBufferToBase64URL(credential.response.authenticatorData),
                client_data_json: arrayBufferToBase64URL(credential.response.clientDataJSON),
                signature: arrayBufferToBase64URL(credential.response.signature),
                user_handle: arrayBufferToBase64URL(credential.response.userHandle)
            },
        };

        console.log('Authentication response:', authResponse);

        const verifyResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/auth/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(authResponse)
        });

        if (!verifyResponse.ok) {
            console.error('Authentication failed:', verifyResponse.status, verifyResponse.statusText);
            const errorText = await verifyResponse.text();

            // Signal unknown credential to the authenticator (WebAuthn Signal API).
            // This tells the authenticator that this credential is not recognized by the server,
            // allowing the authenticator to remove or mark it as invalid.
            // This API is scoped by credentialId only (not user_handle), so it works correctly
            // regardless of PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL setting.
            // Note: This is always called on auth failure regardless of PASSKEY_SIGNAL_API_MODE,
            // because the credential genuinely doesn't exist on the server.
            // Browser support: Chrome 132+, Edge 132+, Safari 26+. Firefox not supported.
            if (
                credential.id &&
                window.PublicKeyCredential &&
                typeof window.PublicKeyCredential.signalUnknownCredential === "function"
            ) {
                try {
                    await window.PublicKeyCredential.signalUnknownCredential({
                        rpId: window.location.hostname,
                        credentialId: credential.id,
                    });
                    console.log("signalUnknownCredential: signaled", credential.id);
                } catch (signalErr) {
                    console.warn("signalUnknownCredential error (non-critical):", signalErr);
                }
            }

            alert('Authentication failed: ' + errorText);
            return;
        }

        // Authentication successful
        // Server returns JSON: { name: "...", user_handle: "...", credential_ids: [...] }
        let userName = '';
        try {
            const data = await verifyResponse.json();
            userName = data.name || '';
            // FIRE-AND-FORGET: Signal API is non-critical, don't block navigation.
            // Awaiting signalAfterLogin can block page reload on iOS Safari and other
            // browsers where the Signal API may be slow or cause issues.
            // The login has already succeeded on the server; proceed immediately.
            signalAfterLogin(data);
        } catch (parseErr) {
            // JSON parse failure is non-critical - login already succeeded
            console.warn("Response parse error (non-critical):", parseErr);
        }

        if (authStatus && userName) {
            authStatus.textContent = `Welcome back ${userName}!`;
        }

        // Proceed immediately with page reload - don't wait for Signal API
        window.location.reload();
    } catch (error) {
        console.error('Error during authentication:', error);
        alert('Authentication failed: ' + error.message);
    }
}

// Notify the authenticator about valid credentials after successful login (WebAuthn Signal API).
//
// This function is called FIRE-AND-FORGET (without await) from the login success handler.
// The caller should NOT await this function because:
// - The login has already succeeded on the server
// - Signal API is non-critical - just a best-effort hint to the authenticator
// - Awaiting can block page reload on iOS Safari and other browsers where the API may be slow
// - User experience should not be degraded by optional sync features
//
// signalAllAcceptedCredentials: Tells the authenticator which credentials are valid for this user.
// - Scoped by userId (user_handle) - only affects credentials with matching user_handle
// - When PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true, only the authenticated credential is affected
// - When false, all credentials for the user are synchronized
//
// Note: signalCurrentUserDetails is NOT called here because user details don't change during login.
// It is called in account.js when the user explicitly updates their credential display name.
//
// The server controls whether to call this by including credential_ids in the response.
// When PASSKEY_SIGNAL_API_MODE includes 'sync', the server includes credential_ids.
//
// Browser support: Chrome 132+, Edge 132+, Safari 26+. Firefox not supported.
// See docs/src/webauthn/user-handle-and-signal-api.md for detailed documentation.
async function signalAfterLogin(data) {
    try {
        // signalAllAcceptedCredentials: Tell authenticator which credentials are valid
        // Only called if server includes credential_ids in the response
        // (controlled by PASSKEY_SIGNAL_API_MODE on the server)
        if (
            window.PublicKeyCredential &&
            typeof window.PublicKeyCredential.signalAllAcceptedCredentials === "function" &&
            data.user_handle && data.credential_ids
        ) {
            const userIdBytes = new TextEncoder().encode(data.user_handle);
            const userIdBase64Url = arrayBufferToBase64URL(userIdBytes.buffer);
            await window.PublicKeyCredential.signalAllAcceptedCredentials({
                rpId: window.location.hostname,
                userId: userIdBase64Url,
                allAcceptedCredentialIds: data.credential_ids,
            });
            console.log("signalAllAcceptedCredentials: signaled", data.credential_ids.length, "credentials");
        }
    } catch (err) {
        console.warn("Signal API error (non-critical):", err);
    }
}

function createRegistrationModal() {
    // Create modal container if it doesn't exist
    let modal = document.getElementById('registration-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'registration-modal';
        modal.className = 'modal';
        modal.style.cssText = 'display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);';

        modal.innerHTML = `
            <h3>Register New Passkey</h3>
            <div style="margin: 10px 0;">
                <input type="text" id="reg-username" placeholder="Username" style="width: 100%; margin-bottom: 10px; padding: 5px;">
                <input type="text" id="reg-displayname" placeholder="Display Name" style="width: 100%; padding: 5px;">
            </div>
            <div style="text-align: right;">
                <button onclick="closeRegistrationModal()">Cancel</button>
                <button onclick="submitRegistration(document.getElementById('registration-modal').dataset.mode)">Register</button>
            </div>
        `;

        document.body.appendChild(modal);
    }
    return modal;
}

function showRegistrationModal(mode) {
    const modal = createRegistrationModal();
    modal.style.display = 'block';
    
    // Store the mode in the modal for later use
    modal.dataset.mode = mode;

    // Set default values immediately
    document.getElementById('reg-username').value = 'username';
    document.getElementById('reg-displayname').value = 'displayname';

    // Try to get current user info to pre-fill the form
    fetch(O2P_ROUTE_PREFIX + '/user/info', {
        method: 'GET',
        credentials: 'same-origin'
    })
    .then(response => {
        if (response.ok) {
            return response.json();
        }
        // If not logged in or error, keep the default values
        return null;
    })
    .then(userData => {
        if (userData) {
            // Pre-fill the form with user data
            const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
            document.getElementById('reg-username').value = userData.account ? `${userData.account}#${today}` : 'username';
            document.getElementById('reg-displayname').value = userData.label || 'displayname';
        }
    })
    .catch(error => {
        console.error('Error fetching user data:', error);
        // Default values already set, so no action needed
    });
}

function closeRegistrationModal() {
    const modal = document.getElementById('registration-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

async function submitRegistration(mode) {
    const username = document.getElementById('reg-username').value.trim();
    const displayname = document.getElementById('reg-displayname').value.trim();

    if (!username || !displayname) {
        alert('Both username and display name are required');
        return;
    }

    closeRegistrationModal();
    await startRegistration(mode, username, displayname);
}

async function startRegistration(mode, username = null, displayname = null) {
    try {
        // Log the explicitly provided mode
        console.log('Registration mode:', mode);

        const request = {
            username,
            displayname,
            mode: mode,
        };

        let startResponse;
        startResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/register/start', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': `${csrfToken}`,
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin', // Important for cookie-based context token
            body: JSON.stringify(request)
        });

        if (!startResponse.ok) {
            const errorText = await startResponse.text();

            console.error('Failed to start registration:', errorText);
            alert('Registration failed: ' + errorText);
            return;
        }

        const options = await startResponse.json();
        console.log('Registration options:', options);

        // Convert base64url strings to Uint8Array
        let userHandle = options.user.user_handle;
        options.challenge = base64URLToUint8Array(options.challenge);
        options.user.id = base64URLToUint8Array(userHandle);

        // Transform excludeCredentials
        if (options.excludeCredentials && Array.isArray(options.excludeCredentials)) {
            options.excludeCredentials = options.excludeCredentials.map(credential => ({
                type: 'public-key',
                id: base64URLToUint8Array(credential.id),
            }));
        } else {
            options.excludeCredentials = [];
        }

        console.log('Registration options:', options);
        console.log('Registration user handle:', userHandle);

        const credential = await navigator.credentials.create({
            publicKey: options
        });

        const credentialResponse = {
            id: credential.id,
            raw_id: arrayBufferToBase64URL(credential.rawId),
            type: credential.type,
            response: {
                attestation_object: arrayBufferToBase64URL(credential.response.attestationObject),
                client_data_json: arrayBufferToBase64URL(credential.response.clientDataJSON)
            },
            user_handle: userHandle,
            mode: mode,
        };

        console.log('Registration response:', credentialResponse);

        // Use the single registration finish endpoint
        const finishResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/register/finish', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': `${csrfToken}`,
                'Content-Type': 'application/json',
            },
            // Include credentials to ensure cookies are sent with the request
            credentials: 'same-origin',
            body: JSON.stringify(credentialResponse)
        });

        if (finishResponse.ok) {
            location.reload(); // Refresh to show authenticated state
        } else {
            const errorText = await finishResponse.text();
            throw new Error('Registration verification failed: ' + errorText);
        }
    } catch (error) {
        console.error('Error during registration:', error);
        alert('Registration failed: ' + error.message);
    }
}
