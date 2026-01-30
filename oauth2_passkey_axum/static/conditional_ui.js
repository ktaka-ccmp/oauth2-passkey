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

// Base64 URL encoding utilities
function arrayBufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const charCode of bytes) {
        str += String.fromCharCode(charCode);
    }
    const base64 = btoa(str);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLToUint8Array(base64URL) {
    const padding = '='.repeat((4 - base64URL.length % 4) % 4);
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/') + padding;
    const str = atob(base64);
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

// Initialize WebAuthn
(async function() {
    // Feature detection
    if (!window.PublicKeyCredential) {
        console.error('WebAuthn not supported');
        return;
    }

    const available = await PublicKeyCredential.isConditionalMediationAvailable();
    if (!available) {
        console.error('Conditional UI not available');
        return;
    }

    let currentOptions = null;
    let credentialRequestAbortController = null;
    let refreshTimer = null;

    // Function to get fresh challenge from server
    async function getFreshChallenge() {
        const response = await fetch(O2P_ROUTE_PREFIX + '/passkey/auth/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(null) // null for username-less auth
        });

        if (!response.ok) {
            console.error('Failed to get server challenge');
            return null;
        }

        const options = await response.json();
        console.log('Got fresh challenge');
        console.log('Server options:', options); 
        return options;
    }

    // Function to start credential request with fresh options
    async function startCredentialRequest(options) {
        // Cancel any existing credential request
        if (credentialRequestAbortController) {
            credentialRequestAbortController.abort();
        }

        // Create new abort controller
        credentialRequestAbortController = new AbortController();

        const publicKeyOptions = {
            challenge: base64URLToUint8Array(options.challenge),
            rpId: options.rpId,
            timeout: options.timeout || 300000,
            // userVerification: 'preferred'
            userVerification: options.userVerification
        };

        try {
            const credential = await navigator.credentials.get({
                mediation: 'conditional',
                publicKey: publicKeyOptions,
                signal: credentialRequestAbortController.signal
            });

            // If we get a credential, verify it
            if (credential) {
                const authResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/auth/finish', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        id: credential.id,
                        raw_id: arrayBufferToBase64URL(credential.rawId),
                        response: {
                            client_data_json: arrayBufferToBase64URL(credential.response.clientDataJSON),
                            authenticator_data: arrayBufferToBase64URL(credential.response.authenticatorData),
                            signature: arrayBufferToBase64URL(credential.response.signature),
                            user_handle: credential.response.userHandle ? arrayBufferToBase64URL(credential.response.userHandle) : null
                        },
                        type: credential.type,
                        auth_id: options.authId
                    })
                });

                if (!authResponse.ok) {
                    const errorText = await authResponse.text();

                    // Signal unknown credential to the authenticator (WebAuthn Signal API).
                    // This tells the authenticator that this credential is not recognized by the server,
                    // allowing the authenticator to remove or mark it as invalid.
                    // This API is scoped by credentialId only (not user_handle), so it works correctly
                    // regardless of PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL setting.
                    // Note: This is always called on auth failure regardless of PASSKEY_SIGNAL_API_MODE,
                    // because the credential genuinely doesn't exist on the server.
                    // Browser support: Chrome 132+, Edge 132+, Safari 26+. Firefox not supported.
                    if (credential.id && hasSignalCapability('signalUnknownCredential')) {
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

                    throw new Error('Verification failed: ' + errorText);
                }

                // Authentication successful
                // Synchronize credentials with authenticator via Signal API (WebAuthn Signal API).
                //
                // FIRE-AND-FORGET: We deliberately don't await signalAllAcceptedCredentials because:
                // - The login has already succeeded on the server
                // - Signal API is non-critical - just a best-effort hint to the authenticator
                // - Awaiting can block page redirect on iOS Safari and other browsers where the API may be slow
                // - User experience should not be degraded by optional sync features
                //
                // signalAllAcceptedCredentials tells the authenticator which credentials are valid for this user.
                // It's scoped by userId (user_handle), so effectiveness depends on
                // PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL setting:
                // - When true: Only the authenticated credential is affected (limited usefulness)
                // - When false: All credentials for the user are synchronized
                //
                // The server controls whether to call this by including credential_ids in the response.
                // When PASSKEY_SIGNAL_API_MODE includes 'sync', the server includes credential_ids.
                //
                // Browser support: Chrome 132+, Edge 132+, Safari 26+. Firefox not supported.
                // See docs/src/webauthn/user-handle-and-signal-api.md for detailed documentation.
                try {
                    const data = await authResponse.json();
                    // Only call signalAllAcceptedCredentials if server includes credential_ids
                    // (controlled by PASSKEY_SIGNAL_API_MODE on the server)
                    if (
                        hasSignalCapability('signalAllAcceptedCredentials') &&
                        data.user_handle && data.credential_ids
                    ) {
                        const userIdBytes = new TextEncoder().encode(data.user_handle);
                        const userIdBase64Url = arrayBufferToBase64URL(userIdBytes.buffer);
                        // Don't await - fire-and-forget to avoid blocking page redirect
                        window.PublicKeyCredential.signalAllAcceptedCredentials({
                            rpId: window.location.hostname,
                            userId: userIdBase64Url,
                            allAcceptedCredentialIds: data.credential_ids,
                        }).then(() => {
                            console.log("signalAllAcceptedCredentials: signaled", data.credential_ids.length, "credentials");
                        }).catch((err) => {
                            console.warn("signalAllAcceptedCredentials error (non-critical):", err);
                        });
                    }
                } catch (parseErr) {
                    // JSON parse failure is non-critical - login already succeeded
                    console.warn("Response parse error (non-critical):", parseErr);
                }

                // Proceed immediately with redirect - don't wait for Signal API
                window.location.href = '/';
            }
        } catch (error) {
            if (error.name === 'AbortError') {
                console.log('Credential request aborted for refresh');
            } else {
                console.error('Authentication error:', error);
            }
        }
    }

    // Function to schedule next refresh
    function scheduleNextRefresh(options) {
        // Clear any existing timer
        if (refreshTimer) {
            clearTimeout(refreshTimer);
        }

        // Calculate refresh time: 75% of timeout (in milliseconds)
        const timeout = options.timeout || 60000; // Default to 60 seconds if not specified
        const refreshTime = Math.floor(timeout * 0.75);
        console.log(`Scheduling next refresh in ${refreshTime}ms (75% of ${timeout}ms timeout)`);

        // Schedule refresh
        refreshTimer = setTimeout(async () => {
            console.log('Refreshing challenge...');
            const newOptions = await getFreshChallenge();
            if (newOptions) {
                startCredentialRequest(newOptions);
                scheduleNextRefresh(newOptions);
            }
        }, refreshTime);
    }

    // Initial challenge
    currentOptions = await getFreshChallenge();
    if (currentOptions) {
        startCredentialRequest(currentOptions);
        scheduleNextRefresh(currentOptions);
    }
})();
