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
        const response = await fetch(PASSKEY_ROUTE_PREFIX + '/auth/start', {
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
                const authResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/auth/finish', {
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
                    throw new Error('Verification failed: ' + errorText);
                }

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
