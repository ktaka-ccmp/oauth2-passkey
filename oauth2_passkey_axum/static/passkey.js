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
            alert('Authentication failed: ' + errorText);
            return;
        }

        // Response is OK, handle success
        setTimeout(() => {
            window.location.reload();
        }, 100);  // Wait for 0.1 second before reloading

        verifyResponse.text().then(function(text) {
            if (authStatus) {
                authStatus.textContent = `Welcome back ${text}!`;
            }
        });
    } catch (error) {
        console.error('Error during authentication:', error);
        alert('Authentication failed: ' + error.message);
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
            document.getElementById('reg-username').value = userData.account ? `${userData.account}#${userData.passkey_count + 1}` : 'username';
            document.getElementById('reg-displayname').value = userData.label ? `${userData.label}#${userData.passkey_count + 1}` : 'displayname';
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

        // Include mode and page context for session boundary verification
        const request = {
            username,
            displayname,
            mode: mode,
            page_context: typeof PAGE_USER_CONTEXT !== 'undefined' ? PAGE_USER_CONTEXT : '',
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
            page_context: typeof PAGE_USER_CONTEXT !== 'undefined' ? PAGE_USER_CONTEXT : '',
        };

        console.log('Registration response:', credentialResponse);

        // Use the single registration finish endpoint
        // The mode has already been verified at the start stage, and the page_context
        // is included in the credential for additional verification
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
