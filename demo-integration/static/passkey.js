// Base64 utility functions
function arrayBufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    bytes.forEach(byte => {
        str += String.fromCharCode(byte);
    });
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function base64URLToUint8Array(base64URL) {
    const padding = '='.repeat((4 - base64URL.length % 4) % 4);
    const base64 = base64URL
        .replace(/-/g, '+')
        .replace(/_/g, '/') + padding;
    const rawData = atob(base64);
    const buffer = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; i++) {
        buffer[i] = rawData.charCodeAt(i);
    }
    return buffer;
}

// Authentication functions
async function startAuthentication(withUsername = false) {
    try {
        let startResponse;
        let username;

        if (withUsername) {
            username = prompt("Please enter your username:");
            if (!username) return;

            startResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/auth/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: username ? JSON.stringify(username) : "{}"
            });
        } else {
            startResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/auth/start', {
                method: 'GET',
            });
        }

        if (!startResponse.ok) {
            const errorText = await startResponse.text();
            alert('Authentication failed: ' + errorText);
            return;
        }

        const options = await startResponse.json();
        console.log('Raw Authentication options:', options);

        // Convert base64url string to Uint8Array
        options.challenge = base64URLToUint8Array(options.challenge);

        // Convert allowCredentials
        if (options.allowCredentials) {
            for (let cred of options.allowCredentials) {
                cred.id = base64URLToUint8Array(cred.id);
            }
        }

        console.log('Processed Authentication options:', options);

        // Start the authentication process
        const credential = await navigator.credentials.get({
            publicKey: options
        });

        // Prepare the authentication response
        const authResponse = {
            id: credential.id,
            rawId: arrayBufferToBase64URL(credential.rawId),
            response: {
                authenticatorData: arrayBufferToBase64URL(credential.response.authenticatorData),
                clientDataJSON: arrayBufferToBase64URL(credential.response.clientDataJSON),
                signature: arrayBufferToBase64URL(credential.response.signature),
            },
            type: credential.type,
        };

        console.log('Authentication response:', authResponse);

        // Send the response to the server
        const verifyResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/auth/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(authResponse)
        });

        if (!verifyResponse.ok) {
            const errorText = await verifyResponse.text();
            alert('Authentication failed: ' + errorText);
            return;
        }

        if (verifyResponse.ok) {
            verifyResponse.text().then(function(text) {
                console.log(text);
                location.reload(); // Refresh to show authenticated state
            });
        } else {
            console.error('Authentication failed');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Authentication failed: ' + error);
    }
}

// Registration functions
async function startRegistration(withUsername = true) {
    try {
        let startResponse;
        let username;

        if (withUsername) {
            username = prompt("Please enter your username:");
            if (!username) return;

            startResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/register/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(username)
            });
        } else {
            startResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/register/start', {
                method: 'GET',
            });
        }

        if (!startResponse.ok) {
            const errorText = await startResponse.text();
            alert('Registration failed: ' + errorText);
            return;
        }

        const options = await startResponse.json();
        console.log('Registration options:', options);

        // Convert base64url strings to Uint8Array
        let userHandle = options.user.id;
        options.challenge = base64URLToUint8Array(options.challenge);
        options.user.id = new TextEncoder().encode(options.user.id);

        console.log('Registration options:', options);
        console.log('Registration user handle:', userHandle);

        // Start the registration process
        const credential = await navigator.credentials.create({
            publicKey: options
        });

        // Prepare the registration response
        const credentialResponse = {
            id: credential.id,
            rawId: arrayBufferToBase64URL(credential.rawId),
            response: {
                attestationObject: arrayBufferToBase64URL(credential.response.attestationObject),
                clientDataJSON: arrayBufferToBase64URL(credential.response.clientDataJSON),
            },
            type: credential.type,
            userHandle: userHandle,
        };

        console.log('Registration response:', credentialResponse);

        // Send the response to the server
        const finishResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/register/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(credentialResponse)
        });

        if (!finishResponse.ok) {
            const errorText = await finishResponse.text();
            alert('Registration failed: ' + errorText);
            return;
        }

        if (finishResponse.ok) {
            location.reload(); // Refresh to show authenticated state
        } else {
            console.error('Registration failed');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Registration failed: ' + error);
    }
}
