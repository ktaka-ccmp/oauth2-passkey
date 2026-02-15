# Passkey JavaScript API

This guide explains how to use the Passkey JavaScript API for WebAuthn/Passkey authentication.

## Loading the Script

Include the `passkey.js` script in your HTML page:

```html
<script src="{{o2p_route_prefix}}/passkey/passkey.js"></script>
```

The script path uses your configured authentication route prefix.

## Setting the Route Prefix

Define `O2P_ROUTE_PREFIX` before loading the script. This tells the script where to find Passkey endpoints:

```javascript
const O2P_ROUTE_PREFIX = '/auth';  // Adjust to match your configuration
```

In templates:

```html
<script>
    const O2P_ROUTE_PREFIX = '{{o2p_route_prefix}}';
</script>
<script src="{{o2p_route_prefix}}/passkey/passkey.js"></script>
```

## WebAuthn Feature Detection

The `passkey.js` script automatically detects WebAuthn Signal API capabilities on page load using the `getClientCapabilities()` API (Chrome 131+, Edge 132+).

### initPasskeyCapabilities()

Called automatically when `passkey.js` loads. Queries the browser for supported WebAuthn capabilities and caches the result.

```javascript
// Called automatically - no need to call manually
// Result cached in _passkeyCapabilities
await initPasskeyCapabilities();
```

### hasSignalCapability(capabilityName)

Check whether a specific WebAuthn Signal API capability is supported by the browser.

```javascript
if (hasSignalCapability('signalUnknownCredential')) {
    // Browser supports telling authenticator about deleted credentials
}

if (hasSignalCapability('signalAllAcceptedCredentials')) {
    // Browser supports credential list synchronization
}
```

Falls back to `typeof` checks when `getClientCapabilities()` is not available.

## CSRF Token for Registration

Passkey registration requires a CSRF token. Obtain it from the response header and define it before calling registration functions:

```javascript
let csrfToken = null;

// Fetch CSRF token from response header
fetch(window.location.href, { method: 'HEAD' })
    .then(response => {
        csrfToken = response.headers.get('X-CSRF-Token') || null;
    });
```

## API Functions

### startAuthentication()

Initiates passkey authentication. Opens the browser's passkey selector and verifies the credential with the server.

```javascript
startAuthentication()
```

On success, the page automatically reloads to reflect the authenticated state.

### showRegistrationModal(mode)

Opens a modal dialog for passkey registration. The user enters a username and display name, then the browser prompts to create a passkey.

#### Create New User

Creates a new user account with a passkey:

```javascript
showRegistrationModal('create_user')
```

The modal pre-fills default values. If the user is already logged in, it attempts to fetch user info and pre-fill based on existing account data.

## Complete HTML Example

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passkey Login Example</title>
    <script>
        const O2P_ROUTE_PREFIX = '/auth';
    </script>
    <script src="/auth/passkey/passkey.js"></script>
</head>
<body>
    <h1>Welcome</h1>

    <div>
        <button onclick="showRegistrationModal('create_user')">Register Passkey</button>
        <button onclick="startAuthentication()">Sign in</button>
    </div>

    <script>
        // CSRF token required for registration
        let csrfToken = null;

        fetch(window.location.href, { method: 'HEAD' })
            .then(response => {
                csrfToken = response.headers.get('X-CSRF-Token') || null;
            });
    </script>
</body>
</html>
```

## Template Example (Jinja2/Tera)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passkey Demo</title>
    <script>
        const O2P_ROUTE_PREFIX = '{{o2p_route_prefix}}';
    </script>
    <script src="{{o2p_route_prefix}}/passkey/passkey.js"></script>
</head>
<body>
    <h1>{{message}}</h1>
    <p>Welcome to our site.</p>

    <div style="display: flex; gap: 10px; margin-bottom: 20px;">
        <button onclick="showRegistrationModal('create_user')">Register Passkey</button>
        <button onclick="startAuthentication()">Sign in</button>
    </div>

    <script>
        let csrfToken = null;

        fetch(window.location.href, { method: 'HEAD' })
            .then(response => {
                csrfToken = response.headers.get('X-CSRF-Token') || null;
            });
    </script>
</body>
</html>
```

## Notes

- The registration modal dynamically creates a form for username and display name input
- On successful authentication or registration, the page automatically reloads
- Browser support for WebAuthn/Passkey is required; check compatibility before deployment
- The `csrfToken` variable must be defined in the global scope for registration to work
