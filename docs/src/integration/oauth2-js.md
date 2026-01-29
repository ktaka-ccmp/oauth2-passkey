# OAuth2 JavaScript API

This guide explains how to use the OAuth2 JavaScript API for popup-based Google authentication.

## Loading the Script

Include the `oauth2.js` script in your HTML page:

```html
<script src="{{auth_route_prefix}}/oauth2/oauth2.js"></script>
```

The script path uses your configured authentication route prefix. If using Jinja2/Tera templates, pass the prefix from your server.

## Setting the Route Prefix

Define `O2P_ROUTE_PREFIX` before using the API. This tells the script where to find OAuth2 endpoints:

```javascript
const O2P_ROUTE_PREFIX = '/auth';  // Adjust to match your configuration
```

In templates:

```html
<script>
    const O2P_ROUTE_PREFIX = '{{auth_route_prefix}}';
</script>
```

## API Functions

### oauth2.openPopup(mode)

Opens a popup window for Google OAuth2 authentication. The `mode` parameter determines the authentication behavior.

#### Create New User

Creates a new user account. Fails if the Google account is already linked:

```javascript
oauth2.openPopup('create_user')
```

#### Login Existing User

Logs in an existing user. Fails if the Google account is not registered:

```javascript
oauth2.openPopup('login')
```

#### Create User or Login

Automatically creates a new user or logs in if the account already exists:

```javascript
oauth2.openPopup('create_user_or_login')
```

## Automatic Page Reload

When authentication completes successfully, the popup sends an `auth_complete` message to the parent window. The `oauth2.js` script automatically reloads the parent page to reflect the new authentication state.

## Complete HTML Example

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth2 Login Example</title>
</head>
<body>
    <h1>Welcome</h1>

    <div>
        <button onclick="oauth2.openPopup('create_user')">Create User</button>
        <button onclick="oauth2.openPopup('login')">Login</button>
        <button onclick="oauth2.openPopup('create_user_or_login')">Either way</button>
    </div>

    <!-- Load the OAuth2 JavaScript -->
    <script src="/auth/oauth2/oauth2.js"></script>
    <script>
        const O2P_ROUTE_PREFIX = '/auth';
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
    <title>OAuth2 Login</title>
</head>
<body>
    <h1>{{message}}</h1>

    <div>
        <button onclick="oauth2.openPopup('create_user')">Create User</button>
        <button onclick="oauth2.openPopup('login')">Login</button>
        <button onclick="oauth2.openPopup('create_user_or_login')">Either way</button>

        <script src="{{auth_route_prefix}}/oauth2/oauth2.js"></script>
        <script>
            const O2P_ROUTE_PREFIX = '{{auth_route_prefix}}';
        </script>
    </div>
</body>
</html>
```

## Notes

- The popup window opens at 550x640 pixels positioned at the right side of the screen
- Popup blockers may interfere with the authentication flow; inform users if popups are blocked
- The script handles cleanup automatically when the page unloads
