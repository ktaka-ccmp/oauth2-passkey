// Passkey Promotion after OAuth2 Login (experimental)
//
// This script runs on the login page and intercepts the OAuth2 'auth_complete'
// message to redirect to the library-controlled promotion page.
//
// When the OAuth2 popup sends 'auth_complete', this listener fires before
// the one in oauth2.js (because passkey_promotion.js is loaded at page load,
// while oauth2.js registers its listener inside openPopup()).
// We use stopImmediatePropagation() to prevent oauth2.js's listener from
// scheduling a competing window.location.reload() that could race with
// our redirect.
//
// This file is only served when O2P_PASSKEY_PROMOTION is set to 'ask' or 'force'.

window.addEventListener('message', function(event) {
    if (event.data === 'auth_complete') {
        // Check permanent opt-out (set by "Don't Ask Again" on the promotion page)
        if (localStorage.getItem('passkey_promotion_dismissed') === 'true') {
            return; // Let oauth2.js reload normally
        }

        // Check WebAuthn support
        if (!window.PublicKeyCredential) {
            return; // Let oauth2.js reload normally
        }

        // Prevent oauth2.js's listener from scheduling a competing reload
        event.stopImmediatePropagation();

        // Redirect to library-controlled promotion page
        window.location.href = O2P_ROUTE_PREFIX + '/passkey/promotion/redirect';
    }
});
