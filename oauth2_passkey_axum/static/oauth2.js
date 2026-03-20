const oauth2 = (function() {
    let popupWindow;
    let isReloading = false;

    // Check if FedCM is available and enabled
    function isFedCMAvailable() {
        return typeof FEDCM_ENABLED !== 'undefined' && FEDCM_ENABLED
            && typeof OAUTH2_CLIENT_ID !== 'undefined'
            && typeof IdentityCredential !== 'undefined';
    }

    // FedCM login flow: nonce -> browser credential picker -> callback
    async function fedcmLogin(mode) {
        // 1. Fetch nonce from server
        const nonceResp = await fetch(
            `${O2P_ROUTE_PREFIX}/oauth2/fedcm/nonce`
        );
        if (!nonceResp.ok) throw new Error('Failed to get FedCM nonce');
        const nonceData = await nonceResp.json();

        // 2. Call navigator.credentials.get() with FedCM (active/button mode)
        // Options aligned with Google's GIS library implementation
        // Timeout: abort if FedCM hangs (Chrome bug: login status mismatch
        // in active mode can cause Promise to never settle)
        const FEDCM_TIMEOUT_MS = 15000;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), FEDCM_TIMEOUT_MS);
        const identityOptions = {
            providers: [{
                configURL: 'https://accounts.google.com/gsi/fedcm.json',
                clientId: OAUTH2_CLIENT_ID,
                fields: ['name', 'email', 'picture'],
                params: {
                    nonce: nonceData.nonce,
                    response_type: 'id_token',
                    scope: 'email profile openid',
                    ss_domain: window.location.origin,
                },
            }],
            mode: 'active',
            context: 'signin',
        };

        let credential;
        try {
            credential = await navigator.credentials.get({
                identity: identityOptions,
                federated: identityOptions,  // Backward compat with older Chrome
                mediation: 'required',
                signal: controller.signal,
            });
        } finally {
            clearTimeout(timeoutId);
        }

        // 3. Extract JWT from credential token
        // Google FedCM may return JSON (e.g. {"token":"eyJ..."}) instead of a raw JWT
        let token = credential.token;
        if (token.startsWith('{')) {
            const parsed = JSON.parse(token);
            token = parsed.token || parsed.id_token || token;
        }

        // 4. POST the token to our callback
        const callbackResp = await fetch(
            `${O2P_ROUTE_PREFIX}/oauth2/fedcm/callback`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    credential: token,
                    nonce_id: nonceData.nonce_id,
                    mode: mode,
                }),
            }
        );

        if (!callbackResp.ok) {
            const errorText = await callbackResp.text();
            throw new Error(errorText || 'FedCM callback failed');
        }

        // 5. Check for passkey promotion or reload
        const data = await callbackResp.json();
        if (data.promotion_url) {
            // Pre-check: only open popup if promotion is actually needed
            const checkResp = await fetch(
                `${O2P_ROUTE_PREFIX}/passkey/promotion/check`
            );
            const checkData = checkResp.ok ? await checkResp.json() : null;
            if (checkData && checkData.should_promote
                && !(checkData.mode === 'ask'
                     && localStorage.getItem('passkey_promotion_dismissed') === 'true')) {
                popupWindow = window.open(
                    data.promotion_url,
                    "PopupWindow",
                    "width=550,height=640,left=1000,top=200,resizable=yes,scrollbars=yes"
                );
                window.addEventListener('message', function(event) {
                    if (event.data === 'auth_complete') {
                        handlePopupClosed();
                    }
                });
                return;
            }
        }
        handlePopupClosed();
    }

    // mode: add_to_user, create_user, login, create_user_or_login
    function openPopup(mode=null, page_context=null) {
        // Only proceed if mode is one of the valid options
        if (mode !== 'add_to_user' && mode !== 'create_user' && mode !== 'login' && mode !== 'create_user_or_login') {
            console.log('Invalid or missing mode parameter');
            return; // Exit the function early
        }

        // Try FedCM for non-add_to_user modes
        if (mode !== 'add_to_user' && isFedCMAvailable()) {
            fedcmLogin(mode).catch(function(err) {
                console.log('FedCM failed, falling back to popup:', err.message);
                openPopupLegacy(mode, page_context);
            });
            return;
        }

        openPopupLegacy(mode, page_context);
    }

    function openPopupLegacy(mode, page_context) {
        if (mode === 'add_to_user') {
            popupWindow = window.open(
                `${O2P_ROUTE_PREFIX}/oauth2/google?mode=${mode}&context=${page_context}`,
                "PopupWindow",
                "width=550,height=640,left=1000,top=200,resizable=yes,scrollbars=yes"
            );
        } else {
            popupWindow = window.open(
                `${O2P_ROUTE_PREFIX}/oauth2/google?mode=${mode}`,
                "PopupWindow",
                "width=550,height=640,left=1000,top=200,resizable=yes,scrollbars=yes"
            );
        }

        // Listen for messages from the auth popup
        window.addEventListener('message', function(event) {
            // Make sure to verify the origin matches your domain
            if (event.data === 'auth_complete') {
                handlePopupClosed();
            }
        });
    }

    function handlePopupClosed() {
        if (isReloading) return;  // Prevent multiple reloads
        isReloading = true;

        const statusElement = document.getElementById('status');
        if (statusElement) {
            statusElement.textContent = 'Popup closed. Reloading parent...';
        }

        // Reload the parent window
        setTimeout(() => {
            window.location.reload();
        }, 10);  // Wait for 0.1 second before reloading
    }

    // Clean up on page unload
    window.addEventListener('unload', () => {
        if (popupWindow) {
            try {
                if (!popupWindow.closed) {
                    // popupWindow.close();
                }
            } catch (e) {
                // Handle COOP error silently
            }
        }
    });

    return {
        openPopup: openPopup
    };
})();
