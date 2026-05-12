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
        const controller = new AbortController();
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
            controller.signal.onabort = null;
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
    // provider: optional. If omitted, routes through the selection popup
    //   (which 302-redirects when only one provider is enabled, so single-
    //   provider setups still work without an extra click).
    function openPopup(mode=null, page_context=null, provider=null) {
        // Only proceed if mode is one of the valid options
        if (mode !== 'add_to_user' && mode !== 'create_user' && mode !== 'login' && mode !== 'create_user_or_login') {
            console.log('Invalid or missing mode parameter');
            return; // Exit the function early
        }

        if (provider === null) {
            openSelectPopup(mode, page_context);
            return;
        }

        // Try FedCM for non-add_to_user modes (Google only)
        if (provider === 'google' && mode !== 'add_to_user' && isFedCMAvailable()) {
            fedcmLogin(mode).catch(function(err) {
                console.log('FedCM failed, falling back to popup:', err.message);
                openPopupLegacy(mode, page_context, provider);
            });
            return;
        }

        openPopupLegacy(mode, page_context, provider);
    }

    // Opens a provider-selection popup. When only one provider is enabled, the
    // server redirects directly to that provider — no extra click needed.
    function openSelectPopup(mode, page_context) {
        const url = page_context
            ? `${O2P_ROUTE_PREFIX}/oauth2/select?mode=${mode}&context=${page_context}`
            : `${O2P_ROUTE_PREFIX}/oauth2/select?mode=${mode}`;
        popupWindow = window.open(
            url,
            "PopupWindow",
            "width=550,height=640,left=1000,top=200,resizable=yes,scrollbars=yes"
        );
        window.addEventListener('message', function(event) {
            if (event.data === 'auth_complete') {
                handlePopupClosed();
            }
        });
    }

    function openPopupLegacy(mode, page_context, provider='google') {
        if (mode === 'add_to_user') {
            popupWindow = window.open(
                `${O2P_ROUTE_PREFIX}/oauth2/${provider}?mode=${mode}&context=${page_context}`,
                "PopupWindow",
                "width=550,height=640,left=1000,top=200,resizable=yes,scrollbars=yes"
            );
        } else {
            popupWindow = window.open(
                `${O2P_ROUTE_PREFIX}/oauth2/${provider}?mode=${mode}`,
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

    // Bootstrap the popup-based OAuth2 account-linking flow via a form POST
    // (Alt 5B with the `OAUTH2_LINKING_MODE=post` setting).
    //
    // The parent page declares a hidden <form> with method=POST, the matching
    // target name, and the session csrf_token in a hidden input. This helper
    // opens the popup synchronously inside the click handler (so popup
    // blockers see a user gesture) and then submits the form to it.
    //
    // The server-side counterpart is `POST /oauth2/select`, which verifies
    // the form-body csrf_token against the current session and renders the
    // provider-select page. The session-boundary attack (page rendered as
    // session A, clicked as session B) is detected here: the form carries
    // the csrf_token captured at parent render time, and the server compares
    // it against the cookie session at click time.
    function startLinkingViaForm(formId, popupName) {
        const name = popupName || 'PopupWindow';
        const popup = window.open('about:blank', name,
            'width=550,height=640,left=1000,top=200,resizable=yes,scrollbars=yes');
        if (!popup) {
            console.log('Popup blocked');
            return;
        }
        popupWindow = popup;

        window.addEventListener('message', function(event) {
            if (event.data === 'auth_complete') {
                handlePopupClosed();
            }
        });

        const form = document.getElementById(formId);
        if (!form) {
            console.error('startLinkingViaForm: form not found:', formId);
            try { popup.close(); } catch (_) { /* COOP */ }
            return;
        }
        form.submit();
    }

    // POST-based linking initiation (Alt 5B).
    //
    // Counterpart to openPopup(mode='add_to_user', ...) that does not
    // require a page_session_token. Uses a CSRF-protected fetch POST
    // to /oauth2/{provider}, then navigates a pre-opened popup to the
    // returned OAuth2 authorization URL.
    //
    // The session-boundary attack (page rendered under session A,
    // clicked under session B) is detected by the standard X-CSRF-Token
    // header check on the POST: a JS-held token from session A's render
    // won't match session B's CSRF, so the POST fails with 401.
    async function linkAccountPost(provider, csrfToken) {
        // 1. Open empty popup synchronously inside the click handler so
        //    popup blockers see a user gesture. Must precede any await.
        const popup = window.open('about:blank', 'PopupWindow',
            'width=550,height=640,left=1000,top=200,resizable=yes,scrollbars=yes');
        if (!popup) {
            console.log('Popup blocked');
            return;
        }
        popupWindow = popup;

        // 2. Listen for the auth_complete message before navigating, so
        //    we don't miss it if the IDP round-trip is fast.
        window.addEventListener('message', function(event) {
            if (event.data === 'auth_complete') {
                handlePopupClosed();
            }
        });

        try {
            // 3. CSRF-protected POST. The existing AuthUser extractor on
            //    the server verifies X-CSRF-Token against the session.
            const response = await fetch(
                `${O2P_ROUTE_PREFIX}/oauth2/${provider}`,
                {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    credentials: 'same-origin',
                }
            );
            if (!response.ok) {
                throw new Error(`POST /oauth2/${provider} failed: ${response.status}`);
            }
            const { auth_url } = await response.json();

            // 4. Navigate the pre-opened popup to the OAuth2 IDP URL.
            popup.location.href = auth_url;
        } catch (e) {
            try { popup.close(); } catch (_) { /* COOP */ }
            console.error('linkAccountPost failed:', e);
            throw e;
        }
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
        openPopup: openPopup,
        openSelectPopup: openSelectPopup,
        linkAccountPost: linkAccountPost,
        startLinkingViaForm: startLinkingViaForm,
    };
})();
