const oauth2 = (function() {
    let popupWindow;
    let isReloading = false;

    // Detect iOS Safari
    function isIOSSafari() {
        const ua = navigator.userAgent;
        const iOS = /iPad|iPhone|iPod/.test(ua);
        const webkit = /WebKit/.test(ua);
        const notChrome = !/CriOS/.test(ua);
        return iOS && webkit && notChrome;
    }

    // mode: add_to_user, create_user, login
    function openPopup(mode=null, page_context=null) {
        // Only proceed if mode is one of the valid options
        if (mode !== 'add_to_user' && mode !== 'create_user' && mode !== 'login' && mode !== 'create_user_or_login') {
            console.log('Invalid or missing mode parameter');
            return; // Exit the function early
        }

        console.log('openPopup called with mode:', mode);

        let url;
        if (mode === 'add_to_user') {
            url = `${O2P_ROUTE_PREFIX}/oauth2/google?mode=${mode}&context=${page_context}`;
        } else {
            url = `${O2P_ROUTE_PREFIX}/oauth2/google?mode=${mode}`;
        }

        console.log('Opening URL:', url);
        console.log('Is iOS Safari:', isIOSSafari());

        // iOS Safari blocks popups aggressively, use full-page redirect instead
        if (isIOSSafari()) {
            console.log('Using full-page redirect for iOS Safari');
            window.location.href = url;
            return;
        }

        // Desktop/other browsers: use popup
        popupWindow = window.open(
            url,
            "PopupWindow",
            "width=550,height=640,resizable=yes,scrollbars=yes"
        );

        console.log('Popup window object:', popupWindow);

        // Check if popup was blocked
        if (!popupWindow || popupWindow.closed || typeof popupWindow.closed === 'undefined') {
            console.error('Popup was blocked by browser!');
            alert('Popup blocked! Please allow popups for this site, or the page will redirect.');
            // Fallback to full-page redirect
            setTimeout(() => {
                window.location.href = url;
            }, 1000);
            return;
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
