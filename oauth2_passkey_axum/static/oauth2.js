const oauth2 = (function() {
    let popupWindow;
    let isReloading = false;

    // mode: add_to_user, create_user, login
    function openPopup(mode=null, page_context=null) {
        // Only proceed if mode is one of the valid options
        if (mode !== 'add_to_user' && mode !== 'create_user' && mode !== 'login' && mode !== 'create_user_or_login') {
            console.log('Invalid or missing mode parameter');
            return; // Exit the function early
        }

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
