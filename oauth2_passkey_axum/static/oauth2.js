function initOAuth2Popup() {
    let popupWindow;
    let isReloading = false;

    function openPopup(mode=null, page_context=null) {
        if (mode === 'add_to_existing_user') {
            popupWindow = window.open(
                `${O2P_ROUTE_PREFIX}/oauth2/google?mode=${mode}&context=${page_context}`,
                "PopupWindow",
                "width=550,height=640,left=1000,top=200,resizable=yes,scrollbars=yes"
            );
        } else {
            popupWindow = window.open(
                `${O2P_ROUTE_PREFIX}/oauth2/google`,
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
        }, 100);  // Wait for 0.1 second before reloading
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
}

// Only define signOutAndRedirect if it doesn't already exist
if (typeof signOutAndRedirect === 'undefined') {
    async function signOutAndRedirect(redirect) {
        if (redirect) {
            await fetch(`${O2P_ROUTE_PREFIX}/user/logout?redirect=${encodeURIComponent(redirect)}`);
        } else {
            await fetch(`${O2P_ROUTE_PREFIX}/user/logout`);
            location.reload();
        }
    }
    // Make it globally available
    window.signOutAndRedirect = signOutAndRedirect;
}
