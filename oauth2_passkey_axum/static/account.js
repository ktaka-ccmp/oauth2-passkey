window.addEventListener("error", function (event) {
    console.error("Uncaught error:", event.error);
});

function toggleEditUserForm() {
    const displayDiv = document.getElementById("user-info-display");
    const editForm = document.getElementById("user-edit-form");

    if (editForm.style.display === "none") {
        displayDiv.style.display = "none";
        editForm.style.display = "block";
    } else {
        displayDiv.style.display = "block";
        editForm.style.display = "none";
    }
}

function updateUserAccount() {
    const userId = document.getElementById("edit-user-id").value;
    const account = document.getElementById("edit-account").value;
    const label = document.getElementById("edit-label").value;

    fetch(`${O2P_ROUTE_PREFIX}/user/update`, {
        method: "PUT",
        headers: {
            "X-CSRF-Token": `${csrfToken}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            user_id: userId,
            account: account,
            label: label,
        }),
    })
        .then(async (response) => {
            if (!response.ok) {
                const text = await response.text();
                throw new Error(text);
            }
            return response.json();
        })
        .then((data) => {
            // Update the display with the new values
            document.getElementById("display-account").textContent =
                data.account;
            document.getElementById("display-label").textContent = data.label;

            // Show a success message
            alert("Profile updated successfully");

            // Toggle back to display view
            toggleEditUserForm();
        })
        .catch((error) => {
            alert(`Error updating profile: ${error.message}`);
        });
}

function DeleteAccount() {
    // Include account name in confirmation for better verification
    if (
        confirm(
            `Are you sure you want to delete your account "${accountName}"? This action cannot be undone and will delete all your data including OAuth2 accounts and passkey credentials.`
        )
    ) {
        // Delete the account on the server first
        fetch(`${O2P_ROUTE_PREFIX}/user/delete`, {
            method: "DELETE",
            headers: {
                "X-CSRF-Token": `${csrfToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ user_id: userId }),
        })
            .then(async (response) => {
                if (!response.ok) {
                    const text = await response.text();
                    throw new Error(`Failed to delete account: ${text}`);
                }
                return response.json();
            })
            .then((data) => {
                // After successful server-side deletion, notify the authenticator about each credential
                console.log("Account deleted successfully on server side");

                // Check if we have credential IDs to notify about
                const credentialIds = data.credential_ids || [];
                if (credentialIds.length > 0) {
                    console.log(
                        `Notifying authenticator about ${credentialIds.length} deleted credentials`
                    );

                    // Create a chain of promises to notify the authenticator about each credential
                    let notificationChain = Promise.resolve();

                    // Process each credential sequentially
                    // Only call signalUnknownCredential if mode includes 'direct'
                    if (signalApiMode === 'direct' || signalApiMode === 'direct+sync') {
                        credentialIds.forEach((credentialId) => {
                            notificationChain = notificationChain.then(() => {
                                return synchronizeCredentialsWithSignalUnknown(
                                    credentialId
                                );
                            });
                        });
                    }

                    return notificationChain;
                } else {
                    console.log("No passkey credentials to notify about");
                    return Promise.resolve();
                }
            })
            .then(() => {
                alert(
                    "Your account has been deleted. You will now be logged out."
                );
                // Redirect to logout to clear the session
                window.location.reload();
            })
            .catch((error) => {
                alert(`Error: ${error.message}`);
            });
    }
}

function unlinkOAuth2Account(provider, providerUserId) {
    if (confirm("Are you sure you want to unlink this OAuth2 account?")) {
        fetch(
            `${O2P_ROUTE_PREFIX}/oauth2/accounts/${provider}/${providerUserId}`,
            {
                method: "DELETE",
                headers: {
                    "X-CSRF-Token": `${csrfToken}`,
                    "Content-Type": "application/json",
                },
            }
        )
            .then(async (response) => {
                if (response.ok) {
                    // Refresh the page to show updated account list
                    window.location.reload();
                } else {
                    const text = await response.text();
                    alert(`Failed to unlink account: ${text}`);
                }
            })
            .catch((error) => {
                alert(`Error: ${error.message}`);
            });
    }
}

// Synchronize credentials with the authenticator using signalAllAcceptedCredentials (WebAuthn Signal API).
//
// This API tells the authenticator which credentials are still valid for this user.
// The authenticator may remove credentials not in the list.
//
// IMPORTANT: This API is scoped by userId (user_handle). It only affects credentials
// that share the same user_handle. When PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true,
// each credential has a unique user_handle, so this API only affects the single credential
// matching the provided user_handle. When false, all credentials share the same user_handle,
// so this API can synchronize all credentials for the user.
//
// Browser support: Chrome 132+, Edge 132+, Safari 26+. Firefox not supported.
//
// FIRE-AND-FORGET: This function should be called without await. The Signal API is
// non-critical - it's a best-effort hint to the authenticator, not essential for
// authentication to work. Awaiting this call can block page navigation/reload on
// browsers where the API is slow or unsupported (e.g., iOS Safari), causing a poor
// user experience. The deletion/login has already succeeded on the server; the UI
// should proceed immediately.
//
// See docs/src/webauthn/user-handle-and-signal-api.md for detailed documentation.
function synchronizeCredentials(userHandle, remainingCredentialIds) {
    // Check if the WebAuthn API and signalAllAcceptedCredentials are available
    if (
        !window.PublicKeyCredential ||
        typeof window.PublicKeyCredential.signalAllAcceptedCredentials !==
            "function"
    ) {
        console.log(
            "WebAuthn credential management API not available or not supported"
        );
        return Promise.resolve(); // Return resolved promise for chaining
    }

    // Exit early if no user handle is provided
    if (!userHandle) {
        console.log(
            "No user handle provided, skipping credential synchronization"
        );
        return Promise.resolve();
    }

    // Encode the user handle in base64url format
    const userIdBytes = new TextEncoder().encode(userHandle);
    const userIdBase64Url = arrayBufferToBase64URL(userIdBytes.buffer);

    const credentialIds = remainingCredentialIds || [];

    // Signal all accepted credentials to the authenticator
    // Credentials not in this list may be removed by the passkey provider
    return window.PublicKeyCredential.signalAllAcceptedCredentials({
        rpId: window.location.hostname,
        userId: userIdBase64Url,
        allAcceptedCredentialIds: credentialIds,
    })
        .then(() => {
            console.log(
                "Successfully signaled accepted credentials to authenticator.",
                "remaining:", credentialIds.length
            );
        })
        .catch((err) => {
            console.warn("Error during credential synchronization:", err);
        });
}

// Signal a specific credential as unknown/deleted using signalUnknownCredential (WebAuthn Signal API).
//
// This API tells the authenticator that a specific credential is no longer recognized
// by the server. The authenticator may remove or mark the credential as invalid.
//
// IMPORTANT: Unlike signalAllAcceptedCredentials, this API is scoped by credentialId only,
// NOT by user_handle. This makes it work correctly regardless of the
// PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL setting. It directly targets the
// specific credential that was deleted.
//
// Browser support: Chrome 132+, Edge 132+, Safari 26+. Firefox not supported.
//
// FIRE-AND-FORGET: This function should be called without await. The Signal API is
// non-critical - it's a best-effort hint to the authenticator, not essential for
// authentication to work. Awaiting this call can block page navigation/reload on
// browsers where the API is slow or unsupported (e.g., iOS Safari), causing a poor
// user experience. The deletion has already succeeded on the server; the UI should
// proceed immediately.
//
// DUAL APPROACH: For credential deletion, we call BOTH signalUnknownCredential (this function)
// and signalAllAcceptedCredentials (synchronizeCredentials). This provides optimal behavior
// for both user_handle modes:
// - signalUnknownCredential: Works in both modes, directly targets the deleted credential
// - signalAllAcceptedCredentials: Additionally syncs remaining credentials when user_handle is shared
//
// See docs/src/webauthn/user-handle-and-signal-api.md for detailed documentation.
function synchronizeCredentialsWithSignalUnknown(credentialId) {
    try {
        // Check if the WebAuthn API is available
        if (!window.PublicKeyCredential) {
            console.log("WebAuthn credential management API not available");
            return Promise.resolve();
        }

        console.log("PublicKeyCredential is available");

        // Check if signalUnknownCredential is available
        if (
            typeof window.PublicKeyCredential.signalUnknownCredential !==
            "function"
        ) {
            console.log(
                "signalUnknownCredential API not supported in this browser"
            );
            return Promise.resolve();
        }

        console.log("signalUnknownCredential API is available");

        let options = {
            rpId: window.location.hostname,
            credentialId: credentialId,
        };

        console.log("Signal unknown credential options:", options);

        // Signal the unknown credential to the authenticator
        return window.PublicKeyCredential.signalUnknownCredential(options)
            .then(() => {
                console.log(
                    "Successfully signaled unknown credential to authenticator. rpId:",
                    window.location.hostname,
                    "credentialId:",
                    credentialId
                );
            })
            .catch((err) => {
                console.warn("Error signalUnknownCredential API:", err);
                return Promise.resolve(); // Return a resolved promise to allow chaining
            });
    } catch (err) {
        console.warn(
            "Unexpected error during credential synchronization with signalUnknown:",
            err
        );
        return Promise.resolve(); // Return a resolved promise to allow chaining
    }
}

// Delete a passkey credential from the server and notify the authenticator via Signal API.
//
// After successful server-side deletion, we use a DUAL APPROACH for authenticator sync:
// 1. signalUnknownCredential: Directly targets the deleted credential by credentialId.
//    Works correctly regardless of PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL setting.
// 2. signalAllAcceptedCredentials: Sends the list of remaining valid credentials.
//    Effective when user_handle is shared (PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=false),
//    harmless but redundant when user_handle is unique per credential.
//
// Both Signal API calls are FIRE-AND-FORGET (no await) because:
// - The deletion has already succeeded on the server
// - Signal API is non-critical - just a hint to the authenticator
// - Awaiting can block page reload on iOS Safari and other browsers where the API may be slow
// - User experience should not be degraded by optional sync features
//
// See docs/src/webauthn/user-handle-and-signal-api.md for detailed documentation.
function deletePasskeyCredential(credentialId, userHandle) {
    if (confirm("Are you sure you want to unlink this passkey credential?")) {
        fetch(`${O2P_ROUTE_PREFIX}/passkey/credentials/${credentialId}`, {
            method: "DELETE",
            headers: {
                "X-CSRF-Token": `${csrfToken}`,
                "Content-Type": "application/json",
            },
        })
            .then(async (response) => {
                if (response.ok) {
                    // Server returns JSON: { remaining_credential_ids: [...], user_handle: "..." }
                    try {
                        const data = await response.json();
                        // Signal API calls based on PASSKEY_SIGNAL_API_MODE
                        // Both are fire-and-forget (no await) to avoid blocking page reload

                        // signalUnknownCredential: directly targets the deleted credential
                        // Currently the only API that works with Google Password Manager
                        if (signalApiMode === 'direct' || signalApiMode === 'direct+sync') {
                            synchronizeCredentialsWithSignalUnknown(credentialId);
                        }

                        // signalAllAcceptedCredentials: syncs remaining credentials
                        // Currently has no effect on Google Password Manager, kept for future compatibility
                        if (signalApiMode === 'sync' || signalApiMode === 'direct+sync') {
                            synchronizeCredentials(
                                data.user_handle || userHandle,
                                data.remaining_credential_ids
                            );
                        }
                    } catch (parseErr) {
                        // JSON parse failure is non-critical - deletion already succeeded
                        console.warn("Response parse error (non-critical):", parseErr);
                    }
                    // Proceed immediately with page reload - don't wait for Signal API
                    window.location.reload();
                } else {
                    const text = await response.text();
                    throw new Error(
                        `Failed to unlink passkey credential: ${text}`
                    );
                }
            })
            .catch((error) => {
                alert(`Error: ${error.message}`);
            });
    }
}

// Function to open the update credential modal
function openUpdateCredentialModal(
    credentialId,
    name,
    displayName,
    userHandle
) {
    document.getElementById("update-credential-id").value = credentialId;
    document.getElementById("update-credential-name").value = name || "";
    document.getElementById("update-credential-display-name").value =
        displayName || "";
    document.getElementById("update-credential-user-handle").value =
        userHandle || "";
    document.getElementById("update-credential-modal").style.display = "block";
}

// Function to close the update credential modal
function closeUpdateCredentialModal() {
    document.getElementById("update-credential-modal").style.display = "none";
}

// Close the modal when clicking outside of it
window.onclick = function (event) {
    const modal = document.getElementById("update-credential-modal");
    if (event.target === modal) {
        modal.style.display = "none";
    }
};

function updateCredentialDetails() {
    const credentialId = document.getElementById("update-credential-id").value;
    const name = document.getElementById("update-credential-name").value;
    const displayName = document.getElementById(
        "update-credential-display-name"
    ).value;
    const userHandle = document.getElementById(
        "update-credential-user-handle"
    ).value;

    console.log("Updating credential:", credentialId);
    console.log("New name:", name);
    console.log("New display name:", displayName);
    console.log("User handle:", userHandle);

    fetch(`${O2P_ROUTE_PREFIX}/passkey/credential/update`, {
        method: "POST",
        headers: {
            "X-CSRF-Token": `${csrfToken}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            credential_id: credentialId,
            name: name,
            display_name: displayName,
            user_handle: userHandle,
        }),
    })
        .then((response) => {
            if (!response.ok) {
                throw new Error("Failed to update credential");
            }
            return response.json();
        })
        .then((data) => {
            console.log("Update successful:", data);

            // Update the UI
            document.getElementById(
                `credential-name-${credentialId}`
            ).textContent = name;
            document.getElementById(
                `credential-display-name-${credentialId}`
            ).textContent = displayName;

            // Signal the update to the authenticator
            signalCurrentUserDetails({
                credentialId: credentialId,
                userHandle: userHandle,
                name: name,
                displayName: displayName,
            });

            closeUpdateCredentialModal();
        })
        .catch((error) => {
            console.error("Error updating credential:", error);
            alert("Failed to update credential: " + error.message);
        });
}

/**
 * Update the user details for a credential in the authenticator
 * @param {Object} options - The options for updating user details
 * @param {string} options.credentialId - The credential ID
 * @param {string} options.userHandle - The user handle
 * @param {string} options.name - The updated name
 * @param {string} options.displayName - The updated display name
 */
async function signalCurrentUserDetails(options) {
    try {
        console.log("signalCurrentUserDetails called with options:", options);

        if (
            !window.PublicKeyCredential ||
            typeof window.PublicKeyCredential.signalCurrentUserDetails !==
                "function"
        ) {
            console.warn(
                "signalCurrentUserDetails is not supported in this browser"
            );
            return;
        }

        // Get the current domain
        const rpId = window.location.hostname;
        console.log("Using rpId:", rpId);

        const signalOptions = {
            rpId: rpId,
            userId: options.userHandle,
            name: options.name,
            displayName: options.displayName,
        };

        console.log(
            "Calling PublicKeyCredential.signalCurrentUserDetails with:",
            signalOptions
        );

        await PublicKeyCredential.signalCurrentUserDetails(signalOptions);

        console.log("Successfully updated user details in authenticator");
        return true;
    } catch (error) {
        console.error("Error updating user details in authenticator:", error);
        // Don't throw the error - this is a non-critical operation
        return false;
    }
}
