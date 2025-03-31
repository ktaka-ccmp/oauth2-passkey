window.addEventListener("error", function (event) {
    console.error("Uncaught error:", event.error);
});

function Logout() {
    window.location.href = `${O2P_ROUTE_PREFIX}/oauth2/logout`;
}

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
                    credentialIds.forEach((credentialId) => {
                        notificationChain = notificationChain.then(() => {
                            return synchronizeCredentialsWithSignalUnknown(
                                credentialId
                            );
                        });
                    });

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

// Function to synchronize credentials with the authenticator using signalAllAcceptedCredentials
// This helps keep the authenticator's credential store in sync with the server
// Takes the user handle of the deleted credential as a parameter
function synchronizeCredentials(userHandle) {
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

    // Signal all accepted credentials with an empty array
    // This tells the authenticator that no credentials are valid for this user and RP
    return window.PublicKeyCredential.signalAllAcceptedCredentials({
        rpId: window.location.hostname,
        userId: userIdBase64Url,
        allAcceptedCredentialIds: [], // Empty array = no valid credentials
    })
        .then(() => {
            console.log(
                "Successfully signaled credential deletion to authenticator"
            );
        })
        .catch((err) => {
            console.warn("Error during credential synchronization:", err);
        });
}

// Function to synchronize credentials with the authenticator using signalUnknownCredential
// This is an alternative approach for testing purposes
// Takes the credential ID of the deleted credential as a parameter
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

function deletePasskeyCredential(credentialId, userHandle) {
    if (confirm("Are you sure you want to unlink this passkey credential?")) {
        fetch(`${O2P_ROUTE_PREFIX}/passkey/credentials/${credentialId}`, {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json",
            },
        })
            .then((response) => {
                if (response.ok) {
                    // After successful deletion, synchronize credentials with the authenticator
                    // Pass the user handle of the deleted credential for accurate synchronization
                    // return synchronizeCredentials(userHandle);
                    return synchronizeCredentialsWithSignalUnknown(
                        credentialId
                    );
                } else {
                    return response.text().then((text) => {
                        throw new Error(
                            `Failed to unlink passkey credential: ${text}`
                        );
                    });
                }
            })
            .then(() => {
                // Refresh the page to show updated credential list
                window.location.reload();
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
        headers: { "Content-Type": "application/json" },
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
