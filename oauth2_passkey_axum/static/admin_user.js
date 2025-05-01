window.addEventListener("error", function (event) {
    console.error("Uncaught error:", event.error);
});

function DeleteAccount(userIdToDelete) {
    // If userIdToDelete is provided, use it; otherwise use the global userId
    const targetUserId = userIdToDelete || userId;
    const targetAccountName = userIdToDelete ? "this account" : accountName;
    
    if (confirm(`Are you sure you want to delete ${targetAccountName}?`)) {
        fetch(`${O2P_ROUTE_PREFIX}/admin/delete_user`, {
            method: "DELETE",
            headers: {
                "X-CSRF-Token": `${csrfToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                user_id: targetUserId
            }),
        })
        .then((response) => {
            if (!response.ok) {
                return response.text().then((text) => {
                    throw new Error(text);
                });
            }
            console.log("Account deleted successfully");
            alert("Account has been deleted.");
            window.location.reload();
        })
        .catch((error) => {
            console.error(`Error deleting account: ${error.message}`);
            alert(`Error: ${error.message}`);
        });
    }
}

function unlinkOAuth2Account(provider, providerUserId, accountUserId) {
    if (confirm("Are you sure you want to unlink this OAuth2 account?")) {
        fetch(
            `${O2P_ROUTE_PREFIX}/admin/delete_oauth2_account/${provider}/${providerUserId}`,
            {
                method: "DELETE",
                headers: {
                    "X-CSRF-Token": `${csrfToken}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    user_id: accountUserId,
                }),
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

function deletePasskeyCredential(credentialId, credentialUserId) {
    if (confirm("Are you sure you want to unlink this passkey credential?")) {
        console.log("Deleting passkey credential with ID: " + credentialId);
        console.log("User ID: " + credentialUserId);
        fetch(`${O2P_ROUTE_PREFIX}/admin/delete_passkey_credential/${credentialId}`, {
            method: "DELETE",
            headers: {
                "X-CSRF-Token": `${csrfToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                user_id: credentialUserId,
            }),
        })
        .then(async (response) => {
            if (response.ok) {
                // Refresh the page to show updated credential list
                window.location.reload();
            } else {
                // Parse error response safely
                let errorText = "Unknown error";
                try {
                    errorText = await response.text();
                } catch (parseError) {
                    console.error("Error parsing response:", parseError);
                }
                throw new Error(`Failed to unlink passkey credential: ${errorText}`);
            }
        })
        .catch((error) => {
            console.error(`Error: ${error.message}`);
            alert(`Error: ${error.message}`);
        });
    }
}

function toggleAdminStatus(userId, currentStatus) {
    const newStatus = !currentStatus;
    const actionText = newStatus ? "make admin" : "remove admin status from";
    
    if (confirm(`Are you sure you want to ${actionText} this user?`)) {
        fetch(`${O2P_ROUTE_PREFIX}/admin/update_admin_status`, {
            method: "PUT",
            headers: {
                "X-CSRF-Token": `${csrfToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                user_id: userId,
                is_admin: newStatus
            }),
        })
        .then(async (response) => {
            if (response.ok) {
                // Update the UI without refreshing the page
                const statusElement = document.getElementById(`admin-status-${userId}`);
                if (statusElement) {
                    statusElement.textContent = newStatus.toString();
                }
                
                // Update the button onclick attribute with the new status
                const button = document.querySelector(`button[onclick="toggleAdminStatus('${userId}', ${currentStatus})"]`);
                if (button) {
                    button.setAttribute("onclick", `toggleAdminStatus('${userId}', ${newStatus})`);
                }
                
                alert(`User admin status updated successfully.`);
            } else {
                // Parse error response safely
                let errorText = "Unknown error";
                try {
                    errorText = await response.text();
                } catch (parseError) {
                    console.error("Error parsing response:", parseError);
                }
                throw new Error(`Failed to update admin status: ${errorText}`);
            }
        })
        .catch((error) => {
            console.error(`Error: ${error.message}`);
            alert(`Error: ${error.message}`);
        });
    }
}
