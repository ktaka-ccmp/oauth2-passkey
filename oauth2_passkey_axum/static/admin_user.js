window.addEventListener("error", function (event) {
    console.error("Uncaught error:", event.error);
});

function DeleteAccount() {
    if (confirm(`Are you sure you want to delete the account ${accountName}?`)) {
        fetch(`${O2P_ROUTE_PREFIX}/admin/delete_user`, {
            method: "DELETE",
            headers: {
                "X-CSRF-Token": `${csrfToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                user_id: userId
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
                    page_user_context: PAGE_USER_CONTEXT
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
        console.log("Page user context: " + PAGE_USER_CONTEXT);
        fetch(`${O2P_ROUTE_PREFIX}/admin/delete_passkey_credential/${credentialId}`, {
            method: "DELETE",
            headers: {
                "X-CSRF-Token": `${csrfToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                user_id: credentialUserId,
                page_user_context: PAGE_USER_CONTEXT,
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
