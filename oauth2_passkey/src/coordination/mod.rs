mod admin;
mod errors;
mod oauth2;
mod passkey;
mod user;

pub use oauth2::{
    delete_oauth2_account_core, get_authorized_core, list_accounts_core, post_authorized_core,
};

pub use admin::{
    delete_oauth2_account_admin, delete_passkey_credential_admin, delete_user_account_admin,
    get_all_users, get_user,
};
pub use passkey::{
    RegistrationStartRequest, delete_passkey_credential_core, handle_finish_authentication_core,
    handle_finish_registration_core, handle_start_authentication_core,
    handle_start_registration_core, list_credentials_core, update_passkey_credential_core,
};
pub use user::{delete_user_account, update_user_account};

pub use errors::CoordinationError;
