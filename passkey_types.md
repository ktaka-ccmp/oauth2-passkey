# Passkey types

## registration

### Client

```javascript
startResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/register/start', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify(username)
});
```

### Server /registration/start

```rust
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct StoredChallenge {
    pub(super) challenge: Vec<u8>,
############### Todo: user -> user_handle: String ###############
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) timestamp: u64,
    pub(super) ttl: u64,
}
```

```rust
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationOptions {
    pub(super) challenge: String,
    pub(super) rp_id: String,
    pub(super) rp: RelyingParty,
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) pub_key_cred_params: Vec<PubKeyCredParam>,
    pub(super) authenticator_selection: AuthenticatorSelection,
    pub(super) timeout: u32,
    pub(super) attestation: String,
}

#[derive(Serialize, Debug)]
pub(super) struct RelyingParty {
    pub(super) name: String,
    pub(super) id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub(super) struct PublicKeyCredentialUserEntity {
############### Todo: id_handle -> user_handle ###############
    pub(super) id_handle: String,
    pub(super) name: String,
    #[serde(rename = "displayName")]
    pub(super) display_name: String,
}

#[derive(Serialize, Debug)]
pub(super) struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub(super) type_: String,
    pub(super) alg: i32,
}

#[derive(Serialize, Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    pub(crate) authenticator_attachment: String,
    pub(crate) resident_key: String,
    pub(crate) user_verification: String,
    pub(crate) require_resident_key: bool,
}
```

### Client

```javascript
const options = await startResponse.json();

############### Todo: id_handle -> user_handle ###############
let userHandle = options.user.id_handle;

options.challenge = base64URLToUint8Array(options.challenge);
options.user.id = new TextEncoder().encode(options.user.id);
```

### Authenticator

```javascript
const credential = await navigator.credentials.create({
    publicKey: options
});
```

### Client

```javascript
const credentialResponse = {
    id: credential.id,
    raw_id: arrayBufferToBase64URL(credential.rawId),
    type: credential.type,
    response: {
        attestation_object: arrayBufferToBase64URL(credential.response.attestationObject),
        client_data_json: arrayBufferToBase64URL(credential.response.clientDataJSON)
    },
    user_handle: userHandle,
};

const finishResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/register/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentialResponse)
});
```

### Server /registration/finish

```rust
#[derive(Deserialize, Debug)]
pub struct RegisterCredential {
    pub(super) id: String,
    pub(super) raw_id: String,
    #[serde(rename = "type")]
    pub(super) type_: String,
    pub(super) response: AuthenticatorAttestationResponse,
#############Todo: remove username ###############
    pub(super) username: Option<String>,
    pub(super) user_handle: Option<String>,
}

#[derive(Deserialize, Debug)]
pub(super) struct AuthenticatorAttestationResponse {
    pub(super) client_data_json: String,
    pub(super) attestation_object: String,
}

#[derive(Debug)]
pub(super) struct AttestationObject {
    pub(super) fmt: String,
    pub(super) auth_data: Vec<u8>,
    pub(super) att_stmt: Vec<(CborValue, CborValue)>,
}

#[derive(Debug)]
pub(super) struct ParsedClientData {
    pub(super) challenge: Vec<u8>,
    pub(super) origin: String,
    pub(super) type_: String,
    pub(super) raw_data: Vec<u8>,
}
```

```rust
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct StoredCredential {
    pub(super) credential_id: Vec<u8>,
    pub(super) public_key: Vec<u8>,
    pub(super) counter: u32,
#############Todo: user -> user_id: String ###############
    pub(super) user: PublicKeyCredentialUserEntity,
}
```

Todo: Create user_id vs name database

## Authentication

### Client

```javascript
const startResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/auth/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: username ? JSON.stringify(username) : "{}"
});
```

### Server /auth/start

```rust
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct StoredChallenge {
    pub(super) challenge: Vec<u8>,
############### Todo: user -> auth_id: String ###############
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) timestamp: u64,
    pub(super) ttl: u64,
}
```

```rust
#[serde(rename_all = "camelCase")]
pub struct AuthenticationOptions {
    pub(super) challenge: String,
    pub(super) timeout: u32,
    pub(super) rp_id: String,
    pub(super) allow_credentials: Vec<AllowCredential>,
    pub(super) user_verification: String,
    pub(super) auth_id: String,
}

#[derive(Serialize, Debug)]
pub(super) struct AllowCredential {
    pub(super) type_: String,
    pub(super) id: Vec<u8>,
}
```

### Client

```javascript
const options = await startResponse.json();

options.challenge = base64URLToUint8Array(options.challenge);

options.allowCredentials = options.allowCredentials.map(credential => ({
    type: 'public-key',  // Required by WebAuthn
    id: new Uint8Array(credential.id),
    transports: credential.transports  // Optional
}));
```

### Authenticator

```javascript
const credential = await navigator.credentials.get({
    publicKey: options
});
```

### Client

```javascript
const authResponse = {
    auth_id: options.authId,
    id: credential.id,
    raw_id: arrayBufferToBase64URL(credential.rawId),
    type: credential.type,
    authenticator_attachment: credential.authenticatorAttachment,
    response: {
        authenticator_data: arrayBufferToBase64URL(credential.response.authenticatorData),
        client_data_json: arrayBufferToBase64URL(credential.response.clientDataJSON),
        signature: arrayBufferToBase64URL(credential.response.signature),
        user_handle: arrayBufferToBase64URL(credential.response.userHandle)
    },
};

const verifyResponse = await fetch(PASSKEY_ROUTE_PREFIX + '/auth/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(authResponse)
});

```

### Server /auth/finish

```rust
#[derive(Deserialize, Debug)]
pub struct AuthenticatorResponse {
    pub(super) id: String,
    raw_id: String,
    pub(super) response: AuthenticatorAssertionResponse,
    authenticator_attachment: Option<String>,
    pub(super) auth_id: String,
}

#[derive(Deserialize, Debug)]
pub(super) struct AuthenticatorAssertionResponse {
    pub(super) client_data_json: String,
    pub(super) authenticator_data: String,
    pub(super) signature: String,
    pub(super) user_handle: Option<String>, #### is this auth_id?
}

#[derive(Debug)]
pub(super) struct AuthenticatorData {
    pub(super) rp_id_hash: Vec<u8>,
    pub(super) flags: u8,
    pub(super) raw_data: Vec<u8>,
}
```

## Misc

### src/types.rs

```rust
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) enum CacheData {
    SessionInfo(SessionInfo),
    EmailUserId(EmailUserId),
    UserIdCredentialIdStr(UserIdCredentialIdStr),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct EmailCredId {
    pub(super) stored_credential: StoredCredential,
    pub(super) user: libsession::User,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct EmailUserId {
    pub(super) email: String,
    pub(super) user_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct UserIdCredentialIdStr {
    pub(super) user_id: String,
    pub(super) credential_id_str: String,
    pub(super) credential_id: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct SessionInfo {
    pub(super) user: libsession::User,
}
```

### src/storage/types.rs

```rust
#[derive(Clone, Debug)]
pub(crate) enum ChallengeStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}

#[derive(Clone, Debug)]
pub(crate) enum CredentialStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}

pub(crate) struct InMemoryChallengeStore {
    pub(super) challenges: HashMap<String, StoredChallenge>,
}

pub(crate) struct InMemoryCredentialStore {
    pub(super) credentials: HashMap<String, StoredCredential>,
}

pub(crate) struct PostgresChallengeStore {
    pub(super) pool: Pool<Postgres>,
}

pub(crate) struct PostgresCredentialStore {
    pub(super) pool: Pool<Postgres>,
}

pub(crate) struct RedisChallengeStore {
    pub(super) client: redis::Client,
}

pub(crate) struct RedisCredentialStore {
    pub(super) client: redis::Client,
}

pub(crate) struct SqliteChallengeStore {
    pub(super) pool: Pool<Sqlite>,
}

pub(crate) struct SqliteCredentialStore {
    pub(super) pool: Pool<Sqlite>,
}

#[derive(Clone, Debug)]
pub(crate) enum CacheStoreType {
    Memory,
    Redis { url: String },
}

pub(crate) struct InMemoryCacheStore {
    pub(super) entry: HashMap<String, CacheData>,
}

pub(crate) struct RedisCacheStore {
    pub(super) client: redis::Client,
}
```
