use crate::oauth2::AppError;
use std::collections::HashMap;

pub(crate) struct InMemoryTokenStore {
    token: HashMap<String, StoredToken>,
}

impl InMemoryTokenStore {
    pub(crate) fn new() -> Self {
        println!("Creating new in-memory token store");
        Self {
            token: HashMap::new(),
        }
    }
}

pub(crate) struct InMemorySessionStore {
    session: HashMap<String, StoredSession>,
}

impl InMemorySessionStore {
    pub(crate) fn new() -> Self {
        println!("Creating new in-memory session store");
        Self {
            session: HashMap::new(),
        }
    }
}

impl TokenStore for InMemoryTokenStore {
    async fn init(&self) -> Result<(), AppError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn store_token(
        &mut self,
        token_id: String,
        token: StoredToken,
    ) -> Result<(), AppError> {
        self.token.insert(token_id, token);
        Ok(())
    }

    async fn get_token(
        &self,
        token_id: &str,
    ) -> Result<Option<StoredToken>, AppError> {
        Ok(self.token.get(token_id).cloned())
    }

    async fn remove_token(&mut self, token_id: &str) -> Result<(), AppError> {
        self.token.remove(token_id);
        Ok(())
    }
}

impl SessionStore for InMemorySessionStore {
    async fn init(&self) -> Result<(), AppError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn store_session(
        &mut self,
        session_id: String,
        session: StoredSession,
    ) -> Result<(), AppError> {
        self.session.insert(session_id, session);
        Ok(())
    }

    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<StoredSession>, AppError> {
        Ok(self.session.get(session_id).cloned())
    }

    async fn remove_session(&mut self, session_id: &str) -> Result<(), AppError> {
        self.session.remove(session_id);
        Ok(())
    }
}
