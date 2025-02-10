use askama::Template;
use axum::{extract::State, http::StatusCode, response::Html};
use libsession::User;

use crate::state::AppState;

#[derive(Template)]
#[template(path = "index_user.j2")]
struct IndexTemplateUser<'a> {
    message: &'a str,
    auth_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "index_anon.j2")]
struct IndexTemplateAnon<'a> {
    message: &'a str,
    auth_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "protected.j2")]
struct ProtectedTemplate<'a> {
    user: User,
    auth_route_prefix: &'a str,
}

pub(crate) async fn index(
    State(s): State<AppState>,
    user: Option<User>,
) -> Result<Html<String>, (StatusCode, String)> {
    match user {
        Some(u) => {
            let message = format!("Hey {}!", u.name);
            let template = IndexTemplateUser {
                message: &message,
                auth_route_prefix: &s.oauth2_state.oauth2_params.oauth2_route_prefix,
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html)
        }
        None => {
            let message = "Click the Login button below.".to_string();
            let template = IndexTemplateAnon {
                message: &message,
                auth_route_prefix: &s.oauth2_state.oauth2_params.oauth2_route_prefix,
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html)
        }
    }
}

pub(crate) async fn protected(
    State(s): State<AppState>,
    user: User,
) -> Result<Html<String>, (StatusCode, String)> {
    let template = ProtectedTemplate {
        user,
        auth_route_prefix: &s.oauth2_state.oauth2_params.oauth2_route_prefix,
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}
