use crate::{
    models::app_user::NewAppUser,
    register::{check_available, register},
    State, ALLOWED_LOCALHOST, ALLOWED_ORIGINS, ALLOWED_SUBDOMAIN, API_VERSION,
};
use axum::extract::Path;
use axum::headers::Origin;
use axum::http::StatusCode;
use axum::Extension;
use axum::{Json, TypedHeader};
use log::{debug, error};
use serde::{Deserialize, Serialize};

pub async fn check_username(
    origin: Option<TypedHeader<Origin>>,
    Extension(state): Extension<State>,
    Path(username): Path<String>,
) -> Result<Json<bool>, (StatusCode, String)> {
    debug!("check_username: {}", username);
    validate_cors(origin)?;

    match check_available(&state, username).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error("check_username", e)),
    }
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub pubkey: String,
    pub federation_id: String,
    pub federation_invite_code: String,
    // TODO blinded message info
}

impl From<RegisterRequest> for NewAppUser {
    fn from(request: RegisterRequest) -> Self {
        NewAppUser {
            pubkey: request.pubkey,
            name: request.name,
            federation_id: request.federation_id,
            federation_invite_code: request.federation_invite_code,
        }
    }
}

#[derive(Serialize)]
pub struct RegisterResponse {}

pub async fn register_route(
    origin: Option<TypedHeader<Origin>>,
    Extension(state): Extension<State>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    debug!("register");
    validate_cors(origin)?;
    match register(&state, req) {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(e),
    }
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

impl HealthResponse {
    /// Fabricate a status: pass response without checking database connectivity
    pub fn new_ok() -> Self {
        Self {
            status: String::from("pass"),
            version: String::from(API_VERSION),
        }
    }
}

/// IETF draft RFC for HTTP API Health Checks:
/// https://datatracker.ietf.org/doc/html/draft-inadarei-api-health-check
pub async fn health_check() -> Result<Json<HealthResponse>, (StatusCode, String)> {
    Ok(Json(HealthResponse::new_ok()))
}

pub fn valid_origin(origin: &str) -> bool {
    ALLOWED_ORIGINS.contains(&origin)
        || origin.ends_with(ALLOWED_SUBDOMAIN)
        || origin.starts_with(ALLOWED_LOCALHOST)
}

pub fn validate_cors(origin: Option<TypedHeader<Origin>>) -> Result<(), (StatusCode, String)> {
    if let Some(TypedHeader(origin)) = origin {
        if origin.is_null() {
            return Ok(());
        }

        let origin_str = origin.to_string();
        if valid_origin(&origin_str) {
            return Ok(());
        }

        // The origin is not in the allowed list block the request
        return Err((StatusCode::NOT_FOUND, String::new()));
    }

    Ok(())
}

pub(crate) fn handle_anyhow_error(function: &str, err: anyhow::Error) -> (StatusCode, String) {
    error!("Error in {function}: {err:?}");
    (StatusCode::BAD_REQUEST, format!("{err}"))
}
