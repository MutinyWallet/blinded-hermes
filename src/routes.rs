use crate::{
    lnurlp::{lnurl_callback, verify, well_known_lnurlp},
    nostr::well_known_nip5,
    register::{check_available, check_registered_pubkey, register},
    State, ALLOWED_LOCALHOST, ALLOWED_ORIGINS, ALLOWED_SUBDOMAIN, API_VERSION,
};
use axum::extract::{Path, Query};
use axum::headers::Origin;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Extension;
use axum::{Json, TypedHeader};
use fedimint_core::Amount;
use fedimint_ln_common::lightning_invoice::Bolt11Invoice;
use log::{error, info};
use nostr::prelude::XOnlyPublicKey;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, fmt::Display, str::FromStr};
use tbs::AggregatePublicKey;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LnUrlErrorResponse {
    pub status: LnurlStatus,
    pub reason: String,
}

impl IntoResponse for LnUrlErrorResponse {
    fn into_response(self) -> Response {
        let body = serde_json::to_value(self).expect("valid json");
        (StatusCode::OK, Json(body)).into_response()
    }
}

pub async fn check_username(
    origin: Option<TypedHeader<Origin>>,
    Extension(state): Extension<State>,
    Path(username): Path<String>,
) -> Result<Json<bool>, (StatusCode, String)> {
    info!("check_username: {}", username);
    validate_cors(origin)?;

    match check_available(&state, username.clone()) {
        Ok(res) => {
            info!("check_username finished: {}", username);
            Ok(Json(res))
        }
        Err(e) => Err(handle_anyhow_error("check_username", e)),
    }
}

pub async fn check_pubkey(
    origin: Option<TypedHeader<Origin>>,
    Extension(state): Extension<State>,
    Path(pubkey): Path<String>,
) -> Result<Json<Option<String>>, (StatusCode, String)> {
    info!("check_pubkey: {}", pubkey);
    validate_cors(origin)?;

    // check it's a valid pubkey
    XOnlyPublicKey::from_str(&pubkey)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Nostr Pubkey Invalid".to_string()))?;

    match check_registered_pubkey(&state, pubkey.clone()) {
        Ok(res) => {
            info!("check_pubkey finished: {}", pubkey);
            Ok(Json(res))
        }
        Err(e) => Err(handle_anyhow_error("check_pubkey", e)),
    }
}

#[derive(Deserialize, Clone)]
pub struct RegisterRequest {
    pub name: Option<String>,
    pub pubkey: String,
    pub federation_invite_code: String,
    pub msg: tbs::Message,
    pub sig: tbs::Signature,
}

impl RegisterRequest {
    pub fn verify(&self, pubkey: AggregatePublicKey) -> bool {
        tbs::verify(self.msg, self.sig, pubkey)
    }
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub name: String,
}

pub async fn register_route(
    origin: Option<TypedHeader<Origin>>,
    Extension(state): Extension<State>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    info!("register: {:?}", req.name);
    validate_cors(origin)?;
    match register(&state, req.clone()).await {
        Ok(res) => {
            info!("register finished: {:?}", req.name);
            Ok(Json(res))
        }
        Err(e) => {
            error!("Error in register {:?}: {e:?}", req.name);
            Err(e)
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserWellKnownNip5Req {
    pub name: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserWellKnownNip5Resp {
    pub names: HashMap<String, XOnlyPublicKey>,
}

pub async fn well_known_nip5_route(
    Extension(state): Extension<State>,
    Query(params): Query<UserWellKnownNip5Req>,
) -> Result<Json<UserWellKnownNip5Resp>, (StatusCode, Json<Value>)> {
    info!("well_known_nip5_route: {:?}", params.name);
    match params.name.clone() {
        Some(name) => {
            let names = well_known_nip5(&state, name)?;
            info!("well_known_nip5_route finished: {:?}", params.name);
            Ok(Json(UserWellKnownNip5Resp { names }))
        }
        None => {
            error!(
                "Error in well_known_nip5_route {:?}: Not Found",
                params.name
            );
            Err((
                StatusCode::NOT_FOUND,
                Json(json!({"status": "ERROR", "error": "Not Found"})),
            ))
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum LnurlType {
    PayRequest,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum LnurlStatus {
    Ok,
    Error,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LnurlWellKnownResponse {
    pub callback: Url,
    pub max_sendable: Amount,
    pub min_sendable: Amount,
    pub metadata: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_allowed: Option<i32>,
    pub tag: LnurlType,
    pub status: LnurlStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<XOnlyPublicKey>,
    pub allows_nostr: bool,
}

pub async fn well_known_lnurlp_route(
    Extension(state): Extension<State>,
    Path(username): Path<String>,
) -> Result<Json<LnurlWellKnownResponse>, LnUrlErrorResponse> {
    info!("well_known_lnurlp_route: {username}");
    match well_known_lnurlp(&state, username.clone()).await {
        Ok(res) => {
            info!("well_known_lnurlp_route finished: {username}");
            Ok(Json(res))
        }
        Err(e) => {
            error!("Error in well_known_lnurlp_route {username}: {e:?}");
            Err(LnUrlErrorResponse {
                status: LnurlStatus::Error,
                reason: e.to_string(),
            })
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LnurlCallbackParams {
    pub amount: Option<u64>, // User specified amount in MilliSatoshi
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub nonce: Option<String>, // Optional parameter used to prevent server response caching
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub comment: Option<String>, // Optional parameter to pass the LN WALLET user's comment to LN SERVICE
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub proofofpayer: Option<String>, // Optional ephemeral secp256k1 public key generated by payer
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub nostr: Option<String>, // Optional zap request
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LnurlCallbackResponse {
    pub status: LnurlStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub pr: Bolt11Invoice,
    pub verify: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_action: Option<LnurlCallbackSuccessAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LnurlCallbackSuccessAction {
    pub tag: String,
    pub message: String,
}

pub async fn lnurl_callback_route(
    Extension(state): Extension<State>,
    Query(params): Query<LnurlCallbackParams>,
    Path(username): Path<String>,
) -> Result<Json<LnurlCallbackResponse>, LnUrlErrorResponse> {
    info!("lnurl_callback_route: {username}");
    match lnurl_callback(&state, username.clone(), params).await {
        Ok(res) => {
            info!("lnurl_callback_route finished: {username}");
            Ok(Json(res))
        }
        Err(e) => {
            error!("Error in lnurl_callback_route {username}: {e:?}");
            Err(LnUrlErrorResponse {
                status: LnurlStatus::Error,
                reason: e.to_string(),
            })
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LnurlVerifyResponse {
    pub status: LnurlStatus,
    pub settled: bool,
    pub preimage: Option<String>,
    pub pr: String,
}

pub async fn lnurl_verify_route(
    Extension(state): Extension<State>,
    Path((username, op_id)): Path<(String, String)>,
) -> Result<Json<LnurlVerifyResponse>, LnUrlErrorResponse> {
    info!("lnurl_callback_route: {username}");
    match verify(&state, username.clone(), op_id).await {
        Ok(res) => {
            info!("lnurl_callback_route finished: {username}");
            Ok(Json(res))
        }
        Err(e) => {
            error!("Error in lnurl_callback_route {username}: {e:?}");
            Err(LnUrlErrorResponse {
                status: LnurlStatus::Error,
                reason: e.to_string(),
            })
        }
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

pub async fn root() -> Redirect {
    Redirect::to("https://plus.mutinywallet.com")
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

pub fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s).map_err(de::Error::custom).map(Some),
    }
}

pub(crate) fn handle_anyhow_error(function: &str, err: anyhow::Error) -> (StatusCode, String) {
    error!("Error in {function}: {err:?}");
    (StatusCode::BAD_REQUEST, format!("{err}"))
}
