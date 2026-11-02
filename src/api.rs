use crate::{
    auth::{self, AppState, Identity, SessionInfo},
    storage,
};
use axum::{
    extract::{rejection::JsonRejection, Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi, ToSchema,
};
use utoipa_swagger_ui::SwaggerUi;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: &'static str,
}
pub(crate) struct ApiError(pub StatusCode, pub &'static str, pub &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.0,
            Json(ErrorBody {
                code: self.1,
                message: self.2,
            }),
        )
            .into_response();
        if self.0 == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        }
        if self.0 == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, "60".parse().unwrap());
        }
        response
    }
}
pub(crate) fn unauthorized() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "Invalid credentials or session",
    )
}
pub(crate) fn unavailable() -> ApiError {
    ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "Service state is unavailable. Restart and unlock the service before retrying.",
    )
}
fn limited() -> ApiError {
    ApiError(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "Too many authentication attempts. Retry in 60 seconds.",
    )
}
pub(crate) fn json_body<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    body.map(|Json(value)| value).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "Request body exceeds the size limit",
            )
        } else {
            ApiError(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Provide a valid JSON request matching the documented schema",
            )
        }
    })
}
#[derive(Deserialize, ToSchema, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    #[schema(min_length = 1, max_length = 64)]
    pub username: String,
    #[schema(format = Password, write_only, min_length = 12, max_length = 1024)]
    pub password: String,
}
#[derive(Serialize, ToSchema, Zeroize, ZeroizeOnDrop)]
pub struct LoginResponse {
    /// Opaque bearer token. Keep in memory; never put it in a URL.
    pub access_token: String,
    pub token_type: String,
    pub expires_at: u64,
    pub idle_timeout_seconds: u64,
    pub session_id: String,
}
#[derive(Deserialize, ToSchema, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PasswordRequest {
    #[schema(format = Password, write_only, max_length = 1024)]
    pub current_password: String,
    #[schema(format = Password, write_only, min_length = 12, max_length = 1024)]
    pub new_password: String,
}
#[derive(Serialize, ToSchema)]
pub struct UserInfo {
    pub id: uuid::Uuid,
    pub username: String,
    pub role: &'static str,
    pub session_id: String,
}
#[derive(Serialize, ToSchema)]
pub struct Health {
    pub status: &'static str,
}
#[derive(Serialize, ToSchema)]
pub struct ServerInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub api_version: &'static str,
    pub local_only: bool,
    pub whatsapp_runtime: bool,
}

#[utoipa::path(get, path = "/healthz", tag = "Service", responses((status = 200, body = Health)))]
async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

#[utoipa::path(post, path = "/api/v1/auth/login", tag = "Authentication", request_body = LoginRequest,
    responses((status = 200, body = LoginResponse), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody), (status = 429, body = ErrorBody), (status = 503, body = ErrorBody)))]
async fn login(
    State(state): State<AppState>,
    Extension(peer): Extension<crate::transport::ClientAddress>,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Json<LoginResponse>, ApiError> {
    let body = json_body(body)?;
    if body.username.len() > 64 || body.password.len() > 1024 {
        return Err(unauthorized());
    }
    {
        let mut core = state.core.lock().await;
        if !core.available {
            return Err(unavailable());
        }
        if !core.allow_password_attempt(&body.username, peer.0) {
            return Err(limited());
        }
    }
    let credential = state
        .database
        .credentials(&body.username)
        .await
        .map_err(|_| unavailable())?;
    let dummy = Zeroizing::new(state.core.lock().await.store.state.password_hash.clone());
    let hash = credential
        .as_ref()
        .map(|user| user.hash.clone())
        .unwrap_or(dummy);
    let permit = state
        .password_work
        .clone()
        .try_acquire_owned()
        .map_err(|_| limited())?;
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        auth::verify_password(&body.password, &hash)
    })
    .await
    .map_err(|_| unavailable())?;
    let credential = credential
        .filter(|user| valid && !user.user.disabled)
        .ok_or_else(unauthorized)?;
    let current = state
        .database
        .user(credential.user.id)
        .await
        .map_err(|_| unavailable())?
        .filter(|(user, generation)| !user.disabled && *generation == credential.generation)
        .ok_or_else(unauthorized)?;
    let mut core = state.core.lock().await;
    if !core.available {
        return Err(unavailable());
    }
    let mut credential = credential;
    credential.user = current.0;
    let (token, session) = core.issue_session(&credential).ok_or(ApiError(
        StatusCode::CONFLICT,
        "session_limit",
        "Session limit reached. Sign out an existing client or restart the service.",
    ))?;
    Ok(Json(LoginResponse {
        access_token: token.to_string(),
        token_type: "Bearer".into(),
        expires_at: session.expires_at,
        idle_timeout_seconds: auth::SESSION_IDLE.as_secs(),
        session_id: session.id,
    }))
}
pub(crate) async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let digest = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .and_then(auth::token_digest)
        .ok_or_else(unauthorized)?;
    let mut core = state.core.lock().await;
    if !core.available {
        return Err(unavailable());
    }
    let mut identity = core.authenticate(digest).ok_or_else(unauthorized)?;
    drop(core);
    let (user, generation) = state
        .database
        .user(identity.user_id)
        .await
        .map_err(|_| unavailable())?
        .filter(|(user, generation)| !user.disabled && *generation == identity.generation)
        .ok_or_else(unauthorized)?;
    identity.username = user.username;
    identity.server_admin = user.server_admin;
    identity.generation = generation;
    request.extensions_mut().insert(identity);
    Ok(next.run(request).await)
}
#[utoipa::path(get, path = "/api/v1/auth/me", tag = "Authentication", security(("bearer_auth" = [])), responses((status = 200, body = UserInfo), (status = 401, body = ErrorBody)))]
async fn me(Extension(identity): Extension<Identity>) -> Json<UserInfo> {
    Json(UserInfo {
        id: identity.user_id,
        username: identity.username,
        role: if identity.server_admin {
            "server_admin"
        } else {
            "user"
        },
        session_id: identity.session_id,
    })
}
#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "Authentication", security(("bearer_auth" = [])), responses((status = 204), (status = 401, body = ErrorBody)))]
async fn logout(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> StatusCode {
    state.core.lock().await.sessions.remove(&identity.digest);
    StatusCode::NO_CONTENT
}
#[utoipa::path(get, path = "/api/v1/auth/sessions", tag = "Sessions", security(("bearer_auth" = [])), responses((status = 200, body = [SessionInfo]), (status = 401, body = ErrorBody)))]
async fn sessions(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> Json<Vec<SessionInfo>> {
    let mut core = state.core.lock().await;
    core.prune();
    let mut sessions = core
        .sessions
        .iter()
        .filter(|(_, session)| session.user_id == identity.user_id)
        .map(|(digest, session)| SessionInfo {
            id: session.id.clone(),
            created_at: session.created_at,
            expires_at: session.expires_at,
            current: *digest == identity.digest,
        })
        .collect::<Vec<_>>();
    sessions.sort_by(|left, right| left.id.cmp(&right.id));
    Json(sessions)
}
#[utoipa::path(delete, path = "/api/v1/auth/sessions/{id}", tag = "Sessions", security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Session identifier returned by login or session listing")),
    responses((status = 204), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody), (status = 404, body = ErrorBody)))]
async fn revoke(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_session_id",
            "Invalid session identifier",
        ));
    }
    let mut core = state.core.lock().await;
    let before = core.sessions.len();
    core.sessions
        .retain(|_, session| session.id != id || session.user_id != identity.user_id);
    if core.sessions.len() == before {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "not_found",
            "Session not found",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(post, path = "/api/v1/auth/password", tag = "Authentication", security(("bearer_auth" = [])), request_body = PasswordRequest,
    responses((status = 204, description = "Password changed; all sessions revoked. Log in again."), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody), (status = 429, body = ErrorBody), (status = 503, body = ErrorBody)))]
async fn password(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    body: Result<Json<PasswordRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let body = json_body(body)?;
    storage::password_policy(&body.new_password).map_err(|_| {
        ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_password",
            "Use at least 12 characters and at most 1024 bytes",
        )
    })?;
    if body.current_password.len() > 1024 {
        return Err(unauthorized());
    }
    let credential = state
        .database
        .credentials(&identity.username)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unauthorized)?;
    {
        let mut core = state.core.lock().await;
        if !core.allow_password_attempt(&identity.username, std::net::Ipv4Addr::LOCALHOST.into()) {
            return Err(limited());
        }
    }
    let permit = state
        .password_work
        .clone()
        .try_acquire_owned()
        .map_err(|_| limited())?;
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if !auth::verify_password(&body.current_password, &credential.hash) {
            return Err(unauthorized());
        }
        auth::hash_password(&body.new_password).map_err(|_| unavailable())
    })
    .await
    .map_err(|_| unavailable())??;
    tokio::spawn(async move {
        let mut tx = crate::management::begin(&state, &identity).await?;
        let value = state
            .database
            .cipher
            .seal(&format!("user:{}:credential", identity.user_id), &hash)
            .map_err(|_| unavailable())?;
        sqlx::query(
            "UPDATE elo_users SET credential = $1, generation = generation + 1 WHERE id = $2",
        )
        .bind(value)
        .bind(identity.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
        tx.commit().await.map_err(|_| unavailable())?;
        state
            .core
            .lock()
            .await
            .sessions
            .retain(|_, session| session.user_id != identity.user_id);
        Ok(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(|_| unavailable())?
}
#[utoipa::path(get, path = "/api/v1/server", tag = "Service", security(("bearer_auth" = [])), responses((status = 200, body = ServerInfo), (status = 401, body = ErrorBody)))]
async fn server_info(State(state): State<AppState>) -> Json<ServerInfo> {
    Json(ServerInfo {
        name: "Elo Talks Server",
        version: env!("CARGO_PKG_VERSION"),
        api_version: "v1",
        local_only: !state.remote_enabled,
        whatsapp_runtime: false,
    })
}
struct Security;
impl Modify for Security {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("opaque")
                        .build(),
                ),
            );
        }
    }
}
#[derive(OpenApi)]
#[openapi(info(title = "Elo Talks Server API", description = "PostgreSQL-backed organizations, workspace access and metadata synchronization. Login does not transmit WhatsApp profiles."),
    paths(health, login, me, logout, sessions, revoke, password, server_info),
    components(schemas(ErrorBody, LoginRequest, LoginResponse, PasswordRequest, UserInfo, SessionInfo, Health, ServerInfo)), modifiers(&Security))]
pub struct ApiDoc;

pub fn specification() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();
    doc.merge(crate::management::ManagementDoc::openapi());
    doc
}
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/sessions", get(sessions))
        .route("/api/v1/auth/sessions/{id}", delete(revoke))
        .route("/api/v1/auth/password", post(password))
        .route("/api/v1/server", get(server_info))
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/auth/login", post(login))
        .merge(protected)
        .merge(crate::management::router(state.clone()))
        .merge(crate::panel::router())
        .merge(
            SwaggerUi::new("/docs")
                .url("/api/v1/openapi.json", specification())
                .config(
                    utoipa_swagger_ui::Config::default()
                        .persist_authorization(false)
                        .query_config_enabled(false)
                        .validator_url("none"),
                ),
        )
        .method_not_allowed_fallback(|| async {
            ApiError(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "Method not allowed",
            )
        })
        .fallback(|| async { ApiError(StatusCode::NOT_FOUND, "not_found", "Endpoint not found") })
        .with_state(state)
}
