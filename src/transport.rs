//! Loopback-only TLS transport and browser boundary checks.
use crate::{
    api::{self, ApiError},
    auth::AppState,
};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderValue, Method},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct ClientAddress(pub std::net::IpAddr);

pub const DEFAULT_PORT: u16 = 8443;
#[derive(Clone)]
struct Policy {
    hosts: Vec<String>,
    own_origins: Vec<String>,
    origins: Vec<String>,
    state: AppState,
}

pub fn certificate_pem(certificate: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", certificate))
}
pub async fn tls_config(certificate: Vec<u8>, private_key: Vec<u8>) -> Result<RustlsConfig> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    RustlsConfig::from_der(vec![certificate], private_key)
        .await
        .context("Invalid TLS certificate or private key")
}
pub fn local_address(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}
pub fn app(state: AppState, port: u16, origins: &[String]) -> Result<Router> {
    ensure!(port != 0, "Port must not be zero");
    app_at(state, &format!("https://127.0.0.1:{port}"), origins)
}
pub fn app_at(state: AppState, public_url: &str, origins: &[String]) -> Result<Router> {
    let public = url::Url::parse(public_url).context("Invalid public HTTPS URL")?;
    ensure!(
        public.scheme() == "https"
            && public.host_str().is_some()
            && public.username().is_empty()
            && public.password().is_none()
            && public.path() == "/"
            && public.query().is_none()
            && public.fragment().is_none(),
        "Public URL must be an HTTPS origin without paths or credentials"
    );
    let authority = public
        .origin()
        .ascii_serialization()
        .trim_start_matches("https://")
        .to_owned();
    let mut hosts = vec![authority];
    let mut own_origins = vec![public.origin().ascii_serialization()];
    if public.host_str() == Some("127.0.0.1") {
        let authority = format!(
            "localhost:{}",
            public.port_or_known_default().unwrap_or(443)
        );
        hosts.push(authority.clone());
        own_origins.push(format!("https://{authority}"));
    }
    let mut allowed = vec![];
    for value in origins {
        let url = url::Url::parse(value).context("Invalid allowed origin")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "Allowed origins must be exact HTTPS origins without paths or credentials"
        );
        allowed.push(url.origin().ascii_serialization());
    }
    ensure!(
        allowed.len() <= 16,
        "At most 16 allowed browser origins are supported"
    );
    let cors = CorsLayer::new()
        .allow_origin(
            allowed
                .iter()
                .map(|origin| origin.parse::<HeaderValue>())
                .collect::<std::result::Result<Vec<_>, _>>()?,
        )
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    let policy = Arc::new(Policy {
        hosts,
        own_origins,
        origins: allowed,
        state: state.clone(),
    });
    Ok(api::router(state)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(cors)
        .layer(middleware::from_fn_with_state(policy, boundary)))
}
async fn boundary(State(policy): State<Arc<Policy>>, mut request: Request, next: Next) -> Response {
    let response = async {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .or_else(|| {
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str())
            })
            .unwrap_or("");
        if !policy.hosts.iter().any(|allowed| allowed == host) {
            return ApiError(
                axum::http::StatusCode::BAD_REQUEST,
                "invalid_host",
                "Use the configured localhost HTTPS address",
            )
            .into_response();
        }
        if let Some(origin) = request.headers().get(header::ORIGIN) {
            if !origin.to_str().is_ok_and(|origin| {
                policy
                    .own_origins
                    .iter()
                    .chain(policy.origins.iter())
                    .any(|allowed| allowed == origin)
            }) {
                return ApiError(
                    axum::http::StatusCode::FORBIDDEN,
                    "origin_not_allowed",
                    "Browser origin is not allowed",
                )
                .into_response();
            }
        }
        let peer = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|peer| peer.0.ip())
            .unwrap_or_else(|| Ipv4Addr::LOCALHOST.into());
        request.extensions_mut().insert(ClientAddress(peer));
        let Ok(_permit) = policy.state.requests.clone().try_acquire_owned() else {
            return ApiError(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "Service is busy. Retry shortly.",
            )
            .into_response();
        };
        match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await {
            Ok(response) => response,
            Err(_) => ApiError(
                axum::http::StatusCode::GATEWAY_TIMEOUT,
                "timeout",
                "Request timed out. Check service state before retrying a change.",
            )
            .into_response(),
        }
    }
    .await;
    harden(response)
}
fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
    ] { headers.insert(axum::http::HeaderName::from_static(name), HeaderValue::from_static(value)); }
    response
}
