use axum::{
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
pub fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../admin/index.html")) }),
        )
        .route(
            "/panel/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../admin/app.js"),
                )
            }),
        )
        .route(
            "/panel/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../admin/style.css"),
                )
            }),
        )
        .route(
            "/favicon.ico",
            get(|| async { StatusCode::NO_CONTENT.into_response() }),
        )
}
