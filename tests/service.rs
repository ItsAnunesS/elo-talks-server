use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
    Router,
};
use elo_talks_server::{
    api,
    auth::{self, AppState, SESSION_IDLE},
    database::Database,
    storage::{self, Store},
    transport,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::{fs, os::unix::fs::PermissionsExt, sync::OnceLock};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;
const PASSWORD: &str = "administrator login password";
const UNLOCK: &str = "server encryption test password";
struct Fixture {
    directory: TempDir,
    state: AppState,
    app: Router,
    url: String,
}
fn hash() -> String {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| auth::hash_password(PASSWORD).unwrap())
        .clone()
}
async fn fixture() -> Fixture {
    let base = std::env::var("ELO_TEST_DATABASE_URL")
        .expect("Set ELO_TEST_DATABASE_URL to an isolated disposable PostgreSQL database");
    let bootstrap = PgPool::connect(&base).await.unwrap();
    let schema = format!("elo_{}", Uuid::new_v4().simple());
    // The identifier is generated exclusively from a UUID, never from user input.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&bootstrap)
        .await
        .unwrap();
    bootstrap.close().await;
    let mut url = url::Url::parse(&base).unwrap();
    url.query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    let url = url.to_string();
    let directory = tempfile::tempdir().unwrap();
    let identity =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let store = Store::initialize(
        directory.path(),
        UNLOCK,
        storage::State {
            version: 1,
            username: "admin".into(),
            password_hash: hash(),
            certificate: identity.cert.der().to_vec(),
            private_key: identity.signing_key.serialize_der(),
        },
    )
    .unwrap();
    let database = Database::connect(&url, &store).await.unwrap();
    let state = AppState::new(store, database);
    let app = transport::app(state.clone(), 8443, &[]).unwrap();
    Fixture {
        directory,
        state,
        app,
        url,
    }
}
async fn response(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Value,
    etag: Option<&str>,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "127.0.0.1:8443")
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(etag) = etag {
        request = request.header("if-none-match", etag);
    }
    app.clone()
        .oneshot(
            request
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let response = response(app, method, path, token, body, None).await;
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| panic!("Non-JSON API error: {status}"))
        },
    )
}
async fn login_as(app: &Router, username: &str, password: &str) -> String {
    let (status, value) = call(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        json!({"username":username,"password":password}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    value["access_token"].as_str().unwrap().to_owned()
}
async fn root(f: &Fixture) -> String {
    login_as(&f.app, "admin", PASSWORD).await
}
async fn org(f: &Fixture, token: &str, name: &str) -> String {
    let (s, v) = call(
        &f.app,
        "POST",
        "/api/v1/organizations",
        Some(token),
        json!({"name":name}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    v["id"].as_str().unwrap().into()
}
async fn user(f: &Fixture, token: &str, username: &str, organization: &str, role: &str) -> String {
    let(s,v)=call(&f.app,"POST","/api/v1/users",Some(token),json!({"username":username,"password":PASSWORD,"organization_id":organization,"role":role,"server_admin":false})).await;
    assert_eq!(s, StatusCode::CREATED);
    v["id"].as_str().unwrap().into()
}
fn document(name: &str) -> Value {
    let category = Uuid::new_v4();
    json!({"name":name,"categories":[{"id":category,"name":"Support"}],"channels":[{"id":Uuid::new_v4(),"name":"Customer service","category_id":category}]})
}
async fn workspace(f: &Fixture, token: &str, org: &str, name: &str) -> Value {
    let (s, v) = call(
        &f.app,
        "POST",
        &format!("/api/v1/organizations/{org}/workspaces"),
        Some(token),
        json!({"revision":null,"document":document(name)}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    v
}
async fn grant(
    f: &Fixture,
    root: &str,
    org: &str,
    workspace: &str,
    user: &str,
    manage: bool,
) -> StatusCode {
    call(
        &f.app,
        "PUT",
        &format!("/api/v1/organizations/{org}/workspaces/{workspace}/access/{user}"),
        Some(root),
        json!({"can_manage":manage}),
    )
    .await
    .0
}
#[tokio::test]
async fn postgres_login_session_rotation_and_revocation() {
    let f = fixture().await;
    assert_eq!(
        call(&f.app, "GET", "/api/v1/auth/me", None, Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let unknown = call(
        &f.app,
        "POST",
        "/api/v1/auth/login",
        None,
        json!({"username":"unknown","password":PASSWORD}),
    )
    .await;
    let wrong = call(
        &f.app,
        "POST",
        "/api/v1/auth/login",
        None,
        json!({"username":"admin","password":"incorrect password"}),
    )
    .await;
    assert_eq!(unknown, wrong);
    let token = root(&f).await;
    let other = root(&f).await;
    let (s, sessions) = call(
        &f.app,
        "GET",
        "/api/v1/auth/sessions",
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(sessions.as_array().unwrap().len(), 2);
    assert!(!sessions.to_string().contains(&token));
    let id = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["current"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap();
    assert_eq!(
        call(
            &f.app,
            "DELETE",
            &format!("/api/v1/auth/sessions/{id}"),
            Some(&token),
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, "GET", "/api/v1/auth/me", Some(&other), Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/v1/auth/password",
            Some(&token),
            json!({"current_password":PASSWORD,"new_password":"replacement login password"})
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, "GET", "/api/v1/auth/me", Some(&token), Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let credential = f
        .state
        .database
        .credentials("admin")
        .await
        .unwrap()
        .unwrap();
    use argon2::PasswordVerifier;
    storage::kdf()
        .verify_password(
            b"replacement login password",
            &argon2::PasswordHash::new(&credential.hash).unwrap(),
        )
        .unwrap();
}
#[tokio::test]
async fn organization_and_workspace_isolation_is_enforced_in_the_api() {
    let f = fixture().await;
    let admin = root(&f).await;
    let a = org(&f, &admin, "Company A").await;
    let b = org(&f, &admin, "Company B").await;
    let member = user(&f, &admin, "member-a", &a, "member").await;
    let token = login_as(&f.app, "member-a", PASSWORD).await;
    let wa = workspace(&f, &admin, &a, "Confidential A").await;
    let wb = workspace(&f, &admin, &b, "Confidential B").await;
    let wa = wa["id"].as_str().unwrap();
    let wb = wb["id"].as_str().unwrap();
    let (s, orgs) = call(
        &f.app,
        "GET",
        "/api/v1/organizations",
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(orgs.as_array().unwrap().len(), 1);
    assert_eq!(orgs[0]["id"], a);
    assert_eq!(
        call(&f.app, "GET", "/api/v1/users", Some(&token), Value::Null)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &f.app,
            "GET",
            &format!("/api/v1/sync?organization_id={b}"),
            Some(&token),
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &f.app,
            "GET",
            &format!("/api/v1/organizations/{a}/workspaces/{wa}"),
            Some(&token),
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        grant(&f, &admin, &a, wa, &member, false).await,
        StatusCode::NO_CONTENT
    );
    let (_, snapshot) = call(
        &f.app,
        "GET",
        &format!("/api/v1/sync?organization_id={a}"),
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(snapshot["workspaces"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["workspaces"][0]["id"], wa);
    assert!(!snapshot.to_string().contains("Confidential B"));
    assert_eq!(
        call(
            &f.app,
            "GET",
            &format!("/api/v1/organizations/{a}/workspaces/{wb}"),
            Some(&token),
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        grant(&f, &admin, &a, wb, &member, false).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/v1/organizations/{a}/workspaces/{wa}"),
            Some(&token),
            json!({"revision":1,"document":document("Illegal")})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn managers_cannot_escalate_and_edit_only_explicitly_managed_workspaces() {
    let f = fixture().await;
    let admin = root(&f).await;
    let org = org(&f, &admin, "Team").await;
    let manager = user(&f, &admin, "manager", &org, "manager").await;
    let member = user(&f, &admin, "member", &org, "member").await;
    let workspace = workspace(&f, &admin, &org, "Operations").await;
    let id = workspace["id"].as_str().unwrap();
    let token = login_as(&f.app, "manager", PASSWORD).await;
    assert_eq!(
        grant(&f, &admin, &org, id, &manager, false).await,
        StatusCode::NO_CONTENT
    );
    let path = format!("/api/v1/organizations/{org}/workspaces/{id}");
    let body = json!({"revision":1,"document":document("Updated")});
    assert_eq!(
        call(&f.app, "PUT", &path, Some(&token), body.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        grant(&f, &admin, &org, id, &manager, true).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, "PUT", &path, Some(&token), body.clone())
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&f.app, "PUT", &path, Some(&token), body).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/v1/organizations/{org}/members/{manager}"),
            Some(&admin),
            json!({"role":"member"})
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/v1/organizations/{org}/members/{manager}"),
            Some(&admin),
            json!({"role":"manager"})
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &path,
            Some(&token),
            json!({"revision":2,"document":document("No privilege resurrection")})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        grant(&f, &token, &org, id, &member, false).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        grant(&f, &admin, &org, id, &member, true).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/v1/organizations/{org}/members/{manager}"),
            Some(&token),
            json!({"role":"organization_admin"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/v1/users",
            Some(&token),
            json!({"username":"rogue","password":PASSWORD,"server_admin":true})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn organization_admins_can_provision_members_but_not_server_admins_or_other_orgs() {
    let f = fixture().await;
    let root = root(&f).await;
    let a = org(&f, &root, "A").await;
    let b = org(&f, &root, "B").await;
    user(&f, &root, "owner", &a, "organization_admin").await;
    let token = login_as(&f.app, "owner", PASSWORD).await;
    user(&f, &token, "teammate", &a, "member").await;
    assert_eq!(call(&f.app,"POST","/api/v1/users",Some(&token),json!({"username":"rogue","password":PASSWORD,"server_admin":true,"organization_id":a,"role":"member"})).await.0,StatusCode::FORBIDDEN);
    assert_eq!(call(&f.app,"POST","/api/v1/users",Some(&token),json!({"username":"crossorg","password":PASSWORD,"server_admin":false,"organization_id":b,"role":"member"})).await.0,StatusCode::NOT_FOUND);
    assert_eq!(
        call(
            &f.app,
            "DELETE",
            &format!("/api/v1/organizations/{a}"),
            Some(&token),
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn access_revocation_changes_etag_and_removes_channels_from_sync() {
    let f = fixture().await;
    let admin = root(&f).await;
    let org = org(&f, &admin, "Team").await;
    let member = user(&f, &admin, "reader", &org, "member").await;
    let workspace = workspace(&f, &admin, &org, "Operations").await;
    let id = workspace["id"].as_str().unwrap();
    grant(&f, &admin, &org, id, &member, false).await;
    let token = login_as(&f.app, "reader", PASSWORD).await;
    let path = format!("/api/v1/sync?organization_id={org}");
    let initial = response(&f.app, "GET", &path, Some(&token), Value::Null, None).await;
    let etag = initial.headers()["etag"].to_str().unwrap().to_owned();
    assert_eq!(initial.status(), StatusCode::OK);
    assert_eq!(
        response(&f.app, "GET", &path, Some(&token), Value::Null, Some(&etag))
            .await
            .status(),
        StatusCode::NOT_MODIFIED
    );
    call(
        &f.app,
        "DELETE",
        &format!("/api/v1/organizations/{org}/workspaces/{id}/access/{member}"),
        Some(&admin),
        Value::Null,
    )
    .await;
    let changed = response(&f.app, "GET", &path, Some(&token), Value::Null, Some(&etag)).await;
    assert_eq!(changed.status(), StatusCode::OK);
    assert_ne!(changed.headers()["etag"], etag);
    let value: Value =
        serde_json::from_slice(&changed.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(value["workspaces"].as_array().unwrap().is_empty());
}
#[tokio::test]
async fn disabling_users_and_resetting_passwords_invalidates_existing_tokens() {
    let f = fixture().await;
    let admin = root(&f).await;
    let org = org(&f, &admin, "Team").await;
    let id = user(&f, &admin, "reader", &org, "member").await;
    let token = login_as(&f.app, "reader", PASSWORD).await;
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/v1/users/{id}"),
            Some(&admin),
            json!({"disabled":true,"server_admin":false,"password":null})
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f.app, "GET", "/api/v1/auth/me", Some(&token), Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/v1/auth/login",
            None,
            json!({"username":"reader","password":PASSWORD})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (_, me) = call(&f.app, "GET", "/api/v1/auth/me", Some(&admin), Value::Null).await;
    assert_eq!(
        call(
            &f.app,
            "PUT",
            &format!("/api/v1/users/{}", me["id"].as_str().unwrap()),
            Some(&admin),
            json!({"disabled":true,"server_admin":false,"password":null})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}
#[tokio::test]
async fn workspace_document_validation_and_last_org_admin_are_protected() {
    let f = fixture().await;
    let admin = root(&f).await;
    let org = org(&f, &admin, "Team").await;
    let (_, me) = call(&f.app, "GET", "/api/v1/auth/me", Some(&admin), Value::Null).await;
    assert_eq!(
        call(
            &f.app,
            "DELETE",
            &format!(
                "/api/v1/organizations/{org}/members/{}",
                me["id"].as_str().unwrap()
            ),
            Some(&admin),
            Value::Null
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let mut invalid = document("Bad");
    invalid["channels"][0]["category_id"] = json!(Uuid::new_v4());
    assert_eq!(
        call(
            &f.app,
            "POST",
            &format!("/api/v1/organizations/{org}/workspaces"),
            Some(&admin),
            json!({"document":invalid,"revision":null})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let original = workspace(&f, &admin, &org, "Original").await;
    assert_eq!(
        call(
            &f.app,
            "POST",
            &format!("/api/v1/organizations/{org}/workspaces"),
            Some(&admin),
            json!({"document":original["document"],"revision":null})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, snapshot) = call(
        &f.app,
        "GET",
        &format!("/api/v1/sync?organization_id={org}"),
        Some(&admin),
        Value::Null,
    )
    .await;
    assert_eq!(snapshot["workspaces"].as_array().unwrap().len(), 1);
}
#[tokio::test]
async fn database_records_are_encrypted_and_bound_to_their_row_identity() {
    let f = fixture().await;
    let token = root(&f).await;
    let org = org(&f, &token, "Secret organization marker").await;
    let workspace = workspace(&f, &token, &org, "Private workspace marker").await;
    let rows = sqlx::query("SELECT credential FROM elo_users")
        .fetch_all(&f.state.database.pool)
        .await
        .unwrap();
    for row in rows {
        let bytes: Vec<u8> = row.get("credential");
        assert!(!bytes.windows(8).any(|w| w == b"argon2id"));
    }
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT document FROM elo_workspaces WHERE id=$1")
        .bind(Uuid::parse_str(workspace["id"].as_str().unwrap()).unwrap())
        .fetch_one(&f.state.database.pool)
        .await
        .unwrap();
    assert!(!bytes.windows(7).any(|w| w == b"Private"));
    assert!(f
        .state
        .database
        .cipher
        .open::<Value>("workspace:wrong-row", &bytes)
        .is_err());
    let other = tempfile::tempdir().unwrap();
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let store = Store::initialize(
        other.path(),
        "different server encryption password",
        storage::State {
            version: 1,
            username: "other".into(),
            password_hash: hash(),
            certificate: identity.cert.der().to_vec(),
            private_key: identity.signing_key.serialize_der(),
        },
    )
    .unwrap();
    assert!(Database::connect(&f.url, &store).await.is_err());
}
#[tokio::test]
async fn swagger_panel_and_domain_boundaries_are_explicit() {
    let f = fixture().await;
    let (_, schema) = call(&f.app, "GET", "/api/v1/openapi.json", None, Value::Null).await;
    assert!(schema["paths"]["/api/v1/sync"]["get"]["security"].is_array());
    assert!(schema["paths"]["/api/v1/users"]["post"].is_object());
    assert_eq!(schema, serde_json::to_value(api::specification()).unwrap());
    for path in [
        "/",
        "/panel/app.js",
        "/panel/style.css",
        "/docs/",
        "/docs/swagger-initializer.js",
    ] {
        let request = Request::builder()
            .uri(path)
            .header("host", "localhost:8443")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            f.app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }
    let domain = transport::app_at(f.state.clone(), "https://panel.example.test", &[]).unwrap();
    for (host, origin, expected) in [
        (
            "panel.example.test",
            Some("https://panel.example.test"),
            StatusCode::OK,
        ),
        ("evil.example", None, StatusCode::BAD_REQUEST),
        (
            "panel.example.test",
            Some("https://evil.example"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut request = Request::builder().uri("/healthz").header("host", host);
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        assert_eq!(
            domain
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            expected
        );
    }
}
#[tokio::test]
async fn tls_rejects_untrusted_certificates_and_plaintext() {
    let f = fixture().await;
    let store = Store::open(f.directory.path(), UNLOCK).unwrap();
    let certificate = store.state.certificate.clone();
    let tls = transport::tls_config(certificate.clone(), store.state.private_key.clone())
        .await
        .unwrap();
    let listener = std::net::TcpListener::bind(transport::local_address(0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = transport::app(f.state.clone(), port, &[]).unwrap();
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    let running = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_der(&certificate).unwrap())
        .build()
        .unwrap();
    let url = format!("https://127.0.0.1:{port}/healthz");
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::OK
    );
    assert!(reqwest::get(url).await.is_err());
    assert!(client
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .await
        .is_err());
    shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(1)));
    running.await.unwrap();
}
#[tokio::test]
async fn sessions_are_private_expire_and_do_not_survive_restart() {
    let f = fixture().await;
    let admin = root(&f).await;
    let org = org(&f, &admin, "Team").await;
    user(&f, &admin, "reader", &org, "member").await;
    let token = login_as(&f.app, "reader", PASSWORD).await;
    let (_, sessions) = call(
        &f.app,
        "GET",
        "/api/v1/auth/sessions",
        Some(&token),
        Value::Null,
    )
    .await;
    assert_eq!(sessions.as_array().unwrap().len(), 1);
    let store = Store::open(f.directory.path(), UNLOCK).unwrap();
    let restarted =
        transport::app(AppState::new(store, f.state.database.clone()), 8443, &[]).unwrap();
    assert_eq!(
        call(
            &restarted,
            "GET",
            "/api/v1/auth/me",
            Some(&token),
            Value::Null
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    tokio::time::pause();
    tokio::time::advance(SESSION_IDLE).await;
    // Resume before PostgreSQL network I/O; the monotonic offset is preserved.
    tokio::time::resume();
    assert_eq!(
        call(&f.app, "GET", "/api/v1/auth/me", Some(&token), Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn database_failures_do_not_turn_into_local_authentication_fallback() {
    let f = fixture().await;
    let token = root(&f).await;
    f.state.database.pool.close().await;
    assert_eq!(
        call(&f.app, "GET", "/api/v1/auth/me", Some(&token), Value::Null)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/v1/auth/login",
            None,
            json!({"username":"admin","password":PASSWORD})
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[test]
fn private_file_and_record_limits_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret");
    fs::write(&path, b"private password file").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(storage::read_password_file(&path).is_ok());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(storage::read_password_file(&path).is_err());
    let guard = storage::lock_directory(dir.path()).unwrap();
    assert!(storage::lock_directory(dir.path()).is_err());
    drop(guard);
}
