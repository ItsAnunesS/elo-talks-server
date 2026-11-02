//! Authorization checks and serialized, revalidated write transactions.
use crate::{
    api::{self, ApiError},
    auth::{AppState, Identity},
    database,
};
use axum::http::StatusCode;
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

pub(super) fn bad() -> ApiError {
    ApiError(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Invalid name, identifiers, role or workspace limits",
    )
}
pub(super) fn forbidden() -> ApiError {
    ApiError(
        StatusCode::FORBIDDEN,
        "forbidden",
        "Your role does not permit this action",
    )
}
pub(super) fn missing() -> ApiError {
    ApiError(
        StatusCode::NOT_FOUND,
        "not_found",
        "Resource not found or not accessible",
    )
}
pub(super) fn conflict() -> ApiError {
    ApiError(
        StatusCode::CONFLICT,
        "conflict",
        "State changed, a limit was reached, or this action would remove the last administrator",
    )
}
pub(super) fn db(error: sqlx::Error) -> ApiError {
    if error
        .as_database_error()
        .is_some_and(|error| matches!(error.code().as_deref(), Some("23505" | "23503" | "23514")))
    {
        conflict()
    } else {
        api::unavailable()
    }
}
pub(crate) async fn begin<'a>(
    state: &'a AppState,
    actor: &Identity,
) -> Result<Transaction<'a, Postgres>, ApiError> {
    let mut tx = state.database.pool.begin().await.map_err(db)?;
    sqlx::query("SELECT pg_advisory_xact_lock(724109302)")
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let (user, generation) = database::user_on(&mut tx, actor.user_id)
        .await
        .map_err(|_| api::unavailable())?
        .ok_or_else(api::unauthorized)?;
    if user.disabled || generation != actor.generation || user.server_admin != actor.server_admin {
        return Err(api::unauthorized());
    }
    Ok(tx)
}
pub(super) async fn org_role(
    connection: &mut PgConnection,
    actor: &Identity,
    org: Uuid,
) -> Result<String, ApiError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM elo_organizations WHERE id = $1)")
            .bind(org)
            .fetch_one(&mut *connection)
            .await
            .map_err(db)?;
    if !exists {
        return Err(missing());
    }
    if actor.server_admin {
        return Ok("server_admin".into());
    }
    sqlx::query_scalar::<_, String>(
        "SELECT role FROM elo_memberships WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org)
    .bind(actor.user_id)
    .fetch_optional(connection)
    .await
    .map_err(db)?
    .ok_or_else(missing)
}
pub(super) async fn org_admin(
    connection: &mut PgConnection,
    actor: &Identity,
    org: Uuid,
) -> Result<(), ApiError> {
    if !matches!(
        org_role(connection, actor, org).await?.as_str(),
        "server_admin" | "organization_admin"
    ) {
        return Err(forbidden());
    }
    Ok(())
}
pub(super) async fn workspace_access(
    connection: &mut PgConnection,
    actor: &Identity,
    org: Uuid,
    workspace: Uuid,
    write: bool,
) -> Result<(), ApiError> {
    let role = org_role(connection, actor, org).await?;
    if matches!(role.as_str(), "server_admin" | "organization_admin") {
        return Ok(());
    }
    let manage = sqlx::query_scalar::<_, bool>("SELECT can_manage FROM elo_workspace_access WHERE organization_id = $1 AND workspace_id = $2 AND user_id = $3")
        .bind(org).bind(workspace).bind(actor.user_id).fetch_optional(connection).await.map_err(db)?.ok_or_else(missing)?;
    if write && (role != "manager" || !manage) {
        return Err(forbidden());
    }
    Ok(())
}
pub(super) fn server_admin(actor: &Identity) -> Result<(), ApiError> {
    if actor.server_admin {
        Ok(())
    } else {
        Err(forbidden())
    }
}
