use crate::{
    api::{self, ApiError},
    auth::{self, AppState, Identity},
    database,
    domain::*,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Extension, Json, Router,
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use utoipa::OpenApi;
use uuid::Uuid;
mod policy;
mod requests;

pub(crate) use policy::begin;
use policy::{
    bad, conflict, db, forbidden, missing, org_admin, org_role, server_admin, workspace_access,
};
pub use requests::*;

#[utoipa::path(get, path="/api/v1/users", tag="Users", security(("bearer_auth"=[])), responses((status=200, body=[UserView]), (status=403, body=api::ErrorBody)))]
async fn users(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
) -> Result<Json<Vec<UserView>>, ApiError> {
    server_admin(&actor)?;
    let rows = sqlx::query(
        "SELECT id, username, server_admin, disabled FROM elo_users ORDER BY username LIMIT 501",
    )
    .fetch_all(&state.database.pool)
    .await
    .map_err(db)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| UserView {
                id: row.get("id"),
                username: row.get("username"),
                server_admin: row.get("server_admin"),
                disabled: row.get("disabled"),
            })
            .collect(),
    ))
}
#[utoipa::path(post, path="/api/v1/users", tag="Users", request_body=CreateUser, security(("bearer_auth"=[])), responses((status=201, body=UserView), (status=403, body=api::ErrorBody), (status=409, body=api::ErrorBody)))]
async fn create_user(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Json(body): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserView>), ApiError> {
    crate::storage::username_policy(&body.username).map_err(|_| bad())?;
    crate::storage::password_policy(&body.password).map_err(|_| bad())?;
    if !actor.server_admin && (body.server_admin || body.organization_id.is_none()) {
        return Err(forbidden());
    }
    {
        let mut connection = state.database.pool.acquire().await.map_err(db)?;
        if let Some(org) = body.organization_id {
            org_admin(&mut connection, &actor, org).await?;
        }
    }
    let permit = state
        .password_work
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "busy",
                "Password service is busy",
            )
        })?;
    let secret = zeroize::Zeroizing::new(body.password.clone());
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        auth::hash_password(&secret)
    })
    .await
    .map_err(|_| api::unavailable())?
    .map_err(|_| bad())?;
    let mut tx = begin(&state, &actor).await?;
    if let Some(org) = body.organization_id {
        org_admin(&mut tx, &actor, org).await?;
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM elo_users")
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    if count >= 500 {
        return Err(conflict());
    }
    let id = Uuid::new_v4();
    let credential = state
        .database
        .cipher
        .seal(&format!("user:{id}:credential"), &hash)
        .map_err(|_| api::unavailable())?;
    sqlx::query(
        "INSERT INTO elo_users (id, username, credential, server_admin) VALUES ($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(&body.username)
    .bind(credential)
    .bind(body.server_admin)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    if let Some(org) = body.organization_id {
        let role = body.role.as_ref().unwrap_or(&Role::Member).as_str();
        sqlx::query("INSERT INTO elo_memberships (organization_id,user_id,role) VALUES ($1,$2,$3)")
            .bind(org)
            .bind(id)
            .bind(role)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
    }
    tx.commit().await.map_err(db)?;
    Ok((
        StatusCode::CREATED,
        Json(UserView {
            id,
            username: body.username.clone(),
            server_admin: body.server_admin,
            disabled: false,
        }),
    ))
}
#[utoipa::path(put, path="/api/v1/users/{id}", tag="Users", request_body=UpdateUser, params(("id"=Uuid,Path)), security(("bearer_auth"=[])), responses((status=204), (status=403, body=api::ErrorBody), (status=409, body=api::ErrorBody)))]
async fn update_user(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUser>,
) -> Result<StatusCode, ApiError> {
    server_admin(&actor)?;
    let new_hash = if let Some(secret) = &body.password {
        crate::storage::password_policy(secret).map_err(|_| bad())?;
        let secret = zeroize::Zeroizing::new(secret.clone());
        let permit = state
            .password_work
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ApiError(
                    StatusCode::TOO_MANY_REQUESTS,
                    "busy",
                    "Password service is busy",
                )
            })?;
        Some(
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                auth::hash_password(&secret)
            })
            .await
            .map_err(|_| api::unavailable())?
            .map_err(|_| bad())?,
        )
    } else {
        None
    };
    let mut tx = begin(&state, &actor).await?;
    let (target, _) = database::user_on(&mut tx, id)
        .await
        .map_err(|_| api::unavailable())?
        .ok_or_else(missing)?;
    if target.server_admin && !target.disabled && (!body.server_admin || body.disabled) {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM elo_users WHERE server_admin AND NOT disabled",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if count <= 1 {
            return Err(conflict());
        }
    }
    let encrypted = new_hash
        .map(|hash| {
            state
                .database
                .cipher
                .seal(&format!("user:{id}:credential"), &hash)
        })
        .transpose()
        .map_err(|_| api::unavailable())?;
    sqlx::query("UPDATE elo_users SET disabled=$1, server_admin=$2, credential=COALESCE($3,credential), generation=generation+1 WHERE id=$4")
        .bind(body.disabled).bind(body.server_admin).bind(encrypted).bind(id).execute(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(get, path="/api/v1/organizations", tag="Organizations", security(("bearer_auth"=[])), responses((status=200, body=[Organization])))]
async fn organizations(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
) -> Result<Json<Vec<Organization>>, ApiError> {
    let rows = sqlx::query("SELECT o.id,o.name,m.role FROM elo_organizations o LEFT JOIN elo_memberships m ON m.organization_id=o.id AND m.user_id=$1 WHERE $2 OR m.user_id IS NOT NULL ORDER BY o.id LIMIT 101")
        .bind(actor.user_id).bind(actor.server_admin).fetch_all(&state.database.pool).await.map_err(db)?;
    let result = rows
        .into_iter()
        .map(|row| {
            let id: Uuid = row.get("id");
            Ok(Organization {
                id,
                name: state
                    .database
                    .cipher
                    .open(&format!("org:{id}:name"), row.get::<&[u8], _>("name"))
                    .map_err(|_| api::unavailable())?,
                role: if actor.server_admin {
                    "server_admin".into()
                } else {
                    row.get("role")
                },
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(result))
}
#[utoipa::path(post, path="/api/v1/organizations", tag="Organizations", request_body=NameInput, security(("bearer_auth"=[])), responses((status=201, body=Organization), (status=403, body=api::ErrorBody)))]
async fn create_org(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Json(body): Json<NameInput>,
) -> Result<(StatusCode, Json<Organization>), ApiError> {
    server_admin(&actor)?;
    valid_name(&body.name).map_err(|_| bad())?;
    let mut tx = begin(&state, &actor).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM elo_organizations")
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    if count >= 100 {
        return Err(conflict());
    }
    let id = Uuid::new_v4();
    let name = state
        .database
        .cipher
        .seal(&format!("org:{id}:name"), &body.name)
        .map_err(|_| api::unavailable())?;
    sqlx::query("INSERT INTO elo_organizations(id,name) VALUES($1,$2)")
        .bind(id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query("INSERT INTO elo_memberships(organization_id,user_id,role) VALUES($1,$2,'organization_admin')").bind(id).bind(actor.user_id).execute(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok((
        StatusCode::CREATED,
        Json(Organization {
            id,
            name: body.name,
            role: "server_admin".into(),
        }),
    ))
}
#[utoipa::path(put, path="/api/v1/organizations/{org}", tag="Organizations", request_body=NameInput, params(("org"=Uuid,Path)), security(("bearer_auth"=[])), responses((status=204)))]
async fn rename_org(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path(org): Path<Uuid>,
    Json(body): Json<NameInput>,
) -> Result<StatusCode, ApiError> {
    valid_name(&body.name).map_err(|_| bad())?;
    let mut tx = begin(&state, &actor).await?;
    org_admin(&mut tx, &actor, org).await?;
    let name = state
        .database
        .cipher
        .seal(&format!("org:{org}:name"), &body.name)
        .map_err(|_| api::unavailable())?;
    sqlx::query("UPDATE elo_organizations SET name=$1 WHERE id=$2")
        .bind(name)
        .bind(org)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(delete, path="/api/v1/organizations/{org}", tag="Organizations", params(("org"=Uuid,Path)), security(("bearer_auth"=[])), responses((status=204)))]
async fn delete_org(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path(org): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    server_admin(&actor)?;
    let mut tx = begin(&state, &actor).await?;
    if sqlx::query("DELETE FROM elo_organizations WHERE id=$1")
        .bind(org)
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected()
        == 0
    {
        return Err(missing());
    }
    tx.commit().await.map_err(db)?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(get, path="/api/v1/organizations/{org}/members", tag="Memberships", params(("org"=Uuid,Path)), security(("bearer_auth"=[])), responses((status=200,body=[Membership])))]
async fn members(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path(org): Path<Uuid>,
) -> Result<Json<Vec<Membership>>, ApiError> {
    let mut connection = state.database.pool.acquire().await.map_err(db)?;
    org_admin(&mut connection, &actor, org).await?;
    let rows=sqlx::query("SELECT u.id,u.username,u.disabled,m.role FROM elo_memberships m JOIN elo_users u ON u.id=m.user_id WHERE m.organization_id=$1 ORDER BY u.username").bind(org).fetch_all(&mut *connection).await.map_err(db)?;
    Ok(Json(
        rows.into_iter()
            .map(|r| {
                Ok(Membership {
                    user_id: r.get("id"),
                    username: r.get("username"),
                    disabled: r.get("disabled"),
                    role: Role::parse(r.get("role")).map_err(|_| api::unavailable())?,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
    ))
}
async fn protect_last_admin(
    connection: &mut PgConnection,
    org: Uuid,
    user: Uuid,
    next: Option<&Role>,
) -> Result<(), ApiError> {
    let current: Option<String> = sqlx::query_scalar(
        "SELECT role FROM elo_memberships WHERE organization_id=$1 AND user_id=$2",
    )
    .bind(org)
    .bind(user)
    .fetch_optional(&mut *connection)
    .await
    .map_err(db)?;
    if current.as_deref() == Some("organization_admin")
        && next.is_none_or(|role| !matches!(role, Role::OrganizationAdmin))
    {
        let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM elo_memberships WHERE organization_id=$1 AND role='organization_admin'").bind(org).fetch_one(connection).await.map_err(db)?;
        if count <= 1 {
            return Err(conflict());
        }
    }
    Ok(())
}
#[utoipa::path(put,path="/api/v1/organizations/{org}/members/{user}",tag="Memberships",params(("org"=Uuid,Path),("user"=Uuid,Path)),request_body=MembershipInput,security(("bearer_auth"=[])),responses((status=204)))]
async fn set_member(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path((org, user)): Path<(Uuid, Uuid)>,
    Json(body): Json<MembershipInput>,
) -> Result<StatusCode, ApiError> {
    let mut tx = begin(&state, &actor).await?;
    org_admin(&mut tx, &actor, org).await?;
    protect_last_admin(&mut tx, org, user, Some(&body.role)).await?;
    sqlx::query("INSERT INTO elo_memberships(organization_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO UPDATE SET role=EXCLUDED.role")
        .bind(org).bind(user).bind(body.role.as_str()).execute(&mut *tx).await.map_err(db)?;
    if !matches!(body.role, Role::Manager) {
        sqlx::query("UPDATE elo_workspace_access SET can_manage=FALSE WHERE organization_id=$1 AND user_id=$2").bind(org).bind(user).execute(&mut *tx).await.map_err(db)?;
    }
    tx.commit().await.map_err(db)?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(delete,path="/api/v1/organizations/{org}/members/{user}",tag="Memberships",params(("org"=Uuid,Path),("user"=Uuid,Path)),security(("bearer_auth"=[])),responses((status=204)))]
async fn remove_member(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path((org, user)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let mut tx = begin(&state, &actor).await?;
    org_admin(&mut tx, &actor, org).await?;
    protect_last_admin(&mut tx, org, user, None).await?;
    sqlx::query("DELETE FROM elo_memberships WHERE organization_id=$1 AND user_id=$2")
        .bind(org)
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn load_workspace(
    state: &AppState,
    connection: &mut PgConnection,
    actor: &Identity,
    org: Uuid,
    id: Uuid,
) -> Result<Workspace, ApiError> {
    workspace_access(connection, actor, org, id, false).await?;
    let row = sqlx::query(
        "SELECT document,revision FROM elo_workspaces WHERE id=$1 AND organization_id=$2",
    )
    .bind(id)
    .bind(org)
    .fetch_optional(&mut *connection)
    .await
    .map_err(db)?
    .ok_or_else(missing)?;
    let role = org_role(connection, actor, org).await?;
    let can_manage = if matches!(role.as_str(), "server_admin" | "organization_admin") {
        true
    } else if role == "manager" {
        sqlx::query_scalar::<_, bool>(
            "SELECT can_manage FROM elo_workspace_access WHERE workspace_id=$1 AND user_id=$2",
        )
        .bind(id)
        .bind(actor.user_id)
        .fetch_optional(connection)
        .await
        .map_err(db)?
        .unwrap_or(false)
    } else {
        false
    };
    Ok(Workspace {
        id,
        organization_id: org,
        revision: row.get("revision"),
        can_manage,
        document: state
            .database
            .cipher
            .open(
                &format!("workspace:{org}:{id}"),
                row.get::<&[u8], _>("document"),
            )
            .map_err(|_| api::unavailable())?,
    })
}
async fn workspace_limits(
    state: &AppState,
    connection: &mut PgConnection,
    org: Uuid,
    replacing: Option<Uuid>,
    document: &WorkspaceDocument,
) -> Result<(), ApiError> {
    let rows = sqlx::query("SELECT id,document FROM elo_workspaces WHERE organization_id=$1")
        .bind(org)
        .fetch_all(connection)
        .await
        .map_err(db)?;
    let mut categories = document.categories.len();
    let mut channels = document.channels.len();
    if replacing.is_none() && rows.len() >= 20 {
        return Err(conflict());
    }
    for row in rows {
        let id: Uuid = row.get("id");
        if replacing == Some(id) {
            continue;
        }
        let other: WorkspaceDocument = state
            .database
            .cipher
            .open(
                &format!("workspace:{org}:{id}"),
                row.get::<&[u8], _>("document"),
            )
            .map_err(|_| api::unavailable())?;
        categories += other.categories.len();
        channels += other.channels.len();
    }
    if categories > 40 || channels > 20 {
        return Err(conflict());
    }
    Ok(())
}
async fn index_channels(
    connection: &mut PgConnection,
    id: Uuid,
    document: &WorkspaceDocument,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM elo_channel_ids WHERE workspace_id=$1")
        .bind(id)
        .execute(&mut *connection)
        .await
        .map_err(db)?;
    for channel in &document.channels {
        sqlx::query("INSERT INTO elo_channel_ids(id,workspace_id) VALUES($1,$2)")
            .bind(channel.id)
            .bind(id)
            .execute(&mut *connection)
            .await
            .map_err(db)?;
    }
    Ok(())
}
#[utoipa::path(post,path="/api/v1/organizations/{org}/workspaces",tag="Workspaces",params(("org"=Uuid,Path)),request_body=WorkspaceInput,security(("bearer_auth"=[])),responses((status=201,body=Workspace)))]
async fn create_workspace(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path(org): Path<Uuid>,
    Json(body): Json<WorkspaceInput>,
) -> Result<(StatusCode, Json<Workspace>), ApiError> {
    body.document.validate().map_err(|_| bad())?;
    let mut tx = begin(&state, &actor).await?;
    org_admin(&mut tx, &actor, org).await?;
    workspace_limits(&state, &mut tx, org, None, &body.document).await?;
    let id = Uuid::new_v4();
    let data = state
        .database
        .cipher
        .seal(&format!("workspace:{org}:{id}"), &body.document)
        .map_err(|_| api::unavailable())?;
    sqlx::query("INSERT INTO elo_workspaces(id,organization_id,document) VALUES($1,$2,$3)")
        .bind(id)
        .bind(org)
        .bind(data)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    index_channels(&mut tx, id, &body.document).await?;
    tx.commit().await.map_err(db)?;
    Ok((
        StatusCode::CREATED,
        Json(Workspace {
            id,
            organization_id: org,
            revision: 1,
            can_manage: true,
            document: body.document,
        }),
    ))
}
#[utoipa::path(get,path="/api/v1/organizations/{org}/workspaces/{id}",tag="Workspaces",params(("org"=Uuid,Path),("id"=Uuid,Path)),security(("bearer_auth"=[])),responses((status=200,body=Workspace)))]
async fn get_workspace(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path((org, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Workspace>, ApiError> {
    let mut connection = state.database.pool.acquire().await.map_err(db)?;
    Ok(Json(
        load_workspace(&state, &mut connection, &actor, org, id).await?,
    ))
}
#[utoipa::path(put,path="/api/v1/organizations/{org}/workspaces/{id}",tag="Workspaces",params(("org"=Uuid,Path),("id"=Uuid,Path)),request_body=WorkspaceInput,security(("bearer_auth"=[])),responses((status=200,body=Workspace),(status=409,body=api::ErrorBody)))]
async fn update_workspace(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path((org, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<WorkspaceInput>,
) -> Result<Json<Workspace>, ApiError> {
    body.document.validate().map_err(|_| bad())?;
    let revision = body
        .revision
        .filter(|revision| *revision > 0)
        .ok_or_else(bad)?;
    let mut tx = begin(&state, &actor).await?;
    workspace_access(&mut tx, &actor, org, id, true).await?;
    workspace_limits(&state, &mut tx, org, Some(id), &body.document).await?;
    let data = state
        .database
        .cipher
        .seal(&format!("workspace:{org}:{id}"), &body.document)
        .map_err(|_| api::unavailable())?;
    if sqlx::query("UPDATE elo_workspaces SET document=$1,revision=revision+1 WHERE id=$2 AND organization_id=$3 AND revision=$4").bind(data).bind(id).bind(org).bind(revision).execute(&mut *tx).await.map_err(db)?.rows_affected()!=1{return Err(conflict());}
    index_channels(&mut tx, id, &body.document).await?;
    tx.commit().await.map_err(db)?;
    Ok(Json(Workspace {
        id,
        organization_id: org,
        revision: revision + 1,
        can_manage: true,
        document: body.document,
    }))
}
#[utoipa::path(delete,path="/api/v1/organizations/{org}/workspaces/{id}",tag="Workspaces",params(("org"=Uuid,Path),("id"=Uuid,Path)),security(("bearer_auth"=[])),responses((status=204)))]
async fn delete_workspace(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path((org, id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let mut tx = begin(&state, &actor).await?;
    org_admin(&mut tx, &actor, org).await?;
    if sqlx::query("DELETE FROM elo_workspaces WHERE id=$1 AND organization_id=$2")
        .bind(id)
        .bind(org)
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected()
        == 0
    {
        return Err(missing());
    }
    tx.commit().await.map_err(db)?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(get,path="/api/v1/organizations/{org}/workspaces/{id}/access",tag="Access",params(("org"=Uuid,Path),("id"=Uuid,Path)),security(("bearer_auth"=[])),responses((status=200,body=[WorkspaceGrant])))]
async fn grants(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path((org, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<WorkspaceGrant>>, ApiError> {
    let mut connection = state.database.pool.acquire().await.map_err(db)?;
    org_admin(&mut connection, &actor, org).await?;
    load_workspace(&state, &mut connection, &actor, org, id).await?;
    let rows=sqlx::query("SELECT a.user_id,u.username,a.can_manage FROM elo_workspace_access a JOIN elo_users u ON u.id=a.user_id WHERE a.workspace_id=$1 AND a.organization_id=$2 ORDER BY u.username").bind(id).bind(org).fetch_all(&mut *connection).await.map_err(db)?;
    Ok(Json(
        rows.into_iter()
            .map(|r| WorkspaceGrant {
                user_id: r.get("user_id"),
                username: r.get("username"),
                can_manage: r.get("can_manage"),
            })
            .collect(),
    ))
}
#[utoipa::path(put,path="/api/v1/organizations/{org}/workspaces/{id}/access/{user}",tag="Access",params(("org"=Uuid,Path),("id"=Uuid,Path),("user"=Uuid,Path)),request_body=GrantInput,security(("bearer_auth"=[])),responses((status=204)))]
async fn set_grant(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path((org, id, user)): Path<(Uuid, Uuid, Uuid)>,
    Json(body): Json<GrantInput>,
) -> Result<StatusCode, ApiError> {
    let mut tx = begin(&state, &actor).await?;
    org_admin(&mut tx, &actor, org).await?;
    load_workspace(&state, &mut tx, &actor, org, id).await?;
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM elo_memberships WHERE organization_id=$1 AND user_id=$2",
    )
    .bind(org)
    .bind(user)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    if role.is_none() || body.can_manage && role.as_deref() != Some("manager") {
        return Err(bad());
    }
    sqlx::query("INSERT INTO elo_workspace_access(organization_id,workspace_id,user_id,can_manage) VALUES($1,$2,$3,$4) ON CONFLICT(workspace_id,user_id) DO UPDATE SET can_manage=EXCLUDED.can_manage").bind(org).bind(id).bind(user).bind(body.can_manage).execute(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(delete,path="/api/v1/organizations/{org}/workspaces/{id}/access/{user}",tag="Access",params(("org"=Uuid,Path),("id"=Uuid,Path),("user"=Uuid,Path)),security(("bearer_auth"=[])),responses((status=204)))]
async fn remove_grant(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Path((org, id, user)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let mut tx = begin(&state, &actor).await?;
    org_admin(&mut tx, &actor, org).await?;
    sqlx::query("DELETE FROM elo_workspace_access WHERE organization_id=$1 AND workspace_id=$2 AND user_id=$3").bind(org).bind(id).bind(user).execute(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(StatusCode::NO_CONTENT)
}
#[utoipa::path(get,path="/api/v1/sync",tag="Synchronization",params(("organization_id"=Uuid,Query)),security(("bearer_auth"=[])),responses((status=200,body=Snapshot),(status=304),(status=404,body=api::ErrorBody)))]
async fn sync(
    State(state): State<AppState>,
    Extension(actor): Extension<Identity>,
    Query(query): Query<SyncQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let mut tx = state.database.pool.begin().await.map_err(db)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let org = query.organization_id;
    let role = org_role(&mut tx, &actor, org).await?;
    let name: Vec<u8> = sqlx::query_scalar("SELECT name FROM elo_organizations WHERE id=$1")
        .bind(org)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    let organization = Organization {
        id: org,
        name: state
            .database
            .cipher
            .open(&format!("org:{org}:name"), &name)
            .map_err(|_| api::unavailable())?,
        role: role.clone(),
    };
    let administrator = matches!(role.as_str(), "server_admin" | "organization_admin");
    let rows = sqlx::query("SELECT w.id,w.document,w.revision,a.can_manage FROM elo_workspaces w LEFT JOIN elo_workspace_access a ON a.workspace_id=w.id AND a.user_id=$3 WHERE w.organization_id=$1 AND ($2 OR a.user_id IS NOT NULL) ORDER BY w.id")
        .bind(org).bind(administrator).bind(actor.user_id).fetch_all(&mut *tx).await.map_err(db)?;
    let workspaces = rows
        .into_iter()
        .map(|row| {
            let id: Uuid = row.get("id");
            Ok(Workspace {
                id,
                organization_id: org,
                revision: row.get("revision"),
                can_manage: administrator
                    || role == "manager"
                        && row.get::<Option<bool>, _>("can_manage").unwrap_or(false),
                document: state
                    .database
                    .cipher
                    .open(
                        &format!("workspace:{org}:{id}"),
                        row.get::<&[u8], _>("document"),
                    )
                    .map_err(|_| api::unavailable())?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    tx.commit().await.map_err(db)?;
    let snapshot = Snapshot {
        organization,
        workspaces,
    };
    let bytes = serde_json::to_vec(&snapshot).map_err(|_| api::unavailable())?;
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(&bytes)));
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok())
        == Some(&etag)
    {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::ETAG, etag),
        ],
        bytes,
    )
        .into_response())
}
#[derive(OpenApi)]
#[openapi(
    paths(
        users,
        create_user,
        update_user,
        organizations,
        create_org,
        rename_org,
        delete_org,
        members,
        set_member,
        remove_member,
        create_workspace,
        get_workspace,
        update_workspace,
        delete_workspace,
        grants,
        set_grant,
        remove_grant,
        sync
    ),
    components(schemas(
        UserView,
        Role,
        Organization,
        Membership,
        Category,
        Channel,
        WorkspaceDocument,
        Workspace,
        Snapshot,
        WorkspaceGrant,
        NameInput,
        CreateUser,
        UpdateUser,
        MembershipInput,
        GrantInput,
        WorkspaceInput
    ))
)]
pub struct ManagementDoc;
pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/users", get(users).post(create_user))
        .route("/api/v1/users/{id}", put(update_user))
        .route("/api/v1/organizations", get(organizations).post(create_org))
        .route(
            "/api/v1/organizations/{org}",
            put(rename_org).delete(delete_org),
        )
        .route("/api/v1/organizations/{org}/members", get(members))
        .route(
            "/api/v1/organizations/{org}/members/{user}",
            put(set_member).delete(remove_member),
        )
        .route(
            "/api/v1/organizations/{org}/workspaces",
            post(create_workspace),
        )
        .route(
            "/api/v1/organizations/{org}/workspaces/{id}",
            get(get_workspace)
                .put(update_workspace)
                .delete(delete_workspace),
        )
        .route(
            "/api/v1/organizations/{org}/workspaces/{id}/access",
            get(grants),
        )
        .route(
            "/api/v1/organizations/{org}/workspaces/{id}/access/{user}",
            put(set_grant).delete(remove_grant),
        )
        .route("/api/v1/sync", get(sync))
        .route_layer(middleware::from_fn_with_state(state, api::authenticate))
}
