//! Validated wire input shapes; password-bearing inputs clear secrets on drop.
use crate::domain::{Role, WorkspaceDocument};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NameInput {
    pub name: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    pub username: String,
    #[schema(format = Password, write_only)]
    pub password: String,
    #[serde(default)]
    pub server_admin: bool,
    pub organization_id: Option<Uuid>,
    pub role: Option<Role>,
}
impl Drop for CreateUser {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateUser {
    pub disabled: bool,
    pub server_admin: bool,
    #[schema(format = Password, write_only)]
    pub password: Option<String>,
}
impl Drop for UpdateUser {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MembershipInput {
    pub role: Role,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantInput {
    pub can_manage: bool,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceInput {
    pub revision: Option<i64>,
    pub document: WorkspaceDocument,
}
#[derive(Deserialize)]
pub struct SyncQuery {
    pub organization_id: Uuid,
}
