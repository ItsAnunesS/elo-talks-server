use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct UserView {
    pub id: Uuid,
    pub username: String,
    pub server_admin: bool,
    pub disabled: bool,
}
#[derive(Clone)]
pub struct UserCredential {
    pub user: UserView,
    pub hash: zeroize::Zeroizing<String>,
    pub generation: i64,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    OrganizationAdmin,
    Manager,
    Member,
}
impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OrganizationAdmin => "organization_admin",
            Self::Manager => "manager",
            Self::Member => "member",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "organization_admin" => Self::OrganizationAdmin,
            "manager" => Self::Manager,
            "member" => Self::Member,
            _ => anyhow::bail!("Invalid membership role"),
        })
    }
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub role: String,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct Membership {
    pub user_id: Uuid,
    pub username: String,
    pub role: Role,
    pub disabled: bool,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Category {
    pub id: Uuid,
    pub name: String,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    pub id: Uuid,
    pub name: String,
    pub category_id: Option<Uuid>,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceDocument {
    pub name: String,
    pub categories: Vec<Category>,
    pub channels: Vec<Channel>,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct Workspace {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub revision: i64,
    pub can_manage: bool,
    pub document: WorkspaceDocument,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkspaceGrant {
    pub user_id: Uuid,
    pub username: String,
    pub can_manage: bool,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct Snapshot {
    pub organization: Organization,
    pub workspaces: Vec<Workspace>,
}
pub fn valid_name(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty()
            && value.chars().count() <= 40
            && !value.chars().any(char::is_control),
        "Use a name of 1-40 printable characters"
    );
    Ok(())
}
impl WorkspaceDocument {
    pub fn validate(&self) -> Result<()> {
        valid_name(&self.name)?;
        ensure!(
            self.categories.len() <= 40 && self.channels.len() <= 20,
            "Workspace limits exceeded"
        );
        let mut ids = HashSet::new();
        for category in &self.categories {
            valid_name(&category.name)?;
            ensure!(ids.insert(category.id), "Duplicate category identifier");
        }
        let mut channels = HashSet::new();
        for channel in &self.channels {
            valid_name(&channel.name)?;
            ensure!(channels.insert(channel.id), "Duplicate channel identifier");
            ensure!(
                channel.category_id.is_none_or(|id| ids.contains(&id)),
                "Channel category does not belong to this workspace"
            );
        }
        Ok(())
    }
}
