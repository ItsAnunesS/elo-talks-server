CREATE TABLE IF NOT EXISTS elo_metadata (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    key_check BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS elo_users (
    id UUID PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    credential BYTEA NOT NULL,
    server_admin BOOLEAN NOT NULL DEFAULT FALSE,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    generation BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS elo_organizations (
    id UUID PRIMARY KEY,
    name BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS elo_memberships (
    organization_id UUID NOT NULL REFERENCES elo_organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES elo_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('organization_admin', 'manager', 'member')),
    PRIMARY KEY (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS elo_memberships_user ON elo_memberships(user_id);
CREATE TABLE IF NOT EXISTS elo_workspaces (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES elo_organizations(id) ON DELETE CASCADE,
    document BYTEA NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    UNIQUE (organization_id, id)
);
CREATE INDEX IF NOT EXISTS elo_workspaces_organization ON elo_workspaces(organization_id);
CREATE TABLE IF NOT EXISTS elo_workspace_access (
    organization_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    user_id UUID NOT NULL,
    can_manage BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (workspace_id, user_id),
    FOREIGN KEY (organization_id, workspace_id) REFERENCES elo_workspaces(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, user_id) REFERENCES elo_memberships(organization_id, user_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS elo_channel_ids (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES elo_workspaces(id) ON DELETE CASCADE
);
