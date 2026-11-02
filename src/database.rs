use crate::{
    domain::{UserCredential, UserView},
    storage::{RecordCipher, Store},
};
use anyhow::{anyhow, ensure, Context, Result};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
    ConnectOptions, PgConnection, PgPool, Row,
};
use std::{str::FromStr, sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
    pub cipher: Arc<RecordCipher>,
}
impl Database {
    pub async fn connect(url: &str, store: &Store) -> Result<Self> {
        url::Url::parse(url).map_err(|_| anyhow!("Invalid PostgreSQL connection URL"))?;
        let options = PgConnectOptions::from_str(url)
            .map_err(|_| anyhow!("Invalid PostgreSQL connection URL"))?;
        let local = matches!(options.get_host(), "localhost" | "127.0.0.1" | "::1")
            || options.get_host().starts_with('/');
        // TCP outside loopback always verifies both the certificate and hostname.
        let options = if local {
            options
        } else {
            options.ssl_mode(PgSslMode::VerifyFull)
        }
        .disable_statement_logging();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::raw_sql("SET statement_timeout = '10s'; SET lock_timeout = '5s'")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .map_err(|_| anyhow!("Could not connect securely to PostgreSQL"))?;
        Self::from_pool(pool, store).await
    }
    pub async fn from_pool(pool: PgPool, store: &Store) -> Result<Self> {
        let database = Self {
            pool,
            cipher: Arc::new(store.record_cipher()),
        };
        let mut tx = database.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(724109301)")
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
            .execute(&mut *tx)
            .await?;
        let existing = sqlx::query(
            "SELECT schema_version, key_check FROM elo_metadata WHERE singleton = TRUE",
        )
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = existing {
            ensure!(
                row.get::<i32, _>("schema_version") == 1,
                "Unsupported PostgreSQL schema version"
            );
            let value: String = database.cipher.open(
                "elo:database:key-check:v1",
                row.get::<&[u8], _>("key_check"),
            )?;
            ensure!(
                value == "elo-talks-postgres",
                "Database encryption identity mismatch"
            );
        } else {
            let check = database
                .cipher
                .seal("elo:database:key-check:v1", &"elo-talks-postgres")?;
            sqlx::query("INSERT INTO elo_metadata (singleton, schema_version, key_check) VALUES (TRUE, 1, $1)").bind(check).execute(&mut *tx).await?;
            let id = Uuid::new_v4();
            let credential = database
                .cipher
                .seal(&format!("user:{id}:credential"), &store.state.password_hash)?;
            sqlx::query("INSERT INTO elo_users (id, username, credential, server_admin) VALUES ($1, $2, $3, TRUE)")
                .bind(id).bind(&store.state.username).bind(credential).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(database)
    }
    pub async fn credentials(&self, username: &str) -> Result<Option<UserCredential>> {
        let row = sqlx::query("SELECT id, username, credential, generation, server_admin, disabled FROM elo_users WHERE username = $1")
            .bind(username).fetch_optional(&self.pool).await?;
        row.map(|row| {
            let id: Uuid = row.get("id");
            Ok(UserCredential {
                user: UserView {
                    id,
                    username: row.get("username"),
                    server_admin: row.get("server_admin"),
                    disabled: row.get("disabled"),
                },
                hash: Zeroizing::new(self.cipher.open(
                    &format!("user:{id}:credential"),
                    row.get::<&[u8], _>("credential"),
                )?),
                generation: row.get("generation"),
            })
        })
        .transpose()
    }
    pub async fn user(&self, id: Uuid) -> Result<Option<(UserView, i64)>> {
        let mut connection = self.pool.acquire().await?;
        user_on(&mut connection, id).await
    }
    pub async fn instance_lock(&self) -> Result<PgConnection> {
        let mut connection = self.pool.acquire().await?.detach();
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(724109303)")
            .fetch_one(&mut connection)
            .await?;
        ensure!(
            acquired,
            "Another service instance is already serving this PostgreSQL database"
        );
        Ok(connection)
    }
    pub async fn reset_admin(&self, username: &str, hash: &str) -> Result<()> {
        let user = self
            .credentials(username)
            .await?
            .context("Bootstrap administrator not found")?;
        ensure!(
            user.user.server_admin,
            "Bootstrap user is not a server administrator"
        );
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(724109302)")
            .execute(&mut *tx)
            .await?;
        let value = self
            .cipher
            .seal(&format!("user:{}:credential", user.user.id), &hash)?;
        sqlx::query("UPDATE elo_users SET credential = $1, generation = generation + 1, disabled = FALSE WHERE id = $2 AND server_admin")
            .bind(value).bind(user.user.id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
pub async fn user_on(connection: &mut PgConnection, id: Uuid) -> Result<Option<(UserView, i64)>> {
    Ok(sqlx::query(
        "SELECT id, username, server_admin, disabled, generation FROM elo_users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(connection)
    .await?
    .map(|row| {
        (
            UserView {
                id: row.get("id"),
                username: row.get("username"),
                server_admin: row.get("server_admin"),
                disabled: row.get("disabled"),
            },
            row.get("generation"),
        )
    }))
}
