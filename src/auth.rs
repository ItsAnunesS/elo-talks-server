use crate::storage::{self, Store};
use anyhow::{anyhow, Result};
use argon2::{password_hash::SaltString, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex, Semaphore},
    time::{Duration, Instant},
};
use utoipa::ToSchema;
use zeroize::Zeroizing;

pub const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
pub const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
const MAX_SESSIONS: usize = 32;
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_ATTEMPTS: usize = 5;

#[derive(Clone)]
pub struct AppState {
    pub remote_enabled: bool,
    pub database: crate::database::Database,
    pub(crate) core: Arc<Mutex<Core>>,
    pub(crate) password_work: Arc<Semaphore>,
    pub(crate) requests: Arc<Semaphore>,
}
pub(crate) struct Core {
    pub store: Store,
    pub sessions: HashMap<[u8; 32], Session>,
    pub available: bool,
    attempts: VecDeque<Instant>,
    subjects: HashMap<String, VecDeque<Instant>>,
}
pub(crate) struct Session {
    pub id: String,
    pub user_id: uuid::Uuid,
    pub generation: i64,
    pub created_at: u64,
    pub expires_at: u64,
    deadline: Instant,
    last_seen: Instant,
}
#[derive(Clone)]
pub(crate) struct Identity {
    pub digest: [u8; 32],
    pub user_id: uuid::Uuid,
    pub generation: i64,
    pub server_admin: bool,
    pub username: String,
    pub session_id: String,
}
#[derive(Serialize, ToSchema)]
pub struct SessionInfo {
    pub id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub current: bool,
}
impl AppState {
    pub fn new(store: Store, database: crate::database::Database) -> Self {
        Self {
            remote_enabled: false,
            database,
            core: Arc::new(Mutex::new(Core {
                store,
                sessions: HashMap::new(),
                available: true,
                attempts: VecDeque::new(),
                subjects: HashMap::new(),
            })),
            password_work: Arc::new(Semaphore::new(2)),
            requests: Arc::new(Semaphore::new(32)),
        }
    }
}
impl Core {
    pub fn allow_password_attempt(&mut self, username: &str, peer: std::net::IpAddr) -> bool {
        let now = Instant::now();
        self.attempts
            .retain(|at| now.duration_since(*at) < LOGIN_WINDOW);
        self.subjects.retain(|_, attempts| {
            attempts.retain(|at| now.duration_since(*at) < LOGIN_WINDOW);
            !attempts.is_empty()
        });
        if self.attempts.len() >= 60 || self.subjects.len() >= 4096 {
            return false;
        }
        let keys = [
            (format!("user:{username}"), LOGIN_ATTEMPTS),
            (format!("ip:{peer}"), 20),
        ];
        if keys.iter().any(|(key, limit)| {
            self.subjects
                .get(key)
                .is_some_and(|attempts| attempts.len() >= *limit)
        }) {
            return false;
        }
        self.attempts.push_back(now);
        for (key, _) in keys {
            self.subjects.entry(key).or_default().push_back(now);
        }
        true
    }
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, session| {
            now < session.deadline && now.duration_since(session.last_seen) < SESSION_IDLE
        });
    }
    pub fn issue_session(
        &mut self,
        user: &crate::domain::UserCredential,
    ) -> Option<(Zeroizing<String>, SessionInfo)> {
        self.prune();
        if self.sessions.len() >= 4096
            || self
                .sessions
                .values()
                .filter(|session| session.user_id == user.user.id)
                .count()
                >= MAX_SESSIONS
        {
            return None;
        }
        let token = random_hex(32);
        let id = random_hex(16).to_string();
        let now = Instant::now();
        let created_at = epoch_seconds();
        let expires_at = created_at + SESSION_LIFETIME.as_secs();
        self.sessions.insert(
            token_digest(&token)?,
            Session {
                id: id.clone(),
                user_id: user.user.id,
                generation: user.generation,
                created_at,
                expires_at,
                deadline: now + SESSION_LIFETIME,
                last_seen: now,
            },
        );
        Some((
            token,
            SessionInfo {
                id,
                created_at,
                expires_at,
                current: true,
            },
        ))
    }
    pub fn authenticate(&mut self, digest: [u8; 32]) -> Option<Identity> {
        self.prune();
        if !self.available {
            return None;
        }
        let session = self.sessions.get_mut(&digest)?;
        session.last_seen = Instant::now();
        Some(Identity {
            digest,
            user_id: session.user_id,
            generation: session.generation,
            server_admin: false,
            username: self.store.state.username.clone(),
            session_id: session.id.clone(),
        })
    }
}
fn random_hex(length: usize) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(vec![0; length]);
    OsRng.fill_bytes(&mut bytes);
    Zeroizing::new(hex::encode(&*bytes))
}
pub(crate) fn token_digest(token: &str) -> Option<[u8; 32]> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(Sha256::digest(token.as_bytes()).into())
}
fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn hash_password(password: &str) -> Result<String> {
    storage::password_policy(password)?;
    storage::kdf()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|hash| hash.to_string())
        .map_err(|_| anyhow!("Could not hash password"))
}
pub(crate) fn verify_password(password: &str, hash: &str) -> bool {
    if password.len() > 1024 {
        return false;
    }
    PasswordHash::new(hash).is_ok_and(|hash| {
        storage::kdf()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}
