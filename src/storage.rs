//! Encrypted single-administrator state. No browser profiles are stored here.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, ensure, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CONTEXT: &[u8] = b"elo-talks-server:state:1";
const MAX_FILE: u64 = 128 * 1024;

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub version: u32,
    pub username: String,
    pub password_hash: String,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub struct Store {
    path: PathBuf,
    salt: [u8; 32],
    key: Zeroizing<Vec<u8>>,
    pub state: State,
}

pub fn password_policy(password: &str) -> Result<()> {
    ensure!(
        (12..=1024).contains(&password.chars().count()) && password.len() <= 1024,
        "Use a password with at least 12 characters and at most 1024 bytes"
    );
    Ok(())
}
pub fn username_policy(username: &str) -> Result<()> {
    ensure!(
        !username.is_empty()
            && username.len() <= 64
            && username
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "Use a username of 1-64 ASCII letters, digits, dots, underscores or hyphens"
    );
    Ok(())
}
pub fn kdf() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 1, Some(32)).expect("fixed Argon2id parameters"),
    )
}
fn derive(password: &str, salt: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(password.len() <= 1024, "Password exceeds the length limit");
    let mut key = Zeroizing::new(vec![0; 32]);
    kdf()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| anyhow!("Could not derive encryption key"))?;
    Ok(key)
}
pub fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() },
        "Data directory must be owned by the service user and must not be a link"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub fn lock_directory(path: &Path) -> Result<File> {
    private_directory(path)?;
    let guard = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join("instance.lock"))?;
    ensure!(
        guard.metadata()?.is_file(),
        "Instance lock must be a regular file"
    );
    guard
        .try_lock_exclusive()
        .context("Another service instance is using this data directory")?;
    Ok(guard)
}
pub fn read_private(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.mode() & 0o077 == 0 && metadata.uid() == unsafe { libc::geteuid() },
        "Secret files must be regular files, owned by the service user, with no group or other permissions");
    ensure!(
        metadata.len() <= limit,
        "Secret file exceeds the size limit"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "Secret file exceeds the size limit"
    );
    Ok(bytes)
}
pub fn read_password_file(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = read_private(path, 1026)?;
    let text = std::str::from_utf8(&bytes).context("Password file must contain UTF-8 text")?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    ensure!(
        !text.is_empty() && text.len() <= 1024 && !text.contains(['\n', '\r']),
        "Password file must contain one password"
    );
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= MAX_FILE,
        "State exceeds the size limit"
    );
    let parent = path.parent().context("Missing state directory")?;
    let mut random = [0; 16];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(".write-{}.tmp", hex::encode(random)));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace {
            fs::rename(&temporary, path)?;
        } else {
            fs::hard_link(&temporary, path)
                .context("State already exists or filesystem does not support atomic creation")?;
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}
#[derive(Clone)]
pub struct RecordCipher {
    key: Zeroizing<Vec<u8>>,
}
impl RecordCipher {
    pub fn seal<T: Serialize>(&self, context: &str, value: &T) -> Result<Vec<u8>> {
        let bytes = Zeroizing::new(serde_json::to_vec(value)?);
        ensure!(bytes.len() <= 128 * 1024, "Record exceeds size limit");
        let mut nonce = [0; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|_| anyhow!("Invalid record key"))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &bytes,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("Could not encrypt record"))?;
        Ok([nonce.to_vec(), ciphertext].concat())
    }
    pub fn open<T: serde::de::DeserializeOwned>(&self, context: &str, bytes: &[u8]) -> Result<T> {
        ensure!(
            (28..=128 * 1024 + 28).contains(&bytes.len()),
            "Invalid encrypted record"
        );
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|_| anyhow!("Invalid record key"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&bytes[..12]),
                    Payload {
                        msg: &bytes[12..],
                        aad: context.as_bytes(),
                    },
                )
                .map_err(|_| anyhow!("Wrong server key or modified database record"))?,
        );
        Ok(serde_json::from_slice(&plain)?)
    }
}
impl Store {
    pub fn record_cipher(&self) -> RecordCipher {
        RecordCipher {
            key: self.key.clone(),
        }
    }

    pub fn initialize(directory: &Path, password: &str, state: State) -> Result<Self> {
        password_policy(password)?;
        private_directory(directory)?;
        Self::validate(&state)?;
        let mut salt = [0; 32];
        OsRng.fill_bytes(&mut salt);
        let store = Self {
            path: directory.join("server.vault"),
            salt,
            key: derive(password, &salt)?,
            state,
        };
        atomic_write(&store.path, &store.encode(&store.state)?, false)?;
        Ok(store)
    }
    pub fn open(directory: &Path, password: &str) -> Result<Self> {
        let bytes = read_private(&directory.join("server.vault"), MAX_FILE)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).context("Invalid encrypted state")?;
        ensure!(
            envelope.version == 1 && envelope.salt.len() == 64 && envelope.nonce.len() == 24,
            "Unsupported or invalid encrypted state"
        );
        let salt: [u8; 32] = hex::decode(&envelope.salt)?
            .try_into()
            .map_err(|_| anyhow!("Invalid salt"))?;
        let nonce = hex::decode(&envelope.nonce)?;
        let key = derive(password, &salt)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("Invalid encryption key"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &hex::decode(&envelope.ciphertext)?,
                        aad: CONTEXT,
                    },
                )
                .map_err(|_| anyhow!("Incorrect server unlock password or modified state"))?,
        );
        let state: State = serde_json::from_slice(&plaintext).context("Invalid server state")?;
        Self::validate(&state)?;
        Ok(Self {
            path: directory.join("server.vault"),
            salt,
            key,
            state,
        })
    }
    fn validate(state: &State) -> Result<()> {
        ensure!(state.version == 1, "Unsupported server state version");
        username_policy(&state.username)?;
        let hash = argon2::PasswordHash::new(&state.password_hash)
            .map_err(|_| anyhow!("Invalid password hash"))?;
        ensure!(
            hash.algorithm.as_str() == "argon2id"
                && hash.version == Some(19)
                && hash.params.get_decimal("m") == Some(65536)
                && hash.params.get_decimal("t") == Some(3)
                && hash.params.get_decimal("p") == Some(1)
                && hash.hash.is_some_and(|output| output.len() == 32),
            "Unsupported password hash parameters"
        );
        ensure!(
            !state.certificate.is_empty()
                && state.certificate.len() <= 16 * 1024
                && !state.private_key.is_empty()
                && state.private_key.len() <= 16 * 1024,
            "Invalid TLS identity"
        );
        Ok(())
    }
    fn encode(&self, state: &State) -> Result<Vec<u8>> {
        Self::validate(state)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(state)?);
        let mut nonce = [0; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|_| anyhow!("Invalid encryption key"))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: CONTEXT,
                },
            )
            .map_err(|_| anyhow!("Could not encrypt state"))?;
        Ok(serde_json::to_vec(&Envelope {
            version: 1,
            salt: hex::encode(self.salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        })?)
    }
    pub async fn change_password_hash(&mut self, password_hash: String) -> Result<()> {
        let mut candidate = self.state.clone();
        candidate.password_hash = password_hash;
        let bytes = self.encode(&candidate)?;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || atomic_write(&path, &bytes, true))
            .await
            .context("State writer stopped")??;
        self.state = candidate;
        Ok(())
    }
}
