use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use elo_talks_server::{
    auth::{self, AppState},
    database::Database,
    storage::{self, Store},
    transport,
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Encrypted PostgreSQL-backed Elo Talks service and administration panel."
)]
struct Cli {
    #[arg(long, default_value = "data", global = true)]
    data_dir: PathBuf,
    /// PostgreSQL URL in a private file; alternatively use DATABASE_URL.
    #[arg(long, global = true)]
    database_url_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Initialize encrypted state and the first administrator. Never overwrites state.
    Init {
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long)]
        unlock_password_file: Option<PathBuf>,
        #[arg(long)]
        admin_password_file: Option<PathBuf>,
    },
    /// Reset the administrator password offline using the server unlock password.
    ResetAdminPassword {
        #[arg(long)]
        unlock_password_file: Option<PathBuf>,
        #[arg(long)]
        admin_password_file: Option<PathBuf>,
    },
    /// Unlock the service and serve local or explicitly configured network HTTPS.
    Serve {
        /// Public HTTPS origin for domain access; requires explicit certificate/key.
        #[arg(long)]
        public_url: Option<String>,
        #[arg(long)]
        listen: Option<std::net::SocketAddr>,
        #[arg(long)]
        tls_cert_file: Option<PathBuf>,
        #[arg(long)]
        tls_key_file: Option<PathBuf>,
        #[arg(long, default_value_t = transport::DEFAULT_PORT, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        #[arg(long)]
        unlock_password_file: Option<PathBuf>,
        /// Explicit trusted HTTPS origin for a separate future client. No wildcard.
        #[arg(long)]
        allowed_origin: Vec<String>,
    },
}
fn read_secret(path: Option<&Path>, label: &str, confirm: bool) -> Result<Zeroizing<String>> {
    if let Some(path) = path {
        return storage::read_password_file(path);
    }
    let value = Zeroizing::new(rpassword::prompt_password(format!("{label}: "))?);
    if confirm {
        let repeated = Zeroizing::new(rpassword::prompt_password(format!("Confirm {label}: "))?);
        ensure!(*value == *repeated, "Passwords do not match");
    }
    storage::password_policy(&value)?;
    Ok(value)
}
#[tokio::main]
async fn main() -> Result<()> {
    unsafe {
        libc::umask(0o077);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        ensure!(
            libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0,
            "Could not disable core dumps"
        );
        ensure!(
            libc::prctl(libc::PR_SET_DUMPABLE, 0) == 0,
            "Could not restrict process dumps"
        );
    }
    let cli = Cli::parse();
    let _guard = storage::lock_directory(&cli.data_dir)?;
    let database_url = match cli.database_url_file.as_deref() {
        Some(path) => storage::read_password_file(path)?,
        None => Zeroizing::new(
            std::env::var("DATABASE_URL")
                .context("Configure PostgreSQL using --database-url-file or DATABASE_URL")?,
        ),
    };
    match cli.command {
        Command::Init {
            username,
            unlock_password_file,
            admin_password_file,
        } => {
            storage::username_policy(&username)?;
            ensure!(
                !cli.data_dir.join("server.vault").exists(),
                "Server state already exists. Initialization never overwrites it."
            );
            let unlock = read_secret(
                unlock_password_file.as_deref(),
                "Server unlock password",
                true,
            )?;
            let password = read_secret(
                admin_password_file.as_deref(),
                "Administrator login password",
                true,
            )?;
            ensure!(
                *unlock != *password,
                "Use different passwords for server encryption and administrator login"
            );
            let identity =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
            let state = storage::State {
                version: 1,
                username,
                password_hash: auth::hash_password(&password)?,
                certificate: identity.cert.der().to_vec(),
                private_key: identity.signing_key.serialize_der(),
            };
            let store = Store::initialize(&cli.data_dir, &unlock, state)?;
            Database::connect(&database_url, &store).await?;
            println!(
                "Initialized encrypted server state. Start the service with the serve command."
            );
        }
        Command::ResetAdminPassword {
            unlock_password_file,
            admin_password_file,
        } => {
            let unlock = read_secret(
                unlock_password_file.as_deref(),
                "Server unlock password",
                false,
            )?;
            let password = read_secret(
                admin_password_file.as_deref(),
                "New administrator login password",
                true,
            )?;
            ensure!(
                *unlock != *password,
                "Use different passwords for server encryption and administrator login"
            );
            let store = Store::open(&cli.data_dir, &unlock)?;
            Database::connect(&database_url, &store)
                .await?
                .reset_admin(&store.state.username, &auth::hash_password(&password)?)
                .await?;
            println!(
                "Administrator password reset. All previous sessions remain invalid after restart."
            );
        }
        Command::Serve {
            public_url,
            listen,
            tls_cert_file,
            tls_key_file,
            port,
            unlock_password_file,
            allowed_origin,
        } => {
            let password = read_secret(
                unlock_password_file.as_deref(),
                "Server unlock password",
                false,
            )?;
            let directory = cli.data_dir.clone();
            let store =
                tokio::task::spawn_blocking(move || Store::open(&directory, &password)).await??;
            let certificate = store.state.certificate.clone();
            let private_key = store.state.private_key.clone();
            ensure!(
                tls_cert_file.is_some() == tls_key_file.is_some(),
                "Provide both TLS certificate and private key"
            );
            ensure!(
                public_url.is_none() || tls_cert_file.is_some(),
                "Domain access requires an explicitly provisioned TLS certificate and key"
            );
            let address = listen.unwrap_or_else(|| transport::local_address(port));
            ensure!(address.port() != 0, "Listen port must not be zero");
            ensure!(
                address.ip().is_loopback() || public_url.is_some(),
                "A network listener requires --public-url and a trusted TLS identity"
            );
            let (config, served_certificate, served_pem) =
                if let (Some(cert), Some(key)) = (tls_cert_file, tls_key_file) {
                    let key = storage::read_private(&key, 64 * 1024)?;
                    let mut pem_bytes = Vec::new();
                    use std::io::Read;
                    std::fs::File::open(cert)?
                        .take(64 * 1024 + 1)
                        .read_to_end(&mut pem_bytes)?;
                    ensure!(
                        pem_bytes.len() <= 64 * 1024,
                        "TLS certificate chain is too large"
                    );
                    let leaf = pem::parse_many(&pem_bytes)?
                        .into_iter()
                        .find(|pem| pem.tag() == "CERTIFICATE")
                        .context("TLS certificate chain is empty")?
                        .contents()
                        .to_vec();
                    (
                        axum_server::tls_rustls::RustlsConfig::from_pem(
                            pem_bytes.clone(),
                            key.to_vec(),
                        )
                        .await?,
                        leaf,
                        pem_bytes,
                    )
                } else {
                    (
                        transport::tls_config(certificate.clone(), private_key).await?,
                        certificate.clone(),
                        transport::certificate_pem(&certificate).into_bytes(),
                    )
                };
            storage::atomic_write(&cli.data_dir.join("certificate.pem"), &served_pem, true)?;
            let database = Database::connect(&database_url, &store).await?;
            let _database_guard = database.instance_lock().await?;
            let mut state = AppState::new(store, database);
            state.remote_enabled = !address.ip().is_loopback();
            let origin =
                public_url.unwrap_or_else(|| format!("https://127.0.0.1:{}", address.port()));
            let app = transport::app_at(state, &origin, &allowed_origin)?;
            let listener = std::net::TcpListener::bind(address)
                .context("Could not bind the local HTTPS port")?;
            listener.set_nonblocking(true)?;
            let handle = axum_server::Handle::new();
            let shutdown = handle.clone();
            tokio::spawn(async move {
                let mut terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM handler");
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
                shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
            });
            println!("Elo Talks Server: {origin}");
            println!("API documentation: {origin}/docs/");
            println!(
                "Certificate SHA-256: {}",
                hex::encode(Sha256::digest(&served_certificate))
            );
            println!(
                "Trust certificate.pem explicitly in your client. No account profiles are opened."
            );
            axum_server::from_tcp_rustls(listener, config)?
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
    }
    Ok(())
}
