# Elo Talks Server

[![Server release](https://github.com/ItsAnunesS/elo-talks-server/actions/workflows/release.yml/badge.svg)](https://github.com/ItsAnunesS/elo-talks-server/actions/workflows/release.yml)

[Releases](https://github.com/ItsAnunesS/elo-talks-server/releases) ·
[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) ·
[Release automation](docs/RELEASING.md) · [MIT license](LICENSE)

Rust service with PostgreSQL, an HTTPS API, a small administration panel, and
server-authoritative workspace metadata synchronization for Elo Talks 0.5.x.

Manage users, independent organizations, categories, channel slots and explicit
workspace access. The panel is served at `/`; Swagger remains at `/docs/` and
OpenAPI at `/api/v1/openapi.json`. No external frontend build or CDN is required.

**WhatsApp profiles, cookies, QR codes and messages are not synchronized.** Each
computer keeps its own encrypted vault and links its own WhatsApp sessions. This
release synchronizes structure and permissions, not a remote WhatsApp browser.

## Roles and boundaries

| Role | Organizations | Users and memberships | Workspace metadata |
|---|---|---|---|
| Server administrator | All; create/rename/delete | Create users, reset passwords, disable sign-in, assign server administrators | All workspaces and grants |
| Organization administrator | Assigned organizations | Create users in that organization; manage its memberships/roles | All workspaces and grants in that organization |
| Manager | Assigned organizations | Own identity/password/sessions | Only granted workspaces; edit only with a manage grant |
| Member | Assigned organizations | Own identity/password/sessions | Read only explicitly granted workspaces |

A manager role alone does not reveal workspaces. Organization administrators do
not get global user lists, global password resets or cross-organization access.
The server prevents removal of the last server administrator or last organization
administrator membership. Authorization is checked in the API, not just the UI.

## PostgreSQL and encrypted identity

PostgreSQL is required. There is no SQLite or flat-file database fallback.
The schema contains users, organizations, memberships, workspaces, access grants
and globally indexed channel identifiers, with foreign keys and checks. All
runtime users/password hashes and workspace metadata live in PostgreSQL.

The local `server.vault` remains an encrypted **server identity/key bootstrap**,
containing the encryption derivation salt, generated local TLS identity and the
initial administrator bootstrap record. This initial credential is imported only
when a new PostgreSQL schema is initialized; it is never a login fallback or
reapplied over an existing database. Subsequent credential changes use PostgreSQL.

Administrator password hashes, organization names and workspace documents are
encrypted with AES-256-GCM, with authenticated row/organization identity. Usernames,
UUIDs, relationships, roles, revisions, sizes and database structure remain
visible to database operators. PostgreSQL administrators are trusted operators;
application encryption is not protection against a malicious live DB administrator.
Back up **both PostgreSQL and `server.vault`**, and protect the server unlock
password separately. Losing the identity or unlock password can make the database
unreadable. Starting with the wrong identity fails rather than replacing state.

## Native development on Linux

Use the pinned Rust toolchain. Configure a dedicated PostgreSQL database through
`DATABASE_URL` or `--database-url-file` (preferred for unattended deployment).
Private credential files must be regular, owned by the process user, mode `0600`
or stricter, and not symlinks. Their contents are never accepted as API parameters.

```sh
cargo build --locked --release
./target/release/elo-talks-server --data-dir ./data \
  --database-url-file ./secrets/database_url init --username admin
./target/release/elo-talks-server --data-dir ./data \
  --database-url-file ./secrets/database_url serve
```

Initialization prompts without echo for a server unlock password and a different
administrator login password. If database preparation fails after identity
creation, preserve `server.vault`, fix the database configuration and retry
`serve`; do not delete the encryption identity to bypass the failure.

By default, the listener is HTTPS at `127.0.0.1:8443`. The generated public local
certificate is exported to `data/certificate.pem` with a SHA-256 fingerprint.
Trust it explicitly in development; never disable TLS validation. For example:

```sh
curl --cacert ./data/certificate.pem https://127.0.0.1:8443/healthz
```

Create an organization and its users/workspaces in the panel after first login.
There are no default credentials or public registration. Tokens live in panel
memory only; reloading asks for sign-in again.

## HTTPS domain deployment

Provision a valid certificate and private key for the domain, point DNS to the
host, and explicitly configure the public origin and listener. For example:

```sh
./target/release/elo-talks-server --data-dir ./data \
  --database-url-file ./secrets/database_url serve \
  --unlock-password-file ./secrets/unlock \
  --public-url https://panel.example.com \
  --listen 0.0.0.0:8443 \
  --tls-cert-file ./tls/fullchain.pem --tls-key-file ./tls/private-key.pem
```

This example requires an end-to-end TLS TCP forwarding rule from public port 443
to the listener's 8443, or use `https://panel.example.com:8443` as the public URL
and client domain. A plaintext TLS-termination hop is not supported. No forwarded
identity headers are trusted. Certificate renewal requires a graceful restart.
Do not run as root or grant broad capabilities just to bind a privileged port.
The private TLS key must satisfy the service's private-file ownership/permission
checks. The exported certificate and displayed fingerprint match the active
identity, including externally provisioned certificates.

Foreign browser origins are denied by default; a separate trusted dashboard can
later use repeatable `--allowed-origin https://dashboard.example.com`. Wildcards,
HTTP origins, credentials and paths are rejected. This allowlist grants browser
transport permission, not user authorization. The included panel is same-origin.

PostgreSQL outside loopback always uses certificate and hostname verification,
even if a connection URL asks for a weaker SSL mode. Provide a trusted CA using
the driver's `sslrootcert` setting. Local Unix sockets/loopback can use a trusted
local database transport. Keep database ports private and use a dedicated role.

## Docker on Linux

`compose.yaml` runs PostgreSQL with a private loopback-published port and the API
with host networking. Create private `data`, `tls` and `secrets` directories.
Supply these operator-managed secret files without putting real values in Git:

- `secrets/postgres_password`: PostgreSQL bootstrap administrator password.
- `secrets/database_url`: PostgreSQL URL for `elo_talks` on `127.0.0.1:15432`.
- `secrets/unlock`: the server unlock password.

Set `ELO_UID`/`ELO_GID` to the owner of those files if different from 1000.
Run `docker compose up -d postgres`, then provision a dedicated application role (not the bootstrap
superuser). In `docker compose exec postgres psql -U postgres -d postgres`:

```sql
CREATE ROLE elo_talks LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
\password elo_talks
CREATE DATABASE elo_talks OWNER elo_talks;
REVOKE ALL ON DATABASE elo_talks FROM PUBLIC;
```

The `\password` prompt avoids putting the application password in SQL history.
Use that application's credentials in `secrets/database_url`. Then initialize
and start the API:

```sh
docker compose run --rm api --database-url-file /run/secrets/database_url init \
  --username admin --unlock-password-file /run/secrets/unlock
docker compose up -d api
```

The API container is non-root, has a read-only root filesystem, no capabilities,
and no-new-privileges. It still needs write access to its bind-mounted data
folder. For domain deployment, override its command with the explicit TLS/domain
arguments above and mount the certificates under `/tls`. Docker Desktop requires
host networking support enabled; clean Linux Engine deployment is a separate
acceptance target. The API process always enforces its configured HTTPS origin.

## API

Existing authentication routes remain under `/api/v1/auth`: login, me, logout,
password change, session listing and session revocation. Sessions are scoped to
their user, expire after 30 idle minutes/eight hours maximum, and do not survive a
service restart. Password changes, resets, disabling and server-role changes
invalidate existing tokens through the PostgreSQL credential generation.
An offline `reset-admin-password` requires the server unlock password and exclusive
local identity lock; it changes the bootstrap administrator's PostgreSQL record.

Management routes cover `/users`, `/organizations`, organization `/members`,
`/workspaces` and workspace `/access`. `GET /api/v1/sync?organization_id=UUID`
returns only authorized workspace documents and an ETag; unchanged snapshots
return 304. Workspace updates require the current revision and return 409 on
conflicts. Counts and request sizes are bounded. Schema and request fields are
available in Swagger, including bearer authorization.

## Validation

```sh
cargo fmt --all --check
# Use a disposable PostgreSQL database; fixtures create isolated schemas.
ELO_TEST_DATABASE_URL=... cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo audit --deny warnings
```

See [security](docs/SECURITY.md) and [validation evidence](docs/VALIDATION.md).
Multi-replica session sharing, WhatsApp runtime hosting, message synchronization,
MFA and production load/desktop acceptance are outside this delivery. A database
advisory lock prevents two API processes from serving the same database.
