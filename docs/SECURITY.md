# Security model

## Trust and storage

This Linux service authenticates users and authorizes organization/workspace
metadata. It does not host WhatsApp browsers, access desktop vault credentials,
or grant remote pages native desktop capabilities. A workspace grant controls
metadata access, not access to the user's WhatsApp messages on their own computer.

PostgreSQL is authoritative for all live users, credentials and permissions.
There is no local authentication fallback when PostgreSQL fails. The encrypted
`server.vault` is the server's identity/key bootstrap; its initial administrator
is imported only into a new schema. A database key-check binds that schema to the
identity. An unrelated identity is rejected without overwriting data.

Application-level AES-256-GCM encrypts credential hashes, organization names and
workspace documents. Authenticated context includes the row UUID and organization
where applicable; ciphertext cannot be moved to a different row without detection.
Keys are derived using Argon2id (64 MiB, three iterations, parallelism one).
Usernames, UUIDs, relationships, roles, revisions, sizes and SQL metadata remain
visible. Database administrators and the service account are trusted; application
encryption does not prevent a malicious live DB operator from editing ACLs.

Use a dedicated non-superuser PostgreSQL role, a private database network, disk
protection and backups. Back up PostgreSQL and the encryption identity together,
keeping the unlock password separate. Restore with the API stopped, then restart
so old sessions are discarded. Authenticated encryption is not rollback protection.
Root, compromised same-user processes, unlocked memory, unencrypted swap and a
compromised host are outside the at-rest model. Zeroization cannot remove every
HTTP or crypto-library copy. No vulnerability-free or certification claim is made.

## Authorization

- Server administrators manage all organizations and global identities.
- Organization administrators manage only their own organization. They can
  provision new users there, but cannot list all global users, reset existing
  users' global passwords, disable global accounts or grant server-administrator
  status. An existing global identity can be added only by its known UUID.
- Managers and members require explicit workspace grants. Only managers with a
  manage grant can edit that workspace. They cannot grant access or change roles.
- Organization/workspace IDs are scoped together in every relevant query; foreign
  keys prevent cross-organization access rows. There is no direct SQL API or
  reliance on hidden buttons. SQL uses bound values; the only dynamic identifier
  in integration tests is a locally generated UUID schema name.

Management writes use transactions and a shared PostgreSQL advisory transaction
lock. The caller is revalidated after acquiring that lock, before scope checks
and mutations. Workspace writes use revisions to reject lost updates. Snapshot
reads use repeatable-read transactions, filter authorization in SQL, then decrypt
only the visible documents. A request already in flight can finish with its
previously authorized snapshot; subsequent requests use current permissions.
Counts are bounded (500 users, 100 organizations, 20 workspaces/20 channels/40
categories per organization). Query/acquisition/lock deadlines and a pool cap
bound database operations. One reserved advisory lock prevents multiple API
processes from serving the same database with separate token caches.

## Credentials and sessions

Login uses Argon2id and generic bad-user/bad-password responses. Password work
runs off the async executor, with two computations maximum. Login attempts are
bounded per username, source IP and globally. Forwarded IP/identity headers are
not trusted. Provisioning/reset operations additionally require authorization
and the same bounded password-worker pool. This does not replace perimeter abuse
controls for an internet deployment.

Opaque 256-bit bearer tokens are represented by SHA-256 digests in bounded
process memory, scoped to their user, with 30-minute idle/eight-hour absolute
expiry and a 32-session per-user cap. Sessions do not survive restart. Every
protected request checks the PostgreSQL user state and credential generation;
password resets, disabling and server-role changes invalidate older tokens.
Session lists and revocation are restricted to the caller's own sessions.
Password updates are committed in an owned task so client cancellation cannot
detach persistence from revocation. There are no cookies, public registration,
passwords in URLs, or persisted browser tokens. Initial passwords must be shared
through a trusted channel and changed by their user; invitation/MFA/SSO flows are
not included. Org administrators cannot reset an existing global identity.

The offline bootstrap-admin reset requires the server unlock password and a
private identity-directory lock. It updates PostgreSQL, increments the user's
credential generation and cannot silently fall back to the original bootstrap
password. Keep operator startup/DB/TLS secrets outside data backups and Git.
Explicit private secret files are supported; no secret is accepted through a
plaintext command-line password option.

## Transport and browser boundary

HTTPS is mandatory. Loopback uses a generated identity; a network listener
requires an explicit HTTPS public origin and supplied certificate/key. The
exported certificate/fingerprint match the active identity. Clients must verify
the certificate; private CA trust must be provisioned through a trusted channel.
There is no HTTP downgrade, broad TLS bypass or trusted forwarded-header mode.
Direct TCP TLS forwarding can preserve HTTPS to the backend. Renewal requires a
graceful restart. Do not run the API as root to bind a privileged port.

Host/Origin checks reject unconfigured origins and DNS-rebinding-style requests.
Explicit HTTPS CORS origins permit transport only, not identity/ACL access.
JSON bodies, handlers and timeouts are bounded. The same-origin admin panel uses
text nodes for user data, a restrictive CSP and memory-only authorization. Swagger
is bundled locally with external validation, query configuration and persistent
authorization disabled. Requests/credentials/messages are not access-logged.

PostgreSQL outside loopback/Unix sockets always uses VerifyFull TLS, overriding
weaker URL modes based on the driver's effective target host. Local trusted
transports can be configured separately. Use a trusted DB CA and keep its role
and port private. Operators still need OS, certificate, backup and dependency
maintenance; these controls are not a full deployment audit.

## Desktop synchronization limits

Desktop clients download only authorized organization/workspace structure. Their
tokens and metadata are stored in the local encrypted vault; login passwords are
not retained. Profiles are namespaced by server origin, username, organization
and workspace/channel IDs. Another server or login cannot select an existing
profile just by reusing an ID. Requests reject redirects and oversized responses.

Clients recheck access periodically. Failure blocks managed views; explicit
removal/revocation is applied after account processes stop. This is bounded
polling, not instantaneous remote revocation. Already downloaded data, user-owned
backups, a modified client or the user's vault password cannot be cryptographically
revoked by changing a server grant. No remote-wipe or remote WhatsApp-session
hosting guarantee is made. See the desktop `docs/SERVER-SYNC.md` for lifecycle
and acceptance limits.
