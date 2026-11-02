# Validation — PostgreSQL organizations and desktop synchronization

Evidence recorded on 2026-11-02 with synthetic data only. The installed desktop
application, real accounts, host trust store and host protections were not changed.

## Rust/API/PostgreSQL

The pinned Rust 1.99.1 build uses a dedicated PostgreSQL 18 container with no host
port publication for the API integration suite. Each fixture creates a UUID-named
schema in its disposable database; it never falls back to mocked SQL or SQLite.
Do not point `ELO_TEST_DATABASE_URL` at production: the role needs schema-creation
permission specifically for isolated fixtures.

Thirteen integration tests cover authentication/password rotation, user-scoped
sessions, expiry/restart invalidation, user disabling and generation checks,
organization isolation, denied cross-organization/workspace IDs, explicit read
and manage grants, manager/member escalation attempts, organization-admin limits,
last-administrator guards, workspace revisions/validation, transactional failure,
ETag changes after revocation, encrypted PostgreSQL records/row binding, identity
mismatch, PostgreSQL failure without auth fallback, actual HTTPS verification,
public-origin/Host checks, and the generated OpenAPI/panel assets. The manager
case also checks that demotion/re-promotion does not resurrect an old manage grant.

`cargo fmt --all --check`, `cargo clippy --locked --all-targets -- -D warnings`
and `cargo audit --deny warnings` passed during this work. RustSec scanning covered
306 locked dependencies, without an advisory ignore list. It is a point-in-time
Rust advisory check, not an audit of the complete application or its JavaScript.

## Real browser administration

The actual CLI initialized a new identity and PostgreSQL database. It served a
configured HTTPS origin with a separate, explicitly supplied certificate/key.
The exported certificate was checked against that active certificate, rather
than the bootstrap certificate. The installed Chrome used a fresh HOME/profile
and a temporary NSS trust database; sandboxing and certificate checks remained
on. No system/browser-wide trust changes or TLS bypass flags were used.

The browser workflow created two organizations, organization-admin/manager/member
users, a workspace, category and channel; assigned manage/read grants; checked a
member's single-organization/read-only view; removed that grant and reloaded the
member's view; and disabled the user, observing sign-out on the next request. An
organization administrator accessed only their membership management. Browser
storage contained no persisted authorization tokens. Normal and 900×640 panel
screens were captured. No page errors occurred.

## Desktop wire contract

The native desktop Rust integration fixture ran against a separate real HTTPS
service and PostgreSQL database, using a member with an explicit workspace grant
and a verified private certificate. It authenticated, received the authorized
snapshot, imported metadata into a synthetic catalog, verified an unchanged
ETag response, and renewed login across multiple memberships without changing
the selected organization or profile IDs. No WhatsApp view or real profile was opened.

The desktop's normal Rust suite passed 62 tests with three ignored fixtures
(two host-FUSE tests and this separately executed service fixture). Its browser
suite passed the server domain/login/organization flow and existing account,
notification, backup and settings regressions. Desktop Clippy passed with existing
vendored GLib compiler warnings; those sources were not changed.

## Limits and remaining acceptance

- Measure sustained/concurrent traffic, latency, CPU/RAM and database behavior on
  deployment hardware before claiming excellent measured performance. Functional
  tests are not a speedup benchmark or a complete security audit.
- Real GNOME/WebKit shutdown on permission revocation, offline transitions,
  notifications with a live test account and an installed 0.5.x AppImage upgrade
  remain manual acceptance. No live account was accessed.
- Actual public DNS/ACME renewal, perimeter abuse controls, external PostgreSQL
  certificate provisioning, backups/power loss/full disk and clean Linux Docker
  Engine host-network deployment remain operator acceptance.
- The included Compose setup must provision a dedicated non-superuser application
  role; the bootstrap PostgreSQL superuser is not the application account.
- WhatsApp runtime hosting, message/profile synchronization, remote wiping,
  invitation verification, MFA/SSO and multi-replica sessions are not implemented.
  A client/backup that already received metadata cannot be cryptographically
  revoked by a server ACL change.

The current 0.2 Docker image built with the final lockfile, panel and migrations.
It initialized a separate synthetic PostgreSQL database and served loopback HTTPS
as a non-root user, with a read-only root filesystem, all capabilities dropped
and no-new-privileges. The listener and private identity file were checked; the
container exited with status zero after SIGTERM. It shared only the isolated test
network namespace and published no host port. The test container and private
fixtures were removed. Compose syntax passed; full clean-host Compose/domain
operator acceptance remains separate.

## Repository and release automation

Thirteen Python release tests passed using temporary real Git repositories and
local bare remotes. They cover deterministic Conventional release commits,
version-only manifest changes, first-run bookkeeping, source/artifact tampering,
numeric version ordering, completed-release retries and concurrent source pushes
without force-pushing. They do not contact GitHub or GHCR.

The official actionlint 1.7.12 binary (checksum verified) accepted both backend
workflows and the desktop release workflow. A clean Node 22 container installed
the exact npm lockfile and passed panel/workflow formatting and JavaScript syntax
checks. Rust formatting, the 13 PostgreSQL integration tests, Clippy and RustSec
checks passed again after extracting management authorization and request shapes.

Actual bot-push permissions, GHCR access, OIDC signing and release publication
must also be verified from the first GitHub Actions run. Local checks alone do
not establish that a remotely published release exists.
