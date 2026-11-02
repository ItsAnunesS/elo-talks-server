# Working on Elo Talks Server

Communicate with the maintainer in Portuguese. Write code, identifiers, comments,
documentation, tests and UI copy in English. Read `CONTRIBUTING.md`,
`docs/SECURITY.md` and the relevant implementation before changing a boundary.

## Scope and structure

This is the Rust HTTPS/PostgreSQL service and its small administration panel.
The desktop is a separate repository. WhatsApp profiles, cookies and messages
remain local to the desktop; do not claim that metadata sync replicates sessions.
The backend's version series is independent from the app's 0.5.x series.

Keep domain shapes, encryption, persistence, authentication, authorization,
transport and panel composition separate as mapped in `CONTRIBUTING.md`.
Apply SOLID, DRY and KISS pragmatically: focused functions and shared policies,
without speculative abstractions, frameworks or incidental dependency upgrades.

## Security invariants

- PostgreSQL is mandatory. Never introduce a plaintext/file authentication fallback.
- Keep authenticated encryption contexts bound to records and preserve the
  database/identity key check. Backups require both PostgreSQL and `server.vault`.
- Server admin, organization admin, manager and member have different privileges.
  Recheck generation, disabled state and authorization within serialized writes.
  Prevent cross-organization IDs, privilege escalation and removal of last admins.
- Managers need explicit workspace manage grants; members cannot manage grants.
- Keep verified HTTPS for clients and nonlocal PostgreSQL, strict Host/Origin
  checks, bounded input/work and secret-file permissions. Never bypass trust checks.
- Do not log passwords, tokens, private keys, database URLs or decrypted content.
  Keep panel tokens in memory and desktop tokens in its encrypted catalog.
- Do not claim vulnerability-free software, cryptographic remote wiping or
  measured performance based only on functional tests.

## Validation and Git

Inspect `git status`; preserve unrelated work and never stage secrets, local
identity/data, TLS keys, build outputs or test fixtures. Run relevant checks from
`CONTRIBUTING.md`; use disposable PostgreSQL and synthetic users. Report native,
deployment and performance acceptance separately from automated test results.

The publication branch is `release`. Use English Conventional Commits and the
maintainer's configured identity/signing. Do not add coauthors, rewrite history,
force-push or replace published tags. Commit/push when authorized by the user.

`release.json` and `scripts/release_version.py` define server versions. Check the
Server release workflow's run number before starting a new version series.
The backend explicitly generates version-only `chore(release)` commits in CI;
this is intentional and differs from the desktop's version policy. Never modify
application logic in a generated commit. Keep Actions pinned by full SHA and
publication privileges limited to the publish job. Preserve immutable releases,
container versions, signed checksums and source-to-artifact identity. Never treat
a successful push as a successful release; verify Actions and report both.

Use a `codex/**` branch or manual Checks run to validate changes before promoting
them to `release`. PR commit validation must use the PR source range, excluding
GitHub's synthetic merge commit. Keep the release test's mocked publication
notices out of real Actions annotations. Dependabot Cargo updates are lockfile-only;
changing cryptographic API/version constraints requires an explicit migration.
