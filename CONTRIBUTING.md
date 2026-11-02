# Contributing

Use English for code, comments, documentation, tests and product text. Use
Conventional Commits with an imperative English description, for example
`fix(auth): revoke sessions after disabling a user`. Preserve the maintainer's
Git identity and signing configuration; do not add coauthor trailers.

## Design

- Keep responsibilities explicit: domain data in `domain`, persistence and schema
  initialization in `database`, encryption in `storage`, authentication in
  `auth`/`api`, authorization in `management/policy`, request shapes in
  `management/requests`, transport policy in `transport`, static assets in `panel`.
- Apply SOLID, DRY and KISS through focused functions and shared invariants. Add a
  trait or generic layer when a real second implementation needs it, rather than
  creating repository/service/factory layers for every table.
- Revalidate actors inside write transactions. Keep organization and workspace
  IDs together, explicit grants, revision checks and last-administrator guards.
- Bound memory, request bodies, password work, sessions and database operations.
  Keep secrets out of logs and retain certificate verification.
- Prefer SQL that filters unauthorized rows before decrypting them. Measure
  performance before claiming an improvement. Never relax security for speed.

## Checks

Use the pinned Rust toolchain and committed Cargo/npm lockfiles. PostgreSQL is
required for integration tests. Use a disposable database with schema-creation
permission; fixtures create isolated schemas, not production-safe sandboxes.

```sh
export ELO_TEST_DATABASE_URL=postgresql://test_user:test_password@127.0.0.1:5432/elo_test
cargo fmt --all --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo audit --deny warnings
npm ci --ignore-scripts
npm run format:check
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/check-commit-messages.py
bash -n scripts/package.sh
git diff --check
```

Run the real HTTPS/browser flows in `docs/VALIDATION.md` when changing permission,
login or panel workflows. Test with synthetic users and isolated browser trust.
Never disable TLS checks or alter the maintainer's real sessions for a test.

See [release automation](docs/RELEASING.md) before changing publication. Existing
tags/releases are immutable; migrations and API compatibility need explicit review.
