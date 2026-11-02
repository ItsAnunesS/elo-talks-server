# Server releases

## Automatic flow

Push English Conventional Commits to `release`. Pull requests run the same
reusable checks without publication privileges. The Server release workflow:

1. Runs formatting, Clippy, all Rust tests against a real disposable PostgreSQL
   18 service, panel formatting, release-policy tests and RustSec checks.
2. Calculates the version from `release.json`: base patch plus workflow run
   number minus `first_run_number`. The first Server release run is `0.2.0`.
   Failed runs can leave version gaps; retrying a run keeps its version.
3. Creates a deterministic `chore(release): publish vX.Y.Z [skip ci]` commit
   changing only the package version in Cargo.toml/Cargo.lock. CI uses the
   GitHub Actions bot identity; local maintainer identity/signing is untouched.
4. Builds the non-root Linux x86_64 Docker image, checks `--version`, and packages
   the binary, license, operator documentation, source archive and dependency
   inventory. Static panel assets and migrations are embedded in the binary.
5. Transfers the generated Git commit and artifacts to the privileged publish
   job. The publisher checks source/run identity, exact version-only tree changes
   and checksums before creating the version tag.
6. Fast-forwards `release` to the generated commit only when possible. If newer
   source was pushed, it retains that work and puts the generated commit on its
   version tag instead. It never force-pushes or cancels prior builds.
7. Publishes `ghcr.io/itsanuness/elo-talks-server:X.Y.Z`, signs the image and
   release checksums with Sigstore, then publishes the GitHub release. There is
   no mutable container `latest` tag. Use the recorded digest for deployments.

Generated bot commits do not recursively publish: they use `GITHUB_TOKEN` and a
skip-CI commit marker. This policy applies to this backend only; the desktop
keeps its existing build-only version policy and 0.5.x release series.

Completed releases and their container tags are not overwritten on a retry.
Incomplete drafts can be resumed. GitHub's latest release is reconciled to the
highest stable published version, even when older builds finish later. A failure
may leave a tag, generated branch commit, draft or image; retry that original
workflow run. Do not manually delete/reuse a published version to recover.

## Repository settings

Checks can also be run manually or by pushing to `codex/**`; validate there
before promoting the same source to `release`. Named stages distinguish
formatting, PostgreSQL integration, Clippy, release-policy and commit failures.
For PRs, Conventional Commit validation uses the source base/head SHAs rather
than GitHub's synthetic merge title. Actual invalid source messages still fail.

Dependabot Cargo updates are lockfile-only: automatic updates stay within the
manifest's compatible version requirements, including Cargo's 0.x rules. API and
cryptographic migrations need an explicit manifest/code change and compatibility
review. RustSec remains a required gate; this policy does not make incompatible
security fixes safe to apply without the required migration. Existing failed
historical runs remain visible and are not deleted to make the history look green.

Use `release` as the default/publication branch. Actions must be enabled with
GitHub-owned Actions and the pinned Sigstore installer allowed. The publish job
requests Contents: write, Packages: write and OIDC id-token: write. Read-only
checks/build jobs do not receive these privileges; PRs never publish.

The built-in `GITHUB_TOKEN` is used by default. Branch rules that prevent the bot
from pushing require an explicitly configured release identity/bypass; do not
disable protections silently. An optional `RELEASE_TOKEN` secret can authorize
Git/release operations (repository-restricted Contents: write and Workflows:
write where GitHub requires it). Container publishing always uses the job's
repository-scoped token. Do not commit tokens. If a previously created GHCR
package exists, grant this repository Actions access to it. Package visibility
is a GitHub setting; verify anonymous pull access before advertising it as public.

No workflows create pull requests or auto-merge source changes. Generated commits
are version bookkeeping only. Maintainer source commits remain explicit.

## Version series and verification

To start a new minor/major series, update `release.json` and set
`first_run_number` to the next **Server release** workflow run number. Do not
use the Checks workflow's counter. Keep a stable `X.Y.Z` base; no RCs are needed.
Do not reset the counter or reuse existing published tags.

After pushing, inspect the Server release run and its checks, generated commit,
release assets and container digest. A push alone proves neither publication nor
production acceptance. The initial pipeline must be observed on GitHub; local
tests cannot prove repository token, registry or branch-policy permissions.

Verify downloaded assets with `sha256sum --check SHA256SUMS` and the Sigstore
bundle, using this identity and issuer:

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity 'https://github.com/ItsAnunesS/elo-talks-server/.github/workflows/release.yml@refs/heads/release' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' SHA256SUMS
cosign verify \
  --certificate-identity 'https://github.com/ItsAnunesS/elo-talks-server/.github/workflows/release.yml@refs/heads/release' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/itsanuness/elo-talks-server@sha256:REPLACE_WITH_RECORDED_DIGEST
```

Only a Linux x86_64 image/binary is produced currently. Upgrade PostgreSQL schemas
and the encrypted identity together according to `README.md`; this pipeline does
not deploy a live server or migrate an operator's database.

The included Compose file builds from source. Use the source archive/checkout
for that flow, or replace the API's `build: .` with an `image:` reference using
the recorded release digest. The binary archive does not contain build sources.
