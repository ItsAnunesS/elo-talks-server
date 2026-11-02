#!/usr/bin/env python3
"""Publish immutable releases and keep the newest published version as latest."""
import json
import os
import pathlib
import subprocess
import tomllib

from release_version import build_version, stable_key

MAX_LATEST_RECONCILIATION_ATTEMPTS = 20


def github_cli(*arguments):
    result = subprocess.run(["gh", *arguments], capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(
            f"GitHub request failed: {detail}\n"
            "Publication requires Contents: write. For historical commits with workflow "
            "changes, configure the RELEASE_TOKEN Actions secret with a fine-grained "
            "token restricted to this repository and Contents: write plus Workflows: "
            "write. GITHUB_TOKEN cannot receive Workflows: write. "
            "See docs/RELEASING.md. Published releases are never overwritten."
        )
    return result.stdout


def highest_published_version(repository):
    pages = json.loads(
        github_cli(
            "api", "--paginate", "--slurp", f"repos/{repository}/releases?per_page=100"
        )
    )
    versions = [
        release["tag_name"]
        for page in pages
        for release in page
        if stable_key(release["tag_name"]) is not None
        and not release["draft"]
        and not release["prerelease"]
    ]
    return max(versions, key=stable_key)


def reconcile_latest(repository):
    for _ in range(MAX_LATEST_RECONCILIATION_ATTEMPTS):
        candidate = highest_published_version(repository)
        github_cli("release", "edit", candidate, "--repo", repository, "--latest")
        actual = json.loads(github_cli("api", f"repos/{repository}/releases/latest"))[
            "tag_name"
        ]
        if actual == highest_published_version(repository):
            return
    raise SystemExit(
        "Could not reconcile latest; existing releases and assets were preserved"
    )


def inspect_release(repository, revision, tag):
    existing = subprocess.run(
        ["gh", "api", f"repos/{repository}/releases/tags/{tag}"],
        capture_output=True,
        text=True,
    )
    if existing.returncode == 0:
        release = json.loads(existing.stdout)
        if release["target_commitish"] != revision:
            raise SystemExit("Existing tag has a different source commit")
        return release

    if "404" not in existing.stderr and '"404"' not in existing.stdout:
        raise SystemExit(
            "Could not inspect the existing release; refusing to create or overwrite it.\n"
            + (existing.stderr.strip() or existing.stdout.strip())
        )

    return None


def prepare_draft(repository, revision, tag, existing):
    if existing:
        return
    notes = pathlib.Path("release-notes.md")
    notes.write_text(
        f"Elo Talks Server {tag}\n\nRelease commit: `{revision}`\n\n"
        "Linux x86_64 service, administration panel and PostgreSQL migrations.\n\n"
        "The versioned container reference is in container-image.txt. No mutable latest "
        "container tag is published. See docs/RELEASING.md and docs/VALIDATION.md.\n\n"
        "Verify SHA256SUMS and its Sigstore signature before running the service.\n"
    )
    github_cli(
        "release",
        "create",
        tag,
        "--repo",
        repository,
        "--target",
        revision,
        "--title",
        f"Elo Talks Server {tag}",
        "--notes-file",
        str(notes),
        "--draft",
    )


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def validate_build():
    """Import only the generated version commit tied to this checked source."""
    metadata = json.loads(pathlib.Path("artifacts/build.json").read_text())
    version = build_version(os.environ["GITHUB_RUN_NUMBER"])
    source = os.environ["GITHUB_SHA"]
    if (
        metadata["version"] != version
        or metadata["source_commit"] != source
        or metadata["repository"] != os.environ["GITHUB_REPOSITORY"]
        or metadata["run_id"] != os.environ["GITHUB_RUN_ID"]
    ):
        raise SystemExit("Release artifact identity mismatch")
    run("git", "fetch", "artifacts/release.bundle", "HEAD")
    revision = run("git", "rev-parse", "FETCH_HEAD")
    if (
        revision != metadata["release_commit"]
        or run("git", "rev-parse", revision + "^") != source
    ):
        raise SystemExit("Release commit has an unexpected identity or parent")
    changed = set(run("git", "diff", "--name-only", source, revision).splitlines())
    if not changed <= {"Cargo.toml", "Cargo.lock"}:
        raise SystemExit("Release commit changes more than the package version")
    # Reconstruct the expected tree rather than accepting arbitrary manifest edits.
    from version import set_version

    set_version(pathlib.Path.cwd(), version)
    for name in ("Cargo.toml", "Cargo.lock"):
        if pathlib.Path(name).read_text() != subprocess.check_output(
            ["git", "show", f"{revision}:{name}"], text=True
        ):
            raise SystemExit("Unexpected release manifest changes")
    if (
        tomllib.loads(pathlib.Path("Cargo.toml").read_text())["package"]["version"]
        != version
    ):
        raise SystemExit("Release manifest version mismatch")
    run("sha256sum", "--check", "SHA256SUMS", cwd="artifacts/dist")
    return metadata


def publish_refs(revision, tag):
    run("gh", "auth", "setup-git")
    run("git", "fetch", "origin", "release")
    source = os.environ["GITHUB_SHA"]
    if (
        subprocess.call(
            ["git", "merge-base", "--is-ancestor", source, "origin/release"]
        )
        != 0
    ):
        raise SystemExit("Source commit is no longer in release history")
    existing = run("git", "ls-remote", "origin", f"refs/tags/{tag}")
    if existing and existing.split()[0] != revision:
        raise SystemExit("Existing release tag points to a different commit")
    if not existing:
        run("git", "push", "origin", f"{revision}:refs/tags/{tag}")
    # Never overwrite newer maintainer work or force-push a version commit.
    if (
        subprocess.call(
            ["git", "merge-base", "--is-ancestor", "origin/release", revision]
        )
        == 0
    ):
        result = subprocess.run(
            ["git", "push", "origin", f"{revision}:refs/heads/release"],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            before = run("git", "rev-parse", "origin/release")
            run("git", "fetch", "origin", "release")
            if run("git", "rev-parse", "origin/release") == before:
                raise SystemExit("Could not fast-forward release: " + result.stderr)
            print(
                "::notice::Release branch advanced; generated commit remains on its version tag"
            )
    else:
        print(
            "::notice::Newer work retained; generated commit remains on its version tag"
        )


def publish_container(repository, version):
    image = f"ghcr.io/{repository.lower()}:{version}"
    run("docker", "load", "--input", "artifacts/container.tar.gz")
    run("docker", "tag", "elo-talks-server:validated", image)
    run(
        "docker",
        "login",
        "ghcr.io",
        "--username",
        os.environ["GITHUB_ACTOR"],
        "--password-stdin",
        input=os.environ["REGISTRY_TOKEN"],
    )
    try:
        run("docker", "push", image)
        digests = json.loads(
            run(
                "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image
            )
        )
        digest = next(
            item
            for item in digests
            if item.startswith(image.rsplit(":", 1)[0] + "@sha256:")
        )
        subprocess.run(["cosign", "sign", "--yes", digest], check=True)
        pathlib.Path("artifacts/dist/container-image.txt").write_text(
            image + "\n" + digest + "\n"
        )
    finally:
        run("docker", "logout", "ghcr.io")


def main():
    metadata = validate_build()
    repository = metadata["repository"]
    revision = metadata["release_commit"]
    tag = "v" + metadata["version"]
    # Finished releases are immutable, including their container tag on retries.
    # Inspect before mutating Git refs or pushing an image.
    existing = inspect_release(repository, revision, tag)
    if existing and not existing["draft"]:
        reconcile_latest(repository)
        print("Already published; immutable release and container retained.")
        return
    publish_refs(revision, tag)
    prepare_draft(repository, revision, tag, existing)
    publish_container(repository, metadata["version"])
    dist = pathlib.Path("artifacts/dist")
    checksums = "".join(
        run("sha256sum", path.name, cwd=dist) + "\n"
        for path in sorted(dist.iterdir())
        if path.is_file()
        and path.name not in {"SHA256SUMS", "SHA256SUMS.sigstore.json"}
    )
    (dist / "SHA256SUMS").write_text(checksums)
    subprocess.run(
        [
            "cosign",
            "sign-blob",
            "--new-bundle-format",
            "--yes",
            "--bundle",
            str(dist / "SHA256SUMS.sigstore.json"),
            str(dist / "SHA256SUMS"),
        ],
        check=True,
    )
    for artifact in sorted(dist.iterdir()):
        if artifact.is_file():
            github_cli(
                "release",
                "upload",
                tag,
                str(artifact),
                "--repo",
                repository,
                "--clobber",
            )
    # An older parallel build must not become latest merely because it finished last.
    github_cli(
        "release",
        "edit",
        tag,
        "--repo",
        repository,
        "--draft=false",
        "--latest=false",
        "--prerelease=false",
    )
    reconcile_latest(repository)


if __name__ == "__main__":
    main()
