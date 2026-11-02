#!/usr/bin/env python3
"""Create a deterministic release commit and transfer it to the publish job."""

import json
import os
import pathlib
import subprocess

from release_version import build_version
from version import set_version

ROOT = pathlib.Path(__file__).resolve().parents[1]


def git(*args, **kwargs):
    return subprocess.check_output(["git", *args], text=True, **kwargs).strip()


def prepare():
    os.chdir(ROOT)
    source = os.environ["GITHUB_SHA"]
    if git("rev-parse", "HEAD") != source or git("status", "--porcelain"):
        raise SystemExit("Release preparation requires a clean checkout of GITHUB_SHA")
    version = build_version(os.environ["GITHUB_RUN_NUMBER"])
    set_version(ROOT, version)
    git("add", "--", "Cargo.toml", "Cargo.lock")
    # CI identity applies to this generated commit only, never the maintainer's setup.
    stamp = git("show", "-s", "--format=%cI", source)
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "github-actions[bot]",
        "GIT_AUTHOR_EMAIL": "41898282+github-actions[bot]@users.noreply.github.com",
        "GIT_COMMITTER_NAME": "github-actions[bot]",
        "GIT_COMMITTER_EMAIL": "41898282+github-actions[bot]@users.noreply.github.com",
        "GIT_AUTHOR_DATE": stamp,
        "GIT_COMMITTER_DATE": stamp,
    }
    git(
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--allow-empty",
        "-m",
        f"chore(release): publish v{version} [skip ci]",
        env=environment,
    )
    metadata = {
        "version": version,
        "source_commit": source,
        "release_commit": git("rev-parse", "HEAD"),
        "repository": os.environ["GITHUB_REPOSITORY"],
        "run_id": os.environ["GITHUB_RUN_ID"],
    }
    artifacts = ROOT / "artifacts"
    artifacts.mkdir()
    (artifacts / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    git("bundle", "create", str(artifacts / "release.bundle"), "HEAD", "^" + source)
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"version={version}\nrevision={metadata['release_commit']}\n")


if __name__ == "__main__":
    prepare()
