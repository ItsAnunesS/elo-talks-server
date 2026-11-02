"""Exercise version policy and real Git release bookkeeping without publication."""

import contextlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release
import release_version
from version import set_version

spec = importlib.util.spec_from_file_location(
    "prepare", ROOT / "scripts/prepare-release.py"
)
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name) / "source"
        self.root.mkdir()
        for name in ("Cargo.toml", "Cargo.lock", "release.json"):
            shutil.copy(ROOT / name, self.root / name)
        set_version(self.root, "0.2.0")
        (self.root / "release.json").write_text(
            '{"version":"0.2.0","first_run_number":1}'
        )
        (self.root / "README.md").write_text("Synthetic source\n")
        git(self.root, "init", "-b", "release")
        git(self.root, "add", ".")
        git(
            self.root,
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "feat(server): initialize synthetic source",
        )
        self.source = git(self.root, "rev-parse", "HEAD")
        self.environment = {
            "GITHUB_SHA": self.source,
            "GITHUB_REPOSITORY": "example/elo-talks-server",
            "GITHUB_RUN_NUMBER": "2",
            "GITHUB_RUN_ID": "42",
            "GITHUB_OUTPUT": str(pathlib.Path(self.temp.name) / "outputs"),
        }
        self.enterContext(patch.dict(os.environ, self.environment))
        self.enterContext(patch.object(release_version, "ROOT", self.root))

    def prepared(self):
        with patch.object(prepare, "ROOT", self.root), contextlib.chdir(self.root):
            prepare.prepare()
        return json.loads((self.root / "artifacts/build.json").read_text())

    def publisher(self):
        clone = pathlib.Path(self.temp.name) / "publisher"
        subprocess.run(
            ["git", "clone", "--quiet", str(self.root), str(clone)], check=True
        )
        git(clone, "checkout", "--detach", self.source)
        shutil.copytree(self.root / "artifacts", clone / "artifacts")
        dist = clone / "artifacts/dist"
        dist.mkdir()
        (dist / "synthetic.txt").write_text("Synthetic artifact\n")
        digest = subprocess.check_output(
            ["sha256sum", "synthetic.txt"], cwd=dist, text=True
        )
        (dist / "SHA256SUMS").write_text(digest)
        return clone

    def test_version_uses_workflow_number_and_rejects_reused_series(self):
        self.assertEqual(release_version.build_version(1), "0.2.0")
        self.assertEqual(release_version.build_version(4), "0.2.3")
        for value in (0, -1, "2; touch injected", "1.5"):
            with self.assertRaises(ValueError):
                release_version.build_version(value)
        (self.root / "release.json").write_text(
            '{"version":"0.3.0","first_run_number":9}'
        )
        with self.assertRaises(ValueError):
            release_version.build_version(8)

    def test_only_own_package_version_changes(self):
        original = (self.root / "Cargo.lock").read_text()
        set_version(self.root, "0.2.8")
        self.assertEqual(
            (self.root / "Cargo.lock").read_text(),
            original.replace(
                'name = "elo-talks-server"\nversion = "0.2.0"',
                'name = "elo-talks-server"\nversion = "0.2.8"',
                1,
            ),
        )
        with self.assertRaises(ValueError):
            set_version(self.root, "0.2.0-rc.1")

    def test_invalid_lockfile_leaves_both_manifests_unchanged(self):
        original = (self.root / "Cargo.toml").read_text()
        (self.root / "Cargo.lock").write_text("version = 4\n")
        with self.assertRaises(ValueError):
            set_version(self.root, "0.2.5")
        self.assertEqual((self.root / "Cargo.toml").read_text(), original)

    def test_generated_commit_is_conventional_version_only_and_deterministic(self):
        metadata = self.prepared()
        revision = metadata["release_commit"]
        self.assertEqual(git(self.root, "rev-parse", "HEAD^"), self.source)
        self.assertEqual(
            git(self.root, "show", "-s", "--format=%s"),
            "chore(release): publish v0.2.1 [skip ci]",
        )
        self.assertEqual(
            set(git(self.root, "diff", "--name-only", "HEAD^").splitlines()),
            {"Cargo.toml", "Cargo.lock"},
        )
        clone = self.publisher()
        shutil.rmtree(clone / "artifacts")
        with patch.object(prepare, "ROOT", clone), contextlib.chdir(clone):
            prepare.prepare()
        self.assertEqual(git(clone, "rev-parse", "HEAD"), revision)

    def test_initial_version_still_has_a_tagged_bookkeeping_commit(self):
        with patch.dict(os.environ, {"GITHUB_RUN_NUMBER": "1"}):
            metadata = self.prepared()
            self.assertEqual(metadata["version"], "0.2.0")
            self.assertEqual(git(self.root, "diff", "--name-only", "HEAD^"), "")
            self.assertNotEqual(metadata["release_commit"], self.source)

    def test_publisher_imports_and_verifies_generated_commit_and_checksums(self):
        metadata = self.prepared()
        clone = self.publisher()
        with contextlib.chdir(clone):
            self.assertEqual(release.validate_build(), metadata)

    def test_publisher_rejects_wrong_source_identity(self):
        self.prepared()
        clone = self.publisher()
        with contextlib.chdir(clone), patch.dict(os.environ, {"GITHUB_SHA": "0" * 40}):
            with self.assertRaisesRegex(SystemExit, "identity mismatch"):
                release.validate_build()

    def test_publisher_rejects_tampered_artifacts(self):
        self.prepared()
        clone = self.publisher()
        (clone / "artifacts/dist/synthetic.txt").write_text("Tampered\n")
        with contextlib.chdir(clone), self.assertRaises(subprocess.CalledProcessError):
            release.validate_build()

    def test_publisher_rejects_non_version_manifest_edits(self):
        metadata = self.prepared()
        manifest = self.root / "Cargo.toml"
        manifest.write_text(
            manifest.read_text().replace(
                'description = "', 'description = "Unexpected '
            )
        )
        git(self.root, "add", "Cargo.toml")
        git(
            self.root,
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--amend",
            "--no-edit",
        )
        metadata["release_commit"] = git(self.root, "rev-parse", "HEAD")
        (self.root / "artifacts/build.json").write_text(json.dumps(metadata))
        (self.root / "artifacts/release.bundle").unlink()
        git(
            self.root,
            "bundle",
            "create",
            "artifacts/release.bundle",
            "HEAD",
            "^" + self.source,
        )
        clone = self.publisher()
        with contextlib.chdir(clone), self.assertRaisesRegex(
            SystemExit, "manifest changes"
        ):
            release.validate_build()

    def publish_refs(self, clone, metadata):
        actual_run = release.run

        def local_only(*args, **kwargs):
            return "" if args[:2] == ("gh", "auth") else actual_run(*args, **kwargs)

        with contextlib.chdir(clone), patch.object(
            release, "run", side_effect=local_only
        ):
            release.publish_refs(metadata["release_commit"], "v" + metadata["version"])

    def remote(self, clone):
        remote = pathlib.Path(self.temp.name) / "remote.git"
        subprocess.run(["git", "init", "--quiet", "--bare", str(remote)], check=True)
        git(self.root, "push", str(remote), self.source + ":refs/heads/release")
        git(clone, "remote", "set-url", "origin", str(remote))
        git(clone, "fetch", "origin")
        return remote

    def test_publication_fast_forwards_branch_and_creates_tag(self):
        metadata = self.prepared()
        clone = self.publisher()
        remote = self.remote(clone)
        self.publish_refs(clone, metadata)
        self.assertEqual(
            git(remote, "rev-parse", "release"), metadata["release_commit"]
        )
        self.assertEqual(git(remote, "rev-parse", "v0.2.1"), metadata["release_commit"])

    def test_publication_preserves_concurrent_source_work(self):
        metadata = self.prepared()
        clone = self.publisher()
        remote = self.remote(clone)
        # A new source commit based on the original source races this older build.
        newer = git(
            self.root,
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=test@example.invalid",
            "commit-tree",
            self.source + "^{tree}",
            "-p",
            self.source,
            "-m",
            "fix(server): retain newer work",
        )
        git(self.root, "push", str(remote), newer + ":refs/heads/release")
        self.publish_refs(clone, metadata)
        self.assertEqual(git(remote, "rev-parse", "release"), newer)
        self.assertEqual(git(remote, "rev-parse", "v0.2.1"), metadata["release_commit"])

    def test_published_versions_are_ordered_numerically(self):
        pages = [
            [
                {"tag_name": tag, "draft": False, "prerelease": False}
                for tag in ("v0.2.9", "v0.2.10", "v0.2.11-rc.1")
            ]
        ]
        with patch.object(release, "github_cli", return_value=json.dumps(pages)):
            self.assertEqual(
                release.highest_published_version("example/server"), "v0.2.10"
            )

    def test_completed_release_retry_never_mutates_git_or_container(self):
        metadata = {
            "version": "0.2.1",
            "repository": "example/server",
            "release_commit": "a" * 40,
        }
        response = subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                {"target_commitish": metadata["release_commit"], "draft": False}
            ),
            "",
        )
        with patch.object(
            release, "validate_build", return_value=metadata
        ), patch.object(release.subprocess, "run", return_value=response), patch.object(
            release, "reconcile_latest"
        ) as latest, patch.object(
            release, "publish_refs"
        ) as refs, patch.object(
            release, "publish_container"
        ) as image:
            release.main()
            refs.assert_not_called()
            image.assert_not_called()
            latest.assert_called_once_with("example/server")


if __name__ == "__main__":
    unittest.main()
