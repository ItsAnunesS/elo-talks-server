"""Check real Git histories, including GitHub's temporary PR merge commit."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

CHECKER = (
    pathlib.Path(__file__).resolve().parents[1] / "scripts/check-commit-messages.py"
)


class CommitMessageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.git("init", "-b", "release")
        self.git("config", "user.name", "CI Test")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.base = self.commit("feat(core): initialize synthetic source")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()

    def commit(self, subject):
        self.git("commit", "--allow-empty", "-m", subject)
        return self.git("rev-parse", "HEAD")

    def check(self, *args):
        return subprocess.run(
            [sys.executable, str(CHECKER), *args],
            cwd=self.root,
            capture_output=True,
            text=True,
        )

    def test_release_history_is_checked(self):
        self.commit("fix(updates): preserve signed release verification")
        self.assertEqual(self.check().returncode, 0)
        self.commit("Unconventional source commit")
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unconventional source commit", result.stderr)

    def test_pr_source_passes_despite_synthetic_merge_and_newer_base(self):
        self.git("checkout", "-b", "topic")
        head = self.commit("build(deps): update a compatible dependency")
        self.git("checkout", "release")
        base = self.commit("Base-only historical maintenance")
        tree = self.git("rev-parse", "HEAD^{tree}")
        merge = self.git(
            "commit-tree",
            tree,
            "-p",
            base,
            "-p",
            head,
            "-m",
            "Merge source into base for GitHub validation",
        )
        self.git("checkout", "--detach", merge)
        self.assertNotEqual(self.check().returncode, 0)
        result = self.check("--base", base, "--head", head)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_pr_source_is_not_hidden_by_range_selection(self):
        head = self.commit("Bump a dependency without a conventional prefix")
        result = self.check("--base", self.base, "--head", head)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Bump a dependency", result.stderr)

    def test_only_full_shas_are_accepted_as_input(self):
        for value in ("--all", "HEAD", "release..HEAD", "a" * 41):
            result = self.check("--head", value)
            self.assertNotEqual(result.returncode, 0)
        result = self.check("--head", "0" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requested source commit history", result.stderr)


if __name__ == "__main__":
    unittest.main()
