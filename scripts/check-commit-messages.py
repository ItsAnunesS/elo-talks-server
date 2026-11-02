#!/usr/bin/env python3
"""Validate all commits reachable from HEAD against Conventional Commits."""
import re
import subprocess

CONVENTIONAL_SUBJECT = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(?:\([a-z0-9][a-z0-9._/-]*\))?!?: \S.*$"
)


def main():
    history = subprocess.check_output(
        ["git", "log", "--format=%h%x09%s", "HEAD"], text=True
    )
    invalid = [
        entry
        for entry in history.splitlines()
        if not CONVENTIONAL_SUBJECT.fullmatch(entry.split("\t", 1)[1])
    ]
    if invalid:
        raise SystemExit("Invalid Conventional Commit subjects:\n" + "\n".join(invalid))
    print("PASS: all commit subjects follow Conventional Commits")


if __name__ == "__main__":
    main()
