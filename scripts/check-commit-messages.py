#!/usr/bin/env python3
"""Validate source commits, optionally restricted to a pull request's range."""
import argparse
import re
import subprocess

CONVENTIONAL_SUBJECT = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(?:\([a-z0-9][a-z0-9._/-]*\))?!?: \S.*$"
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=commit_sha)
    parser.add_argument("--head", type=commit_sha)
    args = parser.parse_args()
    head = args.head or "HEAD"
    selection = f"{args.base}..{head}" if args.base else head
    result = subprocess.run(
        ["git", "log", "--format=%h%x09%s", selection, "--"],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise SystemExit("Could not read the requested source commit history")
    history = result.stdout
    invalid = [
        entry
        for entry in history.splitlines()
        if not CONVENTIONAL_SUBJECT.fullmatch(entry.split("\t", 1)[1])
    ]
    if invalid:
        raise SystemExit("Invalid Conventional Commit subjects:\n" + "\n".join(invalid))
    print("PASS: source commit subjects follow Conventional Commits")


def commit_sha(value):
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        raise argparse.ArgumentTypeError("Expected a full Git commit SHA")
    return value


if __name__ == "__main__":
    main()
