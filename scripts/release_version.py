"""One version policy shared by packaging and publication."""

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
STABLE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def build_version(number):
    if not re.fullmatch(r"[1-9][0-9]*", str(number)):
        raise ValueError("Expected a positive GitHub run number")
    config = json.loads((ROOT / "release.json").read_text())
    version = config["version"]
    if not STABLE.fullmatch(version):
        raise ValueError("Invalid release version")
    first = config["first_run_number"]
    if type(first) is not int or first < 1:
        raise ValueError("Expected a positive first run number")
    offset = int(number) - first
    if offset < 0:
        raise ValueError("Build predates the configured release series")
    major, minor, patch = map(int, version.split("."))
    return f"{major}.{minor}.{patch + offset}"


def stable_key(tag):
    value = tag.removeprefix("v")
    return tuple(map(int, value.split("."))) if STABLE.fullmatch(value) else None
