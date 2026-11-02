"""Update only this package's version; never resolve or upgrade dependencies."""

import pathlib
import re
import tomllib

from release_version import STABLE


def set_version(root: pathlib.Path, version: str):
    if not STABLE.fullmatch(version):
        raise ValueError("Expected a stable semantic version")
    updates = {}
    for name in ("Cargo.toml", "Cargo.lock"):
        path = root / name
        original = path.read_text()
        heading = r"\[package\]" if name == "Cargo.toml" else r"\[\[package\]\]"
        pattern = (
            "(" + heading + r'\s*\nname = "elo-talks-server"\s*\nversion = ")[^"\n]+(")'
        )
        updated, count = re.subn(
            pattern,
            lambda match: match[1] + version + match[2],
            original,
        )
        if count != 1:
            raise ValueError(f"Expected one elo-talks-server package in {name}")
        parsed = tomllib.loads(updated)
        package = (
            parsed["package"]
            if name == "Cargo.toml"
            else next(p for p in parsed["package"] if p["name"] == "elo-talks-server")
        )
        if package["version"] != version:
            raise ValueError(f"Could not validate the version in {name}")
        updates[path] = updated
    for path, content in updates.items():
        path.write_text(content)
