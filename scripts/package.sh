#!/usr/bin/env bash
set -euo pipefail

version=$(python3 -c 'import json; print(json.load(open("artifacts/build.json"))["version"])')
revision=$(git rev-parse HEAD)
epoch=$(git show -s --format=%ct HEAD)
docker build --label "org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}" \
  --label "org.opencontainers.image.revision=$revision" \
  --label "org.opencontainers.image.version=$version" \
  --label "org.opencontainers.image.licenses=MIT" \
  --tag elo-talks-server:validated .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges elo-talks-server:validated --version | grep -Fx "elo-talks-server $version"

package="elo-talks-server-$version-linux-x86_64"
mkdir -p "artifacts/package/$package" artifacts/dist
container=$(docker create elo-talks-server:validated)
trap 'docker rm -f "$container" >/dev/null' EXIT
docker cp "$container:/usr/local/bin/elo-talks-server" "artifacts/package/$package/"
cp LICENSE README.md compose.yaml "artifacts/package/$package/"
cp -R docs "artifacts/package/$package/"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
  -C artifacts/package -cf - "$package" | gzip -n > "artifacts/dist/$package.tar.gz"
git archive --format=tar --prefix="elo-talks-server-$version/" HEAD | gzip -n \
  > "artifacts/dist/elo-talks-server-$version-source.tar.gz"
cp artifacts/build.json artifacts/dist/build-provenance.json
cargo metadata --locked --format-version 1 > artifacts/dist/rust-dependencies.json
(cd artifacts/dist && sha256sum * > SHA256SUMS)
docker save elo-talks-server:validated | gzip -n > artifacts/container.tar.gz
rm -rf artifacts/package
