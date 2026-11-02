FROM rust:1.99.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY admin ./admin
COPY migrations ./migrations
RUN cargo build --release --locked

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/ItsAnunesS/elo-talks-server" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="Elo Talks HTTPS API and PostgreSQL administration service"
RUN install -d -m 700 -o 10001 -g 10001 /data
COPY --from=build /build/target/release/elo-talks-server /usr/local/bin/elo-talks-server
COPY LICENSE /usr/share/doc/elo-talks-server/LICENSE
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["elo-talks-server", "--data-dir", "/data"]
CMD ["serve"]
