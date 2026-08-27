# syntax=docker/dockerfile:1
# musl static release build (mirrors gripsack's release-core approach:
# rust:alpine's host triple IS <arch>-unknown-linux-musl, so a plain
# cargo build is already fully static — no cross config needed).

FROM rust:alpine AS release
RUN apk add --no-cache musl-dev
ARG TARGET
ENV TARGET=${TARGET}
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN rustup target add "${TARGET}" >/dev/null 2>&1 || true \
    && cargo build --release --locked --target "${TARGET}" \
    && strip "target/${TARGET}/release/gripfetch-apt"
