# syntax=docker/dockerfile:1
#
# Multi-stage build for Corvid (mail server: SMTP MTA + submission + relay + webmail).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Corvid links NO OpenSSL: rustls uses the `ring` provider, `rsa` is pure Rust, and sqlx uses
# `rustls`, so the binary depends only on glibc. The DKIM private key and the mail TLS cert are
# NEVER baked in — they are bind-mounted read-only at runtime (DKIM_KEY_PATH / TLS_CERT/TLS_KEY).
# The container HEALTHCHECK uses the built-in `corvid healthcheck` subcommand (no curl needed).

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin corvid \
    && rm -rf src

# Now build the real binary. static/ + templates/ are include_str!'d into the binary, so they
# must be present at compile time.
COPY src ./src
COPY static ./static
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin corvid \
    && strip target/release/corvid

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user.
RUN useradd --system --uid 10001 --user-group --no-create-home corvid
COPY --from=builder /build/target/release/corvid /usr/local/bin/corvid

USER corvid
# Default in-container binds (ALT ports — never :25 here; the host maps real ports at cutover).
ENV SMTP_ADDR=0.0.0.0:2525 \
    SUBMISSION_ADDR=0.0.0.0:2587 \
    WEBMAIL_ADDR=0.0.0.0:8800
EXPOSE 2525 2587 8800

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["corvid", "healthcheck"]

ENTRYPOINT ["corvid"]
