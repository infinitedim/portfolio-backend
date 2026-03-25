FROM rust:1.88-slim-bookworm AS chef

RUN apt-get update && \
  apt-get install -y --no-install-recommends musl-tools && \
  rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

ENV RUSTFLAGS="-C strip=symbols"

RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json

COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM gcr.io/distroless/static-debian12 AS runtime

COPY --from=builder --chown=1001:1001 \
  /app/target/x86_64-unknown-linux-musl/release/portfolio-backend \
  /app/portfolio-backend

COPY --from=builder --chown=1001:1001 \
  /app/target/x86_64-unknown-linux-musl/release/healthcheck \
  /app/healthcheck

USER 1001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD ["/app/healthcheck"]

CMD ["/app/portfolio-backend"]
