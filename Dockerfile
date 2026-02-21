FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
  pkg-config \
  libssl-dev \
  && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./

RUN mkdir -p src && \
  echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
  echo '' > src/lib.rs

RUN cargo build --release --locked && \
  rm -rf src

COPY src ./src

RUN touch src/main.rs src/lib.rs && \
  cargo build --release --locked


FROM debian:bookworm-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y \
  ca-certificates \
  libssl3 \
  wget \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1001 -s /bin/sh appuser

COPY --from=builder /app/target/release/portfolio-backend /app/portfolio-backend

RUN mkdir -p /app/logs && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

ENV HOST=0.0.0.0
ENV PORT=8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["/app/portfolio-backend"]
