FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release || true
RUN rm -rf src

COPY . .
RUN touch src/main.rs src/lib.rs
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/crypto_payment_detector /usr/local/bin/crypto_payment_detector
COPY --from=builder /app/target/release/crypto_payment_api /usr/local/bin/crypto_payment_api

EXPOSE 3000

CMD ["crypto_payment_api"]
