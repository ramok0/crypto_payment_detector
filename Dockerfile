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

# State files and wallet pool paths default to relative locations. Without a
# WORKDIR they would resolve against `/`, scattering them across the image root.
# Mount a volume here to keep them across restarts: the wallet pool holds the
# only copy of the managed wallets' private keys.
WORKDIR /data
RUN mkdir -p /data/wallet_pool
VOLUME ["/data"]

# env_logger filters at `error` when RUST_LOG is unset, which hides the boot
# configuration report and every operational milestone.
ENV RUST_LOG=info

EXPOSE 3030

CMD ["crypto_payment_api"]
