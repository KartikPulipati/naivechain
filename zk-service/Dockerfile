FROM rustlang/rust:nightly-bullseye AS builder

WORKDIR /usr/src/app

# Copy first for dependency caching layer
COPY Cargo.toml Cargo.lock* ./

# Create dummy source tree to satisfy build
RUN mkdir -p src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs

# Download dependencies (cached until Cargo.toml changes)
RUN cargo fetch

# Build dependencies only (cached until Cargo.toml changes)
RUN cargo build --release && \
    rm -rf src

# Now copy real source (this layer only rebuilds on source changes)
COPY . .

# Touch source files to ensure Cargo detects changes
RUN touch src/main.rs

# Build final release binary (fast when deps cached)
RUN cargo build --release

FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin

COPY --from=builder /usr/src/app/target/release/paillier_zk_service /usr/local/bin/paillier-zk-service

ENV RUST_LOG=info
EXPOSE 5000

CMD ["paillier-zk-service"]
