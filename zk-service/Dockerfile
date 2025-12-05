FROM rustlang/rust:nightly as builder
ENV RUSTFLAGS="-C target-feature=-crt-static"
WORKDIR /app
COPY . .
RUN rustup default nightly
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/zk-service /usr/local/bin/zk-service
EXPOSE 5000
CMD ["zk-service"]
