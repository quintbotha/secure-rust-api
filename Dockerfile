# Multi-stage build for minimal, secure production image

# Build stage
FROM rust:1.89-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy main to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs

# Build dependencies (cached layer)
RUN cargo build --release && \
    rm -rf src target/release/deps/secure_rust_api*

# Copy source code
COPY src ./src

# Build application
RUN cargo build --release

# Runtime stage - using distroless for minimal attack surface
FROM gcr.io/distroless/cc-debian12:nonroot

# Copy binary from builder
COPY --from=builder /app/target/release/secure-rust-api /usr/local/bin/secure-rust-api

# Copy example env (will be overridden by docker-compose)
COPY .env.example /app/.env.example

WORKDIR /app

# Create data directory with proper permissions
USER nonroot:nonroot

# Expose port
EXPOSE 8080

# Note: Health checks should be done at container orchestration level (docker-compose, k8s)
# Distroless images don't include health check tools

# Run the application
ENTRYPOINT ["/usr/local/bin/secure-rust-api"]
