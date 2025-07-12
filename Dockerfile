# SentinelEdge Production Docker Image
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libclang-dev \
    linux-headers-generic \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy project files
COPY Cargo.toml Cargo.lock ./
COPY kernel-agent/ ./kernel-agent/
COPY user-agent/ ./user-agent/

# Build the project
RUN cargo build --release

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create sentinel user
RUN useradd -r -s /bin/false sentinel

# Copy binary
COPY --from=0 /app/target/release/sentinel-edge /usr/local/bin/
RUN chmod +x /usr/local/bin/sentinel-edge

# Create directories
RUN mkdir -p /etc/sentinel-edge /var/log/sentinel-edge
RUN chown -R sentinel:sentinel /var/log/sentinel-edge

# Copy default config
COPY examples/config_examples/production.toml /etc/sentinel-edge/config.toml

# Expose ports
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run as non-root user (except for eBPF loading which needs privileges)
USER root

# Default command
CMD ["/usr/local/bin/sentinel-edge", "--config", "/etc/sentinel-edge/config.toml"] 
 