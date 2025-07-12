# SentinelEdge Makefile - Simple and practical

.PHONY: build run demo clean test install

# Build project
build:
	@echo "🔨 Building SentinelEdge..."
	cargo build --release

# Run monitoring program
run:
	@echo "🚀 Starting SentinelEdge..."
	cargo run --release

# Demo mode
demo:
	@echo "🎭 Demo mode..."
	cargo run --release -- --demo

# Simple demo (no cargo required)
simple-demo:
	@echo "⚡ Quick demo..."
	rustc simple_demo.rs -o simple_demo
	./simple_demo

# Test
test:
	@echo "🧪 Running tests..."
	cargo test

# Clean
clean:
	@echo "🧹 Cleaning..."
	cargo clean
	rm -f simple_demo demo.log *.log

# Check dependencies
check-deps:
	@echo "📋 Checking system dependencies..."
	@command -v rustc >/dev/null 2>&1 || { echo "❌ Rust not installed"; exit 1; }
	@command -v cargo >/dev/null 2>&1 || { echo "❌ Cargo not installed"; exit 1; }
	@echo "✅ Dependency check complete"

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "📦 Installing system dependencies..."
	sudo apt update
	sudo apt install -y build-essential clang llvm libclang-dev

# Quick start
quick-start: check-deps simple-demo
	@echo ""
	@echo "🎉 Quick experience complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  make build     # Build full version"
	@echo "  make demo      # Run demo mode"
	@echo "  make run       # Start monitoring"

# Show help
help:
	@echo "SentinelEdge build commands:"
	@echo ""
	@echo "  make quick-start   # Quick start experience"
	@echo "  make simple-demo   # Run simple demo"
	@echo "  make build         # Build project"
	@echo "  make demo          # Demo mode"
	@echo "  make run           # Start monitoring"
	@echo "  make test          # Run tests"
	@echo "  make clean         # Clean files"
	@echo ""

# Default target
all: build 