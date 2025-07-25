# 🧪 SentinelEdge Testing Guide

This guide covers how to run the comprehensive test suite for SentinelEdge, including real eBPF integration tests, performance benchmarks, and system stress testing.

## 📋 Test Categories

### 1. Unit Tests (Mock Mode)
Basic functionality tests that don't require special privileges:

```bash
# Run standard unit tests
cargo test

# Run with detailed output
cargo test -- --nocapture

# Run specific test module
cargo test tests::
```

### 2. Integration Tests (Mock Mode)
Higher-level integration tests using simulated events:

```bash
# Run integration tests
cargo test integration_tests::

# Run with threading control
cargo test integration_tests:: -- --test-threads=1
```

### 3. Real eBPF Integration Tests (Requires Root)
**⚠️ IMPORTANT: These tests require root privileges and run on real system events**

```bash
# Run real eBPF integration tests (requires root)
sudo -E cargo test real_integration_tests:: -- --test-threads=1

# Run specific real integration test
sudo -E cargo test test_real_ebpf_program_loading -- --test-threads=1
sudo -E cargo test test_real_system_events_capture -- --test-threads=1
sudo -E cargo test test_high_load_system_stress -- --test-threads=1
```

**Why root privileges are needed:**
- Loading eBPF programs requires CAP_BPF and CAP_SYS_ADMIN capabilities
- Accessing kernel ring buffers requires privileged access
- Real system event capture needs kernel-level permissions

### 4. Performance Benchmarks
Comprehensive performance testing using Criterion:

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark groups
cargo bench event_parsing
cargo bench batch_processing
cargo bench concurrent_processing
cargo bench realistic_system_stress

# Run with baseline comparison
cargo bench -- --save-baseline initial
# Make changes, then:
cargo bench -- --baseline initial
```

**Benchmark Categories:**
- **Event Parsing**: Tests parsing performance with realistic event data
- **Batch Processing**: Tests high-throughput batch processing
- **Concurrent Processing**: Tests multi-threaded event handling
- **End-to-End Latency**: Tests complete pipeline latency
- **Realistic System Stress**: Tests filesystem, network, and process event scenarios

### 5. System Stress Testing (Requires Root)
Real-world system stress testing:

```bash
# Run comprehensive system stress test (requires root)
sudo ./target/release/examples/system_stress_test

# Build and run in one command
sudo cargo run --release --example system_stress_test
```

**Stress Test Coverage:**
- Filesystem operations (create/read/delete files)
- Process creation and management
- Memory pressure testing
- Concurrent load handling
- Sustained throughput testing
- System impact measurement

### 6. Real eBPF Demo (Requires Root)
Interactive demonstration of real eBPF capabilities:

```bash
# Run the real eBPF demonstration (requires root)
sudo ./target/release/examples/real_ebpf_demo

# Build and run in one command
sudo cargo run --release --example real_ebpf_demo
```

## 🔧 Setup Requirements

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    pkg-config
```

**RHEL/CentOS/Fedora:**
```bash
sudo dnf install -y \
    gcc \
    clang \
    llvm \
    libbpf-devel \
    kernel-headers \
    pkgconfig
```

### Rust Setup
```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install required Rust tools
cargo install cargo-criterion
```

### Permission Setup
For eBPF operations, you need elevated privileges:

```bash
# Option 1: Run with sudo (recommended for testing)
sudo -E cargo test real_integration_tests::

# Option 2: Add capabilities to the binary (production)
sudo setcap cap_bpf,cap_sys_admin+ep ./target/release/examples/real_ebpf_demo

# Option 3: Increase memory limits (may be needed)
echo '* soft memlock unlimited' | sudo tee -a /etc/security/limits.conf
echo '* hard memlock unlimited' | sudo tee -a /etc/security/limits.conf
```

## 📊 Test Execution Examples

### Complete Test Suite
```bash
#!/bin/bash
# comprehensive-test.sh

echo "🧪 Running SentinelEdge Comprehensive Test Suite"
echo "=============================================="

# 1. Unit tests
echo "1️⃣ Running unit tests..."
cargo test tests:: || exit 1

# 2. Integration tests  
echo "2️⃣ Running integration tests..."
cargo test integration_tests:: -- --test-threads=1 || exit 1

# 3. Check if running as root for real tests
if [ "$EUID" -eq 0 ]; then
    echo "3️⃣ Running real eBPF integration tests..."
    cargo test real_integration_tests:: -- --test-threads=1 || exit 1
    
    echo "4️⃣ Running system stress test..."
    cargo run --release --example system_stress_test || exit 1
    
    echo "5️⃣ Running real eBPF demo..."
    timeout 30s cargo run --release --example real_ebpf_demo || true
else
    echo "⚠️  Skipping real eBPF tests (requires root privileges)"
    echo "   Run with: sudo ./comprehensive-test.sh"
fi

# 6. Performance benchmarks
echo "6️⃣ Running performance benchmarks..."
cargo bench || exit 1

echo "✅ All tests completed successfully!"
```

### CI/CD Integration
For automated testing in CI environments:

```yaml
# .github/workflows/test.yml
- name: Run unit and integration tests
  run: |
    cargo test tests::
    cargo test integration_tests::

- name: Run performance benchmarks
  run: cargo bench --message-format=json > benchmark-results.json

# Real eBPF tests only in privileged runners
- name: Run real eBPF tests (privileged runner only)
  if: runner.privileged == true
  run: |
    sudo -E cargo test real_integration_tests:: -- --test-threads=1
    sudo cargo run --release --example system_stress_test
```

## 📈 Performance Baselines

### Expected Benchmark Results
Based on testing on modern hardware (4+ cores, 8GB+ RAM):

**Event Parsing:**
- Single event parsing: ~500ns
- Batch parsing (100 events): ~45μs
- Concurrent parsing: ~2M events/sec

**End-to-End Latency:**
- Single event latency: <50μs (P95)
- Under load latency: <200μs (P95)
- Batch processing: <1ms (P95)

**System Stress:**
- Filesystem operations: >1000 ops/sec
- Process spawning: >50 spawns/sec
- Sustained throughput: >10K events/sec
- Memory growth: <100MB under load

**Failure Indicators:**
- Drop rate >5%
- Latency >1ms consistently
- Memory growth >500MB
- Error rate >1%

## 🔍 Troubleshooting

### Common Issues

**Permission Denied:**
```bash
# Error: Permission denied loading eBPF program
# Solution: Run with sudo or add capabilities
sudo -E cargo test real_integration_tests::
```

**Ring Buffer Full:**
```bash
# Error: Ring buffer full, events dropped
# Solution: Increase buffer size in config
ring_buffer_size = 2097152  # 2MB instead of 1MB
```

**Memory Issues:**
```bash
# Error: Cannot allocate memory
# Solution: Increase locked memory limits
sudo sysctl -w vm.max_map_count=262144
ulimit -l unlimited
```

**Test Timeouts:**
```bash
# Error: Tests timing out
# Solution: Increase test timeout or reduce load
cargo test -- --test-threads=1 --timeout=300
```

### Debugging Commands

**Check system compatibility:**
```bash
# Check kernel version
uname -r

# Check eBPF support
ls -la /sys/fs/bpf/

# Check capabilities
capsh --print

# Check memory limits
ulimit -l
```

**Monitor test execution:**
```bash
# Monitor system resources during tests
watch -n 1 'ps aux | grep -E "(cargo|sentinel)" | head -10'

# Monitor memory usage
watch -n 1 'free -h && echo "---" && ps -o pid,rss,comm -p $(pgrep -f sentinel)'

# Monitor file descriptors
watch -n 1 'lsof -p $(pgrep -f sentinel) | wc -l'
```

## 📝 Test Data Authenticity

### Realistic Test Data
All tests use realistic data based on actual Linux system patterns:

**Process Names:**
- Real system processes: `systemd`, `kthreadd`, `ksoftirqd`, `kworker`
- Common user processes: `bash`, `vim`, `curl`, `ssh`, `python3`
- System daemons: `NetworkManager`, `systemd-resolved`, `cron`

**File Paths:**
- System paths: `/proc/meminfo`, `/sys/devices/`, `/etc/passwd`
- Log files: `/var/log/syslog`, `/var/log/auth.log`
- User paths: `/home/user/`, `/tmp/`, configuration files

**Network Activity:**
- Realistic IP addresses and port ranges
- Common protocols (TCP/UDP)
- Typical connection patterns (HTTP, SSH, DNS)

**Timing and Load:**
- Based on real system measurements
- Realistic event frequencies and bursts
- Actual process lifecycle patterns

### Data Validation
Tests validate that captured data:
- Has realistic timestamps (not zero or future)
- Contains valid process IDs (>0, <65536)
- Uses actual system user IDs
- References real file paths and commands
- Follows kernel event structure layouts

This ensures test results reflect real-world performance and behavior rather than artificial benchmarks.

---

**For production deployment testing, see [DEPLOYMENT.md](DEPLOYMENT.md)**

**For operational procedures, see [OPERATIONS.md](OPERATIONS.md)**