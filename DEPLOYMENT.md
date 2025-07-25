# 🚀 SentinelEdge Production Deployment Guide

This comprehensive guide covers production deployment, monitoring, and operational procedures for SentinelEdge.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Deployment Strategies](#deployment-strategies)
- [Monitoring & Observability](#monitoring--observability)
- [Security Considerations](#security-considerations)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [Backup & Recovery](#backup--recovery)
- [Maintenance](#maintenance)

## Prerequisites

### System Requirements

#### Minimum Requirements
- **OS**: Linux (Ubuntu 20.04+, RHEL 8+, or similar)
- **Kernel**: 5.8+ with eBPF CO-RE support
- **Memory**: 2GB RAM
- **CPU**: 2 cores
- **Storage**: 10GB free space
- **Network**: Stable internet connection

#### Recommended Requirements
- **OS**: Ubuntu 22.04 LTS or RHEL 9
- **Kernel**: 6.0+ with latest eBPF features
- **Memory**: 8GB+ RAM
- **CPU**: 4+ cores (Intel/AMD x86_64)
- **Storage**: 50GB+ SSD storage
- **Network**: Low-latency network (< 10ms)

#### Required Privileges
- **Root access** for eBPF program loading
- **CAP_BPF** and **CAP_SYS_ADMIN** capabilities
- **Locked memory limits** increased (see [Memory Configuration](#memory-configuration))

### Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    curl

# RHEL/CentOS/Fedora
sudo dnf install -y \
    gcc \
    clang \
    llvm \
    libbpf-devel \
    kernel-headers \
    pkgconfig \
    curl
```

## Installation

### Method 1: Binary Release (Recommended)

```bash
# Download latest release
curl -L -o sentineledge.tar.gz \
  https://github.com/your-org/SentinelEdge/releases/latest/download/sentineledge-linux-x64.tar.gz

# Extract and install
tar -xzf sentineledge.tar.gz
sudo cp sentinel-edge /usr/local/bin/
sudo chmod +x /usr/local/bin/sentinel-edge

# Verify installation
sentinel-edge --version
```

### Method 2: Build from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone repository
git clone https://github.com/your-org/SentinelEdge.git
cd SentinelEdge

# Build release binary
cargo build --release

# Install binary
sudo cp target/release/sentinel-edge /usr/local/bin/
```

### Method 3: Docker Deployment

```bash
# Pull image
docker pull sentineledge:latest

# Run container with required privileges
docker run -d \
  --name sentineledge \
  --privileged \
  --pid=host \
  --network=host \
  -v /proc:/host/proc:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/sentineledge:/etc/sentineledge:ro \
  sentineledge:latest
```

## Configuration

### Basic Configuration File

Create `/etc/sentineledge/config.toml`:

```toml
[core]
# Core system settings
log_level = "info"
metrics_enabled = true
health_check_enabled = true

[ebpf]
# eBPF system configuration
ring_buffer_size = 1048576  # 1MB
event_batch_size = 100
poll_timeout_ms = 100
max_events_per_sec = 10000
enable_backpressure = true
auto_recovery = true

# Performance tuning
ring_buffer_poll_timeout_us = 100
batch_size = 64
batch_timeout_us = 1000

[monitoring]
# Monitoring and observability
metrics_interval_sec = 60
prometheus_endpoint = "0.0.0.0:9090"
health_check_port = 8080

[security]
# Security settings
enable_threat_detection = true
log_security_events = true
alert_on_anomalies = true

[logging]
# Logging configuration
log_file = "/var/log/sentineledge/sentinel.log"
log_rotation = "daily"
max_log_files = 30
```

### Environment Variables

```bash
# Core settings
export SENTINEL_LOG_LEVEL=info
export SENTINEL_CONFIG_PATH=/etc/sentineledge/config.toml

# Performance tuning
export SENTINEL_RING_BUFFER_SIZE=1048576
export SENTINEL_MAX_EVENTS_PER_SEC=10000

# Monitoring
export SENTINEL_METRICS_ENABLED=true
export SENTINEL_PROMETHEUS_PORT=9090
```

### Memory Configuration

Increase locked memory limits for eBPF:

```bash
# Add to /etc/security/limits.conf
root soft memlock unlimited
root hard memlock unlimited
sentineledge soft memlock unlimited
sentineledge hard memlock unlimited

# Or use systemd override
sudo mkdir -p /etc/systemd/system/sentineledge.service.d/
cat << EOF | sudo tee /etc/systemd/system/sentineledge.service.d/override.conf
[Service]
LimitMEMLOCK=infinity
EOF
```

## Deployment Strategies

### Systemd Service Deployment

Create `/etc/systemd/system/sentineledge.service`:

```ini
[Unit]
Description=SentinelEdge eBPF Security Monitor
Documentation=https://github.com/your-org/SentinelEdge
After=network.target
Wants=network.target

[Service]
Type=exec
User=root
Group=root
ExecStart=/usr/local/bin/sentinel-edge --config /etc/sentineledge/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

# Security settings
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/sentineledge /var/lib/sentineledge
PrivateTmp=true

# Resource limits
LimitMEMLOCK=infinity
LimitNOFILE=65536

# Environment
Environment=RUST_LOG=info
EnvironmentFile=-/etc/sentineledge/environment

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sentineledge
sudo systemctl start sentineledge
sudo systemctl status sentineledge
```

### Docker Compose Deployment

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  sentineledge:
    image: sentineledge:latest
    container_name: sentineledge
    restart: unless-stopped
    privileged: true
    pid: host
    network_mode: host
    
    volumes:
      - /proc:/host/proc:ro
      - /sys/fs/bpf:/sys/fs/bpf
      - ./config:/etc/sentineledge:ro
      - sentineledge-logs:/var/log/sentineledge
      - sentineledge-data:/var/lib/sentineledge
    
    environment:
      - RUST_LOG=info
      - SENTINEL_CONFIG_PATH=/etc/sentineledge/config.toml
    
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"

  # Optional: Prometheus for metrics
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  # Optional: Grafana for visualization
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=secure_password_here

volumes:
  sentineledge-logs:
  sentineledge-data:
  prometheus-data:
  grafana-data:
```

### Kubernetes Deployment

Create `k8s-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: sentineledge
  namespace: security
  labels:
    app: sentineledge
spec:
  selector:
    matchLabels:
      app: sentineledge
  template:
    metadata:
      labels:
        app: sentineledge
    spec:
      hostPID: true
      hostNetwork: true
      serviceAccountName: sentineledge
      securityContext:
        runAsUser: 0
      containers:
      - name: sentineledge
        image: sentineledge:latest
        imagePullPolicy: Always
        securityContext:
          privileged: true
          capabilities:
            add:
            - SYS_ADMIN
            - BPF
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: RUST_LOG
          value: "info"
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: bpf-fs
          mountPath: /sys/fs/bpf
        - name: config
          mountPath: /etc/sentineledge
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: bpf-fs
        hostPath:
          path: /sys/fs/bpf
      - name: config
        configMap:
          name: sentineledge-config
      tolerations:
      - effect: NoSchedule
        operator: Exists
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sentineledge
  namespace: security
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sentineledge
rules:
- apiGroups: [""]
  resources: ["nodes", "pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sentineledge
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: sentineledge
subjects:
- kind: ServiceAccount
  name: sentineledge
  namespace: security
```

## Monitoring & Observability

### Metrics Collection

SentinelEdge exposes Prometheus metrics on port 9090 by default:

- `sentinel_events_processed_total` - Total events processed
- `sentinel_events_dropped_total` - Total events dropped
- `sentinel_ring_buffer_utilization_percent` - Ring buffer utilization
- `sentinel_memory_usage_bytes` - Memory usage
- `sentinel_cpu_usage_percent` - CPU usage
- `sentinel_errors_by_type_total` - Errors by type

### Health Checks

Health check endpoints:

- `GET /health` - Overall system health
- `GET /ready` - Readiness probe
- `GET /metrics` - Prometheus metrics
- `GET /version` - Version information

### Logging

Configure structured logging:

```toml
[logging]
level = "info"
format = "json"
output = "/var/log/sentineledge/sentinel.log"
rotate = true
max_size = "100MB"
max_files = 10
```

### Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
- name: sentineledge
  rules:
  - alert: SentinelEdgeDown
    expr: up{job="sentineledge"} == 0
    for: 30s
    labels:
      severity: critical
    annotations:
      summary: "SentinelEdge is down"
      description: "SentinelEdge has been down for more than 30 seconds"

  - alert: HighEventDropRate
    expr: rate(sentinel_events_dropped_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High event drop rate"
      description: "Event drop rate is {{ $value }} events/sec"

  - alert: HighMemoryUsage
    expr: sentinel_memory_usage_bytes > 1073741824  # 1GB
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage"
      description: "Memory usage is {{ $value | humanize }}B"
```

## Security Considerations

### Network Security

- **Firewall Rules**: Only expose necessary ports
- **TLS**: Use TLS for metrics and API endpoints
- **Authentication**: Implement API authentication

```bash
# Firewall configuration
sudo ufw allow 8080/tcp  # Health checks
sudo ufw allow 9090/tcp  # Metrics (internal only)
sudo ufw deny 22/tcp     # SSH (if not needed)
```

### File Permissions

```bash
# Configuration files
sudo chown root:root /etc/sentineledge/config.toml
sudo chmod 600 /etc/sentineledge/config.toml

# Log directory
sudo mkdir -p /var/log/sentineledge
sudo chown sentineledge:sentineledge /var/log/sentineledge
sudo chmod 755 /var/log/sentineledge

# Data directory
sudo mkdir -p /var/lib/sentineledge
sudo chown sentineledge:sentineledge /var/lib/sentineledge
sudo chmod 700 /var/lib/sentineledge
```

### SELinux Configuration

For RHEL/CentOS systems with SELinux:

```bash
# Allow eBPF operations
sudo setsebool -P allow_execstack on
sudo setsebool -P allow_execmem on

# Custom SELinux policy might be needed
sudo semanage fcontext -a -t admin_home_t "/usr/local/bin/sentinel-edge"
sudo restorecon -v /usr/local/bin/sentinel-edge
```

## Performance Tuning

### System-Level Tuning

```bash
# Increase file descriptor limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize kernel parameters
cat << EOF >> /etc/sysctl.conf
# Network optimizations
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Memory optimizations
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# BPF optimizations
kernel.bpf_stats_enabled = 1
EOF

sudo sysctl -p
```

### Application-Level Tuning

Configuration optimizations by system size:

#### Small Systems (< 2GB RAM, < 4 cores)
```toml
[ebpf]
ring_buffer_size = 262144      # 256KB
event_batch_size = 32
max_events_per_sec = 1000
ring_buffer_poll_timeout_us = 200
batch_timeout_us = 2000
```

#### Medium Systems (2-8GB RAM, 4-8 cores)
```toml
[ebpf]
ring_buffer_size = 1048576     # 1MB
event_batch_size = 100
max_events_per_sec = 5000
ring_buffer_poll_timeout_us = 100
batch_timeout_us = 1000
```

#### Large Systems (> 8GB RAM, > 8 cores)
```toml
[ebpf]
ring_buffer_size = 4194304     # 4MB
event_batch_size = 200
max_events_per_sec = 20000
ring_buffer_poll_timeout_us = 50
batch_timeout_us = 500
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied
```bash
# Error: Permission denied loading eBPF program

# Solution: Check capabilities and run as root
sudo setcap cap_bpf,cap_sys_admin+ep /usr/local/bin/sentinel-edge
# Or run as root
sudo sentinel-edge
```

#### 2. Ring Buffer Full
```bash
# Error: Ring buffer full, events dropped

# Solution: Increase buffer size or decrease event rate
[ebpf]
ring_buffer_size = 2097152  # Double the size
max_events_per_sec = 5000   # Reduce rate limit
```

#### 3. High Memory Usage
```bash
# Check memory usage
sudo systemctl status sentineledge
free -h

# Reduce memory usage
[ebpf]
ring_buffer_size = 524288   # Reduce buffer
event_batch_size = 50       # Smaller batches
```

#### 4. Service Won't Start
```bash
# Check logs
journalctl -u sentineledge -f

# Check configuration
sentinel-edge --config /etc/sentineledge/config.toml --check-config

# Validate eBPF support
ls -la /sys/fs/bpf/
```

### Debug Mode

Enable debug logging:

```bash
# Environment variable
export RUST_LOG=debug

# Configuration file
[logging]
level = "debug"

# Command line
sentinel-edge --log-level debug
```

### Performance Profiling

```bash
# CPU profiling
perf record -g sentinel-edge
perf report

# Memory profiling
valgrind --tool=massif sentinel-edge

# eBPF program stats
cat /proc/sys/kernel/bpf_stats_enabled
bpftool prog show
```

## Backup & Recovery

### Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/backup/sentineledge/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp -r /etc/sentineledge/* "$BACKUP_DIR/"

# Backup systemd service
cp /etc/systemd/system/sentineledge.service "$BACKUP_DIR/"

# Backup logs (recent)
find /var/log/sentineledge -name "*.log" -mtime -7 -exec cp {} "$BACKUP_DIR/" \;

echo "Backup completed: $BACKUP_DIR"
```

### Disaster Recovery

```bash
#!/bin/bash
# restore-config.sh

BACKUP_DIR="$1"
if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup_directory>"
    exit 1
fi

# Stop service
sudo systemctl stop sentineledge

# Restore configuration
sudo cp -r "$BACKUP_DIR"/* /etc/sentineledge/

# Restore systemd service
sudo cp "$BACKUP_DIR/sentineledge.service" /etc/systemd/system/
sudo systemctl daemon-reload

# Start service
sudo systemctl start sentineledge
sudo systemctl status sentineledge
```

## Maintenance

### Regular Maintenance Tasks

#### Daily
- Check service status
- Monitor resource usage
- Review alert notifications

```bash
#!/bin/bash
# daily-check.sh

echo "=== SentinelEdge Daily Health Check ==="
echo "Date: $(date)"
echo ""

echo "Service Status:"
systemctl is-active sentineledge || echo "ERROR: Service not running"

echo "Memory Usage:"
ps aux | grep sentinel-edge | grep -v grep

echo "Recent Errors:"
journalctl -u sentineledge --since "24 hours ago" | grep -i error | tail -5

echo "Disk Usage:"
df -h /var/log/sentineledge /var/lib/sentineledge
```

#### Weekly
- Log rotation and cleanup
- Performance review
- Configuration validation

```bash
#!/bin/bash
# weekly-maintenance.sh

echo "=== Weekly Maintenance ==="

# Rotate logs if needed
find /var/log/sentineledge -name "*.log" -size +100M -exec logrotate {} \;

# Clean old logs
find /var/log/sentineledge -name "*.log.*" -mtime +30 -delete

# Validate configuration
sentinel-edge --config /etc/sentineledge/config.toml --check-config

# Update system packages (optional)
# sudo apt update && sudo apt upgrade -y
```

#### Monthly
- Security updates
- Performance optimization review
- Backup verification

### Version Updates

```bash
#!/bin/bash
# update-sentineledge.sh

NEW_VERSION="$1"
if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <new_version>"
    exit 1
fi

echo "Updating SentinelEdge to version $NEW_VERSION"

# Backup current installation
cp /usr/local/bin/sentinel-edge /usr/local/bin/sentinel-edge.backup

# Download new version
curl -L -o sentineledge-${NEW_VERSION}.tar.gz \
  "https://github.com/your-org/SentinelEdge/releases/download/${NEW_VERSION}/sentineledge-linux-x64.tar.gz"

# Extract and install
tar -xzf sentineledge-${NEW_VERSION}.tar.gz
sudo systemctl stop sentineledge
sudo cp sentinel-edge /usr/local/bin/
sudo systemctl start sentineledge

# Verify update
sentinel-edge --version
sudo systemctl status sentineledge

echo "Update completed successfully"
```

### Monitoring Scripts

```bash
#!/bin/bash
# monitor-sentineledge.sh

# Set thresholds
CPU_THRESHOLD=80
MEMORY_THRESHOLD=1000000000  # 1GB in bytes
ERROR_THRESHOLD=10

# Get metrics
CPU_USAGE=$(ps -o %cpu -p $(pgrep sentinel-edge) | tail -1 | tr -d ' ')
MEMORY_USAGE=$(ps -o rss -p $(pgrep sentinel-edge) | tail -1 | tr -d ' ')
ERROR_COUNT=$(journalctl -u sentineledge --since "1 hour ago" | grep -c ERROR)

# Check thresholds and alert
if (( $(echo "$CPU_USAGE > $CPU_THRESHOLD" | bc -l) )); then
    echo "ALERT: High CPU usage: ${CPU_USAGE}%"
fi

if (( $MEMORY_USAGE > $MEMORY_THRESHOLD )); then
    echo "ALERT: High memory usage: $((MEMORY_USAGE / 1024))MB"
fi

if (( $ERROR_COUNT > $ERROR_THRESHOLD )); then
    echo "ALERT: High error count: $ERROR_COUNT in last hour"
fi
```

---

## Support and Documentation

- **GitHub Repository**: https://github.com/your-org/SentinelEdge
- **Documentation**: https://docs.sentineledge.io
- **Issues**: https://github.com/your-org/SentinelEdge/issues
- **Community**: https://discord.gg/sentineledge

For production support, please contact: support@sentineledge.io