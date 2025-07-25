# 🔧 SentinelEdge Operations Guide

This guide provides operational procedures, troubleshooting, and maintenance for SentinelEdge in production environments.

## 📋 Table of Contents

- [Operational Procedures](#operational-procedures)
- [Monitoring & Alerting](#monitoring--alerting)
- [Performance Optimization](#performance-optimization)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Incident Response](#incident-response)
- [Capacity Planning](#capacity-planning)
- [Security Operations](#security-operations)

## Operational Procedures

### Startup Procedures

#### 1. Pre-startup Checks
```bash
#!/bin/bash
# pre-startup-check.sh

echo "=== SentinelEdge Pre-startup Checklist ==="

# Check system requirements
echo "Checking system requirements..."
KERNEL_VERSION=$(uname -r)
MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)

echo "Kernel: $KERNEL_VERSION"
echo "Memory: ${MEMORY_GB}GB"
echo "CPU Cores: $CPU_CORES"

# Check eBPF support
if [ ! -d "/sys/fs/bpf" ]; then
    echo "ERROR: BPF filesystem not mounted"
    exit 1
fi

# Check permissions
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

# Check configuration
if ! sentinel-edge --config /etc/sentineledge/config.toml --check-config; then
    echo "ERROR: Configuration validation failed"
    exit 1
fi

# Check disk space
DISK_USAGE=$(df /var/log/sentineledge | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    echo "WARNING: Disk usage is ${DISK_USAGE}%"
fi

echo "✅ Pre-startup checks completed"
```

#### 2. Startup Process
```bash
#!/bin/bash
# startup-sentineledge.sh

echo "Starting SentinelEdge..."

# Start service
sudo systemctl start sentineledge

# Wait for startup
sleep 10

# Verify startup
if systemctl is-active --quiet sentineledge; then
    echo "✅ SentinelEdge started successfully"
    
    # Check health endpoint
    if curl -f http://localhost:8080/health > /dev/null 2>&1; then
        echo "✅ Health check passed"
    else
        echo "⚠️ Health check failed"
    fi
else
    echo "❌ SentinelEdge failed to start"
    journalctl -u sentineledge --no-pager -n 20
    exit 1
fi
```

### Shutdown Procedures

#### 1. Graceful Shutdown
```bash
#!/bin/bash
# shutdown-sentineledge.sh

echo "Shutting down SentinelEdge gracefully..."

# Send shutdown signal
sudo systemctl stop sentineledge

# Wait for graceful shutdown
TIMEOUT=30
COUNTER=0

while systemctl is-active --quiet sentineledge && [ $COUNTER -lt $TIMEOUT ]; do
    echo "Waiting for shutdown... ($COUNTER/$TIMEOUT)"
    sleep 1
    ((COUNTER++))
done

if systemctl is-active --quiet sentineledge; then
    echo "⚠️ Forceful shutdown required"
    sudo systemctl kill sentineledge
    sleep 5
fi

echo "✅ SentinelEdge stopped"

# Check for any remaining processes
if pgrep sentinel-edge > /dev/null; then
    echo "⚠️ Found remaining processes:"
    pgrep sentinel-edge | xargs ps -p
fi
```

#### 2. Emergency Shutdown
```bash
#!/bin/bash
# emergency-shutdown.sh

echo "EMERGENCY SHUTDOWN of SentinelEdge"

# Kill all processes immediately
sudo pkill -9 sentinel-edge

# Clean up BPF programs
sudo bpftool prog show | grep sentinel | awk '{print $1}' | sed 's/:$//' | xargs -I {} sudo bpftool prog del id {}

# Clean up BPF maps
sudo bpftool map show | grep sentinel | awk '{print $1}' | sed 's/:$//' | xargs -I {} sudo bpftool map del id {}

echo "✅ Emergency shutdown completed"
```

### Configuration Management

#### 1. Configuration Validation
```bash
#!/bin/bash
# validate-config.sh

CONFIG_FILE="/etc/sentineledge/config.toml"

echo "Validating configuration: $CONFIG_FILE"

# Syntax validation
if ! sentinel-edge --config "$CONFIG_FILE" --check-config; then
    echo "❌ Configuration validation failed"
    exit 1
fi

# Security validation
if grep -q "password.*=" "$CONFIG_FILE"; then
    echo "⚠️ Warning: Plain text passwords found in config"
fi

# Performance validation
RING_BUFFER_SIZE=$(grep ring_buffer_size "$CONFIG_FILE" | awk '{print $3}')
if [ "$RING_BUFFER_SIZE" -lt 65536 ]; then
    echo "⚠️ Warning: Ring buffer size might be too small"
fi

echo "✅ Configuration validation completed"
```

#### 2. Configuration Backup and Restore
```bash
#!/bin/bash
# config-backup.sh

BACKUP_DIR="/backup/sentineledge/config/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup current configuration
cp -r /etc/sentineledge/* "$BACKUP_DIR/"

# Create metadata
cat > "$BACKUP_DIR/metadata.json" << EOF
{
    "backup_time": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "sentinel_version": "$(sentinel-edge --version)",
    "config_hash": "$(sha256sum /etc/sentineledge/config.toml | awk '{print $1}')"
}
EOF

echo "Configuration backed up to: $BACKUP_DIR"
```

## Monitoring & Alerting

### Key Metrics to Monitor

#### System Health Metrics
```bash
# Check system resources
ps aux | grep sentinel-edge | awk '{print "CPU: " $3 "%, Memory: " $4 "%"}'

# Check eBPF program status
bpftool prog show | grep sentinel

# Check ring buffer statistics
cat /sys/kernel/debug/tracing/events/sentinel/*/enable
```

#### Performance Metrics
- **Event Processing Rate**: Events/second processed
- **Event Drop Rate**: Events/second dropped
- **Memory Usage**: RSS and virtual memory
- **CPU Usage**: CPU percentage
- **Ring Buffer Utilization**: Buffer fill percentage

#### Business Metrics
- **Security Events**: Number of security events detected
- **Threat Detection**: Number of threats identified
- **System Coverage**: Percentage of system monitored

### Alerting Rules

#### Critical Alerts
```yaml
# Prometheus alerting rules
groups:
- name: sentineledge-critical
  rules:
  - alert: SentinelEdgeServiceDown
    expr: up{job="sentineledge"} == 0
    for: 30s
    labels:
      severity: critical
      team: security
    annotations:
      summary: "SentinelEdge service is down"
      description: "SentinelEdge has been down for {{ $for }}"
      runbook: "https://ops.company.com/runbooks/sentineledge-down"

  - alert: HighEventDropRate
    expr: rate(sentinel_events_dropped_total[5m]) > 100
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High event drop rate detected"
      description: "Dropping {{ $value }} events/sec for {{ $for }}"

  - alert: MemoryExhaustion
    expr: sentinel_memory_usage_bytes > 2147483648  # 2GB
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "SentinelEdge memory exhaustion"
      description: "Memory usage: {{ $value | humanizeBytes }}"
```

#### Warning Alerts
```yaml
- name: sentineledge-warning
  rules:
  - alert: HighCPUUsage
    expr: sentinel_cpu_usage_percent > 80
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage"
      description: "CPU usage: {{ $value }}%"

  - alert: RingBufferPressure
    expr: sentinel_ring_buffer_utilization_percent > 75
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Ring buffer under pressure"
      description: "Buffer utilization: {{ $value }}%"
```

### Monitoring Dashboard

Key dashboard panels:

1. **Service Health**
   - Service uptime
   - Health check status
   - Version information

2. **Performance Metrics**
   - Event processing rate
   - CPU and memory usage
   - Ring buffer utilization

3. **Error Tracking**
   - Error rate by type
   - Failed events timeline
   - Recovery attempts

4. **Security Events**
   - Threat detection rate
   - Security event types
   - Alert timeline

## Performance Optimization

### Performance Tuning Checklist

#### 1. System-Level Optimizations
```bash
#!/bin/bash
# system-optimization.sh

echo "Applying system-level optimizations..."

# CPU frequency scaling
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Network optimizations
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.core.netdev_max_backlog=5000

# Memory optimizations
sudo sysctl -w vm.swappiness=1
sudo sysctl -w vm.dirty_ratio=15

# File system optimizations
sudo sysctl -w fs.file-max=2097152

echo "✅ System optimizations applied"
```

#### 2. Application-Level Optimizations
```bash
#!/bin/bash
# app-optimization.sh

CONFIG_FILE="/etc/sentineledge/config.toml"

# Auto-detect optimal settings
CPU_CORES=$(nproc)
MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')

# Calculate optimal ring buffer size (256KB per core, max 4MB)
RING_BUFFER_SIZE=$((256 * 1024 * CPU_CORES))
if [ $RING_BUFFER_SIZE -gt 4194304 ]; then
    RING_BUFFER_SIZE=4194304
fi

# Calculate optimal batch size (16 events per core)
BATCH_SIZE=$((16 * CPU_CORES))
if [ $BATCH_SIZE -gt 200 ]; then
    BATCH_SIZE=200
fi

# Calculate optimal event rate (1000 events per core per second)
MAX_EVENTS_PER_SEC=$((1000 * CPU_CORES))

echo "Recommended optimizations:"
echo "Ring buffer size: $RING_BUFFER_SIZE"
echo "Batch size: $BATCH_SIZE"
echo "Max events/sec: $MAX_EVENTS_PER_SEC"
```

### Performance Testing

#### 1. Load Testing
```bash
#!/bin/bash
# load-test.sh

echo "Starting SentinelEdge load test..."

# Generate system activity to trigger events
for i in {1..100}; do
    # File operations
    touch /tmp/test_file_$i
    rm /tmp/test_file_$i
    
    # Network operations
    ping -c 1 localhost > /dev/null 2>&1
    
    # Process operations
    sleep 0.001 &
done

wait

echo "Load test completed. Check metrics for performance data."
```

#### 2. Stress Testing
```bash
#!/bin/bash
# stress-test.sh

echo "Starting stress test..."

# Install stress-ng if needed
if ! command -v stress-ng &> /dev/null; then
    echo "Installing stress-ng..."
    sudo apt-get install -y stress-ng
fi

# CPU stress
stress-ng --cpu 2 --timeout 60s &
CPU_PID=$!

# Memory stress
stress-ng --vm 1 --vm-bytes 512M --timeout 60s &
MEM_PID=$!

# I/O stress
stress-ng --io 1 --timeout 60s &
IO_PID=$!

echo "Stress test running... Monitor SentinelEdge performance"
sleep 60

# Cleanup
kill $CPU_PID $MEM_PID $IO_PID 2>/dev/null
wait

echo "Stress test completed"
```

## Troubleshooting Guide

### Common Issues and Solutions

#### 1. Service Won't Start

**Symptoms**: systemctl status shows failed state

**Diagnosis**:
```bash
# Check logs
journalctl -u sentineledge -n 50

# Check configuration
sentinel-edge --config /etc/sentineledge/config.toml --check-config

# Check permissions
ls -la /usr/local/bin/sentinel-edge
id $(whoami)
```

**Solutions**:
```bash
# Fix permissions
sudo chown root:root /usr/local/bin/sentinel-edge
sudo chmod +x /usr/local/bin/sentinel-edge

# Fix configuration
sudo nano /etc/sentineledge/config.toml

# Check BPF support
ls -la /sys/fs/bpf/
dmesg | grep -i bpf
```

#### 2. High Memory Usage

**Symptoms**: Memory usage continuously increasing

**Diagnosis**:
```bash
# Check memory usage
ps aux | grep sentinel-edge
cat /proc/$(pgrep sentinel-edge)/status | grep VmRSS

# Check ring buffer usage
bpftool map show | grep sentinel
```

**Solutions**:
```bash
# Reduce ring buffer size
echo 'ring_buffer_size = 262144' >> /etc/sentineledge/config.toml

# Enable memory limits
systemctl edit sentineledge
# Add: MemoryMax=1G

# Restart service
sudo systemctl restart sentineledge
```

#### 3. High Event Drop Rate

**Symptoms**: Events being dropped frequently

**Diagnosis**:
```bash
# Check drop statistics
curl -s http://localhost:9090/metrics | grep dropped

# Check system load
uptime
iostat 1 5
```

**Solutions**:
```bash
# Increase buffer size
ring_buffer_size = 2097152  # 2MB

# Increase batch size
event_batch_size = 200

# Reduce polling timeout
ring_buffer_poll_timeout_us = 50

# Add more processing threads
max_events_per_sec = 20000
```

#### 4. eBPF Program Loading Fails

**Symptoms**: "Permission denied" or "Invalid argument" errors

**Diagnosis**:
```bash
# Check kernel version
uname -r

# Check BPF capabilities
capsh --print | grep bpf

# Check locked memory limits
ulimit -l
```

**Solutions**:
```bash
# Add capabilities
sudo setcap cap_bpf,cap_sys_admin+ep /usr/local/bin/sentinel-edge

# Increase locked memory
echo '* soft memlock unlimited' >> /etc/security/limits.conf
echo '* hard memlock unlimited' >> /etc/security/limits.conf

# Update kernel (if needed)
sudo apt update && sudo apt upgrade linux-generic
```

### Diagnostic Tools

#### 1. Health Check Script
```bash
#!/bin/bash
# health-check.sh

echo "=== SentinelEdge Health Check ==="
echo "Date: $(date)"
echo ""

# Service status
echo "Service Status:"
systemctl is-active sentineledge && echo "✅ Active" || echo "❌ Inactive"

# Process information
echo -e "\nProcess Information:"
ps aux | grep sentinel-edge | grep -v grep || echo "❌ No process found"

# Memory usage
echo -e "\nMemory Usage:"
if pgrep sentinel-edge > /dev/null; then
    ps -o pid,vsz,rss,pmem,comm -p $(pgrep sentinel-edge)
fi

# eBPF programs
echo -e "\neBPF Programs:"
bpftool prog show | grep sentinel || echo "No eBPF programs loaded"

# Network connectivity
echo -e "\nNetwork Connectivity:"
curl -s -o /dev/null -w "Health endpoint: %{http_code}\n" http://localhost:8080/health
curl -s -o /dev/null -w "Metrics endpoint: %{http_code}\n" http://localhost:9090/metrics

# Disk usage
echo -e "\nDisk Usage:"
df -h /var/log/sentineledge /var/lib/sentineledge

# Recent errors
echo -e "\nRecent Errors:"
journalctl -u sentineledge --since "1 hour ago" | grep -i error | tail -5 || echo "No recent errors"

echo -e "\n=== Health Check Complete ==="
```

#### 2. Performance Analysis
```bash
#!/bin/bash
# performance-analysis.sh

echo "=== Performance Analysis ==="

# CPU usage over time
echo "CPU Usage (5 samples):"
for i in {1..5}; do
    ps -o %cpu -p $(pgrep sentinel-edge) | tail -1 | tr -d ' '
    sleep 1
done | awk '{sum+=$1} END {print "Average CPU: " sum/NR "%"}'

# Memory growth analysis
echo -e "\nMemory Usage (5 samples):"
for i in {1..5}; do
    ps -o rss -p $(pgrep sentinel-edge) | tail -1 | tr -d ' '
    sleep 1
done | awk '{print $1/1024 " MB"}' | tail -5

# Event processing rate
echo -e "\nEvent Processing Rate:"
METRICS=$(curl -s http://localhost:9090/metrics)
echo "$METRICS" | grep sentinel_events_processed_total
echo "$METRICS" | grep sentinel_events_dropped_total

# Ring buffer utilization
echo -e "\nRing Buffer Status:"
echo "$METRICS" | grep sentinel_ring_buffer_utilization_percent

echo -e "\n=== Analysis Complete ==="
```

## Incident Response

### Incident Response Playbook

#### 1. Service Down Incident
```bash
#!/bin/bash
# incident-service-down.sh

echo "=== INCIDENT: SentinelEdge Service Down ==="
echo "Timestamp: $(date)"

# Immediate assessment
echo "Step 1: Service Assessment"
systemctl status sentineledge

# Check for obvious issues
echo -e "\nStep 2: Quick Diagnostics"
journalctl -u sentineledge -n 20 --no-pager

# Attempt restart
echo -e "\nStep 3: Restart Attempt"
sudo systemctl restart sentineledge
sleep 10

if systemctl is-active --quiet sentineledge; then
    echo "✅ Service recovered after restart"
else
    echo "❌ Service still down - escalating"
    
    # Gather diagnostics
    echo -e "\nStep 4: Detailed Diagnostics"
    
    # System resources
    free -h
    df -h
    uptime
    
    # Configuration check
    sentinel-edge --config /etc/sentineledge/config.toml --check-config
    
    # Process information
    ps aux | grep sentinel
    
    echo "Manual intervention required"
fi
```

#### 2. High Resource Usage Incident
```bash
#!/bin/bash
# incident-high-resources.sh

echo "=== INCIDENT: High Resource Usage ==="

# Get current usage
CPU_USAGE=$(ps -o %cpu -p $(pgrep sentinel-edge) | tail -1 | tr -d ' ')
MEMORY_USAGE=$(ps -o rss -p $(pgrep sentinel-edge) | tail -1 | tr -d ' ')

echo "Current CPU: ${CPU_USAGE}%"
echo "Current Memory: $((MEMORY_USAGE / 1024))MB"

# Immediate mitigation
if (( $(echo "$CPU_USAGE > 90" | bc -l) )); then
    echo "Applying CPU throttling..."
    renice 10 $(pgrep sentinel-edge)
fi

if (( MEMORY_USAGE > 2097152 )); then  # 2GB in KB
    echo "Memory usage critical - restarting service"
    sudo systemctl restart sentineledge
fi

# Monitor for 5 minutes
echo "Monitoring for 5 minutes..."
for i in {1..300}; do
    CPU_USAGE=$(ps -o %cpu -p $(pgrep sentinel-edge) 2>/dev/null | tail -1 | tr -d ' ')
    MEMORY_USAGE=$(ps -o rss -p $(pgrep sentinel-edge) 2>/dev/null | tail -1 | tr -d ' ')
    
    if [ -z "$CPU_USAGE" ]; then
        echo "Process disappeared - checking service status"
        break
    fi
    
    echo "$i: CPU=${CPU_USAGE}%, MEM=$((MEMORY_USAGE / 1024))MB"
    sleep 1
done
```

### Escalation Procedures

#### Level 1: Automated Response
- Service restart
- Configuration validation
- Resource monitoring

#### Level 2: Operations Team
- Manual diagnostics
- Configuration changes
- Performance tuning

#### Level 3: Engineering Team
- Code analysis
- Deep debugging
- Hotfixes

#### Level 4: Vendor Support
- Complex kernel issues
- eBPF program bugs
- Performance problems

## Capacity Planning

### Growth Monitoring

#### 1. Trend Analysis
```bash
#!/bin/bash
# capacity-trends.sh

echo "=== Capacity Trends Analysis ==="

# Historical data (requires time-series database)
echo "Analyzing 30-day trends..."

# Event processing growth
echo "Event Processing Trend:"
# Query historical metrics from Prometheus/InfluxDB
# prometheus-query 'rate(sentinel_events_processed_total[1d])' --range 30d

# Resource usage growth
echo "Resource Usage Trend:"
# prometheus-query 'sentinel_memory_usage_bytes' --range 30d
# prometheus-query 'sentinel_cpu_usage_percent' --range 30d

# Performance degradation
echo "Performance Metrics:"
# prometheus-query 'rate(sentinel_events_dropped_total[1d])' --range 30d
```

#### 2. Capacity Recommendations
```bash
#!/bin/bash
# capacity-recommendations.sh

# Current system specs
CPU_CORES=$(nproc)
MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
DISK_GB=$(df -BG /var/log/sentineledge | awk 'NR==2 {print $2}' | sed 's/G//')

# Current usage
CURRENT_CPU=$(ps -o %cpu -p $(pgrep sentinel-edge) | tail -1 | tr -d ' ')
CURRENT_MEM_MB=$(ps -o rss -p $(pgrep sentinel-edge) | tail -1 | tr -d ' ')
CURRENT_MEM_MB=$((CURRENT_MEM_MB / 1024))

echo "=== Capacity Recommendations ==="
echo "Current System: ${CPU_CORES} cores, ${MEMORY_GB}GB RAM, ${DISK_GB}GB disk"
echo "Current Usage: ${CURRENT_CPU}% CPU, ${CURRENT_MEM_MB}MB memory"

# Recommendations based on usage
if (( $(echo "$CURRENT_CPU > 70" | bc -l) )); then
    RECOMMENDED_CORES=$((CPU_CORES * 2))
    echo "⚠️ Recommend upgrading to $RECOMMENDED_CORES CPU cores"
fi

if (( CURRENT_MEM_MB > (MEMORY_GB * 1024 * 70 / 100) )); then
    RECOMMENDED_MEMORY=$((MEMORY_GB * 2))
    echo "⚠️ Recommend upgrading to ${RECOMMENDED_MEMORY}GB memory"
fi

# Growth projections
echo -e "\nGrowth Projections (next 12 months):"
echo "- Event volume: +25% (typical growth)"
echo "- Memory usage: +30% (with feature additions)"
echo "- CPU usage: +20% (with optimization improvements)"
```

### Scaling Guidelines

#### Vertical Scaling Triggers
- CPU usage > 70% sustained
- Memory usage > 80% sustained
- Event drop rate > 1%
- Response time > 100ms

#### Horizontal Scaling Considerations
- Multiple SentinelEdge instances per node
- Load balancing across instances
- Shared monitoring and alerting
- Centralized log aggregation

---

**For immediate operational support:**
- Escalation: ops-team@company.com
- Emergency: +1-XXX-XXX-XXXX
- Chat: #sentineledge-ops on Slack