#!/bin/bash

echo "=== SentinelEdge 真实eBPF性能测试 ==="
echo "当前用户: $(whoami)"

if [ "$EUID" -ne 0 ]; then
    echo "❌ 需要root权限，正在切换..."
    exec sudo "$0" "$@"
fi

echo "✅ Root权限确认"
echo "系统: $(uname -r)"
echo ""

cd /home/harrison/SentinelEdge/kernel-agent

echo "1. 检查eBPF支持..."
if [ ! -d "/sys/kernel/debug/tracing" ]; then
    echo "挂载tracefs..."
    mount -t tracefs tracefs /sys/kernel/debug/tracing
fi

echo "2. 编译release版本..."
sudo -u harrison /home/harrison/.cargo/bin/cargo build --release

echo ""
echo "3. 运行真实eBPF测试..."
echo "▶️ 开始eBPF程序加载测试..."
sudo -E /home/harrison/.cargo/bin/cargo test test_real_ebpf_loading --release --lib -- --nocapture --ignored

echo ""
echo "4. 运行性能压力测试..."
echo "▶️ 开始性能测试..."
sudo -E /home/harrison/.cargo/bin/cargo test test_real_performance_under_load --release --lib -- --nocapture --ignored

echo ""
echo "5. 运行完整集成测试..."
echo "▶️ 开始完整集成测试..."
sudo -E /home/harrison/.cargo/bin/cargo test test_full_real_integration --release --lib -- --nocapture --ignored

echo ""
echo "6. 实时内核事件捕获测试..."
echo "▶️ 测试实时事件捕获..."
timeout 5s sudo -E /home/harrison/.cargo/bin/cargo test test_real_event_capture --release --lib -- --nocapture --ignored

echo ""
echo "=== 测试完成 ==="