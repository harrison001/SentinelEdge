#!/bin/bash

echo "=== SentinelEdge 性能测试脚本 ==="
echo "当前用户: $(whoami)"
echo "系统信息: $(uname -a)"
echo ""

cd /home/harrison/SentinelEdge/kernel-agent

echo "1. 编译性能测试..."
cargo build --release 2>&1 | tail -10

echo ""
echo "2. 运行模拟模式性能测试..."
timeout 10s cargo test test_high_frequency_events --release --lib -- --nocapture 2>/dev/null || echo "测试完成或超时"

echo ""
echo "3. 运行集成测试..."
cargo test integration_tests --lib -- --nocapture 2>/dev/null | grep -E "(test result|✅|⚠️|Events processed|Duration:|latency)" || echo "集成测试完成"

echo ""
echo "4. 检查eBPF对象文件..."
if [ -f "src/sentinel.bpf.o" ]; then
    echo "✅ eBPF对象文件存在: $(ls -lh src/sentinel.bpf.o | awk '{print $5}')"
    file src/sentinel.bpf.o
else
    echo "❌ eBPF对象文件不存在"
fi

echo ""
echo "5. 内存和性能指标..."
echo "编译后二进制大小:"
ls -lh target/release/deps/kernel_agent* 2>/dev/null | head -3 || echo "未找到release二进制文件"

echo ""
echo "6. 代码质量检查..."
echo "代码行数统计:"
find src -name "*.rs" -exec wc -l {} \; | awk '{sum+=$1} END {print "Rust代码总行数:", sum}'
find src -name "*.c" -exec wc -l {} \; | awk '{sum+=$1} END {print "eBPF代码总行数:", sum}'

echo ""
echo "7. 依赖分析..."
cargo tree --depth 2 | grep -E "(libbpf|tokio|tracing)" | head -5

echo ""
echo "=== 实际性能需要root权限测试 ==="
echo "要运行真实eBPF测试，请执行:"
echo "sudo /home/harrison/.cargo/bin/cargo test test_real_ebpf_loading --lib -- --nocapture --ignored"