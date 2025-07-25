#!/bin/bash

echo "=== 直接eBPF测试 ==="
echo "当前目录: $(pwd)"
echo "当前用户: $(whoami)"

# 直接运行单个测试
echo "1. 先检查eBPF对象是否存在..."
ls -la src/sentinel.bpf.o

echo ""
echo "2. 直接运行真实eBPF加载测试 (需要sudo密码):"
echo "sudo /home/harrison/.cargo/bin/cargo test test_real_ebpf_loading --release --lib -- --nocapture --ignored"