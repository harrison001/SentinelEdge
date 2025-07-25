#!/bin/bash

echo "=== SentinelEdge 真实Root权限测试 ==="
echo "请运行此脚本获得真正的eBPF拦截功能："
echo ""
echo "方法1: 直接运行"
echo "sudo bash run_as_root.sh"
echo ""
echo "方法2: 切换到root用户"
echo "sudo su -"
echo "cd /home/harrison/SentinelEdge/kernel-agent"
echo "export PATH=/home/harrison/.cargo/bin:\$PATH"
echo ""
echo "然后运行以下任一命令："
echo ""
echo "# 1. 基础eBPF加载测试"
echo "/home/harrison/.cargo/bin/cargo test test_real_ebpf_loading --release --lib -- --nocapture --ignored"
echo ""
echo "# 2. 完整集成测试" 
echo "/home/harrison/.cargo/bin/cargo test test_full_real_integration --release --lib -- --nocapture --ignored"
echo ""
echo "# 3. 性能测试"
echo "/home/harrison/.cargo/bin/cargo test test_real_performance_under_load --release --lib -- --nocapture --ignored"
echo ""
echo "# 4. 事件捕获测试"
echo "/home/harrison/.cargo/bin/cargo test test_real_event_capture --release --lib -- --nocapture --ignored"
echo ""
echo "# 5. 运行所有真实测试"
echo "/home/harrison/.cargo/bin/cargo test real_ebpf_tests --release --lib -- --nocapture --ignored"
echo ""
echo "=== 预期结果 ==="
echo "在真正的root环境下，你应该看到："
echo "✅ Successfully attached program: trace_execve"
echo "✅ Successfully attached program: trace_tcp_connect" 
echo "✅ Successfully attached program: trace_file_open"
echo "✅ Real eBPF program loaded and attached to kernel!"
echo "✅ Captured X real kernel events"
echo ""
echo "=== 如果你有密码访问权限 ==="
echo "1. 确保tracefs已挂载:"
echo "   mount -t tracefs tracefs /sys/kernel/debug/tracing"
echo ""
echo "2. 检查eBPF支持:"
echo "   ls /sys/kernel/debug/tracing/events/syscalls/"
echo ""
echo "3. 提升内存限制:"
echo "   ulimit -l unlimited"
echo ""

# 如果脚本本身以root运行，自动执行测试
if [ "$EUID" -eq 0 ]; then
    echo "检测到root权限，开始自动测试..."
    echo ""
    
    # 设置环境
    export PATH="/home/harrison/.cargo/bin:$PATH"
    cd /home/harrison/SentinelEdge/kernel-agent
    
    # 确保tracefs挂载
    if [ ! -d "/sys/kernel/debug/tracing/events" ]; then
        echo "挂载tracefs..."
        mount -t tracefs tracefs /sys/kernel/debug/tracing
    fi
    
    # 提升内存限制
    ulimit -l unlimited
    
    echo "运行完整eBPF真实测试..."
    /home/harrison/.cargo/bin/cargo test real_ebpf_tests --release --lib -- --nocapture --ignored
    
    echo ""
    echo "=== 测试完成 ==="
fi