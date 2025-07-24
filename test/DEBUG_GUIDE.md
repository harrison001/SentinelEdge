# 🐛 eBPF 深度调试指南

本指南提供**单步跟踪eBPF程序执行**的完整解决方案，实现 line-by-line 调试。

## 🎯 调试方法对比

| 方法 | 复杂度 | 功能深度 | 适用场景 |
|------|--------|----------|----------|
| **eBPF自身调试** | ⭐ | ⭐⭐⭐ | **推荐：最实用** |
| QEMU+GDB | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 深度内核调试 |
| 本机KGDB | ⭐⭐⭐ | ⭐⭐⭐⭐ | 生产环境调试 |
| bpftrace监控 | ⭐⭐ | ⭐⭐ | 快速验证 |

---

## 🚀 **方法1: eBPF自身调试 (推荐)**

### 编译调试版本
```bash
# 1. 编译调试版eBPF程序
clang -O2 -target bpf -c debug_simple.bpf.c -o debug_simple.bpf.o -g -mcpu=v3

# 2. 编译调试客户端
cd src && cargo build --release
```

### 运行调试
```bash
# 启动调试器
sudo ./target/release/debug_main

# 在调试器中使用命令:
(ebpf-debug) w    # 等待新执行
(ebpf-debug) t    # 单步分析
(ebpf-debug) s    # 显示状态
```

### 调试输出示例
```
🔍 === 单步执行分析 ===
✅ 步骤 0: 🚀 函数入口时间戳 = 1234567890
   ⏰ 分析: 时间戳 1234ms
✅ 步骤 1: 📋 获取PID = 12345
   🔍 分析: PID = 12345 (进程ID)
✅ 步骤 2: 📊 入口计数 = 1
✅ 步骤 3: 🔍 检查主计数器 = 0
✅ 步骤 4: ✏️ 更新主计数器 = 999
   🎉 分析: 主计数器成功更新为999!
✅ 步骤 5: ✅ 更新结果检查 = 1
   ✅ 分析: Map更新操作成功
⏱️ 总执行时间: 15423ns (15μs)
```

---

## 🔧 **方法2: QEMU + GDB 完整内核调试**

### 设置环境
```bash
./setup_kernel_debug.sh
```

### 启动调试
```bash
# 终端1: 启动QEMU调试内核
./start_debug_kernel.sh

# 终端2: 启动GDB调试
gdb -x debug_ebpf.gdb
```

### GDB调试会话
```gdb
(gdb) break perf_trace_sys_enter
(gdb) condition 1 $rsi == 786    # 只关注execve事件
(gdb) continue

# 当断点触发时
(gdb) show_bpf_ctx              # 显示BPF上下文
(gdb) dump_bpf_insn $rdi        # 显示BPF指令
(gdb) step                      # 单步执行
```

### 设置条件断点
```gdb
# 只在特定程序执行时断点
(gdb) break __do_execve
(gdb) condition 1 strcmp(filename, "./simple-ebpf-loader") == 0

# 监控Map更新
(gdb) break bpf_map_update_elem
(gdb) commands
    printf "Map更新: key=%p, value=%p\n", $rsi, $rdx
    continue
end
```

---

## 🖥️ **方法3: 本机内核调试 (KGDB)**

### 启用KGDB
```bash
# 1. 设置内核参数
sudo vim /etc/default/grub
# 添加: GRUB_CMDLINE_LINUX="kgdboc=kbd kdb=on"

# 2. 更新GRUB并重启
sudo update-grub && sudo reboot
```

### 触发调试
```bash
# 方法A: Magic SysRq
sudo echo 1 > /proc/sys/kernel/sysrq
sudo echo g > /proc/sysrq-trigger

# 方法B: KDB命令
# 按 Alt+SysRq+g
```

### GDB连接
```bash
# 在另一个终端
gdb vmlinux
(gdb) target remote :1234  # 如果通过网络
(gdb) setup_ebpf_breakpoints
```

---

## 🔍 **调试技巧和最佳实践**

### 1. eBPF代码调试技巧
```c
// 添加详细的bpf_trace_printk
bpf_trace_printk("🔍 步骤X: 变量=%d", 20, variable);

// 使用多个Map存储中间状态
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 20);  // 足够存储调试信息
} debug_info SEC(".maps");

// 记录每个操作的结果
long result = bpf_map_update_elem(&counter, &key, &val, 0);
__u32 debug_key = step++;
__u64 debug_val = (result == 0) ? 1 : 0;
bpf_map_update_elem(&debug_info, &debug_key, &debug_val, 0);
```

### 2. 常见问题诊断

#### 问题: eBPF程序不触发
```bash
# 检查tracepoint状态
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/enable

# 手动触发
strace -e execve /bin/echo "test" 2>&1 | grep execve
```

#### 问题: Map更新失败
```c
// 在eBPF中添加错误检查
long update_result = bpf_map_update_elem(&counter, &key, &val, 0);
if (update_result != 0) {
    bpf_trace_printk("❌ Map更新失败: %d", 20, (int)update_result);
}
```

#### 问题: 权限错误
```bash
# 检查eBPF权限
sudo sysctl kernel.unprivileged_bpf_disabled

# 临时启用
sudo sysctl kernel.unprivileged_bpf_disabled=0
```

### 3. 性能分析
```c
// 在eBPF中测量执行时间
__u64 start = bpf_ktime_get_ns();
// ... 执行操作 ...
__u64 end = bpf_ktime_get_ns();
__u64 duration = end - start;
bpf_trace_printk("⏱️ 耗时: %llu ns", 20, duration);
```

---

## 📊 **实时监控命令**

### 查看bpf_trace_printk输出
```bash
# 实时查看eBPF打印信息
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -E "(🚀|📋|✅|❌)"
```

### 监控系统调用
```bash
# 验证execve调用
strace -e execve -c /bin/echo "test"

# 使用perf监控
sudo perf trace -e syscalls:sys_enter_execve
```

### 检查BPF程序状态
```bash
# 列出当前BPF程序
sudo bpftool prog list

# 检查程序统计
sudo bpftool prog show id <ID> --pretty

# 查看Map内容
sudo bpftool map dump name counter
```

---

## 🎯 **故障排除流程**

### 第1步: 基础验证
```bash
# 1. 检查系统调用是否正常
strace -e execve /bin/echo "test"

# 2. 检查tracepoint是否存在
ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/

# 3. 检查eBPF程序是否加载
sudo bpftool prog list | grep trace
```

### 第2步: eBPF程序验证
```bash
# 1. 编译时添加调试信息
clang -O2 -target bpf -c debug_simple.bpf.c -o debug_simple.bpf.o -g -mcpu=v3

# 2. 检查编译输出
llvm-objdump -h debug_simple.bpf.o

# 3. 验证BTF信息
bpftool btf dump file debug_simple.bpf.o
```

### 第3步: 运行时调试
```bash
# 1. 启动调试版本
sudo ./debug_main

# 2. 在调试器中检查状态
(ebpf-debug) s    # 显示所有Map状态
(ebpf-debug) w    # 等待新执行
```

---

## 💡 **高级调试技巧**

### 条件断点
```gdb
# 只在特定PID时断点
(gdb) break bpf_map_update_elem
(gdb) condition 1 *(int*)($rsi) == 12345
```

### 内存监控
```gdb
# 监控Map内存变化
(gdb) watch *((uint64_t*)map_address)
```

### 自动化脚本
```bash
#!/bin/bash
# auto_debug.sh - 自动化调试脚本
while true; do
    echo "=== $(date) ==="
    sudo ./debug_main <<< "s"
    sleep 5
done
```

---

## 🚀 **快速开始**

```bash
# 1. 编译所有组件
clang -O2 -target bpf -c debug_simple.bpf.c -o debug_simple.bpf.o -g -mcpu=v3
cd src && cargo build --release

# 2. 启动调试
sudo ./target/release/debug_main

# 3. 在另一个终端触发事件
/bin/echo "trigger execve"

# 4. 在调试器中分析
(ebpf-debug) t    # 单步分析执行过程
```

**现在您可以实现真正的 line-by-line eBPF 调试！** 🎯 