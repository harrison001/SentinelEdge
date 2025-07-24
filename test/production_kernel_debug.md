# 🏭 生产环境内核调试方案

## 🎯 **核心问题分析**

**问题：** 生产环境内核未开启KGDB，如何进行内核级eBPF调试？

**制约因素：**
- 生产内核未编译KGDB支持 (`CONFIG_KGDB=n`)
- 不能随意重启或替换生产内核
- 需要保持生产环境稳定性

---

## 📊 **方案可行性对比**

| 方案 | 可行性 | 风险 | 调试深度 | 适用性 |
|------|--------|------|----------|--------|
| **符号文件匹配** | ⚠️ 部分可行 | 🟢 低 | 🟡 中等 | 静态分析 |
| **Live Kernel 调试** | ❌ 不可行 | 🔴 高 | 🔴 无 | KGDB必需 |
| **Crash Dump 分析** | ✅ 完全可行 | 🟢 低 | 🟢 高 | 事后分析 |
| **运行时观测** | ✅ 完全可行 | 🟢 低 | 🟡 中等 | 实时监控 |
| **QEMU 模拟** | ✅ 完全可行 | 🟢 低 | 🟢 高 | 复现调试 |

---

## 🔍 **方案1: 符号文件匹配调试 (部分可行)**

### 可行性分析
```bash
# ✅ 可以做到的：
- 获取准确的符号地址
- 分析内核数据结构
- 理解代码逻辑和调用关系
- 静态分析eBPF程序加载位置

# ❌ 无法做到的：
- 实时断点调试 (需要KGDB)
- 单步执行 (需要调试支持)
- 修改内存内容
- 动态跟踪执行流程
```

### 实现步骤
```bash
# 1. 获取生产内核配置
scp production:/boot/config-$(uname -r) ./config-production

# 2. 获取相同版本内核源码
wget https://kernel.org/pub/linux/kernel/v5.x/linux-5.15.0.tar.xz
tar -xf linux-5.15.0.tar.xz && cd linux-5.15.0

# 3. 使用生产配置编译
cp ../config-production .config
make oldconfig

# 4. 添加调试符号 (不影响运行时)
scripts/config --enable DEBUG_INFO
scripts/config --enable DEBUG_INFO_DWARF4
scripts/config --enable DEBUG_KERNEL

# 5. 编译获取符号文件
make -j$(nproc) vmlinux
# 注意：只编译vmlinux，不需要完整内核
```

### 符号匹配验证
```bash
# 验证符号地址是否匹配
readelf -s vmlinux | grep sys_bpf
cat /proc/kallsyms | grep sys_bpf

# 地址应该相同（如果内核版本、配置、编译器完全一致）
```

---

## 🔍 **方案2: 基于Crash Dump的离线调试 (推荐)**

### 原理
即使生产内核没有KGDB，也可以通过crash dump进行深度分析：

```bash
# 1. 配置crash dump收集
echo 1 > /proc/sys/kernel/sysrq
echo c > /proc/sysrq-trigger  # 触发crash dump

# 2. 使用crash工具分析
crash vmlinux /proc/kcore
```

### Crash 调试会话示例
```bash
# 启动crash分析
crash vmlinux /proc/kcore

# 在crash中分析eBPF
crash> mod -l | grep bpf          # 查看BPF模块
crash> struct bpf_prog            # 查看BPF程序结构
crash> search -k bpf_prog_array   # 搜索BPF程序数组
crash> bt                         # 查看调用栈
```

---

## 🔍 **方案3: 运行时观测调试 (最实用)**

### 基于已有内核功能
```bash
# 1. 使用ftrace (内核自带)
echo 1 > /sys/kernel/debug/tracing/events/bpf/enable
cat /sys/kernel/debug/tracing/trace_pipe

# 2. 使用perf (生产环境友好)
perf record -e bpf:* -a sleep 10
perf script

# 3. 使用bpftrace (如果可用)
bpftrace -e 'kprobe:bpf_prog_run { printf("BPF prog run: %p\n", arg0); }'
```

### 生产环境安全的eBPF监控
```c
// monitor_ebpf.bpf.c - 监控其他eBPF程序
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct bpf_event {
    __u64 timestamp;
    __u32 prog_id;
    __u64 runtime_ns;
    char prog_name[16];
};

// 监控BPF程序执行
SEC("kprobe/bpf_prog_run")
int monitor_bpf_run(struct pt_regs *ctx) {
    struct bpf_prog *prog = (struct bpf_prog *)PT_REGS_PARM1(ctx);
    
    struct bpf_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->prog_id = BPF_CORE_READ(prog, aux, id);
    BPF_CORE_READ_STR_INTO(&event->prog_name, prog, aux, name);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## 🔍 **方案4: QEMU完全模拟调试**

### 构建相同环境
```bash
# 1. 克隆生产环境配置
# 复制 /boot/config, /proc/cpuinfo, /proc/meminfo 等

# 2. 编译完全相同的调试内核
make menuconfig  # 启用所有调试选项
make -j$(nproc)

# 3. 创建相同的根文件系统
# 包含相同的eBPF程序、库版本等

# 4. QEMU启动调试
qemu-system-x86_64 -kernel vmlinuz -initrd rootfs.cpio.gz \
    -append "console=ttyS0 kgdboc=ttyS1 kgdbwait" \
    -serial stdio -serial tcp::1234,server,nowait
```

---

## 💡 **生产环境调试最佳实践**

### 1. 无侵入性监控
```bash
# 使用现有的观测点
echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_bpf/enable
echo 1 > /sys/kernel/debug/tracing/events/bpf/bpf_prog_load/enable

# 监控eBPF程序状态
while true; do
    bpftool prog list > /tmp/bpf_progs_$(date +%s)
    bpftool map list > /tmp/bpf_maps_$(date +%s)
    sleep 5
done
```

### 2. 符号文件的正确使用
```gdb
# 即使无法live调试，也可以用于静态分析
gdb vmlinux
(gdb) info address sys_bpf
(gdb) disassemble bpf_prog_run
(gdb) print sizeof(struct bpf_prog)

# 分析core dump
gdb vmlinux core.dump
(gdb) bt
(gdb) info registers
```

### 3. 远程符号分析
```python
#!/usr/bin/env python3
# analyze_symbols.py
import subprocess
import re

def get_production_kallsyms():
    """从生产环境获取符号表"""
    result = subprocess.run(['cat', '/proc/kallsyms'], 
                          capture_output=True, text=True)
    return result.stdout

def get_vmlinux_symbols():
    """从编译的vmlinux获取符号"""
    result = subprocess.run(['nm', 'vmlinux'], 
                          capture_output=True, text=True)
    return result.stdout

def compare_symbols():
    """比较符号地址是否匹配"""
    prod_syms = get_production_kallsyms()
    vmlinux_syms = get_vmlinux_symbols()
    
    # 分析关键eBPF符号
    ebpf_functions = ['sys_bpf', 'bpf_prog_run', 'bpf_map_update_elem']
    
    for func in ebpf_functions:
        prod_addr = re.search(f'([0-9a-f]+) . {func}', prod_syms)
        vmlinux_addr = re.search(f'([0-9a-f]+) . {func}', vmlinux_syms)
        
        if prod_addr and vmlinux_addr:
            print(f"{func}:")
            print(f"  生产环境: 0x{prod_addr.group(1)}")
            print(f"  vmlinux:  0x{vmlinux_addr.group(1)}")
            print(f"  匹配: {prod_addr.group(1) == vmlinux_addr.group(1)}")

if __name__ == "__main__":
    compare_symbols()
```

---

## 🎯 **结论和建议**

### ✅ **可行的方案：**

1. **静态符号分析** - 编译相同版本内核获取vmlinux，用于代码分析
2. **运行时观测** - 使用ftrace、perf、bpftrace等现有工具  
3. **Crash dump分析** - 事后深度分析
4. **QEMU模拟** - 完全复现环境进行调试

### ❌ **不可行的方案：**

1. **实时KGDB调试** - 必须内核支持，无法绕过
2. **动态断点** - 需要调试接口支持

### 🚀 **推荐策略：**

```bash
# 1. 编译符号匹配的vmlinux (用于静态分析)
# 2. 使用运行时观测工具 (实时监控)  
# 3. QEMU环境复现问题 (深度调试)
# 4. 必要时收集crash dump (事后分析)
```

**总结：虽然无法在生产环境进行live内核调试，但通过组合使用多种方案，仍能实现深度的eBPF调试和问题定位！** 🎯 