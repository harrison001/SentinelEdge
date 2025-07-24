#!/bin/bash

echo "🔧 设置本机内核调试 (KGDB)"
echo "=========================="

# 1. 检查内核配置
echo "📋 1. 检查内核调试支持："
if grep -q "CONFIG_KGDB=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo "   ✅ KGDB 支持已启用"
else
    echo "   ❌ KGDB 支持未启用"
    echo "   💡 需要重新编译内核启用 CONFIG_KGDB=y"
fi

if grep -q "CONFIG_KGDB_SERIAL_CONSOLE=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo "   ✅ KGDB 串口控制台支持已启用"
else
    echo "   ⚠️  KGDB 串口控制台支持未启用"
fi

# 2. 检查 vmlinux 符号文件
echo ""
echo "📋 2. 检查符号文件："
if [ -f vmlinux ]; then
    echo "   ✅ vmlinux 符号文件存在"
    file vmlinux | head -1
elif [ -f /usr/lib/debug/boot/vmlinux-$(uname -r) ]; then
    echo "   ✅ 系统 vmlinux 存在: /usr/lib/debug/boot/vmlinux-$(uname -r)"
    echo "   📋 复制到当前目录..."
    sudo cp /usr/lib/debug/boot/vmlinux-$(uname -r) ./vmlinux
elif [ -f /proc/kcore ]; then
    echo "   ⚠️  可以使用 /proc/kcore 作为符号源"
else
    echo "   ❌ 未找到内核符号文件"
fi

# 3. 设置 KGDB 参数
echo ""
echo "🔧 3. KGDB 设置选项："
echo "选择调试方式："
echo "   1) 通过串口调试 (需要两台机器)"
echo "   2) 通过网络调试 (kgdboe)"
echo "   3) 通过 KDB 本机调试"
echo "   4) 通过 Magic SysRq 触发"

read -p "请选择 [1-4]: " choice

case $choice in
    1)
        echo ""
        echo "📡 串口调试设置："
        echo "   在 GRUB 中添加内核参数:"
        echo "   kgdboc=ttyS0,115200 kgdbwait"
        echo ""
        echo "   连接方式:"
        echo "   调试机: gdb vmlinux"
        echo "   (gdb) target remote /dev/ttyS1"
        ;;
    2)
        echo ""
        echo "🌐 网络调试设置："
        echo "   在 GRUB 中添加内核参数:"
        echo "   kgdboe=@192.168.1.100/,@192.168.1.200/"
        echo "   (替换为实际IP地址)"
        ;;
    3)
        echo ""
        echo "🖥️  KDB 本机调试设置："
        echo "   在 GRUB 中添加内核参数:"
        echo "   kgdboc=kbd kdb=on"
        echo ""
        echo "   触发调试:"
        echo "   echo g > /proc/sysrq-trigger"
        ;;
    4)
        echo ""
        echo "⚡ Magic SysRq 调试："
        echo "   启用 SysRq:"
        echo "   echo 1 > /proc/sys/kernel/sysrq"
        echo ""
        echo "   触发内核调试器:"
        echo "   Alt + SysRq + g  (或 echo g > /proc/sysrq-trigger)"
        ;;
esac

# 4. 创建 GDB 脚本用于本机调试
echo ""
echo "🐛 4. 创建本机调试 GDB 脚本："
cat > debug_local_kernel.gdb << 'EOF'
# 本机内核调试 GDB 脚本

# 加载内核符号
symbol-file vmlinux

# 或者使用 /proc/kcore (实时内核内存)
# core-file /proc/kcore

echo "🔍 本机内核调试环境\n"

# eBPF 相关断点 (需要内核支持调试)
define setup_ebpf_breakpoints
    echo "设置 eBPF 调试断点...\n"
    
    # 如果可以连接到调试会话
    if $kgdb_connected
        # BPF 系统调用
        break sys_bpf
        break bpf_prog_load
        break bpf_prog_run
        
        # Tracepoint 相关
        break perf_trace_sys_enter
        break trace_event_buffer_reserve
        
        # Map 操作
        break bpf_map_update_elem
        break bpf_map_lookup_elem
        
        echo "✅ eBPF 断点已设置\n"
    else
        echo "⚠️  需要先建立 KGDB 连接\n"
    end
end

# 显示当前 BPF 程序
define show_bpf_progs
    if $kgdb_connected
        printf "当前加载的 BPF 程序:\n"
        # 这需要访问内核数据结构
        # p *((struct bpf_prog_aux *)prog_aux)->prog
    else
        echo "需要在调试会话中执行\n"
    end
end

# 转储 BPF 指令
define dump_bpf_prog
    set $prog = (struct bpf_prog *)$arg0
    set $insns = (struct bpf_insn *)$prog->insnsi
    set $len = $prog->len
    
    printf "BPF 程序转储 (长度: %d):\n", $len
    set $i = 0
    while $i < $len
        set $insn = $insns[$i]
        printf "[%3d] %02x %1x %1x %04x %08x\n", \
               $i, $insn.code, $insn.dst_reg, $insn.src_reg, \
               $insn.off, $insn.imm
        set $i = $i + 1
    end
end

echo "💡 可用命令:\n"
echo "  setup_ebpf_breakpoints - 设置 eBPF 断点\n"
echo "  show_bpf_progs        - 显示 BPF 程序\n"
echo "  dump_bpf_prog <addr>  - 转储 BPF 程序\n"
EOF

# 5. 创建实时内核分析脚本
echo ""
echo "📊 5. 创建实时内核分析脚本："
cat > analyze_kernel_live.py << 'EOF'
#!/usr/bin/env python3
"""
实时内核 eBPF 分析工具
使用 /proc/kcore 和符号表分析正在运行的内核
"""

import re
import sys
import struct
import mmap

class KernelAnalyzer:
    def __init__(self, vmlinux_path="vmlinux"):
        self.vmlinux_path = vmlinux_path
        self.symbols = self.load_symbols()
        
    def load_symbols(self):
        """加载内核符号表"""
        symbols = {}
        try:
            # 从 /proc/kallsyms 读取符号
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        addr = int(parts[0], 16)
                        symbol_type = parts[1]
                        name = parts[2]
                        symbols[name] = addr
        except Exception as e:
            print(f"⚠️  无法读取符号表: {e}")
        return symbols
    
    def find_bpf_progs(self):
        """查找当前加载的 BPF 程序"""
        print("🔍 查找 BPF 程序...")
        
        # 这需要内核数据结构知识
        # 简化版本：查找 bpf 相关符号
        bpf_symbols = {k: v for k, v in self.symbols.items() 
                      if 'bpf' in k.lower()}
        
        print(f"📋 找到 {len(bpf_symbols)} 个 BPF 相关符号:")
        for name, addr in sorted(bpf_symbols.items())[:10]:
            print(f"  {name:30} @ 0x{addr:016x}")
    
    def monitor_execve(self):
        """监控 execve 调用"""
        if 'sys_execve' in self.symbols:
            addr = self.symbols['sys_execve']
            print(f"📍 sys_execve 地址: 0x{addr:016x}")
        else:
            print("❌ 未找到 sys_execve 符号")

if __name__ == "__main__":
    analyzer = KernelAnalyzer()
    analyzer.find_bpf_progs()
    analyzer.monitor_execve()
EOF
chmod +x analyze_kernel_live.py

echo ""
echo "📖 6. 使用说明："
echo "==============="
echo ""
echo "🚀 方法A - 使用 Magic SysRq (最简单):"
echo "   1. sudo echo 1 > /proc/sys/kernel/sysrq"
echo "   2. 运行您的 eBPF 程序"
echo "   3. sudo echo g > /proc/sysrq-trigger  # 进入调试器"
echo "   4. 在另一个终端: gdb -x debug_local_kernel.gdb"
echo ""
echo "🔍 方法B - 实时分析:"
echo "   python3 analyze_kernel_live.py"
echo ""
echo "💡 方法C - 添加内核参数重启:"
echo "   编辑 /etc/default/grub，添加:"
echo "   GRUB_CMDLINE_LINUX=\"kgdboc=kbd kdb=on\""
echo "   sudo update-grub && sudo reboot"
echo "" 