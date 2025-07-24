#!/bin/bash

echo "🔧 设置 QEMU + GDB 内核调试环境"
echo "================================="

# 1. 检查必要文件
echo "📋 1. 检查调试文件："
if [ -f vmlinux ]; then
    echo "   ✅ vmlinux 符号文件存在"
    file vmlinux
else
    echo "   ❌ vmlinux 符号文件不存在"
    echo "   💡 需要编译内核获取 vmlinux，或从 /boot/ 复制"
    echo "   sudo cp /boot/vmlinuz-$(uname -r) ./vmlinuz"
    echo "   sudo cp /usr/lib/debug/boot/vmlinux-$(uname -r) ./vmlinux"
fi

# 2. 创建最小根文件系统
echo ""
echo "📦 2. 创建最小 rootfs："
if [ ! -f rootfs.cpio.gz ]; then
    echo "   创建最小根文件系统..."
    mkdir -p rootfs/{bin,sbin,etc,proc,sys,dev}
    
    # 复制必要的二进制文件
    cp /bin/busybox rootfs/bin/
    cp /bin/bash rootfs/bin/ 2>/dev/null || cp /bin/sh rootfs/bin/sh
    cp -a simple.bpf.o rootfs/ 2>/dev/null || echo "   ⚠️  simple.bpf.o 未找到"
    cp -a target/release/simple-ebpf-loader rootfs/ 2>/dev/null || echo "   ⚠️  可执行文件未找到"
    
    # 创建基本文件
    cat > rootfs/init << 'EOF'
#!/bin/sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t debugfs debugfs /sys/kernel/debug
echo "🚀 调试内核启动完成"
echo "💡 使用以下命令测试 eBPF："
echo "   ./simple-ebpf-loader"
/bin/sh
EOF
    chmod +x rootfs/init
    
    # 打包rootfs
    cd rootfs && find . | cpio -o -H newc | gzip > ../rootfs.cpio.gz && cd ..
    echo "   ✅ rootfs.cpio.gz 创建完成"
else
    echo "   ✅ rootfs.cpio.gz 已存在"
fi

# 3. 创建QEMU启动脚本
echo ""
echo "🚀 3. 创建 QEMU 启动脚本："
cat > start_debug_kernel.sh << 'EOF'
#!/bin/bash

# QEMU调试内核启动脚本
echo "🔧 启动调试内核..."
echo "💡 在另一个终端运行: gdb vmlinux"
echo "💡 然后在GDB中执行: target remote :1234"

# 检查KVM支持
if [ -c /dev/kvm ]; then
    ACCEL="-enable-kvm"
    echo "   ✅ 使用 KVM 加速"
else
    ACCEL=""
    echo "   ⚠️  KVM 不可用，使用软件模拟"
fi

# 启动QEMU
qemu-system-x86_64 \
    -kernel vmlinuz \
    -initrd rootfs.cpio.gz \
    -append "console=ttyS0 nokaslr debug" \
    -nographic \
    -s -S \
    $ACCEL \
    -m 2G \
    -smp 2
EOF
chmod +x start_debug_kernel.sh

# 4. 创建GDB调试脚本
echo ""
echo "🐛 4. 创建 GDB 调试脚本："
cat > debug_ebpf.gdb << 'EOF'
# GDB eBPF 调试脚本

# 连接到QEMU
target remote :1234

# 设置搜索路径
set solib-search-path .

# 加载内核符号
symbol-file vmlinux

# eBPF相关断点
echo "🔍 设置 eBPF 相关断点...\n"

# 1. BPF系统调用入口
break sys_bpf
commands
    printf "📞 BPF系统调用: cmd=%d\n", $rdi
    continue
end

# 2. BPF程序执行入口
break bpf_prog_run_generic
commands
    printf "🚀 BPF程序执行: prog=%p\n", $rdi
    # 可以在这里添加条件，只关注特定程序
    continue
end

# 3. Tracepoint触发
break perf_trace_sys_enter
commands
    printf "📍 Tracepoint触发: id=%d\n", $rsi
    # 检查是否是execve (通常是ID 786)
    if $rsi == 786
        printf "🎯 EXECVE Tracepoint 触发!\n"
        # 在这里可以单步调试
        break
    end
    continue
end

# 4. Map操作断点
break bpf_map_update_elem
commands
    printf "🗺️  Map更新: map=%p, key=%p, value=%p\n", $rdi, $rsi, $rdx
    continue
end

# 5. Ring buffer操作
break bpf_ringbuf_reserve
commands
    printf "💍 Ring buffer 预留: size=%ld\n", $rsi
    continue
end

# 定义有用的调试函数
define dump_bpf_insn
    printf "BPF指令: code=0x%02x, dst=%d, src=%d, off=%d, imm=0x%08x\n", \
           ((struct bpf_insn *)$arg0)->code, \
           ((struct bpf_insn *)$arg0)->dst_reg, \
           ((struct bpf_insn *)$arg0)->src_reg, \
           ((struct bpf_insn *)$arg0)->off, \
           ((struct bpf_insn *)$arg0)->imm
end

define show_bpf_ctx
    printf "BPF上下文信息:\n"
    printf "  指令指针: %p\n", $rip
    printf "  寄存器状态:\n"
    printf "    rax: 0x%016lx\n", $rax
    printf "    rbx: 0x%016lx\n", $rbx
    printf "    rcx: 0x%016lx\n", $rcx
    printf "    rdx: 0x%016lx\n", $rdx
end

echo "🎯 eBPF 调试环境已设置\n"
echo "💡 使用 'c' 继续执行，程序会在相关断点停止\n"
echo "💡 使用 'show_bpf_ctx' 显示BPF上下文\n"
echo "💡 使用 'dump_bpf_insn <addr>' 显示BPF指令\n"

# 继续执行
continue
EOF

echo "   ✅ debug_ebpf.gdb 创建完成"

echo ""
echo "📖 5. 使用说明："
echo "==============="
echo ""
echo "🚀 启动调试："
echo "   1. 终端1: ./start_debug_kernel.sh"
echo "   2. 终端2: gdb -x debug_ebpf.gdb"
echo ""
echo "🔍 在GDB中调试："
echo "   (gdb) break __do_execve      # 在execve处断点"
echo "   (gdb) condition 1 strcmp(filename, \"./simple-ebpf-loader\") == 0"
echo "   (gdb) c                      # 继续执行"
echo ""
echo "🎯 测试eBPF程序："
echo "   在QEMU中执行: ./simple-ebpf-loader"
echo ""
echo "💡 高级调试："
echo "   (gdb) watch *((uint64_t*)map_address)  # 监视map变化"
echo "   (gdb) trace bpf_map_update_elem        # 跟踪map更新"
echo "" 