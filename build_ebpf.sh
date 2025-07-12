#!/bin/bash

# SentinelEdge eBPF build script
# Dependencies: clang, llvm, libbpf-dev, linux-headers

set -e

echo "🔨 Compiling eBPF programs..."

# Check dependencies
check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ Error: $1 not installed"
        echo "Please install: sudo apt-get install $2"
        exit 1
    fi
}

echo "📋 Checking dependencies..."
check_dependency clang "clang llvm"
check_dependency llc "llvm"

# Check kernel headers
if [ ! -d "/usr/src/linux-headers-$(uname -r)" ] && [ ! -d "/lib/modules/$(uname -r)/build" ]; then
    echo "❌ Error: Kernel headers not found"
    echo "Please install: sudo apt-get install linux-headers-$(uname -r)"
    exit 1
fi

# Set compilation parameters
KERNEL_SRC="/lib/modules/$(uname -r)/build"
BPF_SRC="kernel-agent/src/sentinel.bpf.c"
BPF_OBJ="kernel-agent/src/sentinel.bpf.o"

# Check vmlinux.h
VMLINUX_H="kernel-agent/src/vmlinux.h"
if [ ! -f "$VMLINUX_H" ]; then
    echo "📦 Generating vmlinux.h..."
    if command -v bpftool &> /dev/null; then
        sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_H"
    else
        echo "⚠️  bpftool not found, using pre-generated vmlinux.h"
        # Create a minimal vmlinux.h
        cat > "$VMLINUX_H" << 'EOF'
#pragma once

// Minimal vmlinux.h for SentinelEdge
// In production, use bpftool to generate complete version

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

// Basic kernel structure definitions
struct task_struct {
    int tgid;
    struct task_struct *real_parent;
};

struct sock {
    // Network socket basic structure
};

struct inet_sock {
    __u32 inet_saddr;
    __u32 inet_daddr; 
    __u16 inet_sport;
    __u16 inet_dport;
};

struct path {
    struct dentry *dentry;
};

struct dentry {
    struct {
        const char *name;
    } d_name;
};

struct trace_event_raw_sys_enter {
    unsigned long args[6];
};

struct pt_regs {
    // Register structure, architecture-dependent
};

#endif /* __VMLINUX_H__ */
EOF
    fi
fi

echo "🔨 Compiling eBPF object file..."

# Compile eBPF program
clang -O2 -g \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -I"$KERNEL_SRC/arch/x86/include" \
    -I"$KERNEL_SRC/arch/x86/include/generated" \
    -I"$KERNEL_SRC/include" \
    -I"$KERNEL_SRC/include/generated" \
    -I"$KERNEL_SRC/arch/x86/include/uapi" \
    -I"$KERNEL_SRC/arch/x86/include/generated/uapi" \
    -I"$KERNEL_SRC/include/uapi" \
    -I"$KERNEL_SRC/include/generated/uapi" \
    -I./kernel-agent/src \
    -c "$BPF_SRC" \
    -o "$BPF_OBJ"

if [ $? -eq 0 ]; then
    echo "✅ eBPF program compiled successfully: $BPF_OBJ"
    echo "📊 File information:"
    ls -lh "$BPF_OBJ"
    
    # Verify eBPF object
    if command -v llvm-objdump &> /dev/null; then
        echo "🔍 eBPF program information:"
        llvm-objdump -h "$BPF_OBJ"
    fi
else
    echo "❌ eBPF program compilation failed"
    exit 1
fi

echo "🎉 eBPF compilation complete!"
echo "💡 Usage:"
echo "   sudo ./target/release/sentinel-edge --demo"
echo "   sudo ./target/release/sentinel-edge --ebpf-demo" 