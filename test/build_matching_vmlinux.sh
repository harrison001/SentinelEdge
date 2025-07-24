#!/bin/bash

echo "🔧 构建符号匹配的vmlinux用于生产环境调试"
echo "============================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. 收集生产环境信息
echo ""
log_info "📋 步骤1: 收集生产环境信息"
echo "=============================="

KERNEL_VERSION=$(uname -r)
KERNEL_ARCH=$(uname -m)
COMPILER_VERSION=$(gcc --version | head -1)

log_info "内核版本: $KERNEL_VERSION"
log_info "架构: $KERNEL_ARCH"  
log_info "编译器: $COMPILER_VERSION"

# 检查内核配置文件
CONFIG_PATHS=(
    "/boot/config-$KERNEL_VERSION"
    "/proc/config.gz"
    "/boot/config"
    "/usr/src/linux/.config"
)

CONFIG_FILE=""
for path in "${CONFIG_PATHS[@]}"; do
    if [ -f "$path" ]; then
        CONFIG_FILE="$path"
        log_success "找到内核配置: $CONFIG_FILE"
        break
    fi
done

if [ -z "$CONFIG_FILE" ]; then
    log_error "未找到内核配置文件"
    echo "请从生产环境复制 /boot/config-$KERNEL_VERSION 文件"
    exit 1
fi

# 复制配置文件
if [[ "$CONFIG_FILE" == *.gz ]]; then
    zcat "$CONFIG_FILE" > production.config
else
    cp "$CONFIG_FILE" production.config
fi

# 2. 获取内核源码
echo ""
log_info "📦 步骤2: 获取内核源码"
echo "========================"

# 提取主版本号
MAJOR_VERSION=$(echo $KERNEL_VERSION | cut -d. -f1)
MINOR_VERSION=$(echo $KERNEL_VERSION | cut -d. -f2)
PATCH_VERSION=$(echo $KERNEL_VERSION | cut -d. -f3 | cut -d- -f1)

BASE_VERSION="${MAJOR_VERSION}.${MINOR_VERSION}"
if [ -n "$PATCH_VERSION" ]; then
    FULL_VERSION="${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}"
else
    FULL_VERSION="${MAJOR_VERSION}.${MINOR_VERSION}"
fi

KERNEL_TARBALL="linux-${FULL_VERSION}.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v${MAJOR_VERSION}.x/${KERNEL_TARBALL}"

log_info "尝试下载: $KERNEL_URL"

if [ ! -f "$KERNEL_TARBALL" ]; then
    if command -v wget &> /dev/null; then
        wget "$KERNEL_URL"
    elif command -v curl &> /dev/null; then
        curl -O "$KERNEL_URL"
    else
        log_error "需要 wget 或 curl 来下载内核源码"
        exit 1
    fi
fi

# 解压内核源码
if [ ! -d "linux-${FULL_VERSION}" ]; then
    log_info "解压内核源码..."
    tar -xf "$KERNEL_TARBALL"
fi

cd "linux-${FULL_VERSION}"

# 3. 配置内核编译
echo ""
log_info "⚙️  步骤3: 配置内核编译"
echo "========================"

# 复制生产配置
cp ../production.config .config

# 检查是否需要更新配置
log_info "更新内核配置..."
make oldconfig

# 启用调试符号（关键！）
log_info "启用调试符号..."
scripts/config --enable CONFIG_DEBUG_INFO
scripts/config --enable CONFIG_DEBUG_INFO_DWARF4  
scripts/config --enable CONFIG_DEBUG_KERNEL
scripts/config --disable CONFIG_DEBUG_INFO_REDUCED

# 可选：启用更多调试信息
scripts/config --enable CONFIG_FRAME_POINTER
scripts/config --enable CONFIG_KALLSYMS
scripts/config --enable CONFIG_KALLSYMS_ALL

# 重新运行oldconfig以确保配置一致性
make oldconfig

# 4. 编译vmlinux
echo ""
log_info "🔨 步骤4: 编译vmlinux"
echo "====================="

log_info "开始编译 (这可能需要20-60分钟)..."
log_info "只编译vmlinux，不编译模块以节省时间"

# 获取CPU核心数
NCPUS=$(nproc)
log_info "使用 $NCPUS 个CPU核心进行编译"

# 编译vmlinux（包含调试符号）
make -j$NCPUS vmlinux

if [ $? -eq 0 ]; then
    log_success "vmlinux 编译完成！"
    ls -lh vmlinux
else
    log_error "vmlinux 编译失败"
    exit 1
fi

# 5. 验证符号匹配
echo ""
log_info "🔍 步骤5: 验证符号匹配"
echo "====================="

log_info "创建符号验证脚本..."
cat > ../verify_symbols.py << 'EOF'
#!/usr/bin/env python3
import subprocess
import re
import sys

def get_production_symbols():
    """获取生产环境符号"""
    try:
        result = subprocess.run(['cat', '/proc/kallsyms'], 
                              capture_output=True, text=True)
        return result.stdout
    except:
        return ""

def get_vmlinux_symbols(vmlinux_path):
    """获取vmlinux符号"""
    try:
        result = subprocess.run(['nm', vmlinux_path], 
                              capture_output=True, text=True)
        return result.stdout
    except:
        return ""

def compare_symbols(vmlinux_path):
    """比较关键eBPF符号"""
    print("🔍 比较关键eBPF符号地址...")
    
    prod_syms = get_production_symbols()
    vmlinux_syms = get_vmlinux_symbols(vmlinux_path)
    
    if not prod_syms:
        print("❌ 无法读取生产环境符号表")
        return False
        
    if not vmlinux_syms:
        print("❌ 无法读取vmlinux符号表")
        return False
    
    # 关键eBPF函数
    ebpf_functions = [
        'sys_bpf', 'bpf_prog_run', 'bpf_map_update_elem', 
        'bpf_map_lookup_elem', 'bpf_prog_load', 'bpf_check'
    ]
    
    matched = 0
    total = 0
    
    for func in ebpf_functions:
        prod_match = re.search(rf'([0-9a-f]+)\s+\w\s+{re.escape(func)}$', prod_syms, re.MULTILINE)
        vmlinux_match = re.search(rf'([0-9a-f]+)\s+\w\s+{re.escape(func)}$', vmlinux_syms, re.MULTILINE)
        
        if prod_match and vmlinux_match:
            total += 1
            prod_addr = prod_match.group(1)
            vmlinux_addr = vmlinux_match.group(1)
            
            if prod_addr == vmlinux_addr:
                print(f"✅ {func:20} | 0x{prod_addr} (匹配)")
                matched += 1
            else:
                print(f"❌ {func:20} | 生产:0x{prod_addr} vmlinux:0x{vmlinux_addr} (不匹配)")
        elif prod_match:
            print(f"⚠️  {func:20} | 仅在生产环境找到: 0x{prod_match.group(1)}")
        elif vmlinux_match:
            print(f"⚠️  {func:20} | 仅在vmlinux找到: 0x{vmlinux_match.group(1)}")
        else:
            print(f"❓ {func:20} | 未找到")
    
    print(f"\n📊 匹配统计: {matched}/{total} ({matched/total*100:.1f}% 匹配)")
    
    if matched == total and total > 0:
        print("🎉 所有符号完全匹配！可以用于静态分析")
        return True
    elif matched > 0:
        print("⚠️  部分符号匹配，可以进行有限的分析")
        return True
    else:
        print("❌ 符号不匹配，可能内核版本或配置不同")
        return False

if __name__ == "__main__":
    vmlinux_path = sys.argv[1] if len(sys.argv) > 1 else "vmlinux"
    success = compare_symbols(vmlinux_path)
    sys.exit(0 if success else 1)
EOF

chmod +x ../verify_symbols.py

# 运行符号验证
cd ..
log_info "运行符号验证..."
python3 verify_symbols.py "linux-${FULL_VERSION}/vmlinux"

# 6. 创建使用指南
echo ""
log_info "📖 步骤6: 创建使用指南"
echo "====================="

cat > debug_usage_guide.md << EOF
# 🔍 生产环境eBPF调试使用指南

## 编译结果
- vmlinux路径: \`$(pwd)/linux-${FULL_VERSION}/vmlinux\`
- 编译时间: $(date)
- 内核版本: $KERNEL_VERSION

## 使用方法

### 1. 静态分析
\`\`\`bash
# 使用GDB进行静态分析
gdb linux-${FULL_VERSION}/vmlinux

# GDB中的命令
(gdb) info address sys_bpf
(gdb) disassemble bpf_prog_run  
(gdb) print sizeof(struct bpf_prog)
(gdb) info types | grep bpf
\`\`\`

### 2. Core Dump分析
\`\`\`bash
# 收集core dump (生产环境谨慎使用!)
echo 1 > /proc/sys/kernel/sysrq
echo c > /proc/sysrq-trigger

# 使用crash工具分析
crash linux-${FULL_VERSION}/vmlinux /proc/kcore
\`\`\`

### 3. 符号地址对比
\`\`\`bash
# 运行符号验证脚本
python3 verify_symbols.py linux-${FULL_VERSION}/vmlinux
\`\`\`

## 注意事项
- ⚠️  此vmlinux仅用于静态分析，不能用于live调试
- ⚠️  符号地址必须完全匹配才能进行准确分析  
- ⚠️  不同编译器版本可能产生不同的符号地址
- ✅ 可以用于理解内核代码结构和eBPF实现
- ✅ 可以分析crash dump和core文件
EOF

log_success "使用指南已保存到: debug_usage_guide.md"

# 7. 总结
echo ""
log_info "🎯 总结"
echo "======="

if [ -f "linux-${FULL_VERSION}/vmlinux" ]; then
    log_success "✅ vmlinux编译成功"
    log_success "✅ 符号验证脚本已创建"  
    log_success "✅ 使用指南已生成"
    
    echo ""
    echo "📝 下一步操作:"
    echo "1. 运行符号验证: python3 verify_symbols.py linux-${FULL_VERSION}/vmlinux"
    echo "2. 阅读使用指南: cat debug_usage_guide.md"
    echo "3. 开始静态分析: gdb linux-${FULL_VERSION}/vmlinux"
    echo ""
    echo "💡 记住: 这种方法提供静态分析能力，不能替代真正的live内核调试"
else
    log_error "❌ vmlinux编译失败"
    echo "请检查编译错误并重试"
fi 