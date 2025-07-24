#!/bin/bash

echo "🔍 快速符号匹配可行性检查"
echo "=========================="
echo "💡 此脚本检查生产环境是否适合符号匹配调试"
echo ""

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

score=0
max_score=0

# 1. 检查内核信息
echo "📋 1. 内核基本信息"
echo "=================="

KERNEL_VERSION=$(uname -r)
KERNEL_ARCH=$(uname -m)
log_info "内核版本: $KERNEL_VERSION"
log_info "架构: $KERNEL_ARCH"

# 检查是否为主流版本
if [[ $KERNEL_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_success "标准内核版本格式"
    ((score++))
else
    log_warning "自定义内核版本，可能难以获取源码"
fi
((max_score++))

# 2. 检查内核配置
echo ""
echo "📋 2. 内核配置检查"
echo "=================="

CONFIG_PATHS=(
    "/boot/config-$KERNEL_VERSION"
    "/proc/config.gz"
    "/boot/config"
)

CONFIG_FOUND=false
for path in "${CONFIG_PATHS[@]}"; do
    if [ -f "$path" ]; then
        log_success "找到配置文件: $path"
        CONFIG_FOUND=true
        CONFIG_FILE="$path"
        ((score++))
        break
    fi
done
((max_score++))

if [ "$CONFIG_FOUND" = false ]; then
    log_error "未找到内核配置文件"
    log_info "尝试安装: apt-get install linux-headers-$(uname -r)"
fi

# 3. 检查编译器
echo ""
echo "📋 3. 编译环境检查"
echo "=================="

if command -v gcc &> /dev/null; then
    GCC_VERSION=$(gcc --version | head -1)
    log_success "GCC可用: $GCC_VERSION"
    ((score++))
else
    log_error "GCC不可用，需要安装编译工具"
fi
((max_score++))

if command -v make &> /dev/null; then
    log_success "Make工具可用"
    ((score++))
else
    log_error "Make工具不可用"
fi
((max_score++))

# 检查内核头文件
if [ -d "/usr/src/linux-headers-$KERNEL_VERSION" ]; then
    log_success "内核头文件已安装"
    ((score++))
else
    log_warning "内核头文件未安装"
    log_info "安装命令: apt-get install linux-headers-$(uname -r)"
fi
((max_score++))

# 4. 检查符号表访问
echo ""
echo "📋 4. 符号表访问检查"
echo "==================="

if [ -r "/proc/kallsyms" ]; then
    SYMBOL_COUNT=$(cat /proc/kallsyms | wc -l)
    log_success "可访问符号表 ($SYMBOL_COUNT 个符号)"
    ((score++))
    
    # 检查关键eBPF符号
    EBPF_SYMBOLS=("sys_bpf" "bpf_prog_run" "bpf_map_update_elem")
    FOUND_SYMBOLS=0
    
    for sym in "${EBPF_SYMBOLS[@]}"; do
        if grep -q "\\b$sym\\b" /proc/kallsyms; then
            log_success "找到关键符号: $sym"
            ((FOUND_SYMBOLS++))
        else
            log_warning "未找到符号: $sym"
        fi
    done
    
    if [ $FOUND_SYMBOLS -eq ${#EBPF_SYMBOLS[@]} ]; then
        log_success "所有关键eBPF符号都存在"
        ((score++))
    else
        log_warning "部分eBPF符号缺失"
    fi
    ((max_score++))
else
    log_error "无法访问 /proc/kallsyms"
fi
((max_score++))

# 5. 检查调试工具
echo ""
echo "📋 5. 调试工具检查"
echo "=================="

TOOLS=("gdb" "nm" "objdump" "readelf")
TOOL_COUNT=0

for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        log_success "$tool 可用"
        ((TOOL_COUNT++))
    else
        log_warning "$tool 不可用"
    fi
done

if [ $TOOL_COUNT -eq ${#TOOLS[@]} ]; then
    log_success "所有调试工具都可用"
    ((score++))
elif [ $TOOL_COUNT -gt 2 ]; then
    log_warning "部分调试工具可用"
else
    log_error "调试工具严重缺失"
fi
((max_score++))

# 检查crash工具
if command -v crash &> /dev/null; then
    log_success "crash工具可用 (内核dump分析)"
    ((score++))
else
    log_info "crash工具不可用 (可选)"
fi
((max_score++))

# 6. 检查KGDB支持情况
echo ""
echo "📋 6. KGDB支持检查"
echo "=================="

if [ -f "$CONFIG_FILE" ]; then
    if [[ "$CONFIG_FILE" == *.gz ]]; then
        CONFIG_CONTENT=$(zcat "$CONFIG_FILE")
    else
        CONFIG_CONTENT=$(cat "$CONFIG_FILE")
    fi
    
    if echo "$CONFIG_CONTENT" | grep -q "CONFIG_KGDB=y"; then
        log_success "内核支持KGDB (可直接调试)"
        log_info "您可以使用live内核调试"
        ((score++))
    else
        log_warning "内核不支持KGDB (需要符号匹配方案)"
    fi
    
    if echo "$CONFIG_CONTENT" | grep -q "CONFIG_DEBUG_INFO=y"; then
        log_success "内核编译包含调试信息"
        ((score++))
    else
        log_warning "生产内核无调试信息"
    fi
    ((max_score += 2))
fi

# 7. 网络下载能力检查
echo ""
echo "📋 7. 内核源码获取能力"
echo "===================="

if command -v wget &> /dev/null || command -v curl &> /dev/null; then
    log_success "可以下载内核源码"
    ((score++))
else
    log_error "无法下载内核源码 (需要wget或curl)"
fi
((max_score++))

# 磁盘空间检查
AVAILABLE_SPACE=$(df . | tail -1 | awk '{print $4}')
AVAILABLE_GB=$((AVAILABLE_SPACE / 1024 / 1024))

if [ $AVAILABLE_GB -gt 20 ]; then
    log_success "磁盘空间充足 (${AVAILABLE_GB}GB 可用)"
    ((score++))
elif [ $AVAILABLE_GB -gt 10 ]; then
    log_warning "磁盘空间紧张 (${AVAILABLE_GB}GB 可用)"
else
    log_error "磁盘空间不足 (${AVAILABLE_GB}GB 可用，需要至少10GB)"
fi
((max_score++))

# 8. 创建符号快速检查脚本
echo ""
echo "📋 8. 创建快速验证工具"
echo "===================="

cat > quick_symbol_compare.py << 'EOF'
#!/usr/bin/env python3
"""
快速符号地址检查工具
用于验证已有的vmlinux是否与当前内核匹配
"""
import subprocess
import re
import sys

def check_symbol_consistency():
    """检查符号地址一致性"""
    print("🔍 检查内核符号一致性...")
    
    try:
        result = subprocess.run(['cat', '/proc/kallsyms'], 
                              capture_output=True, text=True)
        kallsyms = result.stdout
    except:
        print("❌ 无法读取 /proc/kallsyms")
        return False
    
    # 检查KASLR是否启用
    kaslr_pattern = r'ffffffff[89abcdef][0-9a-f]{7}'
    kaslr_symbols = re.findall(kaslr_pattern, kallsyms)
    
    if kaslr_symbols:
        print("⚠️  检测到KASLR (内核地址空间布局随机化)")
        print("   符号地址在每次启动时都会变化")
        print("   静态vmlinux符号分析能力有限")
        return False
    else:
        print("✅ 未检测到KASLR，符号地址固定")
        print("   静态vmlinux符号分析可行")
        return True

def analyze_ebpf_symbols():
    """分析eBPF相关符号"""
    print("\n🔍 分析eBPF符号分布...")
    
    try:
        result = subprocess.run(['cat', '/proc/kallsyms'], 
                              capture_output=True, text=True)
        kallsyms = result.stdout
    except:
        print("❌ 无法读取符号表")
        return
    
    ebpf_symbols = []
    for line in kallsyms.split('\n'):
        if 'bpf' in line.lower() and not line.startswith('0000000000000000'):
            parts = line.split()
            if len(parts) >= 3:
                addr, type_char, name = parts[0], parts[1], parts[2]
                ebpf_symbols.append((addr, name))
    
    print(f"📊 发现 {len(ebpf_symbols)} 个eBPF相关符号")
    
    if ebpf_symbols:
        print("关键符号示例:")
        for addr, name in ebpf_symbols[:10]:
            print(f"  0x{addr} {name}")
        if len(ebpf_symbols) > 10:
            print(f"  ... 还有 {len(ebpf_symbols) - 10} 个符号")

if __name__ == "__main__":
    consistent = check_symbol_consistency()
    analyze_ebpf_symbols()
    
    print(f"\n🎯 符号匹配调试可行性: {'高' if consistent else '低'}")
EOF

chmod +x quick_symbol_compare.py
log_success "符号检查工具已创建: quick_symbol_compare.py"

# 9. 总结报告
echo ""
echo "🎯 总体评估报告"
echo "==============="

PERCENTAGE=$((score * 100 / max_score))

echo "📊 评分: $score / $max_score ($PERCENTAGE%)"

if [ $PERCENTAGE -ge 80 ]; then
    log_success "🎉 环境非常适合符号匹配调试"
    echo "建议执行: ./build_matching_vmlinux.sh"
elif [ $PERCENTAGE -ge 60 ]; then
    log_warning "⚠️  环境基本适合，但可能需要一些准备"
    echo "建议先安装缺失的工具和头文件"
elif [ $PERCENTAGE -ge 40 ]; then
    log_warning "⚠️  环境适合度一般，建议使用运行时观测方案"
    echo "考虑使用 ftrace、perf、bpftrace 等工具"
else
    log_error "❌ 环境不适合符号匹配调试"
    echo "建议使用 QEMU 模拟环境进行调试"
fi

echo ""
echo "📋 推荐的调试策略:"

if [ $PERCENTAGE -ge 60 ]; then
    echo "1. ✅ 编译匹配的vmlinux进行静态分析"
    echo "2. ✅ 使用运行时观测工具"
    echo "3. ✅ 必要时设置QEMU调试环境"
else
    echo "1. ⚠️  优先使用运行时观测工具"
    echo "2. ✅ 设置QEMU调试环境"
    echo "3. ⚠️  考虑升级开发环境"
fi

echo ""
echo "🔧 下一步操作:"
echo "1. 运行符号检查: python3 quick_symbol_compare.py"

if [ $PERCENTAGE -ge 60 ]; then
    echo "2. 编译vmlinux: ./build_matching_vmlinux.sh"
fi

echo "3. 阅读完整指南: cat README_PRODUCTION_DEBUG.md"

echo ""
log_info "💡 记住: 即使无法live调试，运行时观测和静态分析也能解决大多数eBPF问题" 