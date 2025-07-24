#!/bin/bash

echo "🔍 Quick Symbol Matching Feasibility Check"
echo "=========================================="
echo "💡 This script checks if your production environment is suitable for symbol matching debugging"
echo ""

# Color definitions
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

# 1. Check kernel information
echo "📋 1. Kernel Basic Information"
echo "=============================="

KERNEL_VERSION=$(uname -r)
KERNEL_ARCH=$(uname -m)
log_info "Kernel version: $KERNEL_VERSION"
log_info "Architecture: $KERNEL_ARCH"

# Check if it's a standard version
if [[ $KERNEL_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_success "Standard kernel version format"
    ((score++))
else
    log_warning "Custom kernel version, may be difficult to obtain source code"
fi
((max_score++))

# 2. Check kernel configuration
echo ""
echo "📋 2. Kernel Configuration Check"
echo "================================"

CONFIG_PATHS=(
    "/boot/config-$KERNEL_VERSION"
    "/proc/config.gz"
    "/boot/config"
)

CONFIG_FOUND=false
for path in "${CONFIG_PATHS[@]}"; do
    if [ -f "$path" ]; then
        log_success "Found config file: $path"
        CONFIG_FOUND=true
        CONFIG_FILE="$path"
        ((score++))
        break
    fi
done
((max_score++))

if [ "$CONFIG_FOUND" = false ]; then
    log_error "Kernel config file not found"
    log_info "Try installing: apt-get install linux-headers-$(uname -r)"
fi

# 3. Check compiler
echo ""
echo "📋 3. Compilation Environment Check"
echo "==================================="

if command -v gcc &> /dev/null; then
    GCC_VERSION=$(gcc --version | head -1)
    log_success "GCC available: $GCC_VERSION"
    ((score++))
else
    log_error "GCC not available, need to install build tools"
fi
((max_score++))

if command -v make &> /dev/null; then
    log_success "Make tool available"
    ((score++))
else
    log_error "Make tool not available"
fi
((max_score++))

# 4. Check symbol table access
echo ""
echo "📋 4. Symbol Table Access Check"
echo "==============================="

if [ -r "/proc/kallsyms" ]; then
    SYMBOL_COUNT=$(cat /proc/kallsyms | wc -l)
    log_success "Can access symbol table ($SYMBOL_COUNT symbols)"
    ((score++))
    
    # Check key eBPF symbols
    EBPF_SYMBOLS=("sys_bpf" "bpf_prog_run" "bpf_map_update_elem")
    FOUND_SYMBOLS=0
    
    for sym in "${EBPF_SYMBOLS[@]}"; do
        if grep -q "\\b$sym\\b" /proc/kallsyms; then
            log_success "Found key symbol: $sym"
            ((FOUND_SYMBOLS++))
        else
            log_warning "Symbol not found: $sym"
        fi
    done
    
    if [ $FOUND_SYMBOLS -eq ${#EBPF_SYMBOLS[@]} ]; then
        log_success "All key eBPF symbols exist"
        ((score++))
    else
        log_warning "Some eBPF symbols missing"
    fi
    ((max_score++))
else
    log_error "Cannot access /proc/kallsyms"
fi
((max_score++))

# 5. Check debugging tools
echo ""
echo "📋 5. Debugging Tools Check"
echo "==========================="

TOOLS=("gdb" "nm" "objdump" "readelf")
TOOL_COUNT=0

for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        log_success "$tool available"
        ((TOOL_COUNT++))
    else
        log_warning "$tool not available"
    fi
done

if [ $TOOL_COUNT -eq ${#TOOLS[@]} ]; then
    log_success "All debugging tools available"
    ((score++))
elif [ $TOOL_COUNT -gt 2 ]; then
    log_warning "Some debugging tools available"
else
    log_error "Debugging tools severely lacking"
fi
((max_score++))

# 6. Summary report
echo ""
echo "🎯 Overall Assessment Report"
echo "============================"

PERCENTAGE=$((score * 100 / max_score))

echo "📊 Score: $score / $max_score ($PERCENTAGE%)"

if [ $PERCENTAGE -ge 80 ]; then
    log_success "🎉 Environment very suitable for symbol matching debugging"
    echo "Recommended: ./build_vmlinux.sh"
elif [ $PERCENTAGE -ge 60 ]; then
    log_warning "⚠️  Environment basically suitable, but may need some preparation"
    echo "Recommend installing missing tools and headers first"
else
    log_error "❌ Environment not suitable for symbol matching debugging"
    echo "Recommend using QEMU simulation environment for debugging"
fi

echo ""
echo "🔧 Next steps:"
echo "1. Read complete guide: cat README.md"
if [ $PERCENTAGE -ge 60 ]; then
    echo "2. Build vmlinux: ./build_vmlinux.sh"
fi

echo ""
log_info "💡 Remember: Even without live debugging, runtime observation and static analysis can solve most eBPF problems" 