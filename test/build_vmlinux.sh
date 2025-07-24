#!/bin/bash

echo "[BUILD] Building Symbol-Matching vmlinux for Production Environment Debugging"
echo "============================================================================"

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

# 1. Collect production environment information
echo ""
log_info "[STEP] Step 1: Collect Production Environment Information"
echo "========================================================"

KERNEL_VERSION=$(uname -r)
KERNEL_ARCH=$(uname -m)
COMPILER_VERSION=$(gcc --version | head -1)

log_info "Kernel version: $KERNEL_VERSION"
log_info "Architecture: $KERNEL_ARCH"  
log_info "Compiler: $COMPILER_VERSION"

# Check kernel configuration files
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
        log_success "Found kernel config: $CONFIG_FILE"
        break
    fi
done

if [ -z "$CONFIG_FILE" ]; then
    log_error "Kernel config file not found"
    echo "Please copy /boot/config-$KERNEL_VERSION from production environment"
    exit 1
fi

# Copy configuration file
if [[ "$CONFIG_FILE" == *.gz ]]; then
    zcat "$CONFIG_FILE" > production.config
else
    cp "$CONFIG_FILE" production.config
fi

# 2. Get kernel source code
echo ""
log_info "[STEP] Step 2: Get Kernel Source Code"
echo "====================================="

# Extract version numbers
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

log_info "Trying to download: $KERNEL_URL"

if [ ! -f "$KERNEL_TARBALL" ]; then
    if command -v wget &> /dev/null; then
        wget "$KERNEL_URL"
    elif command -v curl &> /dev/null; then
        curl -O "$KERNEL_URL"
    else
        log_error "Need wget or curl to download kernel source"
        exit 1
    fi
fi

# Extract kernel source
if [ ! -d "linux-${FULL_VERSION}" ]; then
    log_info "Extracting kernel source..."
    tar -xf "$KERNEL_TARBALL"
fi

cd "linux-${FULL_VERSION}"

# 3. Configure kernel compilation
echo ""
log_info "[STEP] Step 3: Configure Kernel Compilation"
echo "==========================================="

# Copy production configuration
cp ../production.config .config

# Check if configuration needs updating
log_info "Updating kernel configuration..."
make oldconfig

# Enable debug symbols (crucial!)
log_info "Enabling debug symbols..."
scripts/config --enable CONFIG_DEBUG_INFO
scripts/config --enable CONFIG_DEBUG_INFO_DWARF4  
scripts/config --enable CONFIG_DEBUG_KERNEL
scripts/config --disable CONFIG_DEBUG_INFO_REDUCED

# Optional: enable more debug information
scripts/config --enable CONFIG_FRAME_POINTER
scripts/config --enable CONFIG_KALLSYMS
scripts/config --enable CONFIG_KALLSYMS_ALL

# Re-run oldconfig to ensure configuration consistency
make oldconfig

# 4. Compile vmlinux
echo ""
log_info "[BUILD] Step 4: Compile vmlinux"
echo "==============================="

log_info "Starting compilation (this may take 20-60 minutes)..."
log_info "Only compiling vmlinux, not modules to save time"

# Get CPU core count
NCPUS=$(nproc)
log_info "Using $NCPUS CPU cores for compilation"

# Compile vmlinux (with debug symbols)
make -j$NCPUS vmlinux

if [ $? -eq 0 ]; then
    log_success "vmlinux compilation completed!"
    ls -lh vmlinux
else
    log_error "vmlinux compilation failed"
    exit 1
fi

# 5. Verify symbol matching
echo ""
log_info "[VERIFY] Step 5: Verify Symbol Matching"
echo "========================================"

log_info "Creating symbol verification script..."
cat > ../verify_symbols.py << 'EOF'
#!/usr/bin/env python3
import subprocess
import re
import sys

def get_production_symbols():
    """Get production environment symbols"""
    try:
        result = subprocess.run(['cat', '/proc/kallsyms'], 
                              capture_output=True, text=True)
        return result.stdout
    except:
        return ""

def get_vmlinux_symbols(vmlinux_path):
    """Get vmlinux symbols"""
    try:
        result = subprocess.run(['nm', vmlinux_path], 
                              capture_output=True, text=True)
        return result.stdout
    except:
        return ""

def compare_symbols(vmlinux_path):
    """Compare key eBPF symbols"""
    print("[INFO] Comparing key eBPF symbol addresses...")
    
    prod_syms = get_production_symbols()
    vmlinux_syms = get_vmlinux_symbols(vmlinux_path)
    
    if not prod_syms:
        print("[ERROR] Cannot read production environment symbol table")
        return False
        
    if not vmlinux_syms:
        print("[ERROR] Cannot read vmlinux symbol table")
        return False
    
    # Key eBPF functions
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
                print(f"[OK] {func:20} | 0x{prod_addr} (matched)")
                matched += 1
            else:
                print(f"[FAIL] {func:20} | prod:0x{prod_addr} vmlinux:0x{vmlinux_addr} (mismatched)")
        elif prod_match:
            print(f"[WARN] {func:20} | found only in production: 0x{prod_match.group(1)}")
        elif vmlinux_match:
            print(f"[WARN] {func:20} | found only in vmlinux: 0x{vmlinux_match.group(1)}")
        else:
            print(f"[MISS] {func:20} | not found")
    
    print(f"\n[RESULT] Matching statistics: {matched}/{total} ({matched/total*100:.1f}% matched)")
    
    if matched == total and total > 0:
        print("[SUCCESS] All symbols perfectly matched! Can be used for static analysis")
        return True
    elif matched > 0:
        print("[WARN] Partial symbol matching, limited analysis possible")
        return True
    else:
        print("[ERROR] Symbols don't match, may be different kernel version or config")
        return False

if __name__ == "__main__":
    vmlinux_path = sys.argv[1] if len(sys.argv) > 1 else "vmlinux"
    success = compare_symbols(vmlinux_path)
    sys.exit(0 if success else 1)
EOF

chmod +x ../verify_symbols.py

# Run symbol verification
cd ..
log_info "Running symbol verification..."
python3 verify_symbols.py "linux-${FULL_VERSION}/vmlinux"

# 6. Create usage guide
echo ""
log_info "[GUIDE] Step 6: Create Usage Guide"
echo "=================================="

cat > debug_usage_guide.md << EOF
# Production Environment eBPF Debugging Usage Guide

## Compilation Results
- vmlinux path: \`$(pwd)/linux-${FULL_VERSION}/vmlinux\`
- Compilation time: $(date)
- Kernel version: $KERNEL_VERSION

## Usage Methods

### 1. Static Analysis
\`\`\`bash
# Use GDB for static analysis
gdb linux-${FULL_VERSION}/vmlinux

# GDB commands
(gdb) info address sys_bpf
(gdb) disassemble bpf_prog_run  
(gdb) print sizeof(struct bpf_prog)
(gdb) info types | grep bpf
\`\`\`

### 2. Core Dump Analysis
\`\`\`bash
# Collect core dump (use with caution in production!)
echo 1 > /proc/sys/kernel/sysrq
echo c > /proc/sysrq-trigger

# Use crash tool for analysis
crash linux-${FULL_VERSION}/vmlinux /proc/kcore
\`\`\`

### 3. Symbol Address Comparison
\`\`\`bash
# Run symbol verification script
python3 verify_symbols.py linux-${FULL_VERSION}/vmlinux
\`\`\`

## Important Notes
- WARNING: This vmlinux is for static analysis only, cannot be used for live debugging
- WARNING: Symbol addresses must match exactly for accurate analysis  
- WARNING: Different compiler versions may produce different symbol addresses
- OK: Can be used to understand kernel code structure and eBPF implementation
- OK: Can analyze crash dumps and core files
EOF

log_success "Usage guide saved to: debug_usage_guide.md"

# 7. Summary
echo ""
log_info "[RESULT] Summary"
echo "================"

if [ -f "linux-${FULL_VERSION}/vmlinux" ]; then
    log_success "vmlinux compilation successful"
    log_success "Symbol verification script created"  
    log_success "Usage guide generated"
    
    echo ""
    echo "[NEXT] Next steps:"
    echo "1. Run symbol verification: python3 verify_symbols.py linux-${FULL_VERSION}/vmlinux"
    echo "2. Read usage guide: cat debug_usage_guide.md"
    echo "3. Start static analysis: gdb linux-${FULL_VERSION}/vmlinux"
    echo ""
    echo "NOTE: This method provides static analysis capability, cannot replace true live kernel debugging"
else
    log_error "vmlinux compilation failed"
    echo "Please check compilation errors and retry"
fi 