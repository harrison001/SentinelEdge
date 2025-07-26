// kernel-agent/src/memory_analyzer.bpf.c
// Advanced memory access pattern analysis and buffer overflow detection

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_STACK_DEPTH 10
#define MAX_PROCESSES 1000
#define MAX_MEMORY_REGIONS 5000
#define PAGE_SIZE 4096

// Memory region tracking
struct memory_region {
    __u64 start_addr;
    __u64 end_addr;
    __u64 size;
    __u32 pid;
    __u32 flags;  // mmap flags
    __u8 prot;    // protection flags
    __u64 alloc_time;
    __u64 last_access;
    __u32 access_count;
    __u8 is_suspicious;
    __u32 overflow_score;
};

// Process memory profile
struct memory_profile {
    __u32 pid;
    __u64 total_allocated;
    __u64 total_freed;
    __u32 active_regions;
    __u32 malloc_count;
    __u32 free_count;
    __u32 mmap_count;
    __u32 munmap_count;
    __u32 page_faults;
    __u32 heap_overflows;
    __u32 stack_overflows;
    __u32 use_after_free;
    __u64 peak_memory;
    __u8 leak_detected;
};

// Memory access event
struct memory_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    char comm[16];
    __u64 addr;
    __u64 size;
    __u8 access_type;  // 0=read, 1=write, 2=exec
    __u8 fault_type;   // page fault type
    __u32 stack_id;
    __u32 threat_score;
    __u8 is_overflow;
    __u8 is_leak;
    char violation_type[32];
};

// Stack trace storage
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64) * MAX_STACK_DEPTH);
    __uint(max_entries, 1000);
} stack_traces SEC(".maps");

// Memory region tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // memory address
    __type(value, struct memory_region);
    __uint(max_entries, MAX_MEMORY_REGIONS);
} memory_regions SEC(".maps");

// Process memory profiles
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // PID
    __type(value, struct memory_profile);
    __uint(max_entries, MAX_PROCESSES);
} memory_profiles SEC(".maps");

// Memory events ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} memory_events SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 20);
} stats SEC(".maps");

// Helper functions
static __always_inline void update_stats(__u32 index) {
    __u64 *counter = bpf_map_lookup_elem(&stats, &index);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline int is_stack_address(__u64 addr) {
    // Typical stack addresses on x86_64
    return (addr >= 0x7ffe00000000ULL && addr <= 0x7fffffffffffffffULL);
}

static __always_inline int is_heap_address(__u64 addr) {
    // Typical heap addresses on x86_64
    return (addr >= 0x555555554000ULL && addr <= 0x7ffe00000000ULL);
}

static __always_inline int detect_buffer_overflow(__u64 addr, __u64 size, struct memory_region *region) {
    if (!region) return 0;
    
    // Check if access goes beyond allocated region
    if (addr + size > region->end_addr) {
        return 1;
    }
    
    // Check for suspicious patterns
    if (size > region->size * 2) {
        return 2;  // Extremely large access
    }
    
    return 0;
}

static __always_inline void analyze_access_pattern(__u64 addr, __u64 size, __u32 pid) {
    struct memory_profile *profile = bpf_map_lookup_elem(&memory_profiles, &pid);
    if (!profile) {
        struct memory_profile new_profile = {
            .pid = pid,
            .total_allocated = 0,
            .total_freed = 0,
            .active_regions = 0,
            .malloc_count = 0,
            .free_count = 0,
            .page_faults = 0,
            .heap_overflows = 0,
            .stack_overflows = 0,
            .use_after_free = 0,
            .peak_memory = 0,
            .leak_detected = 0
        };
        bpf_map_update_elem(&memory_profiles, &pid, &new_profile, BPF_ANY);
        profile = &new_profile;
    }
    
    // Update access patterns
    if (is_stack_address(addr)) {
        if (size > 8192) {  // Large stack access
            profile->stack_overflows++;
        }
    } else if (is_heap_address(addr)) {
        if (size > 1024 * 1024) {  // Large heap access
            profile->heap_overflows++;
        }
    }
}

// 手动定义 tracepoint 格式
struct page_fault_ctx {
    __u64 address;
    __u64 ip;
    __u32 error_code;
};

SEC("tracepoint/exceptions/page_fault_user")
int trace_page_fault_user(void *ctx)
{
    struct memory_event *event;
    event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->addr = 0;          // 不去访问 ctx->address 避免非法偏移
    event->fault_type = 0;    // 同理先留空

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/exceptions/page_fault_kernel")
int trace_page_fault_kernel(void *ctx)
{
    struct memory_event *event;

    event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->addr = 0;
    event->fault_type = 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
} 
/*
// Page fault handler - detects memory access violations
SEC("tracepoint/exceptions/page_fault_user")
int trace_page_fault(struct trace_event_raw_page_fault_user *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event) return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->addr = ctx->address;      // tracepoint自带fault地址
    event->fault_type = ctx->error_code;

    // 这里你原来做的stack_id之类的也可以保留
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/do_page_fault")
int trace_page_fault(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Get fault address from CR2 register
    __u64 fault_addr = PT_REGS_PARM2(ctx);
    
    struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->addr = fault_addr;
    event->size = 0;
    event->access_type = 0;  // Will be determined by fault type
    event->fault_type = 1;   // Page fault
    event->threat_score = 0;
    event->is_overflow = 0;
    event->is_leak = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Get stack trace
    event->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    // Analyze fault address
    if (is_stack_address(fault_addr)) {
        event->threat_score += 20;
        __builtin_memcpy(event->violation_type, "STACK_ACCESS", 13);
    } else if (fault_addr < 0x1000) {
        event->threat_score += 50;
        event->is_overflow = 1;
        __builtin_memcpy(event->violation_type, "NULL_DEREF", 11);
    } else if (fault_addr > 0x7fffffffffffffffULL) {
        event->threat_score += 60;
        event->is_overflow = 1;
        __builtin_memcpy(event->violation_type, "INVALID_ACCESS", 15);
    }
    
    // Update process profile
    struct memory_profile *profile = bpf_map_lookup_elem(&memory_profiles, &pid);
    if (profile) {
        profile->page_faults++;
        if (event->is_overflow) {
            if (is_stack_address(fault_addr)) {
                profile->stack_overflows++;
            } else {
                profile->heap_overflows++;
            }
        }
    }
    
    update_stats(0);  // Total page faults
    
    if (event->threat_score > 30) {
        update_stats(1);  // Suspicious page faults
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}
*/
// malloc tracking
SEC("uprobe/malloc")
int trace_malloc(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 size = PT_REGS_PARM1(ctx);
    
    struct memory_profile *profile = bpf_map_lookup_elem(&memory_profiles, &pid);
    if (!profile) {
        struct memory_profile new_profile = {
            .pid = pid,
            .malloc_count = 1,
            .total_allocated = size,
            .active_regions = 1
        };
        bpf_map_update_elem(&memory_profiles, &pid, &new_profile, BPF_ANY);
    } else {
        profile->malloc_count++;
        profile->total_allocated += size;
        profile->active_regions++;
        
        if (profile->total_allocated > profile->peak_memory) {
            profile->peak_memory = profile->total_allocated;
        }
    }
    
    update_stats(2);  // Total malloc calls
    
    // Detect suspicious large allocations
    if (size > 100 * 1024 * 1024) {  // > 100MB
        struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = pid;
            event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
            event->addr = 0;  // Will be filled in return probe
            event->size = size;
            event->access_type = 2;  // Allocation
            event->fault_type = 0;
            event->threat_score = 40;
            event->is_overflow = 0;
            event->is_leak = 0;
            
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->violation_type, "LARGE_ALLOC", 12);
            
            bpf_ringbuf_submit(event, 0);
        }
        
        update_stats(3);  // Large allocation counter
    }
    
    return 0;
}

// malloc return tracking
SEC("uretprobe/malloc")
int trace_malloc_ret(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 addr = PT_REGS_RC(ctx);
    
    if (addr == 0) {
        // malloc failed
        update_stats(4);  // malloc failure counter
        return 0;
    }
    
    // Store memory region info
    struct memory_region region = {
        .start_addr = addr,
        .end_addr = addr + 1024,  // We don't know exact size here
        .size = 1024,
        .pid = pid,
        .flags = 0,
        .prot = 0x3,  // Read/Write
        .alloc_time = bpf_ktime_get_ns(),
        .last_access = bpf_ktime_get_ns(),
        .access_count = 0,
        .is_suspicious = 0,
        .overflow_score = 0
    };
    
    bpf_map_update_elem(&memory_regions, &addr, &region, BPF_ANY);
    
    return 0;
}

// free tracking
SEC("uprobe/free")
int trace_free(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 addr = PT_REGS_PARM1(ctx);
    
    if (addr == 0) {
        return 0;  // free(NULL) is valid
    }
    
    struct memory_region *region = bpf_map_lookup_elem(&memory_regions, &addr);
    if (!region) {
        // Double free or free of untracked memory
        struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = pid;
            event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
            event->addr = addr;
            event->size = 0;
            event->access_type = 3;  // Free
            event->fault_type = 0;
            event->threat_score = 70;
            event->is_overflow = 0;
            event->is_leak = 0;
            
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->violation_type, "DOUBLE_FREE", 12);
            
            bpf_ringbuf_submit(event, 0);
        }
        
        update_stats(5);  // Double free counter
        return 0;
    }
    
    // Update process profile
    struct memory_profile *profile = bpf_map_lookup_elem(&memory_profiles, &pid);
    if (profile) {
        profile->free_count++;
        profile->total_freed += region->size;
        profile->active_regions--;
    }
    
    // Remove from tracking
    bpf_map_delete_elem(&memory_regions, &addr);
    
    update_stats(6);  // Total free calls
    return 0;
}

// mmap tracking
SEC("kprobe/do_mmap")
int trace_mmap(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 addr = PT_REGS_PARM1(ctx);
    __u64 len = PT_REGS_PARM2(ctx);
    __u32 prot = PT_REGS_PARM3(ctx);
    __u32 flags = PT_REGS_PARM4(ctx);
    
    struct memory_profile *profile = bpf_map_lookup_elem(&memory_profiles, &pid);
    if (!profile) {
        struct memory_profile new_profile = {
            .pid = pid,
            .mmap_count = 1,
            .total_allocated = len,
            .active_regions = 1
        };
        bpf_map_update_elem(&memory_profiles, &pid, &new_profile, BPF_ANY);
    } else {
        profile->mmap_count++;
        profile->total_allocated += len;
        profile->active_regions++;
    }
    
    // Detect suspicious mmap calls
    __u32 threat_score = 0;
    char violation_type[32] = {0};
    
    if (prot & 0x4) {  // PROT_EXEC
        threat_score += 30;
        __builtin_memcpy(violation_type, "EXEC_MMAP", 10);
    }
    
    if ((prot & 0x3) == 0x3 && (prot & 0x4)) {  // RWX
        threat_score += 50;
        __builtin_memcpy(violation_type, "RWX_MMAP", 9);
    }
    
    if (len > 100 * 1024 * 1024) {  // > 100MB
        threat_score += 20;
        __builtin_memcpy(violation_type, "LARGE_MMAP", 11);
    }
    
    if (threat_score > 40) {
        struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = pid;
            event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
            event->addr = addr;
            event->size = len;
            event->access_type = 4;  // mmap
            event->fault_type = 0;
            event->threat_score = threat_score;
            event->is_overflow = 0;
            event->is_leak = 0;
            
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->violation_type, violation_type, 32);
            
            bpf_ringbuf_submit(event, 0);
        }
        
        update_stats(7);  // Suspicious mmap counter
    }
    
    update_stats(8);  // Total mmap calls
    return 0;
}

// Memory leak detection - periodic check
SEC("kprobe/do_exit")
int trace_process_exit(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct memory_profile *profile = bpf_map_lookup_elem(&memory_profiles, &pid);
    if (profile) {
        // Check for memory leaks
        if (profile->active_regions > 0 && 
            profile->total_allocated > profile->total_freed + 1024 * 1024) {  // > 1MB leak
            
            profile->leak_detected = 1;
            
            struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
            if (event) {
                event->timestamp = bpf_ktime_get_ns();
                event->pid = pid;
                event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
                event->addr = 0;
                event->size = profile->total_allocated - profile->total_freed;
                event->access_type = 5;  // Leak detection
                event->fault_type = 0;
                event->threat_score = 30;
                event->is_overflow = 0;
                event->is_leak = 1;
                
                bpf_get_current_comm(&event->comm, sizeof(event->comm));
                __builtin_memcpy(event->violation_type, "MEMORY_LEAK", 12);
                
                bpf_ringbuf_submit(event, 0);
            }
            
            update_stats(9);  // Memory leak counter
        }
        
        // Clean up process data
        bpf_map_delete_elem(&memory_profiles, &pid);
    }
    
    return 0;
}

// Stack overflow detection
SEC("kprobe/handle_stack_overflow")
int trace_stack_overflow(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 stack_ptr = PT_REGS_SP(ctx);
    
    // Check if stack pointer is in dangerous range
    if (stack_ptr < 0x7ffe00000000ULL + 8192) {  // Too close to stack bottom
        struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = pid;
            event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
            event->addr = stack_ptr;
            event->size = 0;
            event->access_type = 6;  // Stack overflow
            event->fault_type = 0;
            event->threat_score = 80;
            event->is_overflow = 1;
            event->is_leak = 0;
            
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->violation_type, "STACK_OVERFLOW", 15);
            
            bpf_ringbuf_submit(event, 0);
        }
        
        update_stats(10);  // Stack overflow counter
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 
