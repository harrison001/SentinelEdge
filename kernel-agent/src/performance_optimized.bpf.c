// kernel-agent/src/performance_optimized.bpf.c
// High-performance eBPF with lockless data structures and zero-copy techniques

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BATCH_SIZE 64
#define MAX_EVENTS 100000
#define CACHE_LINE_SIZE 64
#define MAX_CPUS 256

// Lock-free ring buffer entry
struct lockfree_event {
    __u64 timestamp;
    __u32 pid;
    __u32 cpu;
    __u8 event_type;
    __u8 batch_id;
    __u16 data_len;
    __u8 data[48];  // Inline data to avoid pointer chasing
} __attribute__((aligned(CACHE_LINE_SIZE)));

// Per-CPU batch buffer for high-throughput processing
struct batch_buffer {
    __u32 count;
    __u32 head;
    __u32 tail;
    __u32 dropped;
    struct lockfree_event events[MAX_BATCH_SIZE];
} __attribute__((aligned(CACHE_LINE_SIZE)));

// Lock-free statistics with atomic operations
struct atomic_stats {
    __u64 total_events;
    __u64 processed_events;
    __u64 dropped_events;
    __u64 batch_flushes;
    __u64 cpu_migrations;
    __u64 cache_hits;
    __u64 cache_misses;
    __u64 last_flush_time;
} __attribute__((aligned(CACHE_LINE_SIZE)));

// Fast path event for minimal overhead
struct fast_event {
    __u32 pid_tid;
    __u32 timestamp_low;
    __u16 syscall_nr;
    __u8 flags;
    __u8 cpu;
} __attribute__((packed));

// Zero-copy shared memory region
struct shared_memory_region {
    __u64 producer_head;
    __u64 consumer_head;
    __u64 ring_mask;
    __u64 ring_size;
    struct fast_event events[];
} __attribute__((aligned(CACHE_LINE_SIZE)));

// High-performance maps
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct batch_buffer);
    __uint(max_entries, 1);
} per_cpu_batches SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct atomic_stats);
    __uint(max_entries, 1);
} per_cpu_stats SEC(".maps");

// Lock-free hash table for process tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, __u32);  // PID
    __type(value, __u64); // Last seen timestamp
    __uint(max_entries, 10000);
} process_cache SEC(".maps");

// Zero-copy ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);  // 8MB for high throughput
} fast_events SEC(".maps");

// Shared memory for zero-copy
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct shared_memory_region);
    __uint(max_entries, 1);
} shared_memory SEC(".maps");

// Configuration for performance tuning
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 16);
} perf_config SEC(".maps");

// Helper functions for performance optimization
static __always_inline void atomic_add_stats(__u32 stat_index, __u64 value) {
    __u32 key = 0;
    struct atomic_stats *stats = bpf_map_lookup_elem(&per_cpu_stats, &key);
    if (stats) {
        switch (stat_index) {
            case 0:
                __sync_fetch_and_add(&stats->total_events, value);
                break;
            case 1:
                __sync_fetch_and_add(&stats->processed_events, value);
                break;
            case 2:
                __sync_fetch_and_add(&stats->dropped_events, value);
                break;
            case 3:
                __sync_fetch_and_add(&stats->batch_flushes, value);
                break;
        }
    }
}

static __always_inline int should_sample_event(__u32 pid) {
    // Fast sampling decision using bit operations
    __u32 key = 0;
    __u32 *sample_rate = bpf_map_lookup_elem(&perf_config, &key);
    if (!sample_rate || *sample_rate == 0) {
        return 1;  // Sample all events if not configured
    }
    
    // Use PID for deterministic sampling
    return (pid & ((*sample_rate) - 1)) == 0;
}

static __always_inline void flush_batch_buffer(struct batch_buffer *batch) {
    if (batch->count == 0) return;
    
    // Batch submit to ring buffer for efficiency
    for (__u32 i = 0; i < batch->count && i < MAX_BATCH_SIZE; i++) {
        struct lockfree_event *event = bpf_ringbuf_reserve(&fast_events, sizeof(*event), 0);
        if (event) {
            *event = batch->events[i];
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    // Reset batch
    batch->count = 0;
    batch->head = 0;
    batch->tail = 0;
    
    atomic_add_stats(3, 1);  // Batch flush counter
}

static __always_inline int add_to_batch(struct batch_buffer *batch, struct lockfree_event *event) {
    if (batch->count >= MAX_BATCH_SIZE) {
        flush_batch_buffer(batch);
    }
    
    if (batch->count < MAX_BATCH_SIZE) {
        batch->events[batch->count] = *event;
        batch->count++;
        return 0;
    }
    
    batch->dropped++;
    atomic_add_stats(2, 1);  // Dropped events
    return -1;
}

// Ultra-fast syscall entry tracking
SEC("tp/raw_syscalls/sys_enter")
int fast_syscall_enter(struct bpf_raw_tracepoint_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    // Fast sampling check
    if (!should_sample_event(pid)) {
        return 0;
    }
    
    __u32 syscall_nr = ctx->args[1];
    __u64 timestamp = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    
    // Update process cache with lock-free access
    __u64 *last_seen = bpf_map_lookup_elem(&process_cache, &pid);
    if (last_seen) {
        *last_seen = timestamp;
        atomic_add_stats(5, 1);  // Cache hits
    } else {
        bpf_map_update_elem(&process_cache, &pid, &timestamp, BPF_ANY);
        atomic_add_stats(6, 1);  // Cache misses
    }
    
    // Get per-CPU batch buffer
    __u32 key = 0;
    struct batch_buffer *batch = bpf_map_lookup_elem(&per_cpu_batches, &key);
    if (!batch) {
        return 0;
    }
    
    // Create optimized event structure
    struct lockfree_event event = {
        .timestamp = timestamp,
        .pid = pid,
        .cpu = cpu,
        .event_type = 1,  // SYSCALL_ENTER
        .batch_id = batch->count,
        .data_len = 8
    };
    
    // Pack syscall data efficiently
    *(__u32 *)&event.data[0] = syscall_nr;
    *(__u32 *)&event.data[4] = tid;
    
    // Add to batch with minimal overhead
    add_to_batch(batch, &event);
    atomic_add_stats(0, 1);  // Total events
    
    return 0;
}

// High-performance network packet processing
SEC("xdp")
int fast_packet_processor(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Minimal packet validation for performance
    if (data + 14 > data_end) {  // Ethernet header
        return XDP_PASS;
    }
    
    __u16 eth_proto = *(__u16 *)(data + 12);
    if (eth_proto != bpf_htons(0x0800)) {  // Only IPv4
        return XDP_PASS;
    }
    
    if (data + 34 > data_end) {  // IP header
        return XDP_PASS;
    }
    
    __u8 protocol = *(__u8 *)(data + 23);
    __u32 src_ip = *(__u32 *)(data + 26);
    __u32 dst_ip = *(__u32 *)(data + 30);
    
    // Fast path processing with minimal overhead
    __u32 cpu = bpf_get_smp_processor_id();
    __u64 timestamp = bpf_ktime_get_ns();
    
    // Create minimal event for zero-copy processing
    struct fast_event fast_evt = {
        .pid_tid = src_ip,  // Reuse field for source IP
        .timestamp_low = timestamp & 0xFFFFFFFF,
        .syscall_nr = protocol,
        .flags = 0x80,  // Network event flag
        .cpu = cpu
    };
    
    // Zero-copy submission to shared memory
    __u32 key = 0;
    struct shared_memory_region *shared = bpf_map_lookup_elem(&shared_memory, &key);
    if (shared) {
        __u64 head = shared->producer_head;
        __u64 next_head = head + 1;
        
        if ((next_head & shared->ring_mask) != (shared->consumer_head & shared->ring_mask)) {
            shared->events[head & shared->ring_mask] = fast_evt;
            
            // Memory barrier for ordering
            __sync_synchronize();
            shared->producer_head = next_head;
        }
    }
    
    atomic_add_stats(0, 1);  // Total events
    return XDP_PASS;
}

// Lock-free process monitoring
SEC("kprobe/wake_up_new_task")
int fast_process_wake(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
    if (!task) return 0;
    
    __u32 pid = BPF_CORE_READ(task, tgid);
    __u64 timestamp = bpf_ktime_get_ns();
    
    // Fast sampling
    if (!should_sample_event(pid)) {
        return 0;
    }
    
    // Update cache with atomic operation
    bpf_map_update_elem(&process_cache, &pid, &timestamp, BPF_ANY);
    
    // Minimal event creation
    __u32 key = 0;
    struct batch_buffer *batch = bpf_map_lookup_elem(&per_cpu_batches, &key);
    if (batch) {
        struct lockfree_event event = {
            .timestamp = timestamp,
            .pid = pid,
            .cpu = bpf_get_smp_processor_id(),
            .event_type = 2,  // PROCESS_WAKE
            .batch_id = batch->count,
            .data_len = 4
        };
        
        *(__u32 *)&event.data[0] = BPF_CORE_READ(task, flags);
        
        add_to_batch(batch, &event);
    }
    
    atomic_add_stats(0, 1);
    return 0;
}

// Optimized memory allocation tracking
SEC("kprobe/kmem_cache_alloc")
int fast_kmem_alloc(struct pt_regs *ctx) {
    __u64 size = PT_REGS_PARM2(ctx);
    
    // Only track large allocations for performance
    if (size < 4096) {
        return 0;
    }
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!should_sample_event(pid)) {
        return 0;
    }
    
    __u32 key = 0;
    struct batch_buffer *batch = bpf_map_lookup_elem(&per_cpu_batches, &key);
    if (batch) {
        struct lockfree_event event = {
            .timestamp = bpf_ktime_get_ns(),
            .pid = pid,
            .cpu = bpf_get_smp_processor_id(),
            .event_type = 3,  // MEMORY_ALLOC
            .batch_id = batch->count,
            .data_len = 8
        };
        
        *(__u64 *)&event.data[0] = size;
        
        add_to_batch(batch, &event);
    }
    
    atomic_add_stats(0, 1);
    return 0;
}

// Periodic batch flush to prevent buffer overflow
SEC("perf_event")
int periodic_flush(struct bpf_perf_event_data *ctx) {
    __u32 key = 0;
    struct batch_buffer *batch = bpf_map_lookup_elem(&per_cpu_batches, &key);
    if (batch && batch->count > 0) {
        flush_batch_buffer(batch);
    }
    
    // Update flush timestamp
    struct atomic_stats *stats = bpf_map_lookup_elem(&per_cpu_stats, &key);
    if (stats) {
        stats->last_flush_time = bpf_ktime_get_ns();
    }
    
    return 0;
}

// CPU migration detection for performance analysis
SEC("tp/sched/sched_migrate_task")
int trace_cpu_migration(struct trace_event_raw_sched_migrate_task *ctx) {
    __u32 pid = ctx->pid;
    __u32 orig_cpu = ctx->orig_cpu;
    __u32 dest_cpu = ctx->dest_cpu;
    
    if (!should_sample_event(pid)) {
        return 0;
    }
    
    // Track CPU migrations for performance impact
    atomic_add_stats(4, 1);  // CPU migrations
    
    __u32 key = 0;
    struct batch_buffer *batch = bpf_map_lookup_elem(&per_cpu_batches, &key);
    if (batch) {
        struct lockfree_event event = {
            .timestamp = bpf_ktime_get_ns(),
            .pid = pid,
            .cpu = dest_cpu,
            .event_type = 4,  // CPU_MIGRATION
            .batch_id = batch->count,
            .data_len = 8
        };
        
        *(__u32 *)&event.data[0] = orig_cpu;
        *(__u32 *)&event.data[4] = dest_cpu;
        
        add_to_batch(batch, &event);
    }
    
    return 0;
}

// Cache-optimized context switch tracking
SEC("tp/sched/sched_switch")
int fast_context_switch(struct trace_event_raw_sched_switch *ctx) {
    __u32 prev_pid = ctx->prev_pid;
    __u32 next_pid = ctx->next_pid;
    
    // Only sample context switches for monitored processes
    if (!should_sample_event(prev_pid) && !should_sample_event(next_pid)) {
        return 0;
    }
    
    __u64 timestamp = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    
    // Update process cache for both processes
    bpf_map_update_elem(&process_cache, &prev_pid, &timestamp, BPF_ANY);
    bpf_map_update_elem(&process_cache, &next_pid, &timestamp, BPF_ANY);
    
    __u32 key = 0;
    struct batch_buffer *batch = bpf_map_lookup_elem(&per_cpu_batches, &key);
    if (batch) {
        struct lockfree_event event = {
            .timestamp = timestamp,
            .pid = next_pid,
            .cpu = cpu,
            .event_type = 5,  // CONTEXT_SWITCH
            .batch_id = batch->count,
            .data_len = 8
        };
        
        *(__u32 *)&event.data[0] = prev_pid;
        *(__u32 *)&event.data[4] = ctx->prev_state;
        
        add_to_batch(batch, &event);
    }
    
    atomic_add_stats(0, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 