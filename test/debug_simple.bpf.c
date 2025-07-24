#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

typedef unsigned int __u32;
typedef unsigned long long __u64;

// BPF helper function declarations
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
static long (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_ktime_get_ns)(void) = (void *) 5;

// Debug counter Map
struct {
    __uint(type, 2);  // BPF_MAP_TYPE_ARRAY
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10);  // Extended to 10 slots for debugging
} debug_counters SEC(".maps");

// Main counter Map (original)
struct {
    __uint(type, 2);  // BPF_MAP_TYPE_ARRAY
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} counter SEC(".maps");

// Debug info Map - stores execution path
struct {
    __uint(type, 2);  // BPF_MAP_TYPE_ARRAY
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 20);  // Store each step of execution path
} debug_trace SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_debug(void *ctx) {
    __u32 key, step = 0;
    __u64 val, *existing, timestamp;
    
    // Step 1: Record function entry
    timestamp = bpf_ktime_get_ns();
    key = step++;  // key = 0
    bpf_map_update_elem(&debug_trace, &key, &timestamp, 0);
    bpf_trace_printk("[ENTRY] eBPF entry: step=%d, ts=%llu", 35, step-1, timestamp);
    
    // Step 2: Get PID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    key = step++;  // key = 1
    val = (__u64)pid;
    bpf_map_update_elem(&debug_trace, &key, &val, 0);
    bpf_trace_printk("[PID] PID obtained: step=%d, pid=%d", 34, step-1, pid);
    
    // Step 3: Increment entry counter
    key = 0;  // Entry counter
    existing = bpf_map_lookup_elem(&debug_counters, &key);
    if (existing) {
        val = *existing + 1;
        bpf_trace_printk("[COUNT] Entry count: step=%d, existing=%llu", 42, step, *existing);
    } else {
        val = 1;
        bpf_trace_printk("[COUNT] Entry count: step=%d, first", 34, step);
    }
    bpf_map_update_elem(&debug_counters, &key, &val, 0);
    step++;  // step = 3
    
    // Step 4: Check main counter map
    key = 0;
    existing = bpf_map_lookup_elem(&counter, &key);
    if (existing) {
        bpf_trace_printk("[CHECK] Main counter: step=%d, current=%llu", 42, step, *existing);
        val = *existing;
    } else {
        bpf_trace_printk("[CHECK] Main counter: step=%d, not found", 38, step);
        val = 0;
    }
    
    // Record current value to debug_trace
    key = step++;  // key = 4
    bpf_map_update_elem(&debug_trace, &key, &val, 0);
    
    // Step 5: Update main counter to 999
    key = 0;
    val = 999;
    long update_result = bpf_map_update_elem(&counter, &key, &val, 0);
    
    // Record update result
    key = step++;  // key = 5  
    __u64 result_val = (update_result == 0) ? 1 : 0;  // 1=success, 0=failure
    bpf_map_update_elem(&debug_trace, &key, &result_val, 0);
    bpf_trace_printk("[UPDATE] Main counter update: step=%d, result=%d", 46, step-1, (int)update_result);
    
    // Step 6: Verify update result
    existing = bpf_map_lookup_elem(&counter, &key);
    if (existing) {
        bpf_trace_printk("[VERIFY] Verification: step=%d, new_value=%llu", 44, step, *existing);
        key = step++;  // key = 6
        bpf_map_update_elem(&debug_trace, &key, existing, 0);
    } else {
        bpf_trace_printk("[ERROR] Verification failed: step=%d", 35, step);
        key = step++;  // key = 6
        val = 0xFFFFFFFF;  // Error marker
        bpf_map_update_elem(&debug_trace, &key, &val, 0);
    }
    
    // Step 7: Increment success counter
    key = 1;  // Success counter
    existing = bpf_map_lookup_elem(&debug_counters, &key);
    val = existing ? (*existing + 1) : 1;
    bpf_map_update_elem(&debug_counters, &key, &val, 0);
    bpf_trace_printk("[SUCCESS] Success count: step=%d, total=%llu", 42, step, val);
    
    // Step 8: Record function exit
    timestamp = bpf_ktime_get_ns();
    key = step++;  // key = 8
    bpf_map_update_elem(&debug_trace, &key, &timestamp, 0);
    bpf_trace_printk("[EXIT] eBPF exit: step=%d, ts=%llu", 33, step-1, timestamp);
    
    return 0;
}

char _license[] SEC("license") = "GPL"; 