#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

typedef unsigned int __u32;
typedef unsigned long long __u64;

// BPF helper 函数声明
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
static long (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_ktime_get_ns)(void) = (void *) 5;

// 调试计数器Map
struct {
    __uint(type, 2);  // BPF_MAP_TYPE_ARRAY
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10);  // 增加到10个槽位用于调试
} debug_counters SEC(".maps");

// 主计数器Map (原有的)
struct {
    __uint(type, 2);  // BPF_MAP_TYPE_ARRAY
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} counter SEC(".maps");

// 调试信息Map - 存储执行路径
struct {
    __uint(type, 2);  // BPF_MAP_TYPE_ARRAY
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 20);  // 存储执行路径的每一步
} debug_trace SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_debug(void *ctx) {
    __u32 key, step = 0;
    __u64 val, *existing, timestamp;
    
    // 📍 步骤1: 记录函数入口
    timestamp = bpf_ktime_get_ns();
    key = step++;  // key = 0
    bpf_map_update_elem(&debug_trace, &key, &timestamp, 0);
    bpf_trace_printk("🚀 eBPF入口: step=%d, ts=%llu", 28, step-1, timestamp);
    
    // 📍 步骤2: 获取PID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    key = step++;  // key = 1
    val = (__u64)pid;
    bpf_map_update_elem(&debug_trace, &key, &val, 0);
    bpf_trace_printk("📋 PID获取: step=%d, pid=%d", 26, step-1, pid);
    
    // 📍 步骤3: 增加入口计数器
    key = 0;  // 入口计数器
    existing = bpf_map_lookup_elem(&debug_counters, &key);
    if (existing) {
        val = *existing + 1;
        bpf_trace_printk("📊 入口计数: step=%d, 现有=%llu", 29, step, *existing);
    } else {
        val = 1;
        bpf_trace_printk("📊 入口计数: step=%d, 首次", 24, step);
    }
    bpf_map_update_elem(&debug_counters, &key, &val, 0);
    step++;  // step = 3
    
    // 📍 步骤4: 检查主counter map
    key = 0;
    existing = bpf_map_lookup_elem(&counter, &key);
    if (existing) {
        bpf_trace_printk("🔍 主计数器: step=%d, 当前=%llu", 29, step, *existing);
        val = *existing;
    } else {
        bpf_trace_printk("🔍 主计数器: step=%d, 不存在", 26, step);
        val = 0;
    }
    
    // 记录当前值到debug_trace
    key = step++;  // key = 4
    bpf_map_update_elem(&debug_trace, &key, &val, 0);
    
    // 📍 步骤5: 更新主计数器为999
    key = 0;
    val = 999;
    long update_result = bpf_map_update_elem(&counter, &key, &val, 0);
    
    // 记录更新结果
    key = step++;  // key = 5  
    __u64 result_val = (update_result == 0) ? 1 : 0;  // 1=成功, 0=失败
    bpf_map_update_elem(&debug_trace, &key, &result_val, 0);
    bpf_trace_printk("✏️  主计数器更新: step=%d, 结果=%d", 31, step-1, (int)update_result);
    
    // 📍 步骤6: 验证更新结果
    existing = bpf_map_lookup_elem(&counter, &key);
    if (existing) {
        bpf_trace_printk("✅ 验证结果: step=%d, 新值=%llu", 28, step, *existing);
        key = step++;  // key = 6
        bpf_map_update_elem(&debug_trace, &key, existing, 0);
    } else {
        bpf_trace_printk("❌ 验证失败: step=%d", 18, step);
        key = step++;  // key = 6
        val = 0xFFFFFFFF;  // 错误标记
        bpf_map_update_elem(&debug_trace, &key, &val, 0);
    }
    
    // 📍 步骤7: 增加成功计数器
    key = 1;  // 成功计数器
    existing = bpf_map_lookup_elem(&debug_counters, &key);
    val = existing ? (*existing + 1) : 1;
    bpf_map_update_elem(&debug_counters, &key, &val, 0);
    bpf_trace_printk("🎉 成功计数: step=%d, 总共=%llu", 27, step, val);
    
    // 📍 步骤8: 记录函数出口
    timestamp = bpf_ktime_get_ns();
    key = step++;  // key = 8
    bpf_map_update_elem(&debug_trace, &key, &timestamp, 0);
    bpf_trace_printk("🏁 eBPF出口: step=%d, ts=%llu", 28, step-1, timestamp);
    
    return 0;
}

char _license[] SEC("license") = "GPL"; 