#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

typedef unsigned int __u32;
typedef unsigned long long __u64;

static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;

struct {
    __uint(type, 2);  // BPF_MAP_TYPE_ARRAY
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} counter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    __u32 key = 0;
    __u64 val = 999;
    bpf_map_update_elem(&counter, &key, &val, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";