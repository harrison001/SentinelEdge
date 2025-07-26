/**
 * SentinelEdge eBPF Kernel Security Monitor
 *
 * This eBPF program provides real-time system monitoring by hooking into
 * critical kernel syscalls and events. It captures:
 * - Process execution events (execve syscalls)
 * - Network connection attempts (TCP connects)
 * - File system operations (VFS open calls)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>   // ✅ 让 bpf_ntohs/bpf_htons 可用

struct event_net_conn {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct event_exec {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    char filename[256];
};

struct event_file_op {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u32 operation;
    char filename[256];
    __u32 mode;
};

// High-performance ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ========== 1) 进程执行监控 ========= */
SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event_exec *event;
    struct task_struct *task;

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // 获取 syscall 参数 filename
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ========== 2) TCP 连接监控 ========= */
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct event_net_conn *event;
    struct sock *sk;
    struct inet_sock *inet;

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    inet = (struct inet_sock *)sk;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // ✅ 兼容新内核字段
    event->saddr = BPF_CORE_READ(inet, inet_saddr);
    event->daddr = BPF_CORE_READ(inet, sk.__sk_common.skc_daddr);

    __be16 sport = BPF_CORE_READ(inet, inet_sport);
    __be16 dport = BPF_CORE_READ(inet, sk.__sk_common.skc_dport);

    event->sport = bpf_ntohs(sport);
    event->dport = bpf_ntohs(dport);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ========== 3) 文件访问监控 ========= */
SEC("kprobe/vfs_open")
int trace_file_open(struct pt_regs *ctx)
{
    struct event_file_op *event;
    struct path *path;
    struct dentry *dentry;

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->operation = 0; // OPEN

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    path = (struct path *)PT_REGS_PARM1(ctx);
    dentry = BPF_CORE_READ(path, dentry);

    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              BPF_CORE_READ(dentry, d_name.name));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
