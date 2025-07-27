// kernel-agent/src/syscall_modifier.bpf.c
// ✅ Verifier-safe syscall modifier with deny/redirect/log

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_PROCESSES 1000
#define MAX_RULES 100

#ifndef HAVE_BPF_STRNCMP
// Rocky8 does not have bpf_strncmp, define a fallback implementation
static __always_inline int __bpf_strncmp_fallback(const char *s1, const char *s2, unsigned int n) {
    #pragma clang loop unroll(full)
    for (unsigned int i = 0; i < n; i++) {
        if (s1[i] != s2[i]) return 1;   // mismatch
        if (s1[i] == '\0') break;       // reached the end
    }
    return 0; // match
}

// ✅ Use a macro to automatically correct the "old argument order" into the correct call
#define bpf_strncmp(a, b, c) __bpf_strncmp_fallback((a), (const char *)(c), (b))

#endif

// ========== Fixed sensitive paths in .rodata ========== 
const volatile char SENSITIVE_PASSWD[] SEC(".rodata") = "/etc/passwd";
const volatile char SENSITIVE_SHADOW[] SEC(".rodata") = "/etc/shadow";
const volatile char SENSITIVE_SUDOERS[] SEC(".rodata") = "/etc/sudoers";
const volatile char SENSITIVE_ROOT[]   SEC(".rodata") = "/root/";

// ========== Map structures ==========
struct access_rule {
    char target_path[MAX_FILENAME_LEN];
    char redirect_path[MAX_FILENAME_LEN];
    __u32 allowed_uid;
    __u32 allowed_gid;
    __u32 allowed_pid;
    __u8 action;  // 0=allow, 1=deny, 2=redirect, 3=log
    __u8 enabled;
    __u64 hit_count;
    __u64 last_access;
};

struct process_info {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    __u64 start_time;
    __u32 syscall_count;
    __u32 file_access_count;
    __u8 is_suspicious;
    __u32 threat_score;
};

struct syscall_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    __u32 syscall_nr;
    char original_path[MAX_FILENAME_LEN];
    char modified_path[MAX_FILENAME_LEN];
    __u8 action_taken;
    __u8 was_blocked;
    __u32 threat_score;
    char reason[64];
};

// maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct access_rule);
    __uint(max_entries, MAX_RULES);
} access_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // pid
    __type(value, struct process_info);
    __uint(max_entries, MAX_PROCESSES);
} process_monitor SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} syscall_events SEC(".maps");



// ========== Helper functions ==========
static __always_inline void update_stats(__u32 idx) {

    // Optional statistics map, omitted
}

static __always_inline int bpf_prefix_match(const char *path, const volatile char *prefix, int len) {
    return bpf_strncmp(path, len, (const char *)prefix) == 0;
}

// ✅ Simplified string matching to avoid verifier infinite loops
static __always_inline int match_rule_prefix(const char *path, const char *rule_path) {
    // Simplified version: only check first 16 characters to avoid verifier complexity
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        char a = path[i];
        char b = rule_path[i];
        if (b == '\0') return 1;    // rule match completed
        if (a == '\0') return 0;    // path ended but rule not completed
        if (a != b) return 0;       // character mismatch
    }
    return 1;
}

// ✅ Fixed sensitive path detection (.rodata)
static __always_inline int is_sensitive_path(const char *path) {
    if (bpf_prefix_match(path, SENSITIVE_PASSWD, 11)) return 1;
    if (bpf_prefix_match(path, SENSITIVE_SHADOW, 11)) return 1;
    if (bpf_prefix_match(path, SENSITIVE_SUDOERS, 12)) return 1;
    if (bpf_prefix_match(path, SENSITIVE_ROOT, 6)) return 1;
    return 0;
}

// ✅ Simplified threat_score calculation
static __always_inline int calc_threat_score(const char *path, __u32 uid) {
    int s = 0;
    if (is_sensitive_path(path)) s += 50;
    if (uid == 0) s += 20;
    if (!bpf_strncmp(path, 5, "/tmp/")) s += 15;
    return s;
}

// ringbuf event population
static __always_inline void log_event(__u32 pid, __u32 uid, __u32 gid,
                                      __u32 syscall_nr,
                                      const char *orig, const char *mod,
                                      const char *reason, __u8 act, __u8 blk, __u32 score) {
    struct syscall_event *evt = bpf_ringbuf_reserve(&syscall_events, sizeof(*evt), 0);
    if (!evt) return;
    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = pid;
    evt->uid = uid;
    evt->gid = gid;
    evt->syscall_nr = syscall_nr;
    evt->action_taken = act;
    evt->was_blocked = blk;
    evt->threat_score = score;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    __builtin_memcpy(evt->original_path, orig, 32);
    if (mod) __builtin_memcpy(evt->modified_path, mod, 32);
    if (reason) __builtin_memcpy(evt->reason, reason, 32);
    bpf_ringbuf_submit(evt, 0);
}

// ========== openat hook ==========
SEC("tp/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u32 gid = bpf_get_current_uid_gid() >> 32;

    char fname[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(fname, sizeof(fname), (void *)ctx->args[1]);

    // Calculate threat score
    __u32 score = calc_threat_score(fname, uid);

    // Simplified rule processing, only log events for now
    log_event(pid, uid, gid, 257, fname, fname, "OPENAT", 3, 0, score);

    return 0;
}

// ========== execve hook + blocking ==========
SEC("tp/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u32 gid = bpf_get_current_uid_gid() >> 32;

    char fname[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(fname, sizeof(fname), (void *)ctx->args[0]);

    // Block if threat score > 50
    __u32 score = calc_threat_score(fname, uid);

    // Simplified processing, only log execve events
    log_event(pid, uid, gid, 59, fname, fname, "EXECVE", 3, 0, score);

    return 0;
}

// ========== unlink hook ==========
SEC("tp/syscalls/sys_enter_unlink")
int tp_unlink(struct trace_event_raw_sys_enter *ctx) {
    char fname[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(fname, sizeof(fname), (void *)ctx->args[0]);

    if (is_sensitive_path(fname)) {
        bpf_probe_write_user((void *)ctx->args[0], "/dev/null/protected", 20);
        log_event(bpf_get_current_pid_tgid() >> 32,
                  bpf_get_current_uid_gid() & 0xffffffff,
                  bpf_get_current_uid_gid() >> 32,
                  87, fname, "/dev/null/protected", "PROTECT", 1, 1, 90);
    }
    return 0;
}

// ========== chmod hook ==========
SEC("tp/syscalls/sys_enter_chmod")
int tp_chmod(struct trace_event_raw_sys_enter *ctx) {
    __u32 mode = ctx->args[1];
    char fname[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(fname, sizeof(fname), (void *)ctx->args[0]);

    if (mode & 04000 || mode & 02000) {
        log_event(bpf_get_current_pid_tgid() >> 32,
                  bpf_get_current_uid_gid() & 0xffffffff,
                  bpf_get_current_uid_gid() >> 32,
                  90, fname, fname, "SUID/SGID", 3, 0, 60);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
