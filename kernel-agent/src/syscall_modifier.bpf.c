// kernel-agent/src/syscall_modifier.bpf.c
// Advanced syscall parameter modification and access control

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_PROCESSES 1000
#define MAX_RULES 100

// File access control rule
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

// Process monitoring structure
struct process_info {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    __u64 start_time;
    __u32 syscall_count;
    __u32 file_access_count;
    __u32 network_count;
    __u8 is_suspicious;
    __u32 threat_score;
};

// Syscall interception event
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

// Maps for access control and monitoring
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct access_rule);
    __uint(max_entries, MAX_RULES);
} access_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // PID
    __type(value, struct process_info);
    __uint(max_entries, MAX_PROCESSES);
} process_monitor SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} syscall_events SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10);
} config SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 20);
} stats SEC(".maps");

// Helper functions
static __always_inline int str_cmp(const char *s1, const char *s2, int len) {
    for (int i = 0; i < len; i++) {
        if (s1[i] != s2[i]) {
            return s1[i] - s2[i];
        }
        if (s1[i] == '\0') {
            return 0;
        }
    }
    return 0;
}

static __always_inline int str_contains(const char *haystack, const char *needle, int haystack_len) {
    int needle_len = 0;
    for (int i = 0; i < MAX_FILENAME_LEN && needle[i] != '\0'; i++) {
        needle_len++;
    }
    
    if (needle_len == 0) return 0;
    
    for (int i = 0; i <= haystack_len - needle_len; i++) {
        int match = 1;
        for (int j = 0; j < needle_len; j++) {
            if (haystack[i + j] != needle[j]) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

static __always_inline void update_stats(__u32 index) {
    __u64 *counter = bpf_map_lookup_elem(&stats, &index);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline int is_sensitive_path(const char *path) {
    // Check for sensitive system paths
    return str_contains(path, "/etc/passwd", MAX_FILENAME_LEN) ||
           str_contains(path, "/etc/shadow", MAX_FILENAME_LEN) ||
           str_contains(path, "/etc/sudoers", MAX_FILENAME_LEN) ||
           str_contains(path, "/root/", MAX_FILENAME_LEN) ||
           str_contains(path, "/proc/", MAX_FILENAME_LEN) ||
           str_contains(path, "/sys/", MAX_FILENAME_LEN);
}

static __always_inline int calculate_threat_score(const char *path, __u32 uid, __u32 pid) {
    int score = 0;
    
    // High score for sensitive paths
    if (is_sensitive_path(path)) {
        score += 50;
    }
    
    // High score for root access
    if (uid == 0) {
        score += 30;
    }
    
    // Check for suspicious file patterns
    if (str_contains(path, ".sh", MAX_FILENAME_LEN) ||
        str_contains(path, ".py", MAX_FILENAME_LEN) ||
        str_contains(path, ".pl", MAX_FILENAME_LEN)) {
        score += 20;
    }
    
    // Check for temporary directories
    if (str_contains(path, "/tmp/", MAX_FILENAME_LEN) ||
        str_contains(path, "/var/tmp/", MAX_FILENAME_LEN)) {
        score += 15;
    }
    
    return score;
}

// Intercept openat system call
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 gid = bpf_get_current_uid_gid() >> 32;
    
    char filename[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->args[1]);
    
    // Update process monitoring
    struct process_info *proc = bpf_map_lookup_elem(&process_monitor, &pid);
    if (!proc) {
        struct process_info new_proc = {
            .pid = pid,
            .uid = uid,
            .gid = gid,
            .start_time = bpf_ktime_get_ns(),
            .syscall_count = 1,
            .file_access_count = 1,
            .network_count = 0,
            .is_suspicious = 0,
            .threat_score = 0
        };
        bpf_get_current_comm(&new_proc.comm, sizeof(new_proc.comm));
        bpf_map_update_elem(&process_monitor, &pid, &new_proc, BPF_ANY);
        proc = &new_proc;
    } else {
        proc->syscall_count++;
        proc->file_access_count++;
    }
    
    // Calculate threat score
    __u32 threat_score = calculate_threat_score(filename, uid, pid);
    proc->threat_score += threat_score;
    
    // Check access rules
    for (__u32 i = 0; i < MAX_RULES; i++) {
        struct access_rule *rule = bpf_map_lookup_elem(&access_rules, &i);
        if (!rule || !rule->enabled) {
            continue;
        }
        
        if (str_contains(filename, rule->target_path, MAX_FILENAME_LEN)) {
            rule->hit_count++;
            rule->last_access = bpf_ktime_get_ns();
            
            struct syscall_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
            if (!event) {
                continue;
            }
            
            event->timestamp = bpf_ktime_get_ns();
            event->pid = pid;
            event->uid = uid;
            event->gid = gid;
            event->syscall_nr = 257; // __NR_openat
            event->threat_score = threat_score;
            event->action_taken = rule->action;
            event->was_blocked = 0;
            
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->original_path, filename, MAX_FILENAME_LEN);
            
            switch (rule->action) {
                case 0: // Allow
                    __builtin_memcpy(event->reason, "ALLOWED", 8);
                    break;
                    
                case 1: // Deny
                    __builtin_memcpy(event->reason, "DENIED", 7);
                    event->was_blocked = 1;
                    // Modify the filename to point to /dev/null
                    bpf_probe_write_user((void *)ctx->args[1], "/dev/null", 10);
                    __builtin_memcpy(event->modified_path, "/dev/null", 10);
                    update_stats(1); // Blocked access counter
                    break;
                    
                case 2: // Redirect
                    __builtin_memcpy(event->reason, "REDIRECTED", 11);
                    bpf_probe_write_user((void *)ctx->args[1], rule->redirect_path, MAX_FILENAME_LEN);
                    __builtin_memcpy(event->modified_path, rule->redirect_path, MAX_FILENAME_LEN);
                    update_stats(2); // Redirected access counter
                    break;
                    
                case 3: // Log only
                    __builtin_memcpy(event->reason, "LOGGED", 7);
                    __builtin_memcpy(event->modified_path, filename, MAX_FILENAME_LEN);
                    update_stats(3); // Logged access counter
                    break;
            }
            
            bpf_ringbuf_submit(event, 0);
            
            // Mark process as suspicious if high threat score
            if (threat_score > 70) {
                proc->is_suspicious = 1;
            }
            
            break;
        }
    }
    
    update_stats(0); // Total openat calls
    return 0;
}

// Intercept execve system call for process monitoring
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 gid = bpf_get_current_uid_gid() >> 32;
    
    char filename[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->args[0]);
    
    // Check for suspicious executables
    __u32 threat_score = 0;
    char reason[64] = {0};
    
    if (str_contains(filename, "/tmp/", MAX_FILENAME_LEN)) {
        threat_score += 40;
        __builtin_memcpy(reason, "EXEC_FROM_TMP", 14);
    }
    
    if (str_contains(filename, "nc", MAX_FILENAME_LEN) ||
        str_contains(filename, "netcat", MAX_FILENAME_LEN) ||
        str_contains(filename, "ncat", MAX_FILENAME_LEN)) {
        threat_score += 50;
        __builtin_memcpy(reason, "NETCAT_EXEC", 12);
    }
    
    if (str_contains(filename, "bash", MAX_FILENAME_LEN) ||
        str_contains(filename, "sh", MAX_FILENAME_LEN)) {
        if (uid == 0) {
            threat_score += 30;
            __builtin_memcpy(reason, "ROOT_SHELL", 11);
        }
    }
    
    // Check access rules for executable
    for (__u32 i = 0; i < MAX_RULES; i++) {
        struct access_rule *rule = bpf_map_lookup_elem(&access_rules, &i);
        if (!rule || !rule->enabled) {
            continue;
        }
        
        if (str_contains(filename, rule->target_path, MAX_FILENAME_LEN)) {
            if (rule->action == 1) { // Deny execution
                // Replace with /bin/false
                bpf_probe_write_user((void *)ctx->args[0], "/bin/false", 10);
                
                struct syscall_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
                if (event) {
                    event->timestamp = bpf_ktime_get_ns();
                    event->pid = pid;
                    event->uid = uid;
                    event->gid = gid;
                    event->syscall_nr = 59; // __NR_execve
                    event->threat_score = threat_score;
                    event->action_taken = 1;
                    event->was_blocked = 1;
                    
                    bpf_get_current_comm(&event->comm, sizeof(event->comm));
                    __builtin_memcpy(event->original_path, filename, MAX_FILENAME_LEN);
                    __builtin_memcpy(event->modified_path, "/bin/false", 11);
                    __builtin_memcpy(event->reason, "EXEC_BLOCKED", 13);
                    
                    bpf_ringbuf_submit(event, 0);
                }
                
                update_stats(4); // Blocked execution counter
                break;
            }
        }
    }
    
    // Log high-threat executions
    if (threat_score > 40) {
        struct syscall_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = pid;
            event->uid = uid;
            event->gid = gid;
            event->syscall_nr = 59; // __NR_execve
            event->threat_score = threat_score;
            event->action_taken = 3; // Log
            event->was_blocked = 0;
            
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->original_path, filename, MAX_FILENAME_LEN);
            __builtin_memcpy(event->modified_path, filename, MAX_FILENAME_LEN);
            __builtin_memcpy(event->reason, reason, 64);
            
            bpf_ringbuf_submit(event, 0);
        }
        
        update_stats(5); // Suspicious execution counter
    }
    
    update_stats(6); // Total execve calls
    return 0;
}

// Intercept unlink system call (file deletion)
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    char filename[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->args[0]);
    
    // Protect critical system files
    if (str_contains(filename, "/etc/passwd", MAX_FILENAME_LEN) ||
        str_contains(filename, "/etc/shadow", MAX_FILENAME_LEN) ||
        str_contains(filename, "/boot/", MAX_FILENAME_LEN)) {
        
        // Block deletion by changing path to non-existent file
        bpf_probe_write_user((void *)ctx->args[0], "/dev/null/protected", 18);
        
        struct syscall_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = pid;
            event->uid = uid;
            event->gid = bpf_get_current_uid_gid() >> 32;
            event->syscall_nr = 87; // __NR_unlink
            event->threat_score = 90;
            event->action_taken = 1;
            event->was_blocked = 1;
            
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->original_path, filename, MAX_FILENAME_LEN);
            __builtin_memcpy(event->modified_path, "/dev/null/protected", 19);
            __builtin_memcpy(event->reason, "CRITICAL_FILE_PROTECTION", 26);
            
            bpf_ringbuf_submit(event, 0);
        }
        
        update_stats(7); // Protected file access counter
    }
    
    update_stats(8); // Total unlink calls
    return 0;
}

// Intercept chmod system call (permission changes)
SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 mode = ctx->args[1];
    
    char filename[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->args[0]);
    
    // Detect suspicious permission changes
    __u32 threat_score = 0;
    char reason[64] = {0};
    
    // Check for setting executable permissions
    if (mode & 0111) { // Execute permission
        threat_score += 30;
        __builtin_memcpy(reason, "EXEC_PERMISSION_SET", 20);
    }
    
    // Check for world-writable files
    if (mode & 0002) { // World writable
        threat_score += 40;
        __builtin_memcpy(reason, "WORLD_WRITABLE", 15);
    }
    
    // Check for SUID/SGID
    if (mode & 04000 || mode & 02000) { // SUID or SGID
        threat_score += 60;
        __builtin_memcpy(reason, "SUID_SGID_SET", 14);
    }
    
    if (threat_score > 50) {
        struct syscall_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = pid;
            event->uid = uid;
            event->gid = bpf_get_current_uid_gid() >> 32;
            event->syscall_nr = 90; // __NR_chmod
            event->threat_score = threat_score;
            event->action_taken = 3; // Log
            event->was_blocked = 0;
            
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->original_path, filename, MAX_FILENAME_LEN);
            __builtin_memcpy(event->modified_path, filename, MAX_FILENAME_LEN);
            __builtin_memcpy(event->reason, reason, 64);
            
            bpf_ringbuf_submit(event, 0);
        }
        
        update_stats(9); // Suspicious chmod counter
    }
    
    update_stats(10); // Total chmod calls
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 