// kernel-agent/src/kernel_structures.bpf.c
// Advanced kernel data structure access and analysis

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_DEPTH 10
#define MAX_PROCESSES 5000
#define MAX_NAMESPACES 100
#define MAX_MOUNTS 1000

// Process tree node
struct process_node {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    __u64 start_time;
    __u32 children_count;
    __u32 thread_count;
    __u8 is_kernel_thread;
    __u8 is_suspicious;
    __u32 namespace_id;
    __u32 cgroup_id;
};

// Namespace information
struct namespace_info {
    __u32 ns_id;
    __u32 type;  // PID, NET, MNT, etc.
    __u32 creator_pid;
    __u64 creation_time;
    __u32 process_count;
    __u8 is_isolated;
    char name[32];
};

// Mount point information
struct mount_info {
    __u32 mount_id;
    __u32 parent_id;
    __u32 major;
    __u32 minor;
    char fstype[16];
    char source[64];
    char target[64];
    __u32 flags;
    __u8 is_readonly;
    __u8 is_hidden;
};

// File system event
struct fs_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u32 operation;  // open, read, write, unlink, etc.
    char path[256];
    __u32 inode;
    __u32 device;
    __u64 size;
    __u32 mode;
    __u8 is_sensitive;
    __u32 threat_score;
};

// Network namespace event
struct netns_event {
    __u64 timestamp;
    __u32 pid;
    __u32 old_netns;
    __u32 new_netns;
    char comm[16];
    __u8 operation;  // 0=enter, 1=exit, 2=create
    __u32 threat_score;
};

// Cgroup information
struct cgroup_info {
    __u32 cgroup_id;
    __u32 parent_id;
    char name[64];
    __u32 process_count;
    __u64 memory_limit;
    __u64 memory_usage;
    __u32 cpu_shares;
    __u8 is_container;
};

// Maps for kernel structure tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // PID
    __type(value, struct process_node);
    __uint(max_entries, MAX_PROCESSES);
} process_tree SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // namespace ID
    __type(value, struct namespace_info);
    __uint(max_entries, MAX_NAMESPACES);
} namespaces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // mount ID
    __type(value, struct mount_info);
    __uint(max_entries, MAX_MOUNTS);
} mount_points SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // cgroup ID
    __type(value, struct cgroup_info);
    __uint(max_entries, MAX_PROCESSES);
} cgroups SEC(".maps");

// Event ring buffers
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} fs_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} netns_events SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 32);
} kernel_stats SEC(".maps");

// Helper functions
static __always_inline void update_stats(__u32 index) {
    __u64 *counter = bpf_map_lookup_elem(&kernel_stats, &index);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline int is_sensitive_path(const char *path) {
    // Check for sensitive system paths
    return (path[0] == '/' && path[1] == 'e' && path[2] == 't' && path[3] == 'c') ||
           (path[0] == '/' && path[1] == 'r' && path[2] == 'o' && path[3] == 'o' && path[4] == 't') ||
           (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' && path[4] == 'c') ||
           (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's');
}

static __always_inline __u32 get_namespace_id(struct task_struct *task, int ns_type) {
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;
    
    switch (ns_type) {
        case 0: // PID namespace
            return BPF_CORE_READ(nsproxy, pid_ns_for_children, ns.inum);
        case 1: // NET namespace
            return BPF_CORE_READ(nsproxy, net_ns, ns.inum);
        case 2: // MNT namespace
            return BPF_CORE_READ(nsproxy, mnt_ns, ns.inum);
        default:
            return 0;
    }
}

static __always_inline void analyze_process_tree(__u32 pid) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return;
    
    struct process_node *node = bpf_map_lookup_elem(&process_tree, &pid);
    if (!node) {
        struct process_node new_node = {
            .pid = pid,
            .ppid = BPF_CORE_READ(task, real_parent, tgid),
            .uid = bpf_get_current_uid_gid() & 0xFFFFFFFF,
            .gid = bpf_get_current_uid_gid() >> 32,
            .start_time = BPF_CORE_READ(task, start_time),
            .children_count = 0,
            .thread_count = 1,
            .is_kernel_thread = (BPF_CORE_READ(task, flags) & PF_KTHREAD) ? 1 : 0,
            .is_suspicious = 0,
            .namespace_id = get_namespace_id(task, 0),  // PID namespace
            .cgroup_id = 0  // Will be filled later
        };
        
        bpf_get_current_comm(&new_node.comm, sizeof(new_node.comm));
        bpf_map_update_elem(&process_tree, &pid, &new_node, BPF_ANY);
        
        // Update parent's children count
        __u32 ppid = new_node.ppid;
        struct process_node *parent = bpf_map_lookup_elem(&process_tree, &ppid);
        if (parent) {
            parent->children_count++;
        }
    }
}

// Track process creation and tree structure
SEC("kprobe/do_fork")
int trace_process_fork(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    analyze_process_tree(pid);
    
    // Check for suspicious process creation patterns
    struct process_node *node = bpf_map_lookup_elem(&process_tree, &pid);
    if (node) {
        // Check for rapid process creation (fork bomb)
        if (node->children_count > 50) {
            node->is_suspicious = 1;
            update_stats(0);  // Suspicious process creation
        }
        
        // Check for processes in unusual namespaces
        __u32 net_ns = get_namespace_id(task, 1);
        if (net_ns != 0 && net_ns != 0xF0000000) {  // Not default namespace
            update_stats(1);  // Process in custom namespace
        }
    }
    
    update_stats(2);  // Total process creations
    return 0;
}

// Track process exit and cleanup
SEC("kprobe/do_exit")
int trace_process_exit(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct process_node *node = bpf_map_lookup_elem(&process_tree, &pid);
    if (node) {
        // Update parent's children count
        __u32 ppid = node->ppid;
        struct process_node *parent = bpf_map_lookup_elem(&process_tree, &ppid);
        if (parent && parent->children_count > 0) {
            parent->children_count--;
        }
        
        // Clean up from process tree
        bpf_map_delete_elem(&process_tree, &pid);
    }
    
    update_stats(3);  // Total process exits
    return 0;
}

// Track namespace operations
SEC("kprobe/switch_task_namespaces")
int trace_namespace_switch(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    __u32 old_netns = get_namespace_id(task, 1);
    
    // This is called after the switch, so we need to track the change
    struct netns_event *event = bpf_ringbuf_reserve(&netns_events, sizeof(*event), 0);
    if (event) {
        event->timestamp = bpf_ktime_get_ns();
        event->pid = pid;
        event->old_netns = old_netns;
        event->new_netns = get_namespace_id(task, 1);
        event->operation = 0;  // Switch
        event->threat_score = 0;
        
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        
        // Check for suspicious namespace switching
        if (event->old_netns != event->new_netns) {
            event->threat_score = 30;
            update_stats(4);  // Namespace switches
        }
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// Track file system operations with deep analysis
SEC("kprobe/vfs_open")
int trace_vfs_open_deep(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    
    struct fs_event *event = bpf_ringbuf_reserve(&fs_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->uid = uid;
    event->operation = 0;  // OPEN
    event->inode = BPF_CORE_READ(inode, i_ino);
    event->device = BPF_CORE_READ(inode, i_sb, s_dev);
    event->size = BPF_CORE_READ(inode, i_size);
    event->mode = BPF_CORE_READ(inode, i_mode);
    event->is_sensitive = 0;
    event->threat_score = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Get file path
    bpf_probe_read_kernel_str(event->path, sizeof(event->path), 
                              BPF_CORE_READ(dentry, d_name.name));
    
    // Analyze file access patterns
    if (is_sensitive_path(event->path)) {
        event->is_sensitive = 1;
        event->threat_score += 40;
    }
    
    // Check for unusual file access patterns
    if (event->mode & S_ISUID) {  // SUID file
        event->threat_score += 30;
    }
    
    if (event->mode & S_ISGID) {  // SGID file
        event->threat_score += 25;
    }
    
    // Check for access to device files
    if (S_ISCHR(event->mode) || S_ISBLK(event->mode)) {
        event->threat_score += 35;
    }
    
    // Large file access
    if (event->size > 100 * 1024 * 1024) {  // > 100MB
        event->threat_score += 20;
    }
    
    update_stats(5);  // Total file opens
    
    if (event->threat_score > 50) {
        update_stats(6);  // Suspicious file access
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Track mount operations
SEC("kprobe/do_mount")
int trace_mount_operations(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    char *source = (char *)PT_REGS_PARM1(ctx);
    char *target = (char *)PT_REGS_PARM2(ctx);
    char *fstype = (char *)PT_REGS_PARM3(ctx);
    unsigned long flags = PT_REGS_PARM4(ctx);
    
    struct mount_info mount = {
        .mount_id = pid,  // Simplified ID
        .parent_id = 0,
        .major = 0,
        .minor = 0,
        .flags = flags,
        .is_readonly = (flags & MS_RDONLY) ? 1 : 0,
        .is_hidden = 0
    };
    
    if (source) {
        bpf_probe_read_user_str(mount.source, sizeof(mount.source), source);
    }
    
    if (target) {
        bpf_probe_read_user_str(mount.target, sizeof(mount.target), target);
    }
    
    if (fstype) {
        bpf_probe_read_user_str(mount.fstype, sizeof(mount.fstype), fstype);
    }
    
    // Check for suspicious mount operations
    if (mount.fstype[0] == 't' && mount.fstype[1] == 'm' && mount.fstype[2] == 'p') {
        // tmpfs mount - potentially suspicious
        update_stats(7);  // tmpfs mounts
    }
    
    if (mount.target[0] == '/' && mount.target[1] == 't' && mount.target[2] == 'm' && mount.target[3] == 'p') {
        // Mount in /tmp - suspicious
        update_stats(8);  // /tmp mounts
    }
    
    bpf_map_update_elem(&mount_points, &mount.mount_id, &mount, BPF_ANY);
    
    update_stats(9);  // Total mount operations
    return 0;
}

// Track cgroup operations
SEC("kprobe/cgroup_attach_task")
int trace_cgroup_attach(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct cgroup *cgrp = (struct cgroup *)PT_REGS_PARM1(ctx);
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM2(ctx);
    
    if (!cgrp || !task) return 0;
    
    __u32 cgroup_id = BPF_CORE_READ(cgrp, kn, id);
    __u32 target_pid = BPF_CORE_READ(task, tgid);
    
    struct cgroup_info *cgroup = bpf_map_lookup_elem(&cgroups, &cgroup_id);
    if (!cgroup) {
        struct cgroup_info new_cgroup = {
            .cgroup_id = cgroup_id,
            .parent_id = 0,  // Simplified
            .process_count = 1,
            .memory_limit = 0,
            .memory_usage = 0,
            .cpu_shares = 0,
            .is_container = 0
        };
        
        // Try to get cgroup name
        bpf_probe_read_kernel_str(new_cgroup.name, sizeof(new_cgroup.name),
                                  BPF_CORE_READ(cgrp, kn, name));
        
        // Check if this looks like a container cgroup
        if (new_cgroup.name[0] == 'd' && new_cgroup.name[1] == 'o' && new_cgroup.name[2] == 'c') {
            new_cgroup.is_container = 1;
        }
        
        bpf_map_update_elem(&cgroups, &cgroup_id, &new_cgroup, BPF_ANY);
    } else {
        cgroup->process_count++;
    }
    
    // Update process tree with cgroup info
    struct process_node *proc = bpf_map_lookup_elem(&process_tree, &target_pid);
    if (proc) {
        proc->cgroup_id = cgroup_id;
    }
    
    update_stats(10);  // Cgroup attachments
    return 0;
}

// Track memory mapping with detailed analysis
SEC("kprobe/do_mmap")
int trace_mmap_detailed(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 addr = PT_REGS_PARM1(ctx);
    __u64 len = PT_REGS_PARM2(ctx);
    __u32 prot = PT_REGS_PARM3(ctx);
    __u32 flags = PT_REGS_PARM4(ctx);
    
    struct fs_event *event = bpf_ringbuf_reserve(&fs_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->operation = 10;  // MMAP
    event->size = len;
    event->mode = prot;
    event->is_sensitive = 0;
    event->threat_score = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Analyze mmap characteristics
    if (prot & PROT_EXEC) {
        event->threat_score += 30;
        if ((prot & PROT_WRITE) && (prot & PROT_READ)) {
            // RWX mapping - highly suspicious
            event->threat_score += 40;
            event->is_sensitive = 1;
        }
    }
    
    if (flags & MAP_ANONYMOUS) {
        event->threat_score += 15;
    }
    
    if (len > 100 * 1024 * 1024) {  // > 100MB
        event->threat_score += 20;
    }
    
    // Check for unusual memory layouts
    if (addr < 0x400000 && addr != 0) {  // Low memory mapping
        event->threat_score += 50;
        event->is_sensitive = 1;
    }
    
    update_stats(11);  // Total mmap calls
    
    if (event->threat_score > 50) {
        update_stats(12);  // Suspicious mmap calls
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Track kernel module operations
SEC("kprobe/init_module")
int trace_module_init(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct fs_event *event = bpf_ringbuf_reserve(&fs_events, sizeof(*event), 0);
    if (event) {
        event->timestamp = bpf_ktime_get_ns();
        event->pid = pid;
        event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        event->operation = 20;  // MODULE_LOAD
        event->threat_score = 60;  // Module loading is always suspicious
        event->is_sensitive = 1;
        
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        __builtin_memcpy(event->path, "KERNEL_MODULE", 14);
        
        bpf_ringbuf_submit(event, 0);
    }
    
    update_stats(13);  // Kernel module loads
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 