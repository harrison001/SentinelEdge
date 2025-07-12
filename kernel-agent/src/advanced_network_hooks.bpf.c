// kernel-agent/src/advanced_network_hooks.bpf.c
// Advanced network monitoring with XDP, TC, and socket filters

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_CONNECTIONS 10000
#define MAX_PACKET_SIZE 1500
#define MAX_PAYLOAD_INSPECT 128

// Network protocols
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

// Network headers
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ihl:4;
    __u8 version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1:4;
    __u16 doff:4;
    __u16 fin:1;
    __u16 syn:1;
    __u16 rst:1;
    __u16 psh:1;
    __u16 ack:1;
    __u16 urg:1;
    __u16 ece:1;
    __u16 cwr:1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((packed));

// Connection state tracking
struct connection_state {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 state;  // TCP state
    __u64 first_seen;
    __u64 last_seen;
    __u64 bytes_tx;
    __u64 bytes_rx;
    __u32 packets_tx;
    __u32 packets_rx;
    __u8 tcp_flags_seen;
    __u32 anomaly_score;
    __u8 is_suspicious;
};

// Network event
struct network_event {
    __u64 timestamp;
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 direction;  // 0=ingress, 1=egress
    __u16 packet_size;
    __u8 tcp_flags;
    __u8 payload_sample[64];
    __u32 threat_score;
    __u8 action_taken;  // 0=allow, 1=drop, 2=redirect
    char threat_type[32];
    __u8 is_malicious;
};

// DDoS protection state
struct ddos_state {
    __u32 src_ip;
    __u64 packet_count;
    __u64 byte_count;
    __u64 last_reset;
    __u8 is_blocked;
};

// Maps for network monitoring
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // connection hash
    __type(value, struct connection_state);
    __uint(max_entries, MAX_CONNECTIONS);
} connection_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} network_events SEC(".maps");

// DDoS protection
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);  // source IP
    __type(value, struct ddos_state);
    __uint(max_entries, 10000);
} ddos_tracker SEC(".maps");

// Blacklist/whitelist
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP address
    __type(value, __u8);  // 0=whitelist, 1=blacklist
    __uint(max_entries, 10000);
} ip_filter SEC(".maps");

// Port scan detection
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);  // source IP
    __type(value, __u64); // port bitmap
    __uint(max_entries, 1000);
} port_scan_detector SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 32);
} net_stats SEC(".maps");

// Helper functions
static __always_inline __u64 connection_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 16) | ((__u64)dport) | proto;
}

static __always_inline void update_stats(__u32 index) {
    __u64 *counter = bpf_map_lookup_elem(&net_stats, &index);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline int is_suspicious_port(__u16 port) {
    return (port == 4444 || port == 5555 || port == 6666 || 
            port == 1234 || port == 31337 || port == 12345 ||
            port == 9999 || port == 8080 || port == 3389);
}

static __always_inline int detect_port_scan(__u32 saddr, __u16 dport) {
    __u64 *port_bitmap = bpf_map_lookup_elem(&port_scan_detector, &saddr);
    __u64 new_bitmap = 0;
    
    if (port_bitmap) {
        new_bitmap = *port_bitmap;
    }
    
    if (dport < 64) {
        new_bitmap |= (1ULL << dport);
    }
    
    bpf_map_update_elem(&port_scan_detector, &saddr, &new_bitmap, BPF_ANY);
    
    int port_count = __builtin_popcountll(new_bitmap);
    return port_count > 8;  // Threshold for port scan
}

static __always_inline int analyze_payload(__u8 *payload, __u16 len) {
    if (len < 4) return 0;
    
    int threat_score = 0;
    
    // Check for common attack patterns
    if (payload[0] == 0x90 && payload[1] == 0x90) {  // NOP sled
        threat_score += 60;
    }
    
    // Check for SQL injection patterns
    if (len > 8) {
        if ((payload[0] == 'S' || payload[0] == 's') &&
            (payload[1] == 'E' || payload[1] == 'e') &&
            (payload[2] == 'L' || payload[2] == 'l')) {
            threat_score += 40;
        }
    }
    
    // Check for XSS patterns
    if (len > 6) {
        if (payload[0] == '<' && payload[1] == 's' && payload[2] == 'c') {
            threat_score += 35;
        }
    }
    
    // Check for binary content in HTTP
    int binary_count = 0;
    for (int i = 0; i < len && i < 32; i++) {
        if (payload[i] < 0x20 || payload[i] > 0x7e) {
            binary_count++;
        }
    }
    
    if (binary_count > len / 2) {
        threat_score += 25;
    }
    
    return threat_score;
}

static __always_inline int check_ddos_protection(__u32 src_ip, __u16 packet_size) {
    struct ddos_state *state = bpf_map_lookup_elem(&ddos_tracker, &src_ip);
    __u64 current_time = bpf_ktime_get_ns();
    
    if (!state) {
        struct ddos_state new_state = {
            .src_ip = src_ip,
            .packet_count = 1,
            .byte_count = packet_size,
            .last_reset = current_time,
            .is_blocked = 0
        };
        bpf_map_update_elem(&ddos_tracker, &src_ip, &new_state, BPF_ANY);
        return 0;
    }
    
    // Reset counters every second
    if (current_time - state->last_reset > 1000000000ULL) {
        state->packet_count = 1;
        state->byte_count = packet_size;
        state->last_reset = current_time;
        state->is_blocked = 0;
    } else {
        state->packet_count++;
        state->byte_count += packet_size;
    }
    
    // Check thresholds
    if (state->packet_count > 1000 || state->byte_count > 1024 * 1024) {
        state->is_blocked = 1;
        return 1;  // Block this IP
    }
    
    return 0;
}

// XDP program for earliest packet processing
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 packet_size = bpf_ntohs(ip->tot_len);
    
    // Check IP filter (blacklist/whitelist)
    __u8 *filter_result = bpf_map_lookup_elem(&ip_filter, &src_ip);
    if (filter_result && *filter_result == 1) {
        update_stats(0);  // Blacklisted IP counter
        return XDP_DROP;
    }
    
    // DDoS protection
    if (check_ddos_protection(src_ip, packet_size)) {
        update_stats(1);  // DDoS drop counter
        return XDP_DROP;
    }
    
    // Basic protocol filtering
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        
        __u16 dport = bpf_ntohs(tcp->dest);
        
        // Block suspicious ports
        if (is_suspicious_port(dport)) {
            update_stats(2);  // Suspicious port counter
            return XDP_DROP;
        }
        
        // Port scan detection
        if (detect_port_scan(src_ip, dport)) {
            update_stats(3);  // Port scan counter
            return XDP_DROP;
        }
        
        // SYN flood protection
        if (tcp->syn && !tcp->ack) {
            struct ddos_state *state = bpf_map_lookup_elem(&ddos_tracker, &src_ip);
            if (state && state->packet_count > 100) {
                update_stats(4);  // SYN flood counter
                return XDP_DROP;
            }
        }
    }
    
    update_stats(5);  // Total packets processed
    return XDP_PASS;
}

// TC ingress for detailed packet inspection
SEC("tc")
int tc_ingress_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    struct network_event *event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        return TC_ACT_OK;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->saddr = ip->saddr;
    event->daddr = ip->daddr;
    event->protocol = ip->protocol;
    event->direction = 0;  // Ingress
    event->packet_size = bpf_ntohs(ip->tot_len);
    event->tcp_flags = 0;
    event->threat_score = 0;
    event->action_taken = 0;
    event->is_malicious = 0;
    
    __u64 conn_hash = 0;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end) {
            goto submit_event;
        }
        
        event->sport = bpf_ntohs(tcp->source);
        event->dport = bpf_ntohs(tcp->dest);
        event->tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | 
                          (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
        
        conn_hash = connection_hash(ip->saddr, ip->daddr, tcp->source, tcp->dest, IPPROTO_TCP);
        
        // Payload inspection
        void *payload = (void *)tcp + (tcp->doff * 4);
        if (payload < data_end) {
            __u16 payload_len = data_end - payload;
            if (payload_len > 0 && payload_len <= 64) {
                bpf_probe_read_kernel(event->payload_sample, payload_len, payload);
                
                int payload_threat = analyze_payload(event->payload_sample, payload_len);
                event->threat_score += payload_threat;
                
                if (payload_threat > 40) {
                    __builtin_memcpy(event->threat_type, "MALICIOUS_PAYLOAD", 18);
                    event->is_malicious = 1;
                }
            }
        }
        
        // Connection state tracking
        struct connection_state *conn = bpf_map_lookup_elem(&connection_tracker, &conn_hash);
        if (!conn) {
            struct connection_state new_conn = {
                .saddr = ip->saddr,
                .daddr = ip->daddr,
                .sport = event->sport,
                .dport = event->dport,
                .protocol = IPPROTO_TCP,
                .state = 0,
                .first_seen = event->timestamp,
                .last_seen = event->timestamp,
                .bytes_rx = event->packet_size,
                .packets_rx = 1,
                .tcp_flags_seen = event->tcp_flags,
                .anomaly_score = event->threat_score,
                .is_suspicious = 0
            };
            bpf_map_update_elem(&connection_tracker, &conn_hash, &new_conn, BPF_ANY);
        } else {
            conn->last_seen = event->timestamp;
            conn->bytes_rx += event->packet_size;
            conn->packets_rx++;
            conn->tcp_flags_seen |= event->tcp_flags;
            conn->anomaly_score += event->threat_score;
            
            if (conn->anomaly_score > 100) {
                conn->is_suspicious = 1;
                event->is_malicious = 1;
                __builtin_memcpy(event->threat_type, "SUSPICIOUS_CONN", 16);
            }
        }
        
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end) {
            goto submit_event;
        }
        
        event->sport = bpf_ntohs(udp->source);
        event->dport = bpf_ntohs(udp->dest);
        
        // DNS amplification detection
        if (event->dport == 53 && event->packet_size > 512) {
            event->threat_score += 40;
            __builtin_memcpy(event->threat_type, "DNS_AMPLIFICATION", 18);
        }
        
        // UDP flood detection
        conn_hash = connection_hash(ip->saddr, ip->daddr, udp->source, udp->dest, IPPROTO_UDP);
        struct connection_state *conn = bpf_map_lookup_elem(&connection_tracker, &conn_hash);
        if (conn && conn->packets_rx > 100) {
            event->threat_score += 30;
            __builtin_memcpy(event->threat_type, "UDP_FLOOD", 10);
        }
    }
    
    // Determine action
    if (event->threat_score > 60) {
        event->action_taken = 1;  // Drop
        event->is_malicious = 1;
        update_stats(6);  // Malicious packet counter
        
        bpf_ringbuf_submit(event, 0);
        return TC_ACT_SHOT;
    }
    
submit_event:
    update_stats(7);  // Total ingress packets
    bpf_ringbuf_submit(event, 0);
    return TC_ACT_OK;
}

// TC egress for outbound traffic monitoring
SEC("tc")
int tc_egress_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // Monitor for data exfiltration
    __u16 packet_size = bpf_ntohs(ip->tot_len);
    if (packet_size > 1400) {  // Large outbound packets
        struct network_event *event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->saddr = ip->saddr;
            event->daddr = ip->daddr;
            event->protocol = ip->protocol;
            event->direction = 1;  // Egress
            event->packet_size = packet_size;
            event->threat_score = 20;
            event->action_taken = 0;
            event->is_malicious = 0;
            
            __builtin_memcpy(event->threat_type, "LARGE_EGRESS", 13);
            
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (struct tcphdr *)((char *)ip + (ip->ihl * 4));
                if ((void *)(tcp + 1) <= data_end) {
                    event->sport = bpf_ntohs(tcp->source);
                    event->dport = bpf_ntohs(tcp->dest);
                    event->tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | 
                                      (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
                }
            }
            
            bpf_ringbuf_submit(event, 0);
        }
        
        update_stats(8);  // Large egress packet counter
    }
    
    update_stats(9);  // Total egress packets
    return TC_ACT_OK;
}

// Socket filter for application-level monitoring
SEC("socket")
int socket_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return 0;
    }
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end) {
            return 0;
        }
        
        __u16 dport = bpf_ntohs(tcp->dest);
        __u16 sport = bpf_ntohs(tcp->source);
        
        // Monitor HTTP/HTTPS traffic
        if (dport == 80 || dport == 443 || sport == 80 || sport == 443) {
            update_stats(10);  // HTTP/HTTPS traffic counter
            return 1;  // Pass to userspace
        }
        
        // Monitor SSH traffic
        if (dport == 22 || sport == 22) {
            update_stats(11);  // SSH traffic counter
            return 1;
        }
        
        // Monitor database traffic
        if (dport == 3306 || dport == 5432 || dport == 1433) {
            update_stats(12);  // Database traffic counter
            return 1;
        }
    }
    
    return 0;
}

// Cgroup socket filter for process-based filtering
SEC("cgroup/sock")
int cgroup_sock_filter(struct bpf_sock *sk) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Allow local connections
    if (sk->family == AF_UNIX) {
        return 1;
    }
    
    // Check for suspicious process behavior
    if (sk->family == AF_INET) {
        __u32 dst_ip = sk->dst_ip4;
        __u16 dst_port = sk->dst_port;
        
        // Block connections to suspicious IPs/ports
        if (is_suspicious_port(dst_port)) {
            update_stats(13);  // Blocked connection counter
            return 0;  // Deny
        }
        
        // Log outbound connections
        update_stats(14);  // Total connection attempts
    }
    
    return 1;  // Allow
}

char LICENSE[] SEC("license") = "GPL"; 