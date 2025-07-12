// kernel-agent/src/advanced_packet_inspector.bpf.c
// Advanced packet deep inspection with protocol analysis and anomaly detection

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_PACKET_SIZE 1500
#define MAX_CONNECTIONS 10000
#define MAX_PAYLOAD_ANALYSIS 256

// Protocol definitions
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

// TCP flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

// Ethernet header
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

// IP header
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

// TCP header
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

// UDP header
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((packed));

// Connection tracking structure
struct connection_info {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 state;
    __u64 first_seen;
    __u64 last_seen;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u32 packets_sent;
    __u32 packets_received;
    __u8 tcp_flags_seen;
    __u32 anomaly_score;
};

// Packet analysis result
struct packet_analysis {
    __u64 timestamp;
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 tcp_flags;
    __u16 payload_len;
    __u8 payload_sample[64];
    __u32 anomaly_flags;
    __u32 threat_score;
    char threat_type[32];
    __u8 is_malicious;
    __u8 action_taken;
};

// Anomaly detection flags
#define ANOMALY_PORT_SCAN       0x01
#define ANOMALY_SYN_FLOOD       0x02
#define ANOMALY_UNUSUAL_PAYLOAD 0x04
#define ANOMALY_SUSPICIOUS_SIZE 0x08
#define ANOMALY_RAPID_CONNECT   0x10
#define ANOMALY_PROTOCOL_ABUSE  0x20
#define ANOMALY_MALFORMED_PKT   0x40
#define ANOMALY_ENCRYPTED_TUNNEL 0x80

// Maps for connection tracking and analysis
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // connection hash
    __type(value, struct connection_info);
    __uint(max_entries, MAX_CONNECTIONS);
} connection_tracker SEC(".maps");

// Ring buffer for packet analysis events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} packet_events SEC(".maps");

// Statistics counters
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} stats SEC(".maps");

// Port scan detection
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);  // source IP
    __type(value, __u64); // port bitmap
    __uint(max_entries, 1000);
} port_scan_tracker SEC(".maps");

// Helper functions
static __always_inline __u64 connection_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 16) | ((__u64)dport) | proto;
}

static __always_inline int is_suspicious_port(__u16 port) {
    // Common malicious ports
    return (port == 4444 || port == 5555 || port == 6666 || 
            port == 1234 || port == 31337 || port == 12345);
}

static __always_inline int analyze_payload(__u8 *payload, __u16 len) {
    if (len < 4) return 0;
    
    int score = 0;
    
    // Check for common malware signatures
    if (payload[0] == 0x4d && payload[1] == 0x5a) {  // MZ header
        score += 50;
    }
    
    // Check for shell code patterns
    if (payload[0] == 0x90 && payload[1] == 0x90) {  // NOP sled
        score += 30;
    }
    
    // Check for encrypted/encoded content
    int entropy = 0;
    for (int i = 0; i < len && i < 32; i++) {
        if (payload[i] > 0x20 && payload[i] < 0x7f) {
            entropy++;
        }
    }
    
    if (entropy < len / 4) {  // Low printable character ratio
        score += 20;
    }
    
    return score;
}

static __always_inline void update_stats(__u32 index) {
    __u64 *counter = bpf_map_lookup_elem(&stats, &index);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline int detect_port_scan(__u32 saddr, __u16 dport) {
    __u64 *port_bitmap = bpf_map_lookup_elem(&port_scan_tracker, &saddr);
    __u64 new_bitmap = 0;
    
    if (port_bitmap) {
        new_bitmap = *port_bitmap;
    }
    
    // Set bit for this port
    if (dport < 64) {
        new_bitmap |= (1ULL << dport);
    }
    
    bpf_map_update_elem(&port_scan_tracker, &saddr, &new_bitmap, BPF_ANY);
    
    // Count number of different ports accessed
    int port_count = __builtin_popcountll(new_bitmap);
    
    return port_count > 10;  // Threshold for port scan detection
}

// TC ingress hook for incoming packets
SEC("tc")
int tc_ingress_inspector(struct __sk_buff *skb) {
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
    
    // Skip fragmented packets for now
    if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
        return TC_ACT_OK;
    }
    
    struct packet_analysis *analysis = bpf_ringbuf_reserve(&packet_events, sizeof(*analysis), 0);
    if (!analysis) {
        return TC_ACT_OK;
    }
    
    analysis->timestamp = bpf_ktime_get_ns();
    analysis->pid = bpf_get_current_pid_tgid() >> 32;
    analysis->saddr = ip->saddr;
    analysis->daddr = ip->daddr;
    analysis->protocol = ip->protocol;
    analysis->anomaly_flags = 0;
    analysis->threat_score = 0;
    analysis->is_malicious = 0;
    analysis->action_taken = 0;
    
    __u64 conn_hash = 0;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end) {
            goto submit_analysis;
        }
        
        analysis->sport = bpf_ntohs(tcp->source);
        analysis->dport = bpf_ntohs(tcp->dest);
        analysis->tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | 
                             (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
        
        conn_hash = connection_hash(ip->saddr, ip->daddr, tcp->source, tcp->dest, IPPROTO_TCP);
        
        // Port scan detection
        if (detect_port_scan(ip->saddr, bpf_ntohs(tcp->dest))) {
            analysis->anomaly_flags |= ANOMALY_PORT_SCAN;
            analysis->threat_score += 40;
            __builtin_memcpy(analysis->threat_type, "PORT_SCAN", 10);
        }
        
        // SYN flood detection
        if (tcp->syn && !tcp->ack) {
            update_stats(1);  // SYN counter
            analysis->anomaly_flags |= ANOMALY_SYN_FLOOD;
            analysis->threat_score += 20;
        }
        
        // Suspicious port detection
        if (is_suspicious_port(bpf_ntohs(tcp->dest))) {
            analysis->anomaly_flags |= ANOMALY_SUSPICIOUS_SIZE;
            analysis->threat_score += 30;
            __builtin_memcpy(analysis->threat_type, "SUSPICIOUS_PORT", 16);
        }
        
        // Payload analysis
        void *payload = (void *)tcp + (tcp->doff * 4);
        if (payload < data_end) {
            __u16 payload_len = data_end - payload;
            if (payload_len > MAX_PAYLOAD_ANALYSIS) {
                payload_len = MAX_PAYLOAD_ANALYSIS;
            }
            
            analysis->payload_len = payload_len;
            
            if (payload_len >= 64) {
                bpf_probe_read_kernel(analysis->payload_sample, 64, payload);
                
                int payload_score = analyze_payload(analysis->payload_sample, payload_len);
                if (payload_score > 50) {
                    analysis->anomaly_flags |= ANOMALY_UNUSUAL_PAYLOAD;
                    analysis->threat_score += payload_score;
                    __builtin_memcpy(analysis->threat_type, "MALICIOUS_PAYLOAD", 18);
                }
            }
        }
        
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end) {
            goto submit_analysis;
        }
        
        analysis->sport = bpf_ntohs(udp->source);
        analysis->dport = bpf_ntohs(udp->dest);
        analysis->tcp_flags = 0;
        
        conn_hash = connection_hash(ip->saddr, ip->daddr, udp->source, udp->dest, IPPROTO_UDP);
        
        // DNS tunneling detection
        if (bpf_ntohs(udp->dest) == 53 || bpf_ntohs(udp->source) == 53) {
            __u16 dns_len = bpf_ntohs(udp->len);
            if (dns_len > 512) {  // Unusually large DNS packet
                analysis->anomaly_flags |= ANOMALY_ENCRYPTED_TUNNEL;
                analysis->threat_score += 35;
                __builtin_memcpy(analysis->threat_type, "DNS_TUNNEL", 11);
            }
        }
    }
    
    // Update connection tracking
    if (conn_hash != 0) {
        struct connection_info *conn = bpf_map_lookup_elem(&connection_tracker, &conn_hash);
        if (!conn) {
            struct connection_info new_conn = {
                .saddr = ip->saddr,
                .daddr = ip->daddr,
                .sport = analysis->sport,
                .dport = analysis->dport,
                .protocol = ip->protocol,
                .state = 0,
                .first_seen = analysis->timestamp,
                .last_seen = analysis->timestamp,
                .bytes_received = bpf_ntohs(ip->tot_len),
                .packets_received = 1,
                .tcp_flags_seen = analysis->tcp_flags,
                .anomaly_score = analysis->threat_score
            };
            bpf_map_update_elem(&connection_tracker, &conn_hash, &new_conn, BPF_ANY);
        } else {
            conn->last_seen = analysis->timestamp;
            conn->bytes_received += bpf_ntohs(ip->tot_len);
            conn->packets_received++;
            conn->tcp_flags_seen |= analysis->tcp_flags;
            conn->anomaly_score += analysis->threat_score;
        }
    }
    
    // Determine if packet is malicious
    if (analysis->threat_score > 60) {
        analysis->is_malicious = 1;
        analysis->action_taken = 1;  // DROP
        update_stats(2);  // Malicious packet counter
        
        bpf_ringbuf_submit(analysis, 0);
        return TC_ACT_SHOT;  // Drop malicious packet
    }
    
submit_analysis:
    update_stats(0);  // Total packet counter
    bpf_ringbuf_submit(analysis, 0);
    return TC_ACT_OK;
}

// XDP hook for earliest packet processing
SEC("xdp")
int xdp_packet_inspector(struct xdp_md *ctx) {
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
    
    // Quick DDoS protection - drop if too many packets from same source
    __u32 src_ip = ip->saddr;
    __u64 *packet_count = bpf_map_lookup_elem(&port_scan_tracker, &src_ip);
    __u64 current_count = packet_count ? *packet_count : 0;
    
    current_count++;
    bpf_map_update_elem(&port_scan_tracker, &src_ip, &current_count, BPF_ANY);
    
    // Simple rate limiting - drop if more than 1000 packets per second
    if (current_count > 1000) {
        update_stats(3);  // DDoS drop counter
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

// Socket filter for application-level monitoring
SEC("socket")
int socket_packet_filter(struct __sk_buff *skb) {
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
    
    // Only process TCP packets for application monitoring
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end) {
            return 0;
        }
        
        // Monitor specific application ports
        __u16 dport = bpf_ntohs(tcp->dest);
        if (dport == 80 || dport == 443 || dport == 22 || dport == 21) {
            update_stats(4);  // Application traffic counter
            return 1;  // Pass to userspace
        }
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 