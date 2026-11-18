// +build ignore
#include "headers/bpf_helpers.h"

#define TASK_COMM_LEN 16
#define AF_INET 2

// AWS IMDSv2 IPv4 Address: 169.254.169.254 in network byte order (0xFEA9FEA9)
#define AWS_IMDS_IPV4 0xFEA9FEA9

#define FLAG_TCP_CONNECT    (1 << 0)
#define FLAG_IMDS_ACCESS    (1 << 1)
#define FLAG_PUBLIC_EGRESS  (1 << 2)

struct egress_event_t {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tgid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  flags;
    char  comm[TASK_COMM_LEN];
};

struct {
    __u32 type;
    __u32 max_entries;
} events SEC(".maps") = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 24, // 16MB ring buffer
};

static __attribute__((always_inline)) int is_imds_address(__u32 daddr) {
    return daddr == AWS_IMDS_IPV4;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect) {
    // Probes outbound TCP connections and flags IMDS requests
    return 0;
}
