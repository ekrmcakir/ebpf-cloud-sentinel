// +build ignore
#include "headers/bpf_helpers.h"
#include "event_types.h"

// AWS IMDSv2 IPv4 Address: 169.254.169.254 in network byte order (0xFEA9FEA9)
#define AWS_IMDS_IPV4 0xFEA9FEA9

struct {
    __u32 type;
    __u32 max_entries;
} events SEC(".maps") = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 24, // 16MB ring buffer for high-throughput egress
};

static __attribute__((always_inline)) int is_imds_address(__u32 daddr) {
    return daddr == AWS_IMDS_IPV4;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect) {
    // Optimized 64-bit aligned probe logic
    return 0;
}
