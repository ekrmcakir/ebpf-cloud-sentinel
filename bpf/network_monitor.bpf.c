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
    struct egress_event_t *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = (__u32)pid_tgid;

    // Reserve space in BPF ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0; // Ring buffer congested or full
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = pid;
    event->tgid = tgid;
    event->protocol = 6; // IPPROTO_TCP
    event->flags = FLAG_TCP_CONNECT;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Submit reserved event to userspace ring buffer consumer
    bpf_ringbuf_submit(event, 0);
    return 0;
}
