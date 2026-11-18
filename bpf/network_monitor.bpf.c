// +build ignore
#include "headers/bpf_helpers.h"

#define TASK_COMM_LEN 16
#define AF_INET 2

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

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect) {
    // Socket connect lifecycle tracking probe
    return 0;
}
