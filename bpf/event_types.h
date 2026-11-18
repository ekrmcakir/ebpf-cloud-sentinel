#ifndef __EVENT_TYPES_H
#define __EVENT_TYPES_H

#include "headers/bpf_helpers.h"

#define TASK_COMM_LEN 16

#define FLAG_TCP_CONNECT    (1 << 0)
#define FLAG_IMDS_ACCESS    (1 << 1)
#define FLAG_PUBLIC_EGRESS  (1 << 2)
#define FLAG_ANOMALOUS_PORT (1 << 3)

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
} __attribute__((packed));

#endif /* __EVENT_TYPES_H */
