/* Minimal BPF helper declarations for kernel probe compilation */
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(NAME) __attribute__((section(NAME), used))
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0
#define BPF_KPROBE(name, args...) name(void *ctx, ##args)

/* BPF Helper function definitions */
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *) 133;

#endif /* __BPF_HELPERS_H */
