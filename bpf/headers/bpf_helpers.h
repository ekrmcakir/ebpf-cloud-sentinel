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

#endif /* __BPF_HELPERS_H */
