# eBPF Driver & Ring Buffer Architecture

`ebpf-cloud-sentinel` leverages `BPF_MAP_TYPE_RINGBUF` introduced in Linux 5.8+, outperforming traditional `perf_event` arrays by utilizing lock-free multi-producer single-consumer circular buffers.

## Driver Abstraction
The daemon provides two driver backends:
1. **Linux BPF Driver:** Compiles `bpf/network_monitor.bpf.c` and attaches kprobes to kernel TCP sockets.
2. **Mock Driver:** Used during local testing on macOS and within unit tests to stream synthetic network flows without kernel privileges.
