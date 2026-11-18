# Architecture & Hook Point Design

`ebpf-cloud-sentinel` runs as a high-performance Kubernetes DaemonSet, embedding kernel-space eBPF probes to continuously monitor all outbound network flows from containers with zero overhead.

```
+-------------------------------------------------------------------------------+
|                             Kubernetes Node                                  |
|                                                                               |
|  +----------------------------+             +-------------------------------+  |
|  |     Application Pod        |             |  ebpf-cloud-sentinel Daemon   |  |
|  |  (e.g., checkout-service)  |             |  (Go + cilium/ebpf Driver)    |  |
|  +--------------+-------------+             +---------------+---------------+  |
|                 |                                           ^                 |
|                 | connect() / sendto()                      | Ring Buffer Poll|
|                 v                                           |                 |
|  +----------------------------------------------------------+---------------+  |
|  |                           Linux Kernel Space                             |  |
|  |                                                                           |  |
|  |   [ kprobe / tcp_v4_connect ] ----> [ AWS IMDS & Cloud IP Filter ]        |  |
|  |                 |                                    |                    |  |
|  |                 +---------> [ BPF RingBuffer ] <-----+                    |  |
|  +--------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------+
```

## Security Guarantees
1. **Zero-Trust Network Verification:** Detects unauthorized attempts to reach AWS Instance Metadata Service (IMDS `169.254.169.254`), public cloud storage (S3), or STS endpoints.
2. **Context Enrichment via cgroups:** Translates kernel-level cgroup IDs to Kubernetes Namespaces, Pod UIDs, and IAM Roles for Service Accounts (IRSA).
3. **Kernel Performance:** Operates at kernel speed without network proxies or iptables/conntrack churn.
