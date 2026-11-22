<h1 align="center">🛡️ ebpf-cloud-sentinel</h1>
<p align="center">
  <b>eBPF-Powered Kubernetes Zero-Trust Network &amp; IAM Egress Sensor for Cloud-Native Workloads</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.22-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/eBPF-Kernel%20Space-FF4081?style=flat-square&logo=linux&logoColor=white" alt="eBPF" />
  <img src="https://img.shields.io/badge/Kubernetes-DaemonSet-326CE5?style=flat-square&logo=kubernetes&logoColor=white" alt="Kubernetes" />
  <img src="https://img.shields.io/badge/AWS-IRSA%20%26%20IMDSv2-FF9900?style=flat-square&logo=amazon-aws&logoColor=white" alt="AWS" />
  <img src="https://img.shields.io/badge/Observability-Prometheus%20%7C%20OTel-F5A800?style=flat-square&logo=opentelemetry&logoColor=white" alt="OTel" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square" alt="License" />
</p>

---

## 🎯 Overview

**ebpf-cloud-sentinel** is a lightweight, high-performance security sensor that runs inside Linux kernel space via **eBPF (Extended Berkeley Packet Filter)**. 

It intercepts outbound container network flows (socket connects and data transfers) with zero proxy overhead, correlating kernel-level cgroups to **Kubernetes Pods, Namespaces, and AWS IAM Roles for Service Accounts (IRSA)**.

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

---

## ⚡ Key Capabilities

1. **Kernel-Level IMDSv2 SSRF Detection:** Immediately flags any container attempting to contact `169.254.169.254` to scrape AWS instance credentials.
2. **Kubernetes & IRSA Context Enrichment:** Resolves kernel cgroup IDs to Kubernetes Pod Names, Namespaces, Service Accounts, and associated IAM Role ARNs (`eks.amazonaws.com/role-arn`).
3. **High-Frequency Egress Anomaly Detection:** Detects data exfiltration bursts and rogue scraping loops directed at public storage (AWS S3, STS) or unauthorized external endpoints.
4. **Zero Proxy Latency:** Operates asynchronously via BPF ring buffers (`BPF_MAP_TYPE_RINGBUF`), bypassing userspace sidecars or iptables overhead.
5. **Standardized Telemetry:** Exposes `/metrics` for Prometheus and OpenTelemetry (OTLP) log formatting.

---

## 🚀 Quick Start

### 1. Build and Run Locally
```bash
git clone https://github.com/ekrmcakir/ebpf-cloud-sentinel.git
cd ebpf-cloud-sentinel

# Build binaries
make build

# Run in mock/emulation mode (Works on macOS and local Linux without raw BPF privileges)
./bin/ebpf-cloud-sentinel -mock -port 9091
```

### 2. Simulate Attack Scenarios
In another terminal, run the bundled attack simulator:
```bash
# Simulate unauthorized AWS IMDSv2 metadata access attempt (SSRF)
./bin/attack-simulator -attack=imds-ssrf -count=5

# Simulate high-frequency egress burst
./bin/attack-simulator -attack=s3-exfiltration -count=10
```

### 3. Deploy to Kubernetes via Helm
```bash
helm install ebpf-cloud-sentinel ./deploy/helm -n kube-system
```

---

## 🧪 Verification & Test Suite

Run the full Go test suite:
```bash
make test
# or
go test -v -race ./pkg/... ./cmd/... ./test/...
```

```text
=== RUN   TestEgressEventFormatting
--- PASS: TestEgressEventFormatting (0.00s)
=== RUN   TestMockDriverLifecycle
--- PASS: TestMockDriverLifecycle (0.01s)
=== RUN   TestClassifier
--- PASS: TestClassifier (0.00s)
=== RUN   TestExtractContainerID
--- PASS: TestExtractContainerID (0.00s)
=== RUN   TestPodCacheOperations
--- PASS: TestPodCacheOperations (0.00s)
=== RUN   TestIMDSDetector
--- PASS: TestIMDSDetector (0.00s)
=== RUN   TestMetricsExporter
--- PASS: TestMetricsExporter (0.00s)
=== RUN   TestAlertDispatcherWebhook
--- PASS: TestAlertDispatcherWebhook (0.05s)
=== RUN   TestEndToEndEgressCaptureToAlert
--- PASS: TestEndToEndEgressCaptureToAlert (0.00s)
PASS
ok  	github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models	0.12s
ok  	github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/ebpf	0.15s
ok  	github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/engine	0.11s
ok  	github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/enricher	0.13s
ok  	github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/detector	0.12s
ok  	github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/telemetry	0.14s
ok  	github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/alerting	0.18s
ok  	github.com/ekrmcakir/ebpf-cloud-sentinel/test/e2e	0.15s
```

---

## 📦 Directory Structure

```text
ebpf-cloud-sentinel/
├── bpf/                # Kernel-space C eBPF source (probes, event types, ring buffer map)
├── cmd/
│   ├── sentinel/       # Main Go Daemon entrypoint
│   └── simulator/      # Attack simulation CLI (IMDS SSRF, S3 exfiltration burst)
├── pkg/
│   ├── ebpf/           # Go BPF loader, ring buffer reader, and mock driver
│   ├── models/         # Domain event, alert, and pod context models
│   ├── engine/         # IP/CIDR classifier and AWS cloud service range mapper
│   ├── enricher/       # cgroup v2 parser, Kubernetes pod cache, IRSA resolution
│   ├── detector/       # IMDS SSRF rule engine and anomalous rate limiter
│   ├── telemetry/      # Prometheus HTTP metrics exporter and OTLP formatter
│   ├── alerting/       # Multi-channel webhook alert dispatcher
│   └── config/         # Environment configuration loader
├── deploy/
│   ├── helm/           # Production Helm chart
│   └── k8s/            # Kubernetes DaemonSet & RBAC manifests
├── test/e2e/           # End-to-end integration test suite
├── Dockerfile          # Multi-stage production container
└── README.md
```

---

## 📜 License

Licensed under the [Apache License, Version 2.0](LICENSE).
© 2026 Ekrem Cakir.
