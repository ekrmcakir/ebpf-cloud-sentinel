# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-11-22

### Added
- **Kernel-space eBPF Probes:** C socket probes monitoring outbound TCP connections with `BPF_MAP_TYPE_RINGBUF`.
- **AWS IMDSv2 Detection:** Real-time flagging of queries to `169.254.169.254` with CRITICAL severity.
- **cgroup v2 & Kubernetes Metadata Enrichment:** Translates kernel cgroups to Pod, Namespace, and IRSA IAM Role ARNs.
- **Cloud IP Range Classifier:** Automated classification of AWS S3, STS, and public external IPs.
- **Telemetry & Exporters:** Native Prometheus `/metrics` exporter and OpenTelemetry (OTLP) log formatting.
- **Attack Simulator CLI:** Tooling to test and validate detection against simulated SSRF and data bursts.
- **Kubernetes Packaging:** Multi-stage Dockerfile, production Helm chart, and DaemonSet RBAC manifests.
