# Telemetry & Security Metrics Specification

`ebpf-cloud-sentinel` exposes native Prometheus metrics and OpenTelemetry semantic conventions.

## Prometheus Metrics
| Metric Name | Type | Description |
|---|---|---|
| `ebpf_sentinel_egress_events_total` | Counter | Total count of observed kernel egress flows |
| `ebpf_sentinel_imds_queries_total` | Counter | Total count of AWS IMDS (`169.254.169.254`) queries |
| `ebpf_sentinel_security_alerts_total` | Counter | Total security violations generated |

## OpenTelemetry Format
Security alerts are structured following OpenTelemetry Security Schema attributes:
- `security.rule`: Triggered rule name (e.g. `sec-rule-imds-ssrf-block`)
- `security.severity`: Alert level (`CRITICAL`, `HIGH`, `MEDIUM`)
- `k8s.pod.name`: Enriched pod context
- `aws.iam.role`: Target IAM Role ARN
