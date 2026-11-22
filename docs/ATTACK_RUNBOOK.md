# Attack Simulation Runbook

This runbook demonstrates how `ebpf-cloud-sentinel` detects container compromise scenarios.

### Scenario 1: AWS IMDSv2 SSRF Attempt
- **Vector:** An attacker exploits an application vulnerability to curl `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
- **eBPF Detection:** Kernel `kprobe/tcp_v4_connect` detects packet destination `0xFEA9FEA9` (`169.254.169.254`).
- **Enrichment:** Maps PID -> cgroup -> Pod `payment-service` -> IAM Role `payment-processor-role`.
- **Verdict:** Generates `CRITICAL` alert with immediate mitigation advice (Hop Limit = 1).

### Scenario 2: Data Exfiltration Loop
- **Vector:** Compromised container executes high-frequency egress queries against public IP endpoints.
- **eBPF Detection:** Rate limiter detects $> 100$ outbound connects/min.
- **Verdict:** Generates `HIGH` severity egress burst alert.
