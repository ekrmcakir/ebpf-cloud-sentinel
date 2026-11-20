# Kubernetes Pod & IRSA Metadata Enrichment

Linux kernel socket events only expose raw cgroup IDs and PIDs. `ebpf-cloud-sentinel` translates these low-level identifiers into rich Kubernetes context.

## Translation Workflow
1. **cgroup Extraction:** Kernel event yields `cgroup_id`.
2. **Container Lookup:** Daemon extracts container hash from `/sys/fs/cgroup/...`.
3. **Informer Sync:** Queries Kubernetes API client or local cache to resolve Pod name, namespace, labels, and service accounts.
4. **IRSA Association:** Identifies the AWS IAM Role ARN bound to the pod (`eks.amazonaws.com/role-arn`), providing instantaneous visibility into cloud blast radius.
