# Multi-stage build for eBPF kernel sensor daemon
FROM golang:1.22-bookworm AS builder

WORKDIR /workspace
COPY go.mod ./
RUN go mod download || true

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /workspace/bin/ebpf-cloud-sentinel ./cmd/sentinel
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /workspace/bin/attack-simulator ./cmd/simulator

FROM debian:bookworm-slim AS runtime

# Install minimal runtime dependencies for BPF tracepoint mounting
RUN apt-get update && apt-get install -y --no-install-recommends     ca-certificates     iproute2     && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /workspace/bin/ebpf-cloud-sentinel /usr/local/bin/ebpf-cloud-sentinel
COPY --from=builder /workspace/bin/attack-simulator /usr/local/bin/attack-simulator

EXPOSE 9091

ENTRYPOINT ["/usr/local/bin/ebpf-cloud-sentinel"]
