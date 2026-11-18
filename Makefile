.PHONY: all build test lint clean docker-build

BINARY_NAME=ebpf-cloud-sentinel
SIMULATOR_NAME=attack-simulator

all: test build

build:
	go build -o bin/$(BINARY_NAME) ./cmd/sentinel
	go build -o bin/$(SIMULATOR_NAME) ./cmd/simulator

test:
	go test -v -race ./pkg/... ./cmd/...

lint:
	go vet ./...

clean:
	rm -rf bin/ dist/ coverage.txt
