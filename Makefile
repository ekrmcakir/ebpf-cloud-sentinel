.PHONY: all build test lint coverage clean docker-build

BINARY_NAME=ebpf-cloud-sentinel
SIMULATOR_NAME=attack-simulator

all: lint test build

build:
	go build -o bin/$(BINARY_NAME) ./cmd/sentinel
	go build -o bin/$(SIMULATOR_NAME) ./cmd/simulator

test:
	go test -v -race -covermode=atomic -coverprofile=coverage.txt ./...

lint:
	go vet ./...

coverage: test
	go tool cover -func=coverage.txt

docker-build:
	docker build -t $(BINARY_NAME):latest .

clean:
	rm -rf bin/ dist/ coverage.txt
