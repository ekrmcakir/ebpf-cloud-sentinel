package enricher

import (
	"testing"
)

func TestExtractContainerID(t *testing.T) {
	cgroup := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-4f89d3a7b8e1f0c2a9d6e5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4.scope"
	expected := "4f89d3a7b8e1f0c2a9d6e5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4"

	actual := ExtractContainerID(cgroup)
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}

	empty := ExtractContainerID("")
	if empty != "" {
		t.Fatalf("expected empty result, got %s", empty)
	}
}
