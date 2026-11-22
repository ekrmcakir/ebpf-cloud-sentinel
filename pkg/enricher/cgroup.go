package enricher

import (
	"regexp"
)

var (
	// Matches container ID in containerd/docker/crio cgroup paths
	// e.g.: /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-abc1234567890abcdef.scope
	containerIDRegex = regexp.MustCompile(`([0-9a-f]{64})`)
)

// ExtractContainerID parses a Linux cgroup path and retrieves the hex container ID
func ExtractContainerID(cgroupPath string) string {
	if cgroupPath == "" {
		return ""
	}

	match := containerIDRegex.FindString(cgroupPath)
	if match != "" {
		return match
	}

	return ""
}
