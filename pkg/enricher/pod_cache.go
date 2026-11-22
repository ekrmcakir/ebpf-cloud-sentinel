package enricher

import (
	"sync"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// PodCache holds real-time mapping between container IDs and Kubernetes Pod contexts
type PodCache struct {
	mu         sync.RWMutex
	containers map[string]*models.PodContext
	cgroups    map[uint64]*models.PodContext
}

func NewPodCache() *PodCache {
	return &PodCache{
		containers: make(map[string]*models.PodContext),
		cgroups:    make(map[uint64]*models.PodContext),
	}
}

func (c *PodCache) RegisterPod(containerID string, cgroupID uint64, pod *models.PodContext) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if containerID != "" {
		c.containers[containerID] = pod
	}
	if cgroupID != 0 {
		c.cgroups[cgroupID] = pod
	}
}

func (c *PodCache) Lookup(containerID string, cgroupID uint64) *models.PodContext {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var target *models.PodContext
	if containerID != "" {
		if ctx, exists := c.containers[containerID]; exists {
			target = ctx
		}
	}

	if target == nil && cgroupID != 0 {
		if ctx, exists := c.cgroups[cgroupID]; exists {
			target = ctx
		}
	}

	if target == nil {
		return nil
	}

	// Return a copy to avoid concurrency mutation / data race
	copied := *target
	if target.Labels != nil {
		copied.Labels = make(map[string]string, len(target.Labels))
		for k, v := range target.Labels {
			copied.Labels[k] = v
		}
	}
	return &copied
}

func (c *PodCache) Remove(containerID string, cgroupID uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.containers, containerID)
	delete(c.cgroups, cgroupID)
}
