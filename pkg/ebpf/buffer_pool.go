package ebpf

import (
	"sync"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

var eventPool = sync.Pool{
	New: func() any {
		return &models.EgressEvent{}
	},
}

// AcquireEvent retrieves an event from the memory recycling pool
func AcquireEvent() *models.EgressEvent {
	return eventPool.Get().(*models.EgressEvent)
}

// ReleaseEvent returns the event to the pool
func ReleaseEvent(evt *models.EgressEvent) {
	*evt = models.EgressEvent{}
	eventPool.Put(evt)
}
