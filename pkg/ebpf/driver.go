package ebpf

import (
	"context"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// Driver abstracts low-level kernel probe interaction
type Driver interface {
	Init(ctx context.Context) error
	Events() <-chan models.EgressEvent
	Close() error
}
