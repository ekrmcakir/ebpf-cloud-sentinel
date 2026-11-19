package ebpf

import (
	"context"
	"sync"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// RingBufferReader reads and dispatches events from kernel ring buffer
type RingBufferReader struct {
	eventsChan chan models.EgressEvent
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	isClosed   bool
	mu         sync.Mutex
}

func NewRingBufferReader(bufferSize int) *RingBufferReader {
	ctx, cancel := context.WithCancel(context.Background())
	return &RingBufferReader{
		eventsChan: make(chan models.EgressEvent, bufferSize),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (r *RingBufferReader) Channel() <-chan models.EgressEvent {
	return r.eventsChan
}

func (r *RingBufferReader) Push(evt models.EgressEvent) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.isClosed {
		return false
	}

	select {
	case r.eventsChan <- evt:
		return true
	default:
		// Drop or handle overflow
		return false
	}
}

func (r *RingBufferReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.isClosed {
		return nil
	}
	r.isClosed = true
	r.cancel()
	close(r.eventsChan)
	return nil
}
