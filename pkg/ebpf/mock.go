package ebpf

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// MockDriver provides deterministic event generation for macOS, testing, and CI environments
type MockDriver struct {
	reader   *RingBufferReader
	stopChan chan struct{}
	wg       sync.WaitGroup
}

func NewMockDriver() *MockDriver {
	return &MockDriver{
		reader:   NewRingBufferReader(1024),
		stopChan: make(chan struct{}),
	}
}

func (m *MockDriver) Init(ctx context.Context) error {
	return nil
}

func (m *MockDriver) Events() <-chan models.EgressEvent {
	return m.reader.Channel()
}

// InjectEvent manually pushes an event into the reader pipeline
func (m *MockDriver) InjectEvent(evt models.EgressEvent) {
	m.reader.Push(evt)
}

// StartSyntheticTraffic generates periodic realistic egress events
func (m *MockDriver) StartSyntheticTraffic(interval time.Duration) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var counter int
		for {
			select {
			case <-m.stopChan:
				return
			case <-ticker.C:
				counter++
				dstIP := net.ParseIP("54.239.28.85") // Simulated AWS S3 IP
				if counter%5 == 0 {
					dstIP = net.ParseIP("169.254.169.254") // Simulated IMDS
				}

				m.InjectEvent(models.EgressEvent{
					Timestamp:     time.Now(),
					PID:           uint32(2000 + counter),
					TGID:          uint32(2000 + counter),
					CgroupID:      uint64(counter),
					Command:       "curl",
					SourceAddress: net.ParseIP("10.244.1.25"),
					DestAddress:   dstIP,
					SourcePort:    uint16(30000 + (counter % 10000)),
					DestPort:      80,
					Protocol:      "TCP",
				})
			}
		}
	}()
}

func (m *MockDriver) Close() error {
	close(m.stopChan)
	m.wg.Wait()
	return m.reader.Close()
}
