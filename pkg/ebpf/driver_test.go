package ebpf

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

func TestMockDriverLifecycle(t *testing.T) {
	driver := NewMockDriver()
	ctx := context.Background()

	if err := driver.Init(ctx); err != nil {
		t.Fatalf("unexpected init error: %v", err)
	}

	testEvt := models.EgressEvent{
		Timestamp:     time.Now(),
		PID:           1234,
		Command:       "node",
		SourceAddress: net.ParseIP("10.0.0.1"),
		DestAddress:   net.ParseIP("169.254.169.254"),
		DestPort:      80,
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		driver.InjectEvent(testEvt)
	}()

	select {
	case received := <-driver.Events():
		if !received.DestAddress.Equal(testEvt.DestAddress) {
			t.Errorf("expected %v, got %v", testEvt.DestAddress, received.DestAddress)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for event")
	}

	if err := driver.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}
