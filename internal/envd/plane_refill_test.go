package envd

import (
	"context"
	"crypto"
	"testing"
	"time"
)

// refillEngine is a fakeEngine that records the refill loop that the plane starts.
type refillEngine struct {
	fakeEngine
	every chan time.Duration
}

func (e *refillEngine) RunRefill(ctx context.Context, every time.Duration) {
	e.every <- every
	<-ctx.Done()
}

func TestPlaneRefillLoop(t *testing.T) {
	keys := func() []crypto.PublicKey { return nil }
	t.Run("runs at the interval until the context ends", func(t *testing.T) {
		eng := &refillEngine{every: make(chan time.Duration, 1)}
		p, err := NewPlane(PlaneConfig{Env: testEnv, Cluster: planeCluster, Keys: keys, Applier: eng, RefillEvery: 90 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { p.RunRefill(ctx); close(done) }()
		select {
		case got := <-eng.every:
			if got != 90*time.Second {
				t.Fatalf("interval = %s", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the refill loop did not start")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("RunRefill did not stop")
		}
	})
	t.Run("zero interval starts nothing", func(t *testing.T) {
		eng := &refillEngine{every: make(chan time.Duration, 1)}
		p, err := NewPlane(PlaneConfig{Env: testEnv, Cluster: planeCluster, Keys: keys, Applier: eng})
		if err != nil {
			t.Fatal(err)
		}
		p.RunRefill(t.Context())
		if len(eng.every) != 0 {
			t.Fatal("the loop started with a zero interval")
		}
	})
	t.Run("an applier that cannot refill", func(t *testing.T) {
		p, err := NewPlane(PlaneConfig{Env: testEnv, Cluster: planeCluster, Keys: keys, Applier: &fakeEngine{}, RefillEvery: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		p.RunRefill(t.Context())
	})
}
