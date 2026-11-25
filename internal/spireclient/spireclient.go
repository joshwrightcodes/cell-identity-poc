// Package spireclient holds the shared Workload API client settings. A client
// that uses them reconnects to a restarted agent within seconds.
package spireclient

import (
	"math/rand/v2"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	grpcbackoff "google.golang.org/grpc/backoff"
)

const (
	// InitialDelay is the first wait after a failure. It is high enough to
	// prevent a busy loop against a missing socket.
	InitialDelay = 500 * time.Millisecond
	// MaxDelay caps both the watch back-off and the gRPC connection back-off.
	MaxDelay = 5 * time.Second
	// MinConnectTimeout bounds one connection attempt.
	MinConnectTimeout = 3 * time.Second

	jitter = 0.2
)

// ClientOptions returns the Workload API client options with both back-offs
// capped at MaxDelay.
func ClientOptions() []workloadapi.ClientOption {
	return []workloadapi.ClientOption{
		workloadapi.WithBackoffStrategy(Strategy{}),
		workloadapi.WithDialOptions(grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: grpcbackoff.Config{
				BaseDelay:  InitialDelay,
				Multiplier: 2,
				Jitter:     jitter,
				MaxDelay:   MaxDelay,
			},
			MinConnectTimeout: MinConnectTimeout,
		})),
	}
}

// SourceOptions returns ClientOptions as an X.509 source option.
func SourceOptions() workloadapi.X509SourceOption {
	return workloadapi.WithClientOptions(ClientOptions()...)
}

// Strategy is an exponential back-off. The cap applies first, then jitter adds up
// to 20%, so every delay lies between InitialDelay and 1.2 * MaxDelay.
type Strategy struct {
	// Rand returns a value in [0, 1). The zero value uses math/rand/v2.
	Rand func() float64
}

// NewBackoff implements workloadapi.BackoffStrategy.
func (s Strategy) NewBackoff() workloadapi.Backoff {
	r := s.Rand
	if r == nil {
		r = rand.Float64
	}
	return &backoff{rand: r}
}

type backoff struct {
	rand func() float64
	n    uint
}

func (b *backoff) Next() time.Duration {
	d := MaxDelay
	if b.n < 8 {
		d = min(InitialDelay<<b.n, MaxDelay)
	}
	b.n++
	return time.Duration(float64(d) * (1 + jitter*b.rand()))
}

func (b *backoff) Reset() { b.n = 0 }
