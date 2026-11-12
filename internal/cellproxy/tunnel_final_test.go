package cellproxy

import (
	"context"
	"encoding/json"
	stdlog "log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// captureStdLog sends the output of the standard library logger to a buffer until the test ends.
func captureStdLog(t *testing.T) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	prevW, prevF := stdlog.Writer(), stdlog.Flags()
	stdlog.SetOutput(out)
	stdlog.SetFlags(0)
	t.Cleanup(func() { stdlog.SetOutput(prevW); stdlog.SetFlags(prevF) })
	return out
}

// onlyJSON fails the test for each line of out that is not one JSON object.
func onlyJSON(t *testing.T, what string, out *syncBuffer) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if line != "" && json.Unmarshal([]byte(line), &m) != nil {
			t.Errorf("%s: a line on the standard logger is not JSON: %q", what, line)
		}
	}
}

// TestCellTunnelWritesOnlyJSONLines checks the two paths where x/net writes a plain line when it has no error
// logger: a TLS refusal by the hub, and a ping that gets no answer.
func TestCellTunnelWritesOnlyJSONLines(t *testing.T) {
	t.Run("TLS refusal", func(t *testing.T) {
		std := captureStdLog(t)
		h := newTunnelHarness(t, 5*time.Second)
		startCell(t, h.dialerFor(t, "spiffe://dev.env.poc.internal/cell/dev-cell-2/mesh-view"), h.cellHandler(t), WithLogger(jsonLog(h.cellLog)))
		findLog(t, h.cellLog, "tunnel_refused", map[string]any{"reason": PeerNotAllowed}, 5*time.Second)
		time.Sleep(300 * time.Millisecond)
		onlyJSON(t, "a TLS refusal", std)
	})
	t.Run("ping timeout", func(t *testing.T) {
		std := captureStdLog(t)
		h := newTunnelHarness(t, 5*time.Second)
		state := NewTunnelState()
		inner := TunnelDialer(h.server, ClientTLS(source(h.env.svid(t, meshViewID1)), h.mgmt.bundle(), spiffeIDOf(kialiID)), jsonLog(h.cellLog), WithState(state))
		var hole atomic.Pointer[bhConn]
		dial := func(ctx context.Context) (net.Conn, error) {
			c, err := inner(ctx)
			if err != nil {
				return nil, err
			}
			b := newBHConn(c)
			hole.Store(b)
			return b, nil
		}
		startCell(t, dial, h.cellHandler(t), WithKeepalive(300*time.Millisecond, 300*time.Millisecond), WithLogger(jsonLog(h.cellLog)))
		waitStatus(t, "the cell state up", 5*time.Second, func() bool { return state.Status().Up })
		hole.Load().on.Store(true)
		line := findLog(t, h.cellLog, "tunnel_ping_timeout", map[string]any{"reason": "ping_timeout", "level": "WARN"}, 5*time.Second)
		if line["detail"] == nil {
			t.Errorf("the ping timeout line %v has no detail", line)
		}
		onlyJSON(t, "a ping timeout", std)
	})
}

// TestBridgeStdLogWritesJSON checks the bridge for the lines of the hub transport, which has no error logger.
func TestBridgeStdLogWritesJSON(t *testing.T) {
	std := captureStdLog(t)
	out := &syncBuffer{}
	BridgeStdLog(jsonLog(out))
	stdlog.Printf("http2: Transport: unhandled response frame type %T", 1)
	if std.String() != "" {
		t.Errorf("the standard logger still wrote %q", std.String())
	}
	line := findLog(t, out, "http2: Transport: unhandled response frame type int", map[string]any{"level": "WARN"}, time.Second)
	if line["reason"] == nil {
		t.Errorf("the bridged line %v has no reason", line)
	}
}

// TestTunnelRefusedLogIsRateLimited checks that a hub that refuses each dial gives one tunnel_refused line, not
// one for each dial.
func TestTunnelRefusedLogIsRateLimited(t *testing.T) {
	h := newTunnelHarness(t, 5*time.Second)
	dial := h.dialerFor(t, "spiffe://dev.env.poc.internal/cell/dev-cell-2/mesh-view")
	refused := 0
	for range 8 {
		c, err := dial(t.Context())
		if err != nil {
			continue
		}
		_, _ = c.Read(make([]byte, 16))
		_ = c.Close()
		refused++
	}
	if refused < 3 {
		t.Fatalf("only %d dials reached the hub refusal", refused)
	}
	if n := countLog(t, h.cellLog, "tunnel_refused"); n != 1 {
		t.Fatalf("%d tunnel_refused lines for %d refusals, want 1:\n%s", n, refused, h.cellLog.String())
	}
}

// endedConn is a tunnel connection that reports an expiry on the fake clock, and ends at once.
type endedConn struct {
	net.Conn
	expiry time.Time
}

func (c *endedConn) Expiry() time.Time { return c.expiry }

func (c *endedConn) Read([]byte) (int, error) { return 0, net.ErrClosed }

func (c *endedConn) Write(p []byte) (int, error) { return len(p), nil }

// TestTunnelBacksOffOnExpiredLeaf checks that a connection whose leaf has expired, or has less than two minimum
// backoffs left, counts as a failed dial and takes the backoff path. Before this, the loop redialed with no sleep.
func TestTunnelBacksOffOnExpiredLeaf(t *testing.T) {
	type leaf struct {
		left time.Duration
		// stays is true when the tunnel stays open until the loop closes it.
		stays bool
	}
	for name, lf := range map[string]leaf{
		"expired":             {-time.Minute, false},
		"expired and open":    {-time.Minute, true},
		"50 ms left":          {50 * time.Millisecond, false},
		"50 ms left and open": {50 * time.Millisecond, true},
		"1.9 s left":          {1900 * time.Millisecond, false},
	} {
		left := lf.left
		t.Run(name, func(t *testing.T) {
			clock := &fakeClock{t: time.Unix(1000, 0)}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			dials := 0
			dial := func(context.Context) (net.Conn, error) {
				dials++
				if dials > 8 {
					cancel()
					return nil, context.Canceled
				}
				if lf.stays {
					return newRenewConn(clock.now().Add(left), false), nil
				}
				a, b := net.Pipe()
				t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
				return &endedConn{Conn: a, expiry: clock.now().Add(left)}, nil
			}
			done := make(chan error, 1)
			go func() {
				done <- runTunnel(ctx, dial, http.NotFoundHandler(), tunnelClock{now: clock.now, sleep: clock.sleep})
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the tunnel loop did not stop")
			}
			clock.mu.Lock()
			defer clock.mu.Unlock()
			if len(clock.sleeps) < 6 {
				t.Fatalf("%d dials gave %d sleeps %v, want one sleep after each dial", dials, len(clock.sleeps), clock.sleeps)
			}
			for i, base := range []time.Duration{1, 2, 4, 8, 16, 30} {
				base *= time.Second
				if d := clock.sleeps[i]; d < base || d > min(base+base/2, tunnelMaxBackoff) {
					t.Errorf("sleep %d is %s, want %s plus at most half of it", i+1, d, base)
				}
			}
		})
	}
}

// renewConn is a tunnel connection that lives until it closes, and that reports an expiry and its acceptance by the hub.
type renewConn struct {
	net.Conn
	expiry   time.Time
	accepted chan struct{}
	renewed  atomic.Bool
	closed   chan struct{}
	once     sync.Once
}

func newRenewConn(expiry time.Time, ends bool) *renewConn {
	a, _ := net.Pipe()
	c := &renewConn{Conn: a, expiry: expiry, accepted: make(chan struct{}), closed: make(chan struct{})}
	if ends {
		c.once.Do(func() { close(c.closed) })
	}
	return c
}

func (c *renewConn) Expiry() time.Time { return c.expiry }

func (c *renewConn) MarkRenewed() { c.renewed.Store(true) }

func (c *renewConn) Accepted() <-chan struct{} { return c.accepted }

func (c *renewConn) Read([]byte) (int, error) { <-c.closed; return 0, net.ErrClosed }

func (c *renewConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *renewConn) Close() error { c.once.Do(func() { close(c.closed) }); return c.Conn.Close() }

// TestTunnelRenewal checks the two rules of a renewal: the backoff resets only when the new leaf expires later than the
// old one, and the old tunnel counts as renewed only after the hub accepts the new one.
func TestTunnelRenewal(t *testing.T) {
	run := func(t *testing.T, second func(expiry time.Time) *renewConn) (*renewConn, *renewConn, []time.Duration) {
		t.Helper()
		clock := &fakeClock{t: time.Unix(1000, 0)}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var expiry time.Time
		var first, next *renewConn
		step := 0
		dial := func(context.Context) (net.Conn, error) {
			step++
			switch step {
			case 1, 2:
				return nil, net.ErrClosed
			case 3:
				expiry = clock.now().Add(2 * time.Second)
				first = newRenewConn(expiry, false)
				return first, nil
			case 4:
				next = second(expiry)
				return next, nil
			}
			cancel()
			return nil, context.Canceled
		}
		done := make(chan error, 1)
		go func() {
			done <- runTunnel(ctx, dial, http.NotFoundHandler(), tunnelClock{now: clock.now, sleep: clock.sleep})
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the tunnel loop did not stop")
		}
		clock.mu.Lock()
		defer clock.mu.Unlock()
		return first, next, append([]time.Duration(nil), clock.sleeps...)
	}
	t.Run("same expiry keeps the backoff", func(t *testing.T) {
		_, _, sleeps := run(t, func(e time.Time) *renewConn { return newRenewConn(e, true) })
		// Two failed dials (1 s, 2 s), a renewal that ends at once, then the sleep before the dial that stops the loop.
		if len(sleeps) < 3 {
			t.Fatalf("sleeps %v", sleeps)
		}
		if d := sleeps[2]; d < 4*time.Second {
			t.Errorf("the sleep after a renewal with the same expiry is %s, want at least 4 s: the backoff was reset", d)
		}
	})
	t.Run("later expiry resets the backoff", func(t *testing.T) {
		_, _, sleeps := run(t, func(e time.Time) *renewConn { return newRenewConn(e.Add(time.Minute), true) })
		if len(sleeps) < 3 {
			t.Fatalf("sleeps %v", sleeps)
		}
		if d := sleeps[2]; d > 1500*time.Millisecond {
			t.Errorf("the sleep after a renewal with a later expiry is %s, want 1 s plus jitter", d)
		}
	})
	t.Run("old tunnel counts as renewed after the hub accepts the new one", func(t *testing.T) {
		first, next, _ := run(t, func(e time.Time) *renewConn {
			c := newRenewConn(e.Add(time.Minute), true)
			close(c.accepted)
			return c
		})
		_ = next
		deadline := time.Now().Add(3 * time.Second)
		for !first.renewed.Load() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !first.renewed.Load() {
			t.Error("the old tunnel was never marked renewed")
		}
	})
	t.Run("old tunnel is not renewed when the hub refuses the new one", func(t *testing.T) {
		first, _, _ := run(t, func(e time.Time) *renewConn { return newRenewConn(e.Add(time.Minute), true) })
		time.Sleep(200 * time.Millisecond)
		if first.renewed.Load() {
			t.Error("the old tunnel was marked renewed, but the hub never accepted the new one")
		}
	})
}
