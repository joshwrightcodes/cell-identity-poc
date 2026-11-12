package mgmt

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// setPending shortens the pool settings of the API listener for one test.
func setPending(t *testing.T, size int, hard, first time.Duration) {
	t.Helper()
	oldSize, oldHard, oldFirst := maxPendingHandshakes, handshakeDeadline, firstByteDeadline
	maxPendingHandshakes, handshakeDeadline, firstByteDeadline = size, hard, first
	t.Cleanup(func() { maxPendingHandshakes, handshakeDeadline, firstByteDeadline = oldSize, oldHard, oldFirst })
}

func silentConn(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// An unauthenticated peer cannot deny envd. Silent connections fill only the pending pool. A full
// pool refuses a new connection at once and evicts none, and every pending connection ends at its
// first-byte deadline.
func TestAPIPendingHandshakesCannotDenyEnvd(t *testing.T) {
	setPending(t, 4, 3*time.Second, 1200*time.Millisecond)
	rig := startAPI(t, NewAPIHandler(&fakeSpec{bundle: testBundle()}, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard)), nil, nil)
	envd := rig.devCA.Source(t, envdSPIFFE)
	get := func() error {
		resp, err := rig.client(t, envd).Get(rig.specURL("dev"))
		if err == nil {
			resp.Body.Close()
		}
		return err
	}

	var silent []net.Conn
	for i := 0; i < 3; i++ {
		silent = append(silent, silentConn(t, rig.addr))
	}
	time.Sleep(100 * time.Millisecond)
	if err := get(); err != nil {
		t.Fatalf("envd with 3 of 4 pending slots taken: %v", err)
	}
	silent = append(silent, silentConn(t, rig.addr))
	time.Sleep(100 * time.Millisecond)

	// The pool is full. A new connection is closed at once, and the pending ones stay.
	extra := silentConn(t, rig.addr)
	_ = extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := extra.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("a connection beyond the pool was not closed at once: %v", err)
	}
	if err := get(); err == nil {
		t.Fatal("envd got through a full pool")
	}
	_ = silent[0].SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := silent[0].Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("the oldest pending connection was evicted: %v", err)
	}
	waitLog(t, rig.logs, "pool_full")
	rig.logs.mu.Lock()
	n := strings.Count(rig.logs.buf.String(), `"reason":"pool_full"`)
	rig.logs.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d pool_full lines, want 1 in the window", n)
	}

	// The first-byte deadline frees the pool.
	for i, c := range silent {
		_ = c.SetReadDeadline(time.Now().Add(2200 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Fatalf("silent connection %d was not closed by the first-byte deadline: %v", i, err)
		}
	}
	if err := get(); err != nil {
		t.Fatalf("envd after the pending connections ended: %v", err)
	}
	waitLog(t, rig.logs, "handshake_timeout")
}

// A trickle that sends its first byte in time still ends at the hard deadline.
func TestAPIPendingHardDeadline(t *testing.T) {
	setPending(t, 4, 800*time.Millisecond, 300*time.Millisecond)
	rig := startAPI(t, NewAPIHandler(&fakeSpec{bundle: testBundle()}, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard)), nil, nil)
	c := silentConn(t, rig.addr)
	if _, err := c.Write([]byte{0x16}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the trickling connection stayed open: %v", err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("closed after %s, want about 800 ms", d)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return err != nil && (errors.As(err, &ne) && ne.Timeout())
}
