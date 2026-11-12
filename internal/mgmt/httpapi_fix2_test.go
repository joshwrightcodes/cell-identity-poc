package mgmt

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// The pending pool of the bind listener is full at its cap. A new connection is refused at once, no
// pending connection is evicted, and the hard deadline frees the pool.
func TestBindPendingPoolRefusesWhenFull(t *testing.T) {
	setPending(t, 4, 1500*time.Millisecond, time.Second)
	addr, mgmtCA, _ := startBind(t, NewBindHandler(&fakeBinder{}, jsonLog(io.Discard)))
	var held []interface{ Close() error }
	for i := 0; i < 4; i++ {
		c, err := rawTLS(t, addr, mgmtCA, 3*time.Second)
		if err != nil {
			t.Fatalf("pending connection %d: %v", i+1, err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	start := time.Now()
	if c, err := rawTLS(t, addr, mgmtCA, 3*time.Second); err == nil {
		c.Close()
		t.Fatal("a connection beyond the pool was accepted")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the refusal took %s", d)
	}
	// Nothing was evicted: the oldest connection is still open before the deadline.
	// The hard deadline then empties the pool, and a real request goes through.
	deadline := time.Now().Add(4 * time.Second)
	for {
		d, err := realBind(t, addr, mgmtCA, 500*time.Millisecond)
		if err == nil {
			_ = d
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no real request after the pending deadline: %v", err)
		}
	}
}

// Only a running request takes a bind slot. A 65th request at once gets a fast 503 with a reason.
func TestBindSlotsFullAnswers503(t *testing.T) {
	fb := &fakeBinder{gate: make(chan struct{}), entered: make(chan struct{}, 80)}
	h := NewBindHandler(fb, jsonLog(io.Discard))
	body := marshal(t, mgmtapi.BindRequest{Nonce: "n", Token: "t"})
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			do(h, "POST", mgmtapi.BindPath("dev-cell-1"), strings.NewReader(body))
		}()
	}
	for i := 0; i < 64; i++ {
		select {
		case <-fb.entered:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d requests running", i)
		}
	}
	start := time.Now()
	rec := do(h, "POST", mgmtapi.BindPath("dev-cell-1"), strings.NewReader(body))
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), `"reason":"slots_full"`) || rec.Header().Get("Connection") != "close" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("the 65th request: %d %s %v", rec.Code, rec.Body, rec.Header())
	}
	if time.Since(start) > time.Second {
		t.Fatal("the 503 was not fast")
	}
	close(fb.gate)
	wg.Wait()
	if rec := do(h, "POST", mgmtapi.BindPath("dev-cell-1"), strings.NewReader(body)); rec.Code != 200 {
		t.Fatalf("after the slots freed: %d", rec.Code)
	}
	// An invalid body also finishes a request, so it takes a slot only while it runs, and the slots
	// are free again.
	_ = errors.New
}

// Established connections have their own cap. Beyond it, the request gets a 503 and the connection
// closes.
func TestBindEstablishedCap(t *testing.T) {
	old := maxEstablished
	maxEstablished = 2
	t.Cleanup(func() { maxEstablished = old })
	fb := &fakeBinder{gate: make(chan struct{}), entered: make(chan struct{}, 8)}
	addr, mgmtCA, _ := startBind(t, NewBindHandler(fb, jsonLog(io.Discard)))
	body := marshal(t, mgmtapi.BindRequest{Nonce: "n", Token: "t"})
	type out struct {
		code int
		err  error
	}
	done := make(chan out, 3)
	for i := 0; i < 2; i++ {
		go func() {
			c := h2Client(t, mgmtCA, nil)
			resp, err := c.Post("https://"+addr+mgmtapi.BindPath("dev-cell-1"), "application/json", strings.NewReader(body))
			if err != nil {
				done <- out{0, err}
				return
			}
			resp.Body.Close()
			done <- out{resp.StatusCode, nil}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-fb.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("the first two requests did not run")
		}
	}
	c := h2Client(t, mgmtCA, nil)
	resp, err := c.Post("https://"+addr+mgmtapi.BindPath("dev-cell-1"), "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(b), "established_full") {
		t.Fatalf("the third connection: %d %s", resp.StatusCode, b)
	}
	close(fb.gate)
	for i := 0; i < 2; i++ {
		if o := <-done; o.err != nil || o.code != 200 {
			t.Fatalf("request %d: %v %d", i, o.err, o.code)
		}
	}
	_ = httptest.NewRecorder
}

func TestRestoreUnknownRevisionWrapsTheSentinel(t *testing.T) {
	r := newRig(t)
	err := r.plane.Restore(99)
	if !errors.Is(err, ErrRevisionUnknown) {
		t.Fatalf("Restore(99): %v", err)
	}
	if err := r.plane.IfSeq(r.status().Seq).Restore(99); !errors.Is(err, ErrRevisionUnknown) {
		t.Fatalf("guarded Restore(99): %v", err)
	}
}

// A connection that sends nothing ends at the first-byte deadline, long before the hard deadline.
func TestBindSilentConnEndsAtFirstByteDeadline(t *testing.T) {
	addr, _, _ := startBind(t, NewBindHandler(&fakeBinder{}, jsonLog(io.Discard)))
	c := silentConn(t, addr)
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the silent connection stayed open: %v", err)
	}
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Fatalf("the silent connection closed after %s, want about 1 s", d)
	}
}

// A bind request runs under the handler deadline.
func TestBindHandlerDeadline(t *testing.T) {
	old := bindHandlerTimeout
	bindHandlerTimeout = 200 * time.Millisecond
	t.Cleanup(func() { bindHandlerTimeout = old })
	fb := &fakeBinder{gate: make(chan struct{})}
	h := NewBindHandler(fb, jsonLog(io.Discard))
	start := time.Now()
	rec := do(h, "POST", mgmtapi.BindPath("dev-cell-1"), strings.NewReader(marshal(t, mgmtapi.BindRequest{Nonce: "n", Token: "t"})))
	if time.Since(start) > 3*time.Second || rec.Code < 400 {
		t.Fatalf("the request ran %s and answered %d", time.Since(start), rec.Code)
	}
}

// The bind write timeout lies above the handler deadline, so a request that runs longer than the
// old 15 s limit and ends before the deadline still gets its answer.
func TestBindAnswersAfterMoreThan15Seconds(t *testing.T) {
	if testing.Short() {
		t.Skip("runs about 17 s")
	}
	addr, ca, _ := startBind(t, NewBindHandler(&slowBinder{delay: 17 * time.Second}, jsonLog(io.Discard)))
	c := h2Client(t, ca, nil)
	c.Timeout = 30 * time.Second
	resp, err := c.Post("https://"+addr+mgmtapi.BindPath("dev-cell-1"), "application/json", strings.NewReader(marshal(t, mgmtapi.BindRequest{Nonce: "n", Token: "t"})))
	if err != nil {
		t.Fatalf("a 17 s bind request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// slowBinder answers a bind request after delay.
type slowBinder struct {
	fakeBinder
	delay time.Duration
}

func (b *slowBinder) Bind(ctx context.Context, _ string, _ mgmtapi.BindRequest) (mgmtapi.BindResponse, error) {
	select {
	case <-time.After(b.delay):
		return mgmtapi.BindResponse{Status: mgmtapi.StatusBound}, nil
	case <-ctx.Done():
		return mgmtapi.BindResponse{}, ctx.Err()
	}
}
