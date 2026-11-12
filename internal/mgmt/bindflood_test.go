package mgmt

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

// The kinds of anonymous holder. Each one takes a pending connection and keeps it for as long as the
// server lets it.
const (
	holdSilent      = "silent_tcp"
	holdSlowTLS     = "slow_tls"
	holdTLSIdle     = "tls_idle"
	holdSlowHeaders = "slow_headers"
	holdSlowBody    = "slow_body"
)

func holdHeaders(addr string, pad int) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, h := range [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", addr}, {":path", mgmtapi.BindPath("dev-cell-1")}, {"content-type", "application/json"}, {"x-pad", strings.Repeat("p", pad)}} {
		_ = enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
	}
	return buf.Bytes()
}

// hold opens one connection of the given kind and returns when the server closes it or ctx ends.
func hold(ctx context.Context, addr string, mgmtCA *spiffetest.CA, kind string, t testing.TB) {
	var conn net.Conn
	switch kind {
	case holdSilent, holdSlowTLS:
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			return
		}
		conn = c
	default:
		c, err := rawTLS(t, addr, mgmtCA, 5*time.Second)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			return
		}
		conn = c
	}
	defer conn.Close()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_, _ = io.Copy(io.Discard, conn)
	}()
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-closed:
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var fr *http2.Framer
	if kind == holdTLSIdle || kind == holdSlowHeaders || kind == holdSlowBody {
		fr = http2.NewFramer(conn, conn)
		_, _ = conn.Write([]byte(http2.ClientPreface))
		_ = fr.WriteSettings()
	}
	switch kind {
	case holdSlowTLS:
		_, _ = conn.Write([]byte{0x16, 0x03, 0x01, 0x10, 0x00})
	case holdSlowHeaders:
		block := holdHeaders(addr, 400)
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:1], EndHeaders: false})
		block = block[1:]
		for len(block) > 0 {
			select {
			case <-tick.C:
				if fr.WriteContinuation(1, false, block[:1]) != nil {
					return
				}
				block = block[1:]
			case <-closed:
				return
			}
		}
	case holdSlowBody:
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: holdHeaders(addr, 1), EndHeaders: true})
	}
	for {
		select {
		case <-tick.C:
			switch kind {
			case holdSlowTLS:
				if _, err := conn.Write([]byte{0x00}); err != nil {
					return
				}
			case holdSlowBody:
				if fr.WriteData(1, false, []byte{'{'}) != nil {
					return
				}
			}
		case <-closed:
			return
		}
	}
}

// realBind makes a celld-like nonce request on a new connection, and retries with a short backoff
// until it succeeds or the window ends.
func realBind(t *testing.T, addr string, mgmtCA *spiffetest.CA, window time.Duration) (time.Duration, error) {
	start := time.Now()
	var last error
	for time.Since(start) < window {
		c := h2Client(t, mgmtCA, nil)
		c.Timeout = 10 * time.Second
		resp, err := c.Post("https://"+addr+mgmtapi.NoncePath("dev-cell-1"), "application/json", nil)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return time.Since(start), nil
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return time.Since(start), last
}

// Probe table of the re-review (N1). K anonymous holders redial at once each time the server closes
// one. A real cell must still bind: 4 of 4 real binds finish within 30 s, in every row.
func TestBindFloodRealBindsFinish(t *testing.T) {
	if testing.Short() {
		t.Skip("runs about 20 s")
	}
	sem := make(chan struct{}, 3)
	for _, kind := range []string{holdSilent, holdSlowTLS, holdTLSIdle, holdSlowHeaders, holdSlowBody} {
		for _, k := range []int{64, 180} {
			t.Run(fmt.Sprintf("%s_%d", kind, k), func(t *testing.T) {
				t.Parallel()
				sem <- struct{}{}
				defer func() { <-sem }()
				addr, mgmtCA, _ := startBind(t, NewBindHandler(&fakeBinder{}, jsonLog(io.Discard)))
				ctx, cancel := context.WithCancel(t.Context())
				var wg sync.WaitGroup
				defer func() { cancel(); wg.Wait() }()
				for i := 0; i < k; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for ctx.Err() == nil {
							hold(ctx, addr, mgmtCA, kind, t)
						}
					}()
				}
				time.Sleep(1500 * time.Millisecond)
				type result struct {
					d   time.Duration
					err error
				}
				results := make(chan result, 4)
				for i := 0; i < 4; i++ {
					go func() {
						d, err := realBind(t, addr, mgmtCA, 30*time.Second)
						results <- result{d, err}
					}()
				}
				ok := 0
				var slowest time.Duration
				for i := 0; i < 4; i++ {
					r := <-results
					if r.err == nil {
						ok++
					} else {
						t.Logf("a real bind failed after %s: %v", r.d, r.err)
					}
					if r.d > slowest {
						slowest = r.d
					}
				}
				t.Logf("%s with %d holders: %d of 4 real binds, slowest %s", kind, k, ok, slowest)
				if ok != 4 {
					t.Fatalf("%d of 4 real binds finished within 30 s", ok)
				}
			})
		}
	}
}

var _ = tls.VersionTLS13
