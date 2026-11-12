package mgmt

import (
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// A bind listener that is full refuses a new connection at once, so a real cell fails fast and
// retries. It never leaves the cell behind a queue of anonymous connections. Probe of the security
// review: 180 holders, then a real nonce request.
func TestBindFullListenerAnswersRealCellFast(t *testing.T) {
	addr, mgmtCA, _ := startBind(t, NewBindHandler(&fakeBinder{}, jsonLog(io.Discard)))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var held []*tls.Conn
	for i := 0; i < 180; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := rawTLS(t, addr, mgmtCA, 5*time.Second)
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}()
	}
	wg.Wait()
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	if len(held) > 64 {
		t.Fatalf("%d connections stayed open, want at most 64", len(held))
	}
	good := h2Client(t, mgmtCA, nil)
	good.Timeout = 10 * time.Second
	start := time.Now()
	resp, err := good.Post("https://"+addr+mgmtapi.NoncePath("dev-cell-1"), "application/json", nil)
	if err == nil {
		resp.Body.Close()
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the real request took %s with the listener full (error %v), want an answer or a refusal within 3 s", d, err)
	}
	_ = http.StatusOK
}
