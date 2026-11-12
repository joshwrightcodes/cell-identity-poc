package cellproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// DefaultStatusAddr is the loopback address where a tunnel process serves its state. The state is not
// reachable from another pod. mesh:status and the probe of the tunnel pod read it with `cell-proxy
// tunnel-status`, which runs in the same container.
const DefaultStatusAddr = "127.0.0.1:18099"

// EndInfo says how the last tunnel of a side ended.
type EndInfo struct {
	// Cause is expiry (the timer of an SVID), replaced (the hub closed it for a newer tunnel), peer_closed
	// (the peer ended the connection: Detail has the error), ping_timeout or local_close (this side closed it).
	Cause  string    `json:"cause"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
	// Age is how long the tunnel lived.
	AgeSeconds float64 `json:"age_seconds"`
}

// CellStatus is the state of the tunnel of one cell at the hub, or of the tunnel of this cell.
type CellStatus struct {
	// Up is true when a usable tunnel exists. A tunnel that the hub replaced with a newer one never makes
	// the cell read as down.
	Up     bool   `json:"up"`
	ConnID uint64 `json:"conn_id,omitempty"`
	// ExpiresAt is when the open tunnel ends at the latest: the earlier expiry of the two leaves.
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	AgeSeconds  float64    `json:"age_seconds,omitempty"`
	DownSeconds float64    `json:"down_seconds,omitempty"`
	LastEnd     *EndInfo   `json:"last_end,omitempty"`
}

// TunnelStatus is the document that the status listener serves.
type TunnelStatus struct {
	// Side is hub or cell.
	Side string `json:"side"`
	// Up is true when every cell of the hub, or the tunnel of the cell, is up.
	Up    bool                  `json:"up"`
	Cells map[string]CellStatus `json:"cells"`
}

// TunnelState is the state of the tunnel of a cell, kept by the cell side. Several tunnels can be open
// at once while the cell renews: the cell is up while at least one is.
type TunnelState struct {
	mu      sync.Mutex
	started time.Time
	open    map[uint64]time.Time
	expires map[uint64]time.Time
	next    uint64
	last    *EndInfo
	downAt  time.Time
}

// NewTunnelState returns the state of a cell that has had no tunnel yet.
func NewTunnelState() *TunnelState {
	return &TunnelState{started: time.Now(), downAt: time.Now(), open: map[uint64]time.Time{}, expires: map[uint64]time.Time{}}
}

func (s *TunnelState) opened(expiry time.Time) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	s.open[s.next] = time.Now()
	s.expires[s.next] = expiry
	return s.next
}

func (s *TunnelState) closed(id uint64, cause, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.open[id]
	if !ok {
		return
	}
	delete(s.open, id)
	delete(s.expires, id)
	s.last = &EndInfo{Cause: cause, Detail: detail, At: time.Now(), AgeSeconds: time.Since(at).Seconds()}
	if len(s.open) == 0 {
		s.downAt = time.Now()
	}
}

// Status returns the document of the cell side.
func (s *TunnelState) Status() TunnelStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := CellStatus{Up: len(s.open) > 0, LastEnd: s.last}
	if c.Up {
		var newest uint64
		for id := range s.open {
			newest = max(newest, id)
		}
		c.ConnID, c.AgeSeconds = newest, time.Since(s.open[newest]).Seconds()
		if e := s.expires[newest]; !e.IsZero() {
			c.ExpiresAt = &e
		}
	} else {
		c.DownSeconds = time.Since(s.downAt).Seconds()
	}
	return TunnelStatus{Side: sideCell, Up: c.Up, Cells: map[string]CellStatus{"self": c}}
}

// ServeStatus serves the document of status on addr until ctx ends. The address must be a loopback
// address, so no other pod reads it.
func ServeStatus(ctx context.Context, addr string, status func() TunnelStatus, log *slog.Logger) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("status address %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("status address %q is not a loopback address", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status())
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: readHeaderTimeout, ErrorLog: proxyErrorLog(log)}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// FetchStatus reads the document of a status listener.
func FetchStatus(ctx context.Context, addr string) (TunnelStatus, error) {
	var st TunnelStatus
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/status", nil)
	if err != nil {
		return st, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return st, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return st, err
	}
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("status listener answers %d: %.200s", resp.StatusCode, body)
	}
	return st, json.Unmarshal(body, &st)
}
