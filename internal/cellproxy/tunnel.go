package cellproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	tunnelMinBackoff  = time.Second
	tunnelMaxBackoff  = 30 * time.Second
	tunnelStableAfter = 60 * time.Second
	tunnelMaxStreams  = 250
	defaultTunnelWait = 10 * time.Second
	maxReviewBody     = 64 << 10
	readHeaderTimeout = 10 * time.Second
)

// tunnelClock lets a test run the redial loop on a fake clock.
type tunnelClock struct {
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

var realClock = tunnelClock{now: time.Now, sleep: sleepContext}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RunTunnel is the cell side of the mesh-view tunnel. It dials the management plane with dial,
// serves HTTP/2 with h on the dialed connection, and dials again when the connection ends. The
// wait between dials starts at 1 second, doubles up to 30 seconds, and has up to half of itself
// added as jitter, within the 30-second cap. A connection that lived for 60 seconds resets the
// wait to 1 second. RunTunnel returns nil when ctx ends.
func RunTunnel(ctx context.Context, dial func(context.Context) (net.Conn, error), h http.Handler) error {
	return runTunnel(ctx, dial, h, realClock)
}

func runTunnel(ctx context.Context, dial func(context.Context) (net.Conn, error), h http.Handler, c tunnelClock) error {
	srv := newTunnelServer()
	backoff := tunnelMinBackoff
	for {
		if conn, err := dial(ctx); err == nil {
			start := c.now()
			serveTunnel(ctx, srv, conn, h)
			if c.now().Sub(start) >= tunnelStableAfter {
				backoff = tunnelMinBackoff
			}
		}
		if c.sleep(ctx, jitter(backoff)) != nil {
			return nil
		}
		backoff = min(2*backoff, tunnelMaxBackoff)
	}
}

func jitter(d time.Duration) time.Duration {
	return min(d+rand.N(d/2+1), tunnelMaxBackoff)
}

// newTunnelServer pings an idle tunnel, so that the cell finds a dead connection and dials again.
func newTunnelServer() *http2.Server {
	return &http2.Server{MaxConcurrentStreams: tunnelMaxStreams, ReadIdleTimeout: upstreamReadIdle, PingTimeout: upstreamPingTimeout}
}

func serveTunnel(ctx context.Context, srv *http2.Server, conn net.Conn, h http.Handler) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	srv.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: h})
	_ = conn.Close()
}

// TunnelDialer returns the dial function of RunTunnel: TCP to addr, then a TLS handshake with
// cfg, which comes from ClientTLS. A refused server gives a *PeerError.
func TunnelDialer(addr string, cfg *tls.Config, log *slog.Logger) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: dialTimeout, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: keepAlivePeriod, Interval: keepAlivePeriod}}
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			log.Warn("tunnel dial failed", "reason", string(UpstreamUnavailable), "upstream", addr, "error", err.Error())
			return nil, err
		}
		conn := tls.Client(raw, cfg)
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		err = conn.HandshakeContext(hctx)
		cancel()
		if err != nil {
			_ = conn.Close()
			var pe *PeerError
			if errors.As(err, &pe) {
				log.Warn("peer refused", "reason", string(pe.Reason), "spiffe_id", pe.ID, "error", pe.Err.Error())
			} else {
				log.Warn("handshake failed", "upstream", addr, "error", err.Error())
			}
			return nil, err
		}
		log.Info("tunnel connected", "upstream", addr)
		return &loggedConn{Conn: conn, log: log, start: time.Now()}, nil
	}
}

// loggedConn logs the end of a tunnel once.
type loggedConn struct {
	net.Conn
	log   *slog.Logger
	start time.Time
	once  sync.Once
}

func (c *loggedConn) Close() error {
	c.once.Do(func() { c.log.Info("tunnel closed", "lived_seconds", int(time.Since(c.start).Seconds())) })
	return c.Conn.Close()
}

type cellHandler struct {
	api   *url.URL
	proxy *httputil.ReverseProxy
	log   *slog.Logger
}

// NewCellHandler serves the requests that arrive through the tunnel. It passes a request to the
// Kubernetes API at api only when the path is canonical and Allowed admits it. The upstream URL
// holds the checked path and the allowed query keys only. The handler deletes Authorization,
// Impersonate-*, Upgrade, Connection and the forwarding headers, so rt sets the token of the pod.
// A refusal is HTTP 403 with {"error":"denied","request_id":"<id>"}, and a log line with reason
// request_not_allowed.
func NewCellHandler(api *url.URL, rt http.RoundTripper, log *slog.Logger) http.Handler {
	h := &cellHandler{api: api, log: log}
	h.proxy = &httputil.ReverseProxy{
		Rewrite:       h.rewrite,
		Transport:     rt,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			upstreamFailed(w, r, log, err)
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return h
}

func (h *cellHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !Allowed(r.Method, r.URL) {
		refuse(w, r, h.log, RequestNotAllowed, "not an allowed Kubernetes read")
		return
	}
	if r.Method == http.MethodPost {
		if err := bufferBody(w, r, maxReviewBody); err != nil {
			refuse(w, r, h.log, RequestNotAllowed, err.Error())
			return
		}
	} else {
		dropBody(r)
	}
	h.proxy.ServeHTTP(w, r)
}

func (h *cellHandler) rewrite(pr *httputil.ProxyRequest) {
	p, _ := CanonicalPath(pr.In.URL)
	q, _ := url.ParseQuery(pr.In.URL.RawQuery)
	kept := url.Values{}
	for k, v := range q {
		if queryKeys[k] {
			kept[k] = v
		}
	}
	target := *h.api
	target.Path = strings.TrimSuffix(h.api.Path, "/") + p
	target.RawPath = ""
	target.RawQuery = kept.Encode()
	pr.Out.URL = &target
	pr.Out.Host = ""
	stripIdentity(pr.Out.Header)
}

// stripIdentity deletes every header that could carry an identity or a protocol switch.
func stripIdentity(h http.Header) {
	for k := range h {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "upgrade" || lk == "connection" || lk == "forwarded" || lk == "x-real-ip" ||
			strings.HasPrefix(lk, "impersonate-") || strings.HasPrefix(lk, "x-forwarded-") {
			delete(h, k)
		}
	}
}

// bufferBody reads at most limit bytes of the body, so the upstream gets a body of known size.
func bufferBody(w http.ResponseWriter, r *http.Request, limit int64) error {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(bodyReadTimeout))
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	_ = rc.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("body is larger than %d bytes", limit)
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	r.TransferEncoding = nil
	return nil
}

func dropBody(r *http.Request) {
	r.Body = http.NoBody
	r.ContentLength = 0
	r.TransferEncoding = nil
}

// refuse logs the reason and answers with the HTTP status of the reason and a body with only
// "denied" (or the reason, for a status other than 403) and a request ID.
func refuse(w http.ResponseWriter, r *http.Request, log *slog.Logger, reason Reason, detail string) {
	id := requestID()
	log.Warn("request denied", "reason", string(reason), "request_id", id, "method", r.Method, "path", r.URL.Path, "error", detail)
	word := "denied"
	if reason.HTTPStatus() != http.StatusForbidden {
		word = string(reason)
	}
	body, _ := json.Marshal(struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}{word, id})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", id)
	w.WriteHeader(reason.HTTPStatus())
	_, _ = w.Write(append(body, '\n'))
}

// upstreamFailed answers a failed upstream call. A request that its client canceled gets no
// answer and no warning.
func upstreamFailed(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	if r.Context().Err() != nil {
		log.Info("request canceled", "method", r.Method, "path", r.URL.Path)
		return
	}
	refuse(w, r, log, UpstreamUnavailable, err.Error())
}

// TunnelHub is the management side of the mesh-view tunnel. It keeps one HTTP/2 client
// connection for each cell, over the connection that the cell dialed, and serves a local
// handler for each cell that sends requests through it.
type TunnelHub struct {
	cells   map[string]string
	wait    time.Duration
	log     *slog.Logger
	mu      sync.Mutex
	conns   map[string]*tunnelConn
	changed chan struct{}
}

type tunnelConn struct {
	cc   *http2.ClientConn
	done <-chan struct{}
}

func (t *tunnelConn) usable() bool {
	select {
	case <-t.done:
		return false
	default:
	}
	st := t.cc.State()
	return !st.Closed && !st.Closing
}

// NewTunnelHub returns a hub for cells, a map from each cell name to the address of its local
// listener. A request waits up to wait for a tunnel. A zero wait means 10 seconds.
func NewTunnelHub(cells map[string]string, wait time.Duration, log *slog.Logger) *TunnelHub {
	if wait == 0 {
		wait = defaultTunnelWait
	}
	return &TunnelHub{cells: cells, wait: wait, log: log, conns: map[string]*tunnelConn{}, changed: make(chan struct{})}
}

// Accept makes conn the tunnel of the cell of s, and returns when conn ends. The newest
// connection of a cell wins: the hub closes the one before it. The client connection pings an
// idle tunnel after 30 seconds, and closes it when the ping gets no answer within 15 seconds.
func (h *TunnelHub) Accept(conn *tls.Conn, s Source) {
	log := h.log.With("cell", s.Cell)
	if _, ok := h.cells[s.Cell]; !ok || s.Plane != PlaneCell {
		log.Warn("tunnel refused", "reason", string(PeerNotAllowed), "error", "no tunnel listener for this cell")
		_ = conn.Close()
		return
	}
	nc := &notifyConn{Conn: conn, done: make(chan struct{})}
	t := &http2.Transport{ReadIdleTimeout: upstreamReadIdle, PingTimeout: upstreamPingTimeout}
	cc, err := t.NewClientConn(nc)
	if err != nil {
		log.Warn("tunnel failed", "reason", string(UpstreamUnavailable), "error", err.Error())
		_ = nc.Close()
		return
	}
	tc := &tunnelConn{cc: cc, done: nc.done}
	h.mu.Lock()
	old := h.conns[s.Cell]
	h.conns[s.Cell] = tc
	close(h.changed)
	h.changed = make(chan struct{})
	h.mu.Unlock()
	if old != nil {
		_ = old.cc.Close()
	}
	log.Info("tunnel_up", "env", s.Env)
	<-nc.done
	h.mu.Lock()
	if h.conns[s.Cell] == tc {
		delete(h.conns, s.Cell)
	}
	h.mu.Unlock()
	_ = cc.Close()
	log.Info("tunnel_down")
}

// await returns a usable tunnel of cell, or nil when none comes within the wait of the hub.
func (h *TunnelHub) await(ctx context.Context, cell string) *tunnelConn {
	timer := time.NewTimer(h.wait)
	defer timer.Stop()
	for {
		h.mu.Lock()
		tc, changed := h.conns[cell], h.changed
		h.mu.Unlock()
		if tc != nil && tc.usable() {
			return tc
		}
		select {
		case <-changed:
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// Handler sends each request through the tunnel of cell. With no tunnel, it waits for one up to
// the wait of the hub, then answers 503 with upstream_unavailable. It refuses a protocol
// upgrade, which HTTP/2 cannot carry.
func (h *TunnelHub) Handler(cell string) http.Handler {
	log := h.log.With("cell", cell)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			refuse(w, r, log, RequestNotAllowed, "protocol upgrade")
			return
		}
		tc := h.await(r.Context(), cell)
		if tc == nil {
			refuse(w, r, log, UpstreamUnavailable, "no tunnel from the cell")
			return
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme = "http"
				pr.Out.URL.Host = cell
				pr.Out.Host = ""
			},
			Transport:     tc.cc,
			FlushInterval: -1,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				upstreamFailed(w, r, log, err)
			},
			ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		}
		proxy.ServeHTTP(w, r)
	})
}

// Serve listens on the address of each cell and serves its handler there, until ctx ends or a
// listener fails.
func (h *TunnelHub) Serve(ctx context.Context) error {
	cells := make([]string, 0, len(h.cells))
	for c := range h.cells {
		cells = append(cells, c)
	}
	slices.Sort(cells)
	var servers []*http.Server
	var lns []net.Listener
	for _, c := range cells {
		ln, err := net.Listen("tcp", h.cells[c])
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			return fmt.Errorf("listen for cell %s: %w", c, err)
		}
		lns = append(lns, ln)
		servers = append(servers, &http.Server{
			Handler:           h.Handler(c),
			ReadHeaderTimeout: readHeaderTimeout,
			ErrorLog:          slog.NewLogLogger(h.log.Handler(), slog.LevelWarn),
		})
	}
	errc := make(chan error, len(servers))
	var wg sync.WaitGroup
	for i, srv := range servers {
		h.log.Info("tunnel listening", "cell", cells[i], "addr", lns[i].Addr().String())
		wg.Go(func() {
			if err := srv.Serve(lns[i]); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("serve cell %s: %w", cells[i], err)
			}
		})
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	for _, srv := range servers {
		_ = srv.Close()
	}
	wg.Wait()
	return err
}

// notifyConn closes done when the connection closes or its read fails.
type notifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) signal() { c.once.Do(func() { close(c.done) }) }

func (c *notifyConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			c.signal()
		}
	}
	return n, err
}

func (c *notifyConn) Close() error {
	c.signal()
	return c.Conn.Close()
}

type tunnelBackend struct{ hub *TunnelHub }

// NewTunnelBackend returns the tunnel backend. It hands each verified cell connection to h.
func NewTunnelBackend(h *TunnelHub) Backend { return &tunnelBackend{hub: h} }

func (b *tunnelBackend) Name() string { return "tunnel" }

// Serve keeps conn as the tunnel of its cell until conn or ctx ends.
func (b *tunnelBackend) Serve(ctx context.Context, conn *tls.Conn, src Source) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	b.hub.Accept(conn, src)
	return nil
}
