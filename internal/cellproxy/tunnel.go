package cellproxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/net/http2"
)

// MeshViewRole is the only role that may hold the tunnel of a cell.
const MeshViewRole = "mesh-view"

const (
	tunnelMinBackoff  = time.Second
	tunnelMaxBackoff  = 30 * time.Second
	tunnelStableAfter = 30 * time.Second
	tunnelMaxStreams  = 250
	defaultTunnelWait = 10 * time.Second
	maxReviewBody     = 64 << 10
	readHeaderTimeout = 10 * time.Second
	// hubIdleTimeout closes a listener connection that sits idle between requests. A watch is a
	// request in progress, so it never counts as idle.
	hubIdleTimeout = 2 * time.Minute
	// hubMaxHeaderBytes bounds the request header that a client of a cell listener may send.
	hubMaxHeaderBytes = 64 << 10
	// hubMaxStreams is the number of requests that one cell listener passes into the tunnel at the
	// same time. It stays below tunnelMaxStreams, so a flood is refused at the hub and never queues
	// in the HTTP/2 client connection.
	hubMaxStreams = 200
)

// forwardHeaders are the only request headers that cross the tunnel and reach the Kubernetes
// API. The transport of the pod adds Authorization with the pod token.
var forwardHeaders = []string{"Accept", "Accept-Encoding", "Content-Type", "User-Agent"}

// allowedHeaders returns a new header with only the forwardHeaders of in.
func allowedHeaders(in http.Header) http.Header {
	out := http.Header{}
	for _, k := range forwardHeaders {
		if v := in.Values(k); len(v) > 0 {
			out[k] = slices.Clone(v)
		}
	}
	return out
}

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
// added as jitter, within the 30-second cap. A connection that lived for 30 seconds resets the
// wait to 1 second. RunTunnel returns nil when ctx ends.
func RunTunnel(ctx context.Context, dial func(context.Context) (net.Conn, error), h http.Handler, opts ...TunnelOption) error {
	return runTunnelWith(ctx, dial, h, realClock, applyOptions(opts))
}

func runTunnel(ctx context.Context, dial func(context.Context) (net.Conn, error), h http.Handler, c tunnelClock) error {
	return runTunnelWith(ctx, dial, h, c, tunnelOptions{})
}

func runTunnelWith(ctx context.Context, dial func(context.Context) (net.Conn, error), h http.Handler, c tunnelClock, o tunnelOptions) error {
	srv := newTunnelServer(o.keepalive())
	log := cmp.Or(o.log, slog.Default())
	base := &http.Server{ErrorLog: proxyErrorLog(log)}
	skips := newLogLimiter()
	var wg sync.WaitGroup
	defer wg.Wait()
	serve := func(conn net.Conn) chan struct{} {
		ended := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(ended)
			serveTunnel(ctx, srv, conn, h, base)
		}()
		return ended
	}
	backoff := tunnelMinBackoff
	// The current tunnel: its end, its start, when to dial the next one, and how long it must live to
	// count as stable. A connection with an Expiry method (the TLS connection of a cell) is renewed
	// before it ends: the next tunnel opens at 60 percent of the remaining life, with the SVID that
	// the source holds by then, and the hub closes the older tunnel when the newer one arrives.
	var ended chan struct{}
	var cur net.Conn
	var start, renewAt, expiry time.Time
	stable := tunnelStableAfter
	// connect dials and serves the new tunnel. With no tunnel open, a connection with an Expiry that leaves
	// less than two minimum backoffs counts as a failed dial: the leaf of the cell is expired, or the agent
	// does not renew it, and a new dial would give the same short life. A renewal keeps such a connection,
	// because the hub already made it the tunnel of the cell.
	connect := func(renewing bool) bool {
		conn, err := dial(ctx)
		if err != nil {
			return false
		}
		now := c.now()
		var exp time.Time
		if e, ok := conn.(interface{ Expiry() time.Time }); ok {
			exp = e.Expiry()
		}
		if !renewing && !exp.IsZero() && exp.Sub(now) < 2*tunnelMinBackoff {
			_ = conn.Close()
			o.metrics.connect(ctx, attribute.String("side", sideCell), attribute.String("result", dialLeafExpiring))
			if ok, suppressed, _ := skips.allow(log, "tunnel_dial_skipped", nil); ok {
				log.Warn("tunnel_dial_skipped", "reason", string(LeafExpiring), "not_after", exp.UTC().Format(time.RFC3339), "suppressed", suppressed)
			}
			o.state.skipped(exp)
			return false
		}
		start, cur, expiry = now, conn, exp
		ended = serve(conn)
		renewAt, stable = time.Time{}, tunnelStableAfter
		if !exp.IsZero() {
			life := exp.Sub(start)
			renewAt = start.Add(max(life*6/10, tunnelMinBackoff))
			stable = min(tunnelStableAfter, life/2)
		}
		return true
	}
	for {
		if ended == nil {
			if !connect(false) {
				if c.sleep(ctx, jitter(backoff)) != nil {
					return nil
				}
				backoff = min(2*backoff, tunnelMaxBackoff)
				continue
			}
		}
		var renew <-chan time.Time
		var timer *time.Timer
		if !renewAt.IsZero() {
			timer = time.NewTimer(max(0, renewAt.Sub(c.now())))
			renew = timer.C
		}
		select {
		case <-ended:
			if timer != nil {
				timer.Stop()
			}
			if c.now().Sub(start) >= stable {
				backoff = tunnelMinBackoff
			}
			ended = nil
			if c.sleep(ctx, jitter(backoff)) != nil {
				return nil
			}
			backoff = min(2*backoff, tunnelMaxBackoff)
		case <-renew:
			old, oldStart, oldStable, oldExpiry := ended, start, stable, expiry
			oldConn := cur
			beginRenewal(oldConn)
			if connect(true) {
				markRenewedAfterAccept(oldConn, cur, ended)
				if expiry.After(oldExpiry) {
					backoff = tunnelMinBackoff
				} else {
					renewAt = start.Add(max(renewAt.Sub(start), jitter(backoff)))
				}
			} else {
				endRenewal(oldConn)
				ended, start, stable, expiry = old, oldStart, oldStable, oldExpiry
				renewAt = c.now().Add(jitter(backoff))
				backoff = min(2*backoff, tunnelMaxBackoff)
			}
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		}
	}
}

// beginRenewal tells the old tunnel that a renewal is under way, before the cell dials the new one. The
// hub closes the old tunnel as soon as it accepts the new one, and the cell can read that close before it
// reads the first bytes of the new tunnel. A tunnel that the hub closes while a renewal is undecided waits
// for the decision before it logs who closed it.
func beginRenewal(old net.Conn) {
	if r, ok := old.(interface{ BeginRenewal() }); ok {
		r.BeginRenewal()
	}
}

// endRenewal ends the undecided state that beginRenewal started, with the old tunnel not renewed.
func endRenewal(old net.Conn) {
	if r, ok := old.(interface{ EndRenewal() }); ok {
		r.EndRenewal()
	}
}

// markRenewedAfterAccept marks the old tunnel as renewed when the hub accepts the new one, which the
// new connection shows with its first read. A new tunnel that the hub refuses leaves the old one
// unmarked, so its end is not logged as a planned renewal.
func markRenewedAfterAccept(old, next net.Conn, nextEnded <-chan struct{}) {
	r, ok := old.(interface{ MarkRenewed() })
	if !ok {
		return
	}
	a, ok := next.(interface{ Accepted() <-chan struct{} })
	if !ok {
		r.MarkRenewed()
		return
	}
	go func() {
		select {
		case <-a.Accepted():
			r.MarkRenewed()
			return
		default:
		}
		select {
		case <-a.Accepted():
			r.MarkRenewed()
		case <-nextEnded:
			endRenewal(old)
		}
	}()
}

func jitter(d time.Duration) time.Duration {
	return min(d+rand.N(d/2+1), tunnelMaxBackoff)
}

// newTunnelServer pings an idle tunnel, so that the cell finds a dead connection and dials again.
func newTunnelServer(readIdle, pingTimeout time.Duration) *http2.Server {
	return &http2.Server{MaxConcurrentStreams: tunnelMaxStreams, ReadIdleTimeout: readIdle, PingTimeout: pingTimeout}
}

// serveTunnel serves h on conn. base carries the error logger of the HTTP/2 server, which writes to the
// standard logger when it has none.
func serveTunnel(ctx context.Context, srv *http2.Server, conn net.Conn, h http.Handler, base *http.Server) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	srv.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: h, BaseConfig: base})
	_ = conn.Close()
}

// TunnelDialer returns the dial function of RunTunnel: TCP to addr, then a TLS handshake with
// cfg, which comes from ClientTLS. A refused server gives a *PeerError. In TLS 1.3 the hub checks
// the client certificate after the client finishes its handshake, so the cell logs
// tunnel_connected only when the first HTTP/2 bytes of the hub arrive. A hub that ends the
// connection before that is logged as tunnel_refused with reason peer_not_allowed.
func TunnelDialer(addr string, cfg *tls.Config, log *slog.Logger, opts ...TunnelOption) func(context.Context) (net.Conn, error) {
	o := applyOptions(opts)
	m, state := o.metrics, o.state
	up := &atomic.Bool{}
	limiter := newLogLimiter()
	series := attribute.NewSet(attribute.String("side", sideCell), attribute.String("upstream", addr))
	if err := m.observeUp(func() map[attribute.Set]bool { return map[attribute.Set]bool{series: up.Load()} }); err != nil {
		log.Warn("tunnel metric not registered", "error", err.Error())
	}
	result := func(ctx context.Context, r string) {
		m.connect(ctx, attribute.String("side", sideCell), attribute.String("result", r))
	}
	return func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: dialTimeout, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: keepAlivePeriod, Interval: keepAlivePeriod}}
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			result(ctx, dialFailed)
			log.Warn("tunnel_dial_failed", "reason", string(UpstreamUnavailable), "upstream", addr, "error", err.Error())
			return nil, err
		}
		// own records the expiry of the client certificate that the handshake sends.
		var own time.Time
		cc := cfg.Clone()
		if orig := cfg.GetClientCertificate; orig != nil {
			cc.GetClientCertificate = func(ri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, err := orig(ri)
				if err == nil && len(cert.Certificate) > 0 {
					if x, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
						own = x.NotAfter
					}
				}
				return cert, err
			}
		}
		conn := tls.Client(raw, cc)
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		err = conn.HandshakeContext(hctx)
		cancel()
		if err != nil {
			_ = conn.Close()
			var pe *PeerError
			if errors.As(err, &pe) {
				result(ctx, dialServerRefused)
				log.Warn("peer refused", "reason", string(pe.Reason), "spiffe_id", pe.ID, "error", pe.Err.Error())
			} else {
				result(ctx, dialFailed)
				log.Warn("tunnel_dial_failed", "reason", string(UpstreamUnavailable), "upstream", addr, "error", err.Error())
			}
			return nil, err
		}
		if o.proof != nil {
			pctx, pcancel := context.WithTimeout(ctx, handshakeTimeout)
			err := o.proof(pctx, conn)
			pcancel()
			if err != nil {
				_ = conn.Close()
				result(ctx, dialFailed)
				log.Warn("tunnel_dial_failed", "reason", string(ProofFailed), "upstream", addr, "error", err.Error())
				return nil, err
			}
		}
		cn := &cellConn{Conn: conn, log: log, upstream: addr, up: up, result: result, state: state, limiter: limiter, accepted: make(chan struct{})}
		// The cell ends the tunnel at the earlier expiry of its own leaf and the leaf of the hub, so a
		// hub that never closes cannot keep the access past a credential.
		if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
			cn.expiry = certs[0].NotAfter
		}
		if !own.IsZero() && (cn.expiry.IsZero() || own.Before(cn.expiry)) {
			cn.expiry = own
		}
		if !cn.expiry.IsZero() {
			cn.mu.Lock()
			cn.timer = time.AfterFunc(time.Until(cn.expiry), func() {
				log.Info("tunnel_expired", "side", sideCell, "upstream", addr, "not_after", cn.expiry.UTC().Format(time.RFC3339))
				cn.expired.Store(true)
				_ = cn.Close()
			})
			cn.mu.Unlock()
		}
		return cn, nil
	}
}

// cellConn is the cell end of one tunnel. It logs the acceptance or the refusal by the hub, and
// the end of the tunnel with who closed it.
type cellConn struct {
	net.Conn
	log      *slog.Logger
	upstream string
	up       *atomic.Bool
	result   func(context.Context, string)

	expiry time.Time
	// timer ends the tunnel at expiry. mu guards it, because the callback of the timer can run
	// before the dial stores it.
	timer   *time.Timer
	expired atomic.Bool
	renewed atomic.Bool
	state   *TunnelState
	stateID uint64
	// limiter holds back repeated tunnel_refused lines. accepted closes at the first bytes of the hub.
	limiter  *logLimiter
	accepted chan struct{}

	mu         sync.Mutex
	acceptedAt time.Time
	// renewal is open while the cell has not yet learned whether the hub accepted the newer tunnel.
	renewal chan struct{}
	closing bool
	peerErr error
	once    sync.Once
}

func (c *cellConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > 0 && c.acceptedAt.IsZero() {
		c.acceptedAt = time.Now()
		c.up.Store(true)
		if c.state != nil {
			c.stateID = c.state.opened(c.expiry)
		}
		c.result(context.Background(), dialConnected)
		c.log.Info("tunnel_connected", "upstream", c.upstream)
		if c.accepted != nil {
			close(c.accepted)
		}
	}
	if err != nil && !c.closing && c.peerErr == nil {
		c.peerErr = err
		if c.acceptedAt.IsZero() {
			c.result(context.Background(), dialRefusedByHub)
			if ok, suppressed, _ := c.limiter.allow(c.log, "tunnel_refused", nil); ok {
				c.log.Warn("tunnel_refused", "reason", string(PeerNotAllowed), "upstream", c.upstream, "error", refusalDetail(err), "suppressed", suppressed)
			}
		}
	}
	return n, err
}

// refusalDetail says why the hub ended a tunnel before HTTP/2 started.
func refusalDetail(err error) string {
	if errors.Is(err, io.EOF) {
		return "the hub closed the tunnel before HTTP/2 started: it refused this source"
	}
	return err.Error()
}

// Accepted closes when the first bytes of the hub arrive, which shows that the hub accepted the tunnel.
func (c *cellConn) Accepted() <-chan struct{} { return c.accepted }

// MarkRenewed says that the cell opened a newer tunnel, so the end of this one is planned.
func (c *cellConn) MarkRenewed() {
	c.renewed.Store(true)
	c.EndRenewal()
}

// BeginRenewal says that the cell dials a newer tunnel and does not know yet if the hub accepts it.
func (c *cellConn) BeginRenewal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.renewal == nil {
		c.renewal = make(chan struct{})
	}
}

// EndRenewal says that the cell knows if the hub accepted the newer tunnel.
func (c *cellConn) EndRenewal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.renewal != nil {
		close(c.renewal)
		c.renewal = nil
	}
}

// Expiry is the earlier expiry of the leaf of the cell and the leaf of the hub.
func (c *cellConn) Expiry() time.Time { return c.expiry }

func (c *cellConn) Close() error {
	c.mu.Lock()
	undecided, hubEnded := c.renewal, c.peerErr != nil
	c.mu.Unlock()
	if undecided != nil && hubEnded {
		<-undecided
	}
	c.mu.Lock()
	c.closing = true
	acceptedAt, peerErr, stateID, timer := c.acceptedAt, c.peerErr, c.stateID, c.timer
	c.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	if c.state != nil && stateID != 0 {
		switch {
		case c.expired.Load():
			c.state.closed(stateID, "expiry", "")
		case c.renewed.Load():
			c.state.closed(stateID, "renewal", "")
		case peerErr != nil:
			c.state.closed(stateID, "peer_closed", peerErr.Error())
		default:
			c.state.closed(stateID, "local_close", "")
		}
	}
	c.once.Do(func() {
		if acceptedAt.IsZero() {
			return
		}
		c.up.Store(false)
		lived := time.Since(acceptedAt)
		closedBy, level, attrs := "cell", slog.LevelInfo, []any{}
		if peerErr != nil {
			closedBy = "hub"
			attrs = append(attrs, "error", peerErr.Error())
			if c.renewed.Load() {
				// The hub closed this tunnel for the newer one that the cell opened: a planned end.
				closedBy = "renewal"
			} else if lived < tunnelStableAfter {
				level = slog.LevelWarn
			}
		}
		attrs = append(attrs, "upstream", c.upstream, "lived_seconds", int(lived.Seconds()), "closed_by", closedBy)
		c.log.Log(context.Background(), level, "tunnel_closed", attrs...)
	})
	return c.Conn.Close()
}

type cellHandler struct {
	api     *url.URL
	proxy   *httputil.ReverseProxy
	log     *slog.Logger
	metrics *TunnelMetrics
}

// NewCellHandler serves the requests that arrive through the tunnel. It passes a request to the
// Kubernetes API at api only when the path is canonical and Allowed admits it. A list or watch of the
// ConfigMaps of every namespace goes to istio-system only. The upstream URL
// holds the checked path and the allowed query keys only, encoded again. The request carries only
// the headers in forwardHeaders, so rt sets the token of the pod, and no client header reaches
// the API. A refusal is HTTP 403 with {"error":"denied","request_id":"<id>"}, and a log line with
// reason request_not_allowed.
func NewCellHandler(api *url.URL, rt http.RoundTripper, log *slog.Logger, opts ...TunnelOption) http.Handler {
	h := &cellHandler{api: api, log: log, metrics: applyOptions(opts).metrics}
	h.proxy = &httputil.ReverseProxy{
		Rewrite:       h.rewrite,
		Transport:     rt,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				h.refuse(w, r, UpstreamUnavailable, err.Error())
				return
			}
			log.Info("request canceled", "method", r.Method, "path", r.URL.Path)
		},
		ErrorLog: proxyErrorLog(log),
	}
	return h
}

func (h *cellHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !Allowed(r.Method, r.URL) {
		h.refuse(w, r, RequestNotAllowed, "not an allowed Kubernetes read")
		return
	}
	if r.Method == http.MethodPost {
		if err := bufferBody(w, r, maxReviewBody); err != nil {
			h.refuse(w, r, RequestNotAllowed, err.Error())
			return
		}
	} else {
		dropBody(r)
	}
	h.proxy.ServeHTTP(w, r)
}

func (h *cellHandler) refuse(w http.ResponseWriter, r *http.Request, reason Reason, detail string) {
	h.metrics.refusedRequest(r.Context(), attribute.String("side", sideCell), attribute.String("reason", string(reason)))
	refuse(w, r, h.log, reason, detail)
}

func (h *cellHandler) rewrite(pr *httputil.ProxyRequest) {
	p, _ := CanonicalPath(pr.In.URL)
	if p == allConfigMapsPath {
		// The ConfigMaps of every other namespace stay out of reach, and so does the RBAC rule for them.
		p = "/api/v1/namespaces/" + configMapNS + "/" + configMapsName
	}
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
	pr.Out.Header = allowedHeaders(pr.In.Header)
}

// stripIdentity deletes every header that could carry an identity, a forwarding chain or a
// protocol switch. The Prometheus proxy uses it.
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

// TunnelHub is the management side of the mesh-view tunnel. It keeps one HTTP/2 client
// connection for each cell, over the connection that the cell dialed, and serves a local
// handler for each cell that sends requests through it.
type TunnelHub struct {
	cells                 map[string]string
	wait                  time.Duration
	log                   *slog.Logger
	metrics               *TunnelMetrics
	maxStreams            int
	statusAddr            string
	readIdle, pingTimeout time.Duration
	started               time.Time
	ids                   atomic.Uint64
	mu                    sync.Mutex
	conns                 map[string]*tunnelConn
	ends                  map[string]*EndInfo
	downAt                map[string]time.Time
	changed               chan struct{}
}

type tunnelConn struct {
	id       uint64
	cc       *http2.ClientConn
	done     <-chan struct{}
	remote   string
	start    time.Time
	notAfter time.Time
	replaced atomic.Bool
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
func NewTunnelHub(cells map[string]string, wait time.Duration, log *slog.Logger, opts ...TunnelOption) *TunnelHub {
	if wait == 0 {
		wait = defaultTunnelWait
	}
	o := applyOptions(opts)
	if o.maxStreams <= 0 {
		o.maxStreams = hubMaxStreams
	}
	idle, ping := o.keepalive()
	h := &TunnelHub{cells: cells, wait: wait, log: log, metrics: o.metrics, maxStreams: o.maxStreams, statusAddr: o.statusAddr, started: time.Now(),
		readIdle: idle, pingTimeout: ping,
		conns: map[string]*tunnelConn{}, ends: map[string]*EndInfo{}, downAt: map[string]time.Time{}, changed: make(chan struct{})}
	if err := h.metrics.observeUp(h.upSeries); err != nil {
		log.Warn("tunnel metric not registered", "error", err.Error())
	}
	return h
}

// upSeries reports each configured cell, with a usable tunnel or not.
func (h *TunnelHub) upSeries() map[attribute.Set]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[attribute.Set]bool, len(h.cells))
	for cell := range h.cells {
		tc := h.conns[cell]
		out[attribute.NewSet(attribute.String("side", sideHub), attribute.String("cell", cell))] = tc != nil && tc.usable()
	}
	return out
}

// Accept makes conn the tunnel of the cell of s, and returns when conn ends. Only the role
// mesh-view of a cell with a listener may hold a tunnel, whatever --allow-id admits. The newest
// connection of a cell wins: the hub closes the one before it and logs tunnel_replaced. The hub
// closes a tunnel when the leaf certificate of the cell expires, so the cell dials again with its
// new SVID. The client connection pings an idle tunnel after 30 seconds, and closes it when the
// ping gets no answer within 15 seconds.
func (h *TunnelHub) Accept(conn *tls.Conn, s Source) {
	log := h.log.With("cell", s.Cell)
	if _, ok := h.cells[s.Cell]; !ok || s.Plane != PlaneCell || s.Role != MeshViewRole {
		h.metrics.connect(context.Background(), attribute.String("side", sideHub), attribute.String("cell", s.Cell),
			attribute.String("result", "refused"), attribute.String("reason", string(PeerNotAllowed)), attribute.String("role", s.Role))
		log.Warn("tunnel_refused", "reason", string(PeerNotAllowed), "plane", s.Plane, "role", s.Role,
			"error", "only the "+MeshViewRole+" role of a cell with a tunnel listener may hold a tunnel")
		_ = conn.Close()
		return
	}
	nc := &notifyConn{Conn: conn, done: make(chan struct{})}
	t := &http2.Transport{ReadIdleTimeout: h.readIdle, PingTimeout: h.pingTimeout}
	cc, err := t.NewClientConn(nc)
	if err != nil {
		log.Warn("tunnel_failed", "reason", string(UpstreamUnavailable), "error", err.Error())
		_ = nc.Close()
		return
	}
	tc := &tunnelConn{id: h.ids.Add(1), cc: cc, done: nc.done, remote: conn.RemoteAddr().String(), start: time.Now(), notAfter: time.Now().Add(2 * time.Minute)}
	log = log.With("conn_id", tc.id)
	if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
		notAfter := certs[0].NotAfter
		tc.notAfter = notAfter
		expiry := time.AfterFunc(time.Until(notAfter), func() {
			log.Info("tunnel_expired", "not_after", notAfter.UTC().Format(time.RFC3339))
			nc.expired.Store(true)
			_ = nc.Close()
		})
		defer expiry.Stop()
	}
	h.mu.Lock()
	old := h.conns[s.Cell]
	h.conns[s.Cell] = tc
	close(h.changed)
	h.changed = make(chan struct{})
	h.mu.Unlock()
	if old != nil {
		old.replaced.Store(true)
		log.Info("tunnel_replaced", "old_conn_id", old.id, "new_conn_id", tc.id, "old_remote", old.remote, "new_remote", tc.remote,
			"old_age_seconds", time.Since(old.start).Seconds(), "new_age_seconds", time.Since(tc.start).Seconds())
		// The older tunnel drains: it takes no new request, and its streams in flight end on their own. The
		// connection closes when the last one ends, or at the expiry of the older leaf, whichever comes first.
		go func() {
			ctx, cancel := context.WithDeadline(context.Background(), old.notAfter)
			defer cancel()
			_ = old.cc.Shutdown(ctx)
			_ = old.cc.Close()
		}()
	}
	h.metrics.connect(context.Background(), attribute.String("side", sideHub), attribute.String("cell", s.Cell),
		attribute.String("result", "accepted"), attribute.Bool("replaced", old != nil))
	log.Info("tunnel_up", "env", s.Env, "remote", tc.remote)
	<-nc.done
	cause, detail := nc.cause()
	if tc.replaced.Load() {
		cause = "replaced"
	}
	h.mu.Lock()
	if h.conns[s.Cell] == tc {
		delete(h.conns, s.Cell)
		h.downAt[s.Cell] = time.Now()
	}
	h.ends[s.Cell] = &EndInfo{Cause: cause, Detail: detail, At: time.Now(), AgeSeconds: time.Since(tc.start).Seconds()}
	h.mu.Unlock()
	_ = cc.Close()
	log.Info("tunnel_down", "replaced", tc.replaced.Load(), "age_seconds", time.Since(tc.start).Seconds(), "cause", cause, "detail", detail)
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

// Handler sends each request through the tunnel of cell, with only the headers in forwardHeaders.
// With no tunnel, it waits for one up to the wait of the hub, then answers 503 with
// upstream_unavailable. It passes at most the stream cap of requests at once, and answers 503 with
// overloaded to the next one. It refuses a protocol upgrade, which HTTP/2 cannot carry.
func (h *TunnelHub) Handler(cell string) http.Handler {
	log := h.log.With("cell", cell)
	streams := make(chan struct{}, h.maxStreams)
	cellAttr := attribute.String("cell", cell)
	refuseHub := func(w http.ResponseWriter, r *http.Request, reason Reason, detail string) {
		h.metrics.refusedRequest(r.Context(), attribute.String("side", sideHub), cellAttr, attribute.String("reason", string(reason)))
		refuse(w, r, log, reason, detail)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			refuseHub(w, r, RequestNotAllowed, "protocol upgrade")
			return
		}
		select {
		case streams <- struct{}{}:
			defer func() { <-streams }()
		default:
			refuseHub(w, r, Overloaded, fmt.Sprintf("the listener of cell %s holds %d requests", cell, cap(streams)))
			return
		}
		tc := h.await(r.Context(), cell)
		if tc == nil {
			if r.Context().Err() != nil {
				return
			}
			refuseHub(w, r, UpstreamUnavailable, "no tunnel from the cell")
			return
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme = "http"
				pr.Out.URL.Host = cell
				pr.Out.Host = ""
				pr.Out.Header = allowedHeaders(pr.In.Header)
			},
			Transport:     tc.cc,
			FlushInterval: -1,
			ModifyResponse: func(resp *http.Response) error {
				h.metrics.response(resp.Request.Context(), attribute.String("side", sideHub), cellAttr, attribute.Int("status", resp.StatusCode))
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if r.Context().Err() != nil {
					log.Info("request canceled", "method", r.Method, "path", r.URL.Path)
					return
				}
				refuseHub(w, r, UpstreamUnavailable, err.Error())
			},
			ErrorLog: proxyErrorLog(log),
		}
		proxy.ServeHTTP(w, r)
	})
}

// Run listens on the address of each cell and serves its handler there, until ctx ends or a
// listener fails.
func (h *TunnelHub) Run(ctx context.Context) error {
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
		servers = append(servers, h.newServer(c))
	}
	errc := make(chan error, len(servers))
	var wg sync.WaitGroup
	for i, srv := range servers {
		h.log.Info("tunnel_listening", "cell", cells[i], "addr", lns[i].Addr().String(), "wait_seconds", h.wait.Seconds(), "cells", cells)
		wg.Go(func() {
			if err := srv.Serve(lns[i]); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("serve cell %s: %w", cells[i], err)
			}
		})
	}
	if h.statusAddr != "" {
		go func() {
			if err := ServeStatus(ctx, h.statusAddr, h.Status, h.log); err != nil {
				h.log.Warn("tunnel status listener ended", "error", err.Error())
			}
		}()
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

// newServer returns the HTTP server of the listener of cell. It sets no read or write timeout,
// because a watch is one long response, and bounds the header time, the idle time and the header
// size.
func (h *TunnelHub) newServer(cell string) *http.Server {
	return &http.Server{
		Handler:           h.Handler(cell),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       hubIdleTimeout,
		MaxHeaderBytes:    hubMaxHeaderBytes,
		ErrorLog:          proxyErrorLog(h.log),
	}
}

// Status returns the tunnel state of each cell, from the connections that the hub holds now. A replaced
// tunnel is not in the map, so a cell with a newer tunnel never reads as down.
func (h *TunnelHub) Status() TunnelStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := TunnelStatus{Side: sideHub, Up: true, Cells: map[string]CellStatus{}}
	for cell := range h.cells {
		c := CellStatus{LastEnd: h.ends[cell]}
		if tc := h.conns[cell]; tc != nil && tc.usable() {
			c.Up, c.ConnID, c.AgeSeconds = true, tc.id, time.Since(tc.start).Seconds()
			na := tc.notAfter
			c.ExpiresAt = &na
		} else {
			since := h.started
			if t, ok := h.downAt[cell]; ok {
				since = t
			}
			c.DownSeconds = time.Since(since).Seconds()
			st.Up = false
		}
		st.Cells[cell] = c
	}
	return st
}

// notifyConn closes done when the connection closes or its read fails.
type notifyConn struct {
	net.Conn
	once    sync.Once
	done    chan struct{}
	expired atomic.Bool
	mu      sync.Mutex
	readErr error
	// localFirst is true when this side closed the connection before any read error: the transport closes
	// the connection after a read error too, so only the order tells the two apart.
	localFirst bool
}

// cause says why the connection ended: expiry (the timer of the SVID), peer_closed (a read error or an
// end of the stream from the peer, with the error), or local_close (this side closed it: a failed ping,
// a replaced tunnel or a shutdown).
func (c *notifyConn) cause() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.expired.Load():
		return "expiry", ""
	case !c.localFirst && c.readErr != nil:
		return "peer_closed", c.readErr.Error()
	}
	return "local_close", ""
}

func (c *notifyConn) signal() { c.once.Do(func() { close(c.done) }) }

func (c *notifyConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			c.mu.Lock()
			if c.readErr == nil {
				c.readErr = err
			}
			c.mu.Unlock()
			c.signal()
		}
	}
	return n, err
}

func (c *notifyConn) Close() error {
	c.mu.Lock()
	if c.readErr == nil {
		c.localFirst = true
	}
	c.mu.Unlock()
	c.signal()
	return c.Conn.Close()
}

type tunnelBackend struct{ hub *TunnelHub }

// NewTunnelBackend returns the tunnel backend. It hands each verified cell connection to h, and
// its Run serves the local listeners of h.
func NewTunnelBackend(h *TunnelHub) Backend { return &tunnelBackend{hub: h} }

func (b *tunnelBackend) Name() string { return "tunnel" }

// Serve keeps conn as the tunnel of its cell until conn or ctx ends.
func (b *tunnelBackend) Serve(ctx context.Context, conn *tls.Conn, src Source) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	b.hub.Accept(conn, src)
	return nil
}

// Run serves the local listeners of the hub until ctx ends.
func (b *tunnelBackend) Run(ctx context.Context) error { return b.hub.Run(ctx) }

// levelWriter sends the lines of a standard library logger to log, each with a reason. The errors that every
// ended tunnel makes in the reverse proxy go to Debug, and so does the failed preface of a refused TLS client,
// which tunnel_refused already reports. A ping without an answer is a Warn line of its own.
type levelWriter struct{ log *slog.Logger }

func (w levelWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	switch {
	case strings.Contains(msg, "timeout waiting for PING response"):
		w.log.Warn("tunnel_ping_timeout", "reason", string(PingTimeout), "detail", msg)
	case strings.Contains(msg, "error reading preface from client"):
		w.log.Debug(msg, "reason", string(HandshakeFailed))
	case strings.Contains(msg, "force closed via ClientConn.Close") || strings.Contains(msg, "use of closed network connection"):
		w.log.Debug(msg, "reason", string(LibraryLog))
	default:
		w.log.Warn(msg, "reason", string(LibraryLog))
	}
	return len(p), nil
}

func proxyErrorLog(log *slog.Logger) *stdlog.Logger { return stdlog.New(levelWriter{log}, "", 0) }

// BridgeStdLog sends the lines of the standard library logger to log. The HTTP/2 client of the hub
// has no error logger of its own and writes to the standard logger.
func BridgeStdLog(log *slog.Logger) {
	stdlog.SetFlags(0)
	stdlog.SetOutput(levelWriter{log})
}
