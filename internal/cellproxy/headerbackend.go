package cellproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	maxConcurrentStreams = 100
	upstreamReadIdle     = 30 * time.Second
	upstreamPingTimeout  = 15 * time.Second
	// The downstream side pings a silent agent too, so a dead peer ends before the TCP keepalive.
	downstreamReadIdle    = 30 * time.Second
	downstreamPingTimeout = 15 * time.Second

	pathAuthenticate = "/authapi.Authentication/Authenticate"
	pathRefreshToken = "/authapi.Authentication/RefreshToken"
)

// closeGrace lets the last frames of a finished request leave before the downstream closes.
const closeGrace = 500 * time.Millisecond

// bodyReadTimeout bounds the read of a RefreshToken body. Tests shorten it.
var bodyReadTimeout = 10 * time.Second

// headerBackend serves gRPC from a cell agent and proxies it to the Argo CD Agent principal. It
// sets the identity header to the agent name of the verified source, and checks that the token
// of each request names that agent.
type headerBackend struct {
	upstream string
	header   string
	log      *slog.Logger
}

// NewHeaderBackend returns the grpc-header backend. It dials upstream once for each downstream
// connection, and sets header to <env>-<cell> on each request.
func NewHeaderBackend(upstream, header string, log *slog.Logger) Backend {
	return &headerBackend{upstream: upstream, header: http.CanonicalHeaderKey(header), log: log}
}

func (b *headerBackend) Name() string { return "grpc-header" }

// Serve serves HTTP/2 on conn until conn, ctx or the upstream connection ends, then closes the
// upstream connection. The downstream ends with its upstream, so the agent dials again and gets
// a new upstream connection.
func (b *headerBackend) Serve(ctx context.Context, conn *tls.Conn, src Source) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	log := b.log.With("agent", src.AgentName())
	d := net.Dialer{Timeout: dialTimeout, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: keepAlivePeriod, Interval: keepAlivePeriod}}
	raw, err := d.DialContext(ctx, "tcp", b.upstream)
	if err != nil {
		log.Warn("upstream dial failed", "reason", string(UpstreamUnavailable), "error", err.Error())
		return nil
	}
	h := &headerHandler{backend: b, src: src, log: log, end: cancel}
	t := &http2.Transport{ReadIdleTimeout: upstreamReadIdle, PingTimeout: upstreamPingTimeout}
	cc, err := t.NewClientConn(&watchedConn{Conn: raw, onError: h.upstreamEnded})
	if err != nil {
		_ = raw.Close()
		log.Warn("upstream connection failed", "reason", string(UpstreamUnavailable), "error", err.Error())
		return nil
	}
	defer func() { _ = cc.Close() }()
	h.proxy = &httputil.ReverseProxy{
		Rewrite:   h.rewrite,
		Transport: cc,
		// ReverseProxy flushes a streamed response at once, because its ContentLength is -1. A
		// trailers-only response has ContentLength 0, and -1 here would flush its headers from a
		// timer that races the trailers, so the client could lose the status.
		FlushInterval: 0,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.deny(w, r, UpstreamUnavailable, err.Error())
			if !cc.CanTakeNewRequest() {
				h.upstreamEnded()
			}
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	srv := &http2.Server{
		MaxConcurrentStreams: maxConcurrentStreams, IdleTimeout: idleTimeout(ctx),
		ReadIdleTimeout: downstreamReadIdle, PingTimeout: downstreamPingTimeout,
	}
	srv.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: h})
	return nil
}

// watchedConn calls onError once when a read fails, so a dead upstream ends the downstream.
type watchedConn struct {
	net.Conn
	once    sync.Once
	onError func()
}

func (c *watchedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.once.Do(c.onError)
	}
	return n, err
}

type headerHandler struct {
	backend *headerBackend
	src     Source
	log     *slog.Logger
	proxy   *httputil.ReverseProxy
	// end closes the downstream connection.
	end func()

	mu     sync.Mutex
	active int
	gone   bool
}

// upstreamEnded marks the upstream connection as unusable. The downstream ends closeGrace after
// its last open request, so the responses of those requests still reach the agent.
func (h *headerHandler) upstreamEnded() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.gone {
		return
	}
	h.gone = true
	h.log.Warn("upstream connection ended", "reason", string(UpstreamUnavailable), "open_requests", h.active)
	if h.active == 0 {
		time.AfterFunc(closeGrace, h.end)
	}
}

func (h *headerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.active++
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.active--; h.active == 0 && h.gone {
			time.AfterFunc(closeGrace, h.end)
		}
	}()
	h.serve(w, r)
}

func (h *headerHandler) serve(w http.ResponseWriter, r *http.Request) {
	// The path must reach the upstream as the handler sees it: no query and no escapes.
	if r.Method != http.MethodPost || !isGRPC(r) || r.RequestURI != r.URL.Path || h.src.Plane != PlaneCell {
		h.deny(w, r, RequestNotAllowed, "not a gRPC request from a cell")
		return
	}
	auth := r.Header.Values("Authorization")
	switch r.URL.Path {
	case pathAuthenticate:
	case pathRefreshToken:
		if len(auth) != 0 {
			h.deny(w, r, SubjectMismatch, "RefreshToken carries an authorization value")
			return
		}
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(bodyReadTimeout))
		frame, token, err := readRefreshFrame(r.Body)
		_ = rc.SetReadDeadline(time.Time{})
		if err == nil {
			err = checkSubject(token, h.src.AgentName())
		}
		if err != nil {
			h.deny(w, r, SubjectMismatch, err.Error())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(frame))
		r.ContentLength = int64(len(frame))
	default:
		if len(auth) != 1 {
			h.deny(w, r, SubjectMismatch, "request needs exactly one authorization value, got "+strconv.Itoa(len(auth)))
			return
		}
		if err := checkSubject(auth[0], h.src.AgentName()); err != nil {
			h.deny(w, r, SubjectMismatch, err.Error())
			return
		}
	}
	h.proxy.ServeHTTP(w, r)
}

// rewrite sends the request to the upstream, with the identity of the connection as the only
// identity header.
func (h *headerHandler) rewrite(pr *httputil.ProxyRequest) {
	pr.Out.URL.Scheme = "http"
	pr.Out.URL.Host = h.backend.upstream
	pr.Out.Host = h.backend.upstream
	for k := range pr.Out.Header {
		lk := strings.ToLower(k)
		if k == h.backend.header || lk == "forwarded" || lk == "x-real-ip" || strings.HasPrefix(lk, "x-forwarded-") {
			delete(pr.Out.Header, k)
		}
	}
	pr.Out.Header.Set(h.backend.header, h.src.AgentName())
}

func isGRPC(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+") || strings.HasPrefix(ct, "application/grpc;")
}

// deny logs the reason and answers with only "denied" and a request ID.
func (h *headerHandler) deny(w http.ResponseWriter, r *http.Request, reason Reason, detail string) {
	id := requestID()
	h.log.Warn("request denied", "reason", string(reason), "request_id", id, "path", r.URL.Path, "error", detail)
	w.Header().Set("X-Request-Id", id)
	if !isGRPC(r) {
		http.Error(w, "denied", reason.HTTPStatus())
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", strconv.Itoa(int(reason.GRPCCode())))
	w.Header().Set("Grpc-Message", "denied")
	w.WriteHeader(http.StatusOK)
}

func requestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
