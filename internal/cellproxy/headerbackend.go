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
	"time"

	"golang.org/x/net/http2"
)

const (
	maxConcurrentStreams = 100
	upstreamReadIdle     = 30 * time.Second
	upstreamPingTimeout  = 15 * time.Second
	// bodyReadTimeout bounds the read of a RefreshToken body.
	bodyReadTimeout = 10 * time.Second

	pathAuthenticate = "/authapi.Authentication/Authenticate"
	pathRefreshToken = "/authapi.Authentication/RefreshToken"
)

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

// Serve serves HTTP/2 on conn until conn or ctx ends, then closes the upstream connection.
func (b *headerBackend) Serve(ctx context.Context, conn *tls.Conn, src Source) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	h := &headerHandler{backend: b, src: src, log: b.log.With("agent", src.AgentName())}
	d := net.Dialer{Timeout: dialTimeout, KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: keepAlivePeriod, Interval: keepAlivePeriod}}
	if up, err := d.DialContext(ctx, "tcp", b.upstream); err != nil {
		h.log.Warn("upstream dial failed", "reason", string(UpstreamUnavailable), "error", err.Error())
	} else {
		t := &http2.Transport{ReadIdleTimeout: upstreamReadIdle, PingTimeout: upstreamPingTimeout}
		cc, err := t.NewClientConn(up)
		if err != nil {
			_ = up.Close()
			h.log.Warn("upstream connection failed", "reason", string(UpstreamUnavailable), "error", err.Error())
		} else {
			defer func() { _ = cc.Close() }()
			h.proxy = &httputil.ReverseProxy{
				Rewrite:       h.rewrite,
				Transport:     cc,
				FlushInterval: -1,
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					h.deny(w, r, UpstreamUnavailable, err.Error())
				},
				ErrorLog: slog.NewLogLogger(h.log.Handler(), slog.LevelWarn),
			}
		}
	}
	srv := &http2.Server{MaxConcurrentStreams: maxConcurrentStreams, IdleTimeout: idleTimeout(ctx)}
	srv.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: h})
	return nil
}

type headerHandler struct {
	backend *headerBackend
	src     Source
	log     *slog.Logger
	proxy   *httputil.ReverseProxy
}

func (h *headerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The path must reach the upstream as the handler sees it: no query and no escapes.
	if r.Method != http.MethodPost || !isGRPC(r) || r.RequestURI != r.URL.Path || h.src.Plane != PlaneCell {
		h.deny(w, r, RequestNotAllowed, "not a gRPC request from a cell")
		return
	}
	if h.proxy == nil {
		h.deny(w, r, UpstreamUnavailable, "no upstream connection")
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
