package cellproxy

import (
	"log/slog"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	maxPromForm = 1 << 20
	formType    = "application/x-www-form-urlencoded"
)

// promGet are the Prometheus paths that Kiali v2.34.0 reads, through client_golang v1.23.2:
// Query, QueryRange, LabelValues("__name__"), Buildinfo, Config, Runtimeinfo, and the health
// probe <url>/-/healthy (prometheus/lazy_client.go, business/istio_status.go).
var promGet = map[string]bool{
	"/api/v1/query":                 true,
	"/api/v1/query_range":           true,
	"/api/v1/label/__name__/values": true,
	"/api/v1/status/buildinfo":      true,
	"/api/v1/status/config":         true,
	"/api/v1/status/runtimeinfo":    true,
	"/-/healthy":                    true,
}

// promPost are the paths where client_golang sends a form POST (DoGetFallback).
var promPost = map[string]bool{
	"/api/v1/query":       true,
	"/api/v1/query_range": true,
}

// PromAllowed reports whether the read-only Prometheus proxy may send a request upstream: GET on
// a path in promGet, or POST on a path in promPost. The path must be canonical. Every write,
// admin, OTLP, federation and lifecycle path is denied. The proxy also requires a form body of
// at most 1 MiB on POST.
func PromAllowed(method string, u *url.URL) bool {
	p, ok := CanonicalPath(u)
	if !ok {
		return false
	}
	switch method {
	case http.MethodGet:
		return promGet[p]
	case http.MethodPost:
		return promPost[p]
	}
	return false
}

type promProxy struct {
	proxy *httputil.ReverseProxy
	log   *slog.Logger
}

// NewPromProxy returns a handler that passes the Prometheus reads of Kiali to upstream, and
// answers every other request with 403 and {"error":"denied","request_id":"<id>"}.
func NewPromProxy(upstream *url.URL, log *slog.Logger) http.Handler {
	p := &promProxy{log: log}
	p.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			stripIdentity(pr.Out.Header)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			refuse(w, r, log, UpstreamUnavailable, err.Error())
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return p
}

func (p *promProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !PromAllowed(r.Method, r.URL) {
		refuse(w, r, p.log, RequestNotAllowed, "not a Prometheus read")
		return
	}
	if r.Method == http.MethodPost {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || !strings.EqualFold(mt, formType) {
			refuse(w, r, p.log, RequestNotAllowed, "POST body is not a form")
			return
		}
		if err := bufferBody(w, r, maxPromForm); err != nil {
			refuse(w, r, p.log, RequestNotAllowed, err.Error())
			return
		}
	} else {
		dropBody(r)
	}
	p.proxy.ServeHTTP(w, r)
}
