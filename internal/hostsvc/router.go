package hostsvc

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

type route int

const (
	routeKeys route = iota
	routeSpec
	routeSteps
)

// classify returns the route class of a path. A path that no route names belongs to the key
// handler, which answers 404.
func classify(path string) route {
	switch {
	case path == mgmtapi.HostSpecPath:
		return routeSpec
	case strings.HasPrefix(path, "/v1/steps/"):
		return routeSteps
	}
	return routeKeys
}

type router struct {
	keys, spec, steps http.Handler
	mgmtID, stepsID   spiffeid.ID
	maxInFlight       int
	log               *slog.Logger
	lim               *lograte.Limiter

	mu       sync.Mutex
	inFlight map[string]int
}

// NewRouter sends each request to the handler of its route, for the peer that may use the route:
// /v1/clusters/ and /v1/spec only for mgmtID, and /v1/steps/ only for stepsID. Any other peer gets
// 403 peer_not_allowed. At most maxInFlight requests run at once for one peer ID, and the next one
// gets 503. The client certificate checks run in the TLS handshake (see ServerTLS).
func NewRouter(keys, spec, steps http.Handler, mgmtID, stepsID spiffeid.ID, maxInFlight int) http.Handler {
	return &router{
		keys: keys, spec: spec, steps: steps, mgmtID: mgmtID, stepsID: stepsID, maxInFlight: maxInFlight,
		log: slog.Default(), lim: lograte.New(denialWindow, denialMaxKeys, time.Now), inFlight: map[string]int{},
	}
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	peer, ok := PeerID(r.Context())
	class := classify(r.URL.Path)
	var want spiffeid.ID
	var h http.Handler
	switch class {
	case routeSteps:
		want, h = rt.stepsID, rt.steps
	case routeSpec:
		want, h = rt.mgmtID, rt.spec
	default:
		want, h = rt.mgmtID, rt.keys
	}
	if !ok || peer != want {
		rt.reject(w, r, peer, http.StatusForbidden, "", step.DetailPeerNotAllowed)
		return
	}
	if h == nil {
		rt.reject(w, r, peer, http.StatusNotFound, "", "not_found")
		return
	}
	key := peer.String()
	rt.mu.Lock()
	if rt.inFlight[key] >= rt.maxInFlight {
		rt.mu.Unlock()
		rt.reject(w, r, peer, http.StatusServiceUnavailable, retryAfterBusy, "inflight_limit")
		return
	}
	rt.inFlight[key]++
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		if rt.inFlight[key]--; rt.inFlight[key] <= 0 {
			delete(rt.inFlight, key)
		}
		rt.mu.Unlock()
	}()
	h.ServeHTTP(w, r)
}

func (rt *router) reject(w http.ResponseWriter, r *http.Request, peer spiffeid.ID, status int, retryAfter, reason string) {
	rid := deny(w, status, retryAfter)
	if _, ok, suppressed, _ := rt.lim.Allow(reason); ok {
		rt.log.Warn("request denied", "reason", reason, "status", status, "request_id", rid, "peer", peer.String(), "suppressed", suppressed)
	}
}
