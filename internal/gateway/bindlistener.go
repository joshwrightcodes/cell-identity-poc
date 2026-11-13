package gateway

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/connlimit"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

// Limits of the bind listener. Tests shorten the variables.
const (
	bindBodyLimit     = 16 << 10
	bindConnCap       = 32
	bindPerSource     = 4
	bindStreamsPerCon = 2
	defaultBindRate   = 10
	bindRateWindow    = time.Minute
	reasonBadRequest  = "request_invalid"
)

var (
	bindMaxAge       = 15 * time.Second
	bindGrace        = 5 * time.Second
	bindReadTimeout  = 10 * time.Second
	bindWriteTimeout = 15 * time.Second
	bindIdleTimeout  = 30 * time.Second
)

// BindConfig holds the settings of the bind handler. CellNodes maps each cell to the address of
// its node, which is the only source that the handler serves for that cell. A zero
// PerSourcePerMinute means 10.
type BindConfig struct {
	CellNodes          map[string]netip.Addr
	Subject            record.Subject
	PerSourcePerMinute int
	Now                func() time.Time
	Log                *slog.Logger
	Meter              metric.Meter
}

// BindHandler serves the nonce, bind and bind result routes of the cells.
type BindHandler struct {
	st    *Store
	cfg   BindConfig
	log   *slog.Logger
	ins   *instruments
	limit *lograte.Limiter
	mux   *http.ServeMux
	nodes map[string]netip.Addr

	mu       sync.Mutex
	rate     map[netip.Addr][]time.Time
	refusals map[string]mgmtapi.BindRefusal
}

// NewBindHandler returns the handler of the three bind routes. Every route first compares the
// source address, after Unmap, with the node of the cell. Each denial is HTTP 403 with the same
// body, and the handler keeps the last denial of each known cell for the gateway status.
func NewBindHandler(st *Store, cfg BindConfig) *BindHandler {
	if cfg.PerSourcePerMinute <= 0 {
		cfg.PerSourcePerMinute = defaultBindRate
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	nodes := make(map[string]netip.Addr, len(cfg.CellNodes))
	for cell, a := range cfg.CellNodes {
		nodes[cell] = a.Unmap().WithZone("")
	}
	h := &BindHandler{st: st, cfg: cfg, log: cfg.Log, ins: newInstruments(cfg.Meter), nodes: nodes,
		limit: lograte.New(10*time.Second, 32, time.Now), mux: http.NewServeMux(),
		rate: map[netip.Addr][]time.Time{}, refusals: map[string]mgmtapi.BindRefusal{}}
	h.mux.HandleFunc("GET "+mgmtapi.NoncePattern, h.guard(h.nonce))
	h.mux.HandleFunc("POST "+mgmtapi.BindPattern, h.guard(h.bind))
	h.mux.HandleFunc("GET "+gwapi.BindResultPattern, h.guard(h.result))
	h.mux.HandleFunc("/", http.NotFound)
	return h
}

func (h *BindHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p := r.URL.Path; p == "" || p != path.Clean(p) {
		http.NotFound(w, r)
		return
	}
	h.mux.ServeHTTP(w, r)
}

// LastRefusals returns the last denial of each cell.
func (h *BindHandler) LastRefusals() map[string]mgmtapi.BindRefusal {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]mgmtapi.BindRefusal, len(h.refusals))
	for k, v := range h.refusals {
		out[k] = v
	}
	return out
}

// source returns the address of the client without a zone or a 4-in-6 form.
func source(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap().WithZone("")
}

// guard compares the source with the node of the cell before the route runs.
func (h *BindHandler) guard(next func(w http.ResponseWriter, r *http.Request, cell string, src netip.Addr)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cell := r.PathValue("cell")
		src := source(r)
		if want, ok := h.nodes[cell]; !ok || !src.IsValid() || src != want {
			h.deny(w, r, cell, gwapi.ReasonSourceMismatch, "")
			return
		}
		next(w, r, cell, src)
	}
}

// allow counts one post of src and reports whether it is within the rate.
func (h *BindHandler) allow(src netip.Addr) bool {
	now := h.cfg.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	kept := h.rate[src][:0]
	for _, t := range h.rate[src] {
		if now.Sub(t) < bindRateWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) >= h.cfg.PerSourcePerMinute {
		h.rate[src] = kept
		return false
	}
	h.rate[src] = append(kept, now)
	return true
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

func (h *BindHandler) deny(w http.ResponseWriter, r *http.Request, cell, reason, detail string) {
	id := newRequestID()
	writeJSON(w, http.StatusForbidden, mgmtapi.Denied{Error: mgmtapi.DeniedError, RequestID: id})
	h.ins.refused(r.Context(), reason)
	if _, known := h.nodes[cell]; known {
		h.mu.Lock()
		h.refusals[cell] = mgmtapi.BindRefusal{Reason: reason, RequestID: id, At: h.cfg.Now().UTC()}
		h.mu.Unlock()
	}
	if _, ok, suppressed, _ := h.limit.Allow(reason); ok {
		h.log.WarnContext(r.Context(), "bind_denied", "reason", reason, "detail", detail, "cell", clip(cell), "request_id", id, "suppressed", suppressed)
	}
}

func (h *BindHandler) failed(w http.ResponseWriter, r *http.Request, what string, err error) {
	id := newRequestID()
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal", "request_id": id})
	h.log.ErrorContext(r.Context(), "bind_failed", "what", what, "request_id", id, "error", err.Error())
}

func (h *BindHandler) nonce(w http.ResponseWriter, r *http.Request, cell string, _ netip.Addr) {
	latest, _, ok, err := h.st.CellInfo(r.Context(), cell)
	if err != nil {
		h.failed(w, r, "cell_info", err)
		return
	}
	if !ok || latest.Nonce == "" {
		h.deny(w, r, cell, gwapi.ReasonCellUnknown, "")
		return
	}
	writeJSON(w, http.StatusOK, mgmtapi.NonceResponse{
		Nonce: latest.Nonce, Audience: mgmtapi.BindAudience(cell, latest.Nonce), ExpiresAt: latest.NonceExpiresAt, Bound: latest.Bound,
	})
}

func (h *BindHandler) bind(w http.ResponseWriter, r *http.Request, cell string, src netip.Addr) {
	if !h.allow(src) {
		h.deny(w, r, cell, gwapi.ReasonOverloaded, "rate")
		return
	}
	body, bad := readBody(w, r, bindBodyLimit)
	var req mgmtapi.BindRequest
	if bad == "" {
		if err := record.DecodeStrict(body, &req); err != nil {
			bad = "body_invalid"
		}
	}
	if bad != "" {
		h.deny(w, r, cell, reasonBadRequest, bad)
		return
	}
	latest, previous, ok, err := h.st.CellInfo(r.Context(), cell)
	if err != nil {
		h.failed(w, r, "cell_info", err)
		return
	}
	if !ok {
		h.deny(w, r, cell, gwapi.ReasonCellUnknown, "")
		return
	}
	now := h.cfg.Now()
	if !nonceLive(latest, req.Nonce, now) && !nonceLive(previous, req.Nonce, now) {
		h.deny(w, r, cell, gwapi.ReasonNonceInvalid, "")
		return
	}
	if err := clusterjwt.Precheck(req.Token, "", mgmtapi.BindAudience(cell, req.Nonce), h.cfg.Subject, now); err != nil {
		h.deny(w, r, cell, gwapi.ReasonTokenInvalid, string(clusterjwt.ReasonOf(err)))
		return
	}
	item, err := json.Marshal(req)
	if err != nil {
		h.failed(w, r, "encode", err)
		return
	}
	id, err := h.st.Append(r.Context(), gwapi.Item{Kind: gwapi.KindBind, Cell: cell, Body: item, Token: req.Token})
	switch {
	case err == nil:
	case errors.Is(err, gwapi.ErrOverloaded):
		h.deny(w, r, cell, gwapi.ReasonOverloaded, "pending_binds")
		return
	default:
		h.failed(w, r, "append", err)
		return
	}
	writeJSON(w, http.StatusAccepted, gwapi.BindAccepted{ID: id})
}

func nonceLive(info mgmtapi.CellInfo, nonce string, now time.Time) bool {
	return info.Nonce != "" && info.Nonce == nonce && now.Before(info.NonceExpiresAt)
}

func (h *BindHandler) result(w http.ResponseWriter, r *http.Request, cell string, _ netip.Addr) {
	id, err := gwapi.ParseItemID(r.PathValue("id"))
	if err != nil {
		h.deny(w, r, cell, reasonBadRequest, "id_invalid")
		return
	}
	o, found, err := h.st.Outcome(r.Context(), cell, id)
	if err != nil {
		h.failed(w, r, "outcome", err)
		return
	}
	res := gwapi.BindResult{Status: gwapi.BindPending}
	if found {
		res = gwapi.BindResultFor(o)
	}
	writeJSON(w, http.StatusOK, res)
}

// BindServerTLS returns the TLS settings of the bind listener: TLS 1.3 and ALPN h2 only, with the
// server certificate of svids and no client certificate.
func BindServerTLS(svids x509svid.Source) *tls.Config {
	cfg := pinTLS13(tlsconfig.TLSServerConfig(svids))
	cfg.ClientAuth = tls.NoClientCert
	return cfg
}

// ListenBind wraps ln for the bind server: at most 32 connections and 4 for each source address,
// and a hard end 15 s plus 5 s after accept. A connection above the per-source cap closes at once.
func ListenBind(ln net.Listener, cfg *tls.Config) net.Listener {
	return tls.NewListener(connlimit.ListenPerSource(ln, bindConnCap, bindPerSource, bindMaxAge, bindGrace, nil), cfg)
}

// NewBindServer returns the HTTP/2 server of the bind listener. The listener has no
// authentication, so a trace context from the caller does not continue.
func NewBindServer(h http.Handler, cfg *tls.Config, tracer trace.Tracer) *http.Server {
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	return &http.Server{
		Handler:   telemetry.Handler(orNoop(tracer), "cellgw.bind", connlimit.MaxAge(h), telemetry.WithPublicEndpoint()),
		TLSConfig: cfg, Protocols: protos, ConnContext: connlimit.ConnContext,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: bindStreamsPerCon},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: bindReadTimeout, WriteTimeout: bindWriteTimeout,
		IdleTimeout: bindIdleTimeout, MaxHeaderBytes: 16 << 10,
	}
}
