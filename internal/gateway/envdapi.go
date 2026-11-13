package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/trace"

	"github.com/joshwrightcodes/cell-identity-poc/internal/connlimit"
	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

// Limits of the envd API.
const (
	envdMaxBody  = 4 << 20
	envdConns    = 8
	envdTimeout  = 15 * time.Second
	peekItems    = 100
	peekBytes    = 900 << 10
	maxAdminBody = 1 << 20
	// maxEnvelopeBytes keeps a lease frame, which carries the envelope, below gwapi.MaxFrame.
	maxEnvelopeBytes = gwapi.MaxFrame - 4<<10
	// envdConnAge is the hard end of an envd connection. connlimit needs a positive age, and envd
	// dials again when a connection ends.
	envdConnAge = 24 * time.Hour
)

// EnvdOption changes the envd handler.
type EnvdOption func(*envdHandler)

// WithKeyHints sets the source of the key hints that the sync answer returns. The source gives
// each hint once.
func WithKeyHints(take func() []mgmtapi.KeyHint) EnvdOption {
	return func(h *envdHandler) { h.hints = take }
}

// WithEnv pins the environment: a spec of another env is refused with env_mismatch, also when the
// store has seen no spec yet.
func WithEnv(env string) EnvdOption {
	return func(h *envdHandler) { h.env = env }
}

type envdHandler struct {
	env          string
	st           *Store
	keys         []ed25519.PublicKey
	envd         spiffeid.ID
	streams      func() map[string]int
	lastRefusals func() map[string]mgmtapi.BindRefusal
	hints        func() []mgmtapi.KeyHint
	log          *slog.Logger
	mux          *http.ServeMux
}

// NewEnvdHandler serves the sync and ack routes to envd. It checks the peer ID from the TLS state
// of each request. POST SyncPath applies the spec and the records, enqueues each operation, takes
// the cell nonces when the list is not empty, and answers the oldest outbox items with the status.
// An empty operation list or cell list is no information: it never withdraws anything. POST AckPath
// stores the outcomes of the management plane.
func NewEnvdHandler(st *Store, keys []ed25519.PublicKey, envd spiffeid.ID, streams func() map[string]int,
	lastRefusals func() map[string]mgmtapi.BindRefusal, log *slog.Logger, opts ...EnvdOption) http.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &envdHandler{st: st, keys: keys, envd: envd, streams: streams, lastRefusals: lastRefusals, log: log, mux: http.NewServeMux()}
	for _, o := range opts {
		o(h)
	}
	h.mux.HandleFunc("POST "+gwapi.SyncPath, h.sync)
	h.mux.HandleFunc("POST "+gwapi.AckPath, h.ack)
	h.mux.HandleFunc("/", http.NotFound)
	return h
}

func (h *envdHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p := r.URL.Path; p == "" || p != path.Clean(p) {
		http.NotFound(w, r)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		h.deny(w, r)
		return
	}
	leaf := r.TLS.PeerCertificates[0]
	id, err := x509svid.IDFromCert(leaf)
	if err != nil || id != h.envd || time.Now().After(leaf.NotAfter) {
		h.deny(w, r)
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *envdHandler) deny(w http.ResponseWriter, r *http.Request) {
	id := newRequestID()
	writeJSON(w, http.StatusForbidden, mgmtapi.Denied{Error: mgmtapi.DeniedError, RequestID: id})
	h.log.WarnContext(r.Context(), "envd_api_denied", "reason", "peer_not_allowed", "request_id", id)
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

// readBody reads a body of at most limit bytes. The detail is a fixed word.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, string) {
	if r.ContentLength > limit {
		return nil, "body_too_large"
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, "body_too_large"
		}
		return nil, "body_unreadable"
	}
	return b, ""
}

// isRefusal reports whether err is a refusal of the spec or the records, as opposed to a store
// failure.
func isRefusal(err error) bool {
	for _, target := range []error{ErrSpecOld, ErrSpecConflict, ErrRecordMissing, ErrRecordOld, ErrRecordConflict,
		ErrEnvMismatch, ErrMarkUnlisted, ErrRetiredBelowMark, ErrRecordUnindexed, spec.ErrUnindexed, spec.ErrMismatch,
		record.ErrPayloadType, record.ErrSignature, record.ErrDecode} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func (h *envdHandler) sync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body, bad := readBody(w, r, envdMaxBody)
	var req gwapi.SyncRequest
	if bad == "" {
		if err := record.DecodeStrict(body, &req); err != nil {
			bad = "body_invalid"
		}
	}
	if bad != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": bad})
		return
	}
	if h.env != "" {
		if sp, _, err := spec.Verify(req.SpecEnvelope, h.keys); err == nil && sp.Env != h.env {
			h.log.WarnContext(ctx, "sync_refused", "error", "spec env differs from the pinned env", "spec_env", sp.Env)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "spec env differs from the pinned env", "reason": mgmtapi.ReasonEnvMismatch})
			return
		}
	}
	if err := h.st.ApplySync(ctx, req.SpecEnvelope, req.Records, h.keys); err != nil {
		if isRefusal(err) {
			h.log.WarnContext(ctx, "sync_refused", "error", err.Error())
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error(), "reason": refusalReason(err)})
			return
		}
		h.storeFailed(ctx, w, "apply_sync", err)
		return
	}
	for _, env := range req.Ops {
		if err := h.enqueue(ctx, env); err != nil {
			h.storeFailed(ctx, w, "enqueue", err)
			return
		}
	}
	if len(req.Cells) > 0 {
		if err := h.st.SetCells(ctx, req.Cells); err != nil {
			h.storeFailed(ctx, w, "set_cells", err)
			return
		}
	}
	if err := h.st.MarkSynced(ctx, time.Now()); err != nil {
		h.storeFailed(ctx, w, "mark_synced", err)
		return
	}
	items, err := h.st.Peek(ctx, peekItems, peekBytes)
	if err != nil {
		h.storeFailed(ctx, w, "peek", err)
		return
	}
	status, err := h.st.Stats(ctx)
	if err != nil {
		h.storeFailed(ctx, w, "stats", err)
		return
	}
	if h.streams != nil {
		for cell, n := range h.streams() {
			status.Streams[cell] = n
		}
	}
	if h.lastRefusals != nil {
		for cell, ref := range h.lastRefusals() {
			status.LastBindRefusal[cell] = ref
		}
	}
	if h.hints != nil {
		status.KeyHints = append(status.KeyHints, h.hints()...)
	}
	if items == nil {
		items = []gwapi.OutItem{}
	}
	writeJSON(w, http.StatusOK, gwapi.SyncResponse{Items: items, Status: status})
}

func refusalReason(err error) string {
	switch {
	case errors.Is(err, ErrRecordOld):
		return mgmtapi.ReasonRecordOld
	case errors.Is(err, ErrRecordConflict):
		return mgmtapi.ReasonRecordConflict
	case errors.Is(err, ErrSpecOld):
		return mgmtapi.ReasonRevisionOld
	case errors.Is(err, ErrSpecConflict):
		return mgmtapi.ReasonRevisionConflict
	case errors.Is(err, ErrEnvMismatch):
		return mgmtapi.ReasonEnvMismatch
	case errors.Is(err, ErrRecordUnindexed):
		return mgmtapi.ReasonRecordUnindexed
	case errors.Is(err, record.ErrSignature):
		return mgmtapi.ReasonSignatureInvalid
	}
	return mgmtapi.ReasonSpecInvalid
}

// enqueue adds one envelope. An envelope that cannot be read, or that names no cell, is logged and
// skipped. A done row that meets a re-signed envelope is an expected event after a key rotation.
// Only a store failure is returned.
func (h *envdHandler) enqueue(ctx context.Context, env json.RawMessage) error {
	if len(env) > maxEnvelopeBytes {
		h.log.WarnContext(ctx, "sync_op_too_large", "bytes", len(env), "limit", maxEnvelopeBytes)
		return nil
	}
	_, cell, _, err := op.Peek(env)
	if err != nil {
		h.log.WarnContext(ctx, "sync_op_skipped", "error", err.Error())
		return nil
	}
	_, _, err = h.st.Enqueue(ctx, cell, env)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gwapi.ErrEnvelopeConflict):
		h.log.DebugContext(ctx, "sync_op_conflict", "cell", cell)
		return nil
	}
	return err
}

func (h *envdHandler) storeFailed(ctx context.Context, w http.ResponseWriter, what string, err error) {
	id := newRequestID()
	h.log.ErrorContext(ctx, "sync_store_failed", "what", what, "error", err.Error(), "request_id", id)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal", "request_id": id})
}

func (h *envdHandler) ack(w http.ResponseWriter, r *http.Request) {
	body, bad := readBody(w, r, envdMaxBody)
	var req gwapi.AckRequest
	if bad == "" {
		if err := record.DecodeStrict(body, &req); err != nil {
			bad = "body_invalid"
		}
	}
	if bad != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": bad})
		return
	}
	if err := h.st.Ack(r.Context(), req.Outcomes); err != nil {
		h.storeFailed(r.Context(), w, "ack", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EnvdServerTLS returns the TLS settings of the envd listener: TLS 1.3 and ALPN h2 only, and a
// client certificate for exactly envd.
func EnvdServerTLS(svids x509svid.Source, bundles x509bundle.Source, envd spiffeid.ID) *tls.Config {
	return pinTLS13(tlsconfig.MTLSServerConfig(svids, bundles, tlsconfig.AuthorizeID(envd)))
}

// ListenEnvd wraps ln for the envd server, with at most 8 connections.
func ListenEnvd(ln net.Listener, cfg *tls.Config) net.Listener {
	return tls.NewListener(connlimit.Listen(ln, envdConns, envdConnAge, 0, nil), cfg)
}

// NewEnvdServer returns the HTTP/2 server of the envd listener.
func NewEnvdServer(h http.Handler, cfg *tls.Config, tracer trace.Tracer) *http.Server {
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	return &http.Server{
		Handler: telemetry.Handler(orNoop(tracer), "cellgw.envd", h), TLSConfig: cfg, Protocols: protos,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: 4},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: envdTimeout, WriteTimeout: envdTimeout,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}
