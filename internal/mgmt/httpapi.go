package mgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/connlimit"
	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// maxRequestBody is the largest request body of either listener.
const maxRequestBody = 16 << 10

// denialWindow and denialKeys bound the denial log lines of a handler.
const (
	denialWindow = 10 * time.Second
	denialKeys   = 32
)

// SpecServer is what the API handler needs from the plane.
type SpecServer interface {
	Spec() mgmtapi.SpecBundle
	Report(mgmtapi.StatusReport)
}

// Binder is what the bind handler needs from the plane.
type Binder interface {
	Nonce(cell string) (mgmtapi.NonceResponse, error)
	Bind(ctx context.Context, cell string, req mgmtapi.BindRequest) (mgmtapi.BindResponse, error)
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

// readBody reads a body of at most maxRequestBody bytes. The detail is a fixed word, so that a log
// line never echoes the body.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, string) {
	if r.ContentLength > maxRequestBody {
		return nil, "body_too_large"
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, "body_too_large"
		}
		return nil, "body_unreadable"
	}
	return b, ""
}

// cleanPathOnly answers 404 for a path that the mux would redirect.
func cleanPathOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == "" || p != path.Clean(p) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// ---- API

type apiHandler struct {
	p     SpecServer
	env   string
	allow spiffeid.ID
	log   *slog.Logger
	limit *lograte.Limiter
	mux   *http.ServeMux
}

// NewAPIHandler serves the signed spec of env to the one peer allow, and takes its status reports.
// It checks the peer again on every request, from the TLS state or from the verified peer that the
// listener recorded. Every other request gets 404.
func NewAPIHandler(p SpecServer, env string, allow spiffeid.ID, log *slog.Logger) http.Handler {
	h := &apiHandler{p: p, env: env, allow: allow, log: log, limit: lograte.New(denialWindow, denialKeys, time.Now), mux: http.NewServeMux()}
	h.mux.HandleFunc(mgmtapi.SpecPattern, h.spec)
	h.mux.HandleFunc(mgmtapi.StatusPattern, h.status)
	h.mux.HandleFunc("/", http.NotFound)
	return cleanPathOnly(h)
}

// requestPeer returns the verified SPIFFE ID of the client of r.
func requestPeer(r *http.Request) (spiffeid.ID, bool) {
	if r.TLS != nil {
		if len(r.TLS.PeerCertificates) == 0 {
			return spiffeid.ID{}, false
		}
		id, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0])
		return id, err == nil
	}
	return peerFromContext(r.Context())
}

func (h *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, ok := requestPeer(r)
	if !ok || id != h.allow {
		reqID := newRequestID()
		writeJSON(w, http.StatusForbidden, mgmtapi.Denied{Error: mgmtapi.DeniedError, RequestID: reqID})
		if _, ok, suppressed, _ := h.limit.Allow("peer"); ok {
			h.log.Warn("api_denied", "reason", "peer_not_allowed", "peer", id.String(), "request_id", reqID, "suppressed", suppressed)
		}
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *apiHandler) spec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.PathValue("env") != h.env {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, h.p.Spec())
}

func (h *apiHandler) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.PathValue("env") != h.env {
		http.NotFound(w, r)
		return
	}
	body, bad := readBody(w, r)
	var rep mgmtapi.StatusReport
	if bad == "" {
		if err := record.DecodeStrict(body, &rep); err != nil {
			bad = "body_invalid"
		}
	}
	if bad != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": bad})
		return
	}
	h.p.Report(rep)
	w.WriteHeader(http.StatusNoContent)
}

// ---- Bind

type bindHandler struct {
	p     Binder
	log   *slog.Logger
	limit *lograte.Limiter
	mux   *http.ServeMux
}

// NewBindHandler serves the nonce and bind routes of the cells. Every denial is HTTP 403 with the
// same body. The log line holds the reason, the detail, the cell and the request ID, and never the
// token or the body.
func NewBindHandler(p Binder, log *slog.Logger) http.Handler {
	h := &bindHandler{p: p, log: log, limit: lograte.New(denialWindow, denialKeys, time.Now), mux: http.NewServeMux()}
	h.mux.HandleFunc(mgmtapi.NoncePattern, h.nonce)
	h.mux.HandleFunc(mgmtapi.BindPattern, h.bind)
	h.mux.HandleFunc("/", http.NotFound)
	return cleanPathOnly(h.mux)
}

func (h *bindHandler) onlyPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost {
		return true
	}
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (h *bindHandler) nonce(w http.ResponseWriter, r *http.Request) {
	if !h.onlyPost(w, r) {
		return
	}
	cell := r.PathValue("cell")
	body, bad := readBody(w, r)
	if bad == "" && len(body) > 0 {
		var none struct{}
		if err := record.DecodeStrict(body, &none); err != nil {
			bad = "body_invalid"
		}
	}
	if bad != "" {
		h.deny(w, cell, "request_invalid", bad)
		return
	}
	resp, err := h.p.Nonce(cell)
	if err != nil {
		h.fail(w, cell, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *bindHandler) bind(w http.ResponseWriter, r *http.Request) {
	if !h.onlyPost(w, r) {
		return
	}
	cell := r.PathValue("cell")
	body, bad := readBody(w, r)
	var req mgmtapi.BindRequest
	if bad == "" {
		if err := record.DecodeStrict(body, &req); err != nil {
			bad = "body_invalid"
		}
	}
	if bad != "" {
		h.deny(w, cell, "request_invalid", bad)
		return
	}
	resp, err := h.p.Bind(r.Context(), cell, req)
	if err != nil {
		h.fail(w, cell, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *bindHandler) fail(w http.ResponseWriter, cell string, err error) {
	var e *Error
	if errors.As(err, &e) {
		h.deny(w, cell, e.Reason, e.Detail)
		return
	}
	id := newRequestID()
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal", "request_id": id})
	if _, ok, suppressed, _ := h.limit.Allow("internal"); ok {
		h.log.Error("bind_failed", "cell", clip(cell), "request_id", id, "error", err.Error(), "suppressed", suppressed)
	}
}

func (h *bindHandler) deny(w http.ResponseWriter, cell, reason, detail string) {
	id := newRequestID()
	writeJSON(w, http.StatusForbidden, mgmtapi.Denied{Error: mgmtapi.DeniedError, RequestID: id})
	if _, ok, suppressed, _ := h.limit.Allow(reason); ok {
		h.log.Warn("bind_denied", "reason", reason, "detail", detail, "cell", clip(cell), "request_id", id, "suppressed", suppressed)
	}
}

// ---- Admin

type adminHandler struct {
	p       *Plane
	publish func(context.Context, ed25519.PublicKey) error
}

// publishTimeout bounds the publish of a rotated key.
const publishTimeout = 30 * time.Second

// NewAdminHandler serves the commands of `mgmtd ctl` on the local admin socket. Each POST takes the
// query expect-seq, and then runs only while the state version is that number. POST /rotate-key
// calls publish with the new key before it answers.
func NewAdminHandler(p *Plane, publish func(context.Context, ed25519.PublicKey) error) http.Handler {
	h := &adminHandler{p: p, publish: publish}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", h.status)
	mux.HandleFunc("GET /records", h.records)
	mux.HandleFunc("GET /pubkey", h.pubkey)
	mux.HandleFunc("GET /keys/{cell}", h.keys)
	mux.HandleFunc("POST /keycheck/{cell}", h.keycheck)
	mux.HandleFunc("POST /restore/{revision}", h.restore)
	mux.HandleFunc("POST /rotate-key", h.rotate)
	return cleanPathOnly(mux)
}

func adminError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	out := map[string]any{"error": err.Error()}
	if reason := ReasonOf(err); reason != "" {
		out["reason"] = reason
		switch reason {
		case mgmtapi.ReasonConflict:
			status = http.StatusConflict
		case mgmtapi.ReasonCellUnknown:
			status = http.StatusNotFound
		default:
			status = http.StatusUnprocessableEntity
		}
	}
	writeJSON(w, status, out)
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
}

// expectSeq reads the query expect-seq.
func expectSeq(r *http.Request) (seq uint64, ok bool, err error) {
	vals, present := r.URL.Query()["expect-seq"]
	if !present {
		return 0, false, nil
	}
	if len(vals) != 1 {
		return 0, false, errors.New("expect-seq may appear once")
	}
	seq, err = strconv.ParseUint(vals[0], 10, 64)
	if err != nil {
		return 0, false, errors.New("expect-seq must be a state version number")
	}
	return seq, true, nil
}

func (h *adminHandler) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.p.Status())
}

func (h *adminHandler) records(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.p.Records())
}

func (h *adminHandler) pubkey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"spec.pub": base64.StdEncoding.EncodeToString(h.p.PublicKey())})
}

func (h *adminHandler) keys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.p.PreviewKeys(r.Context(), r.PathValue("cell"))
	if err != nil {
		adminError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (h *adminHandler) keycheck(w http.ResponseWriter, r *http.Request) {
	seq, guarded, err := expectSeq(r)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	cell := r.PathValue("cell")
	var res CheckResult
	if guarded {
		res, err = h.p.IfSeq(seq).KeyCheck(r.Context(), cell)
	} else {
		res, err = h.p.KeyCheck(r.Context(), cell)
	}
	if err != nil {
		adminError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cell": cell, "result": string(res)})
}

func (h *adminHandler) restore(w http.ResponseWriter, r *http.Request) {
	seq, guarded, err := expectSeq(r)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	var counter uint64
	if v := r.PathValue("revision"); v != "latest" {
		if counter, err = strconv.ParseUint(v, 10, 64); err != nil || counter == 0 {
			badRequest(w, "revision must be latest or a counter above 0")
			return
		}
	}
	if guarded {
		err = h.p.IfSeq(seq).Restore(counter)
	} else {
		err = h.p.Restore(counter)
	}
	if err != nil {
		adminError(w, err)
		return
	}
	st := h.p.Status()
	writeJSON(w, http.StatusOK, map[string]any{"served": st.Served, "restoreActive": st.RestoreActive, "seq": st.Seq})
}

func (h *adminHandler) rotate(w http.ResponseWriter, r *http.Request) {
	seq, guarded, err := expectSeq(r)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	var pub ed25519.PublicKey
	if guarded {
		pub, err = h.p.IfSeq(seq).RotateKey(r.Context())
	} else {
		pub, err = h.p.RotateKey(r.Context())
	}
	if err != nil {
		adminError(w, err)
		return
	}
	if h.publish != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), publishTimeout)
		defer cancel()
		if err := h.publish(ctx, pub); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":   fmt.Sprintf("the key rotated, but its public half did not publish: %v", err),
				"rotated": true,
			})
			return
		}
	}
	st := h.p.Status()
	writeJSON(w, http.StatusOK, map[string]any{"spec.pub": base64.StdEncoding.EncodeToString(pub), "signed": st.Signed, "seq": st.Seq})
}

// ---- TLS

func pinTLS13(cfg *tls.Config) *tls.Config {
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.NextProtos = []string{"h2"}
	cfg.SessionTicketsDisabled = true
	return cfg
}

// APIServerTLS returns the TLS settings of the API listener: TLS 1.3 and ALPN h2 only, and a client
// certificate that chains to peer and carries exactly allow.
func APIServerTLS(svids x509svid.Source, peer x509bundle.Source, allow spiffeid.ID) *tls.Config {
	return pinTLS13(tlsconfig.MTLSServerConfig(svids, peer, tlsconfig.AuthorizeID(allow)))
}

// BindServerTLS returns the TLS settings of the bind listener: TLS 1.3 and ALPN h2 only, with the
// server certificate of svids and no client certificate.
func BindServerTLS(svids x509svid.Source) *tls.Config {
	cfg := pinTLS13(tlsconfig.TLSServerConfig(svids))
	cfg.ClientAuth = tls.NoClientCert
	return cfg
}

// ErrPeerRootMissing is the error of a peer bundle file that does not exist.
var ErrPeerRootMissing = errors.New("peer_root_missing: the peer bundle file does not exist")

// FileBundleSource returns the bundle of td from the PEM file at path. It reads the file again when
// its modification time, size or identity changes. While the file is absent, unreadable or empty,
// every lookup fails, so no handshake succeeds.
func FileBundleSource(path string, td spiffeid.TrustDomain) x509bundle.Source {
	return &fileBundle{path: path, td: td}
}

type fileBundle struct {
	path string
	td   spiffeid.TrustDomain

	mu     sync.Mutex
	info   fs.FileInfo
	bundle *x509bundle.Bundle
}

func (f *fileBundle) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if td != f.td {
		return nil, fmt.Errorf("no bundle for trust domain %q", td)
	}
	info, err := os.Stat(f.path)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.info, f.bundle = nil, nil
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrPeerRootMissing
		}
		return nil, fmt.Errorf("peer bundle file: %w", err)
	}
	if f.bundle != nil && f.info != nil && os.SameFile(f.info, info) && f.info.ModTime().Equal(info.ModTime()) && f.info.Size() == info.Size() {
		return f.bundle, nil
	}
	f.info, f.bundle = nil, nil
	b, err := x509bundle.Load(td, f.path)
	if err != nil {
		return nil, fmt.Errorf("peer bundle file: %w", err)
	}
	if b.Empty() {
		return nil, errors.New("peer bundle file holds no certificate")
	}
	f.info, f.bundle = info, b
	return b, nil
}

// ---- Servers

// Limits of the shared table.
const (
	apiStreams        = 4
	bindStreams       = 2
	readHeaderTimeout = 10 * time.Second
	maxHeaderBytes    = 16 << 10
)

// connContext marks the connection for the maximum age and adds the verified API peer.
func connContext(ctx context.Context, c net.Conn) context.Context {
	ctx = connlimit.ConnContext(ctx, c)
	if v, ok := peerIDs.LoadAndDelete(connKey(c)); ok {
		ctx = context.WithValue(ctx, peerCtxKey{}, v.(spiffeid.ID))
	}
	return ctx
}

// NewServers returns the servers of the two listeners, with the limits of the shared table and
// HTTP/2 only. Each handler runs under connlimit.MaxAge. Serve apiSrv on a listener from
// ListenAPI and bindSrv on one from ListenBind.
func NewServers(api, bind http.Handler, apiTLS, bindTLS *tls.Config) (apiSrv, bindSrv *http.Server) {
	apiProtos := new(http.Protocols)
	apiProtos.SetHTTP2(true)
	// The API listener finishes the TLS handshake before the server sees the connection, so the
	// server reads HTTP/2 from that connection as from a plain one.
	apiProtos.SetUnencryptedHTTP2(true)
	bindProtos := new(http.Protocols)
	bindProtos.SetHTTP2(true)
	apiSrv = &http.Server{
		Handler: connlimit.MaxAge(api), TLSConfig: apiTLS, Protocols: apiProtos,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: apiStreams},
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: maxHeaderBytes, ConnContext: connContext,
	}
	bindSrv = &http.Server{
		Handler: connlimit.MaxAge(bind), TLSConfig: bindTLS, Protocols: bindProtos,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: bindStreams},
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: maxHeaderBytes, ConnContext: connContext,
	}
	return apiSrv, bindSrv
}
