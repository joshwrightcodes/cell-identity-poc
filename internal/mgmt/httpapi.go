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
	"slices"
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
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// maxRequestBody is the largest body of a status post or an admin request. A report post has its
// own larger limits.
const maxRequestBody = 16 << 10

// A report post holds at most maxReportBody bytes and maxReportItems items.
const (
	maxReportBody  = 1 << 20
	maxReportItems = 100
)

// reportsHandlerTimeout is the deadline of one report post. Plane.Reports bounds its bind work
// against the context that it gets, so a slow batch ends with retry outcomes under this deadline.
// It stays below the write timeout of the API server, so that the answer still goes out.
var reportsHandlerTimeout = 12 * time.Second

// denialWindow and denialKeys bound the denial log lines of a handler.
const (
	denialWindow = 10 * time.Second
	denialKeys   = 32
)

// SpecServer is what the API handler needs from the plane for the spec and the status.
type SpecServer interface {
	Spec() mgmtapi.SpecBundle
	Report(mgmtapi.StatusReport)
}

// APIServer is what the API handler needs from the plane.
type APIServer interface {
	SpecServer
	OpenOps() mgmtapi.OpsBundle
	Reports(context.Context, mgmtapi.ReportBatch) mgmtapi.ReportResult
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

// readBody reads a body of at most maxRequestBody bytes.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, string) {
	return readBodyLimit(w, r, maxRequestBody)
}

// readBodyLimit reads a body of at most limit bytes. The detail is a fixed word, so that a log line
// never echoes the body.
func readBodyLimit(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, string) {
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
	p     APIServer
	env   string
	allow spiffeid.ID
	log   *slog.Logger
	limit *lograte.Limiter
	mux   *http.ServeMux
}

// NewAPIHandler serves the signed spec and the open operations of env to the one peer allow, and
// takes its status posts and report batches. It checks the peer again on every request, from the TLS
// state or from the verified peer that the listener recorded. A report batch has at most 1 MiB and
// 100 items, and strict JSON; any other batch gets 403 and never reaches the plane. Every other
// request gets 404.
func NewAPIHandler(p APIServer, env string, allow spiffeid.ID, log *slog.Logger) http.Handler {
	h := &apiHandler{p: p, env: env, allow: allow, log: log, limit: lograte.New(denialWindow, denialKeys, time.Now), mux: http.NewServeMux()}
	h.mux.HandleFunc(mgmtapi.SpecPattern, h.spec)
	h.mux.HandleFunc(mgmtapi.StatusPattern, h.status)
	h.mux.HandleFunc(mgmtapi.OpsPattern, h.ops)
	h.mux.HandleFunc(mgmtapi.ReportsPattern, h.reports)
	h.mux.HandleFunc("/", http.NotFound)
	return cleanPathOnly(h)
}

// requestPeer returns the verified SPIFFE ID of the client of r and the end of its certificate.
func requestPeer(r *http.Request) (peerInfo, bool) {
	if r.TLS != nil {
		if len(r.TLS.PeerCertificates) == 0 {
			return peerInfo{}, false
		}
		leaf := r.TLS.PeerCertificates[0]
		id, err := x509svid.IDFromCert(leaf)
		return peerInfo{ID: id, NotAfter: leaf.NotAfter}, err == nil
	}
	return peerFromContext(r.Context())
}

func (h *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	peer, ok := requestPeer(r)
	id := peer.ID
	if !ok || id != h.allow || time.Now().After(peer.NotAfter) {
		reqID := newRequestID()
		writeJSON(w, http.StatusForbidden, mgmtapi.Denied{Error: mgmtapi.DeniedError, RequestID: reqID})
		if _, ok, suppressed, _ := h.limit.Allow("peer"); ok {
			h.log.WarnContext(r.Context(), "api_denied", "reason", "peer_not_allowed", "peer", id.String(), "request_id", reqID, "suppressed", suppressed)
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

func (h *apiHandler) ops(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.PathValue("env") != h.env {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, h.p.OpenOps())
}

func (h *apiHandler) reports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.PathValue("env") != h.env {
		http.NotFound(w, r)
		return
	}
	body, bad := readBodyLimit(w, r, maxReportBody)
	var batch mgmtapi.ReportBatch
	if bad == "" {
		if err := record.DecodeStrict(body, &batch); err != nil {
			bad = "body_invalid"
		} else if len(batch.Items) > maxReportItems {
			bad = "too_many_items"
		}
	}
	if bad != "" {
		id := newRequestID()
		writeJSON(w, http.StatusForbidden, mgmtapi.Denied{Error: mgmtapi.DeniedError, RequestID: id})
		if _, ok, suppressed, _ := h.limit.Allow("reports:" + bad); ok {
			h.log.WarnContext(r.Context(), "reports_denied", "reason", bad, "request_id", id, "suppressed", suppressed)
		}
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), reportsHandlerTimeout)
	defer cancel()
	res := h.p.Reports(ctx, batch)
	if res.Outcomes == nil {
		res.Outcomes = []mgmtapi.ItemOutcome{}
	}
	writeJSON(w, http.StatusOK, res)
}

// ---- Admin

type adminHandler struct {
	p       *Plane
	publish func(context.Context, ed25519.PublicKey) error
}

// publishTimeout bounds the publish of a rotated key.
const publishTimeout = 30 * time.Second

// NewAdminHandler serves the commands of `mgmtd ctl` on the local admin socket. The commands that
// change keys or records take the query expect-seq, and then run only while the state version is
// that number. POST /rotate-key calls publish before it answers: with the staged key for stage=1,
// and with the new signing key for commit=1 and for a rotation with no query (the emergency
// rotation, which needs no stage).
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
	mux.HandleFunc("POST /ops", h.createOp)
	mux.HandleFunc("GET /ops", h.listOps)
	mux.HandleFunc("GET /ops/{id}", h.getOp)
	mux.HandleFunc("POST /ops/{id}/close", h.closeOp)
	return cleanPathOnly(mux)
}

// ReasonNotFound is the reason of a restore for a revision that the plane does not hold, and
// ReasonNotStaged the reason of a key commit when no key is staged.
const (
	ReasonNotFound  = "not_found"
	ReasonNotStaged = "not_staged"
)

func adminError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	out := map[string]any{"error": err.Error()}
	switch {
	case errors.Is(err, ErrRevisionUnknown):
		out["reason"] = ReasonNotFound
		status = http.StatusNotFound
	case errors.Is(err, ErrOpUnknown):
		out["reason"] = ErrOpUnknown.Error()
		status = http.StatusNotFound
	case errors.Is(err, ErrOpNotExpired):
		out["reason"] = ErrOpNotExpired.Error()
		status = http.StatusConflict
	case errors.Is(err, ErrOpFinal):
		out["reason"] = ErrOpFinal.Error()
		status = http.StatusConflict
	default:
		status, out = refusalStatus(status, out, err)
	}
	writeJSON(w, status, out)
}

func refusalStatus(status int, out map[string]any, err error) (int, map[string]any) {
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
	return status, out
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

// rotateMode reads the queries stage and commit. Each takes the value 1, and the two exclude each
// other.
func rotateMode(r *http.Request) (stage, commit bool, err error) {
	q := r.URL.Query()
	flag := func(name string) (bool, error) {
		vals, present := q[name]
		if !present {
			return false, nil
		}
		if len(vals) != 1 || vals[0] != "1" {
			return false, fmt.Errorf("%s must be 1", name)
		}
		return true, nil
	}
	if stage, err = flag("stage"); err != nil {
		return false, false, err
	}
	if commit, err = flag("commit"); err != nil {
		return false, false, err
	}
	if stage && commit {
		return false, false, errors.New("stage and commit exclude each other")
	}
	return stage, commit, nil
}

func (h *adminHandler) rotate(w http.ResponseWriter, r *http.Request) {
	seq, guarded, err := expectSeq(r)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	stage, commit, err := rotateMode(r)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	if stage {
		h.stage(w, r, seq, guarded)
		return
	}
	var staged ed25519.PublicKey
	if commit {
		var ok bool
		if staged, ok = h.p.StagedPublicKey(); !ok {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "no key is staged; run rotate-key --stage first", "reason": ReasonNotStaged})
			return
		}
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
	if commit && !pub.Equal(staged) {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "the key that signs is not the staged key", "rotated": true})
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

// stage makes the next signing key and publishes its public half as next.pub. The signing key does
// not change. The guard checks the state version before the stage, which is a no-op while a key is
// staged.
func (h *adminHandler) stage(w http.ResponseWriter, r *http.Request, seq uint64, guarded bool) {
	if guarded {
		if err := h.p.CheckSeq(seq); err != nil {
			adminError(w, err)
			return
		}
	}
	pub, err := h.p.StageKey(r.Context())
	if err != nil {
		adminError(w, err)
		return
	}
	if h.publish != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), publishTimeout)
		defer cancel()
		if err := h.publish(ctx, pub); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":  fmt.Sprintf("the key is staged, but its public half did not publish: %v", err),
				"staged": true,
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"next.pub": base64.StdEncoding.EncodeToString(pub), "staged": true, "seq": h.p.Status().Seq})
}

// StagedPublicKey returns the public key of the staged signing key, when the state names a staged
// key and its file holds that key.
func (p *Plane) StagedPublicKey() (ed25519.PublicKey, bool) {
	key, ok := p.stagedKey(p.snap.Load().st)
	if !ok {
		return nil, false
	}
	return slices.Clone(key.Public().(ed25519.PublicKey)), true
}

// ---- Admin: operations

// opView is one operation as the admin socket shows it.
type opView struct {
	ID        string          `json:"id"`
	Cell      string          `json:"cell"`
	Kind      string          `json:"kind,omitempty"`
	State     string          `json:"state"`
	Final     string          `json:"final,omitempty"`
	Served    bool            `json:"served"`
	KeyEpoch  uint64          `json:"keyEpoch"`
	IssuedAt  time.Time       `json:"issuedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
	ExpiredAt time.Time       `json:"expiredAt,omitzero"`
	ResultAt  time.Time       `json:"resultAt,omitzero"`
	Result    *op.Result      `json:"result,omitempty"`
	Envelopes []string        `json:"envelopes,omitempty"`
	Envelope  json.RawMessage `json:"envelope,omitempty"`
}

// newOpView describes o. The envelope is left out when withEnvelope is false.
func (p *Plane) newOpView(id string, o *OpState, withEnvelope bool) opView {
	v := opView{
		ID: id, Cell: o.Cell, Served: o.Served, KeyEpoch: o.KeyEpoch, IssuedAt: o.IssuedAt, ExpiresAt: o.ExpiresAt,
		ExpiredAt: o.ExpiredAt, ResultAt: o.ResultAt, Result: o.Result, Final: o.Final,
	}
	switch {
	case o.Final != "":
		v.State = "final"
	case o.open(p.cfg.Now()):
		v.State = "open"
	default:
		v.State = "expired"
	}
	if cur, err := decodeOpUnverified(o.Envelope); err == nil {
		v.Kind = cur.Kind
	}
	if withEnvelope {
		v.Envelopes = slices.Clone(o.Envelopes)
		v.Envelope = slices.Clone(json.RawMessage(o.Envelope))
	}
	return v
}

// maxListedOps is the most operations that GET /ops lists.
const maxListedOps = OpHistory

type createOpRequest struct {
	Cell string          `json:"cell"`
	Kind string          `json:"kind"`
	Args json.RawMessage `json:"args"`
	TTL  string          `json:"ttl"`
}

// createOp signs an operation. With the query serve=0 the operation is signed and recorded, and
// OpenOps never offers it.
func (h *adminHandler) createOp(w http.ResponseWriter, r *http.Request) {
	serve := true
	if vals, present := r.URL.Query()["serve"]; present {
		switch {
		case len(vals) == 1 && vals[0] == "0":
			serve = false
		case len(vals) == 1 && vals[0] == "1":
		default:
			badRequest(w, "serve must be 0 or 1")
			return
		}
	}
	body, bad := readBody(w, r)
	var req createOpRequest
	if bad == "" {
		if err := record.DecodeStrict(body, &req); err != nil {
			bad = "body_invalid"
		}
	}
	var ttl time.Duration
	if bad == "" && req.TTL != "" {
		var err error
		if ttl, err = time.ParseDuration(req.TTL); err != nil {
			bad = "ttl_invalid"
		}
	}
	if bad != "" {
		badRequest(w, bad)
		return
	}
	o, env, err := h.p.CreateOp(r.Context(), req.Cell, req.Kind, req.Args, ttl, serve)
	if err != nil {
		adminError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, opView{
		ID: o.ID, Cell: o.Cell, Kind: o.Kind, State: "open", Served: serve, KeyEpoch: o.KeyEpoch,
		IssuedAt: o.IssuedAt, ExpiresAt: o.ExpiresAt, Envelope: json.RawMessage(env),
	})
}

func (h *adminHandler) getOp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	o := h.p.snap.Load().st.Ops[id]
	if o == nil {
		adminError(w, ErrOpUnknown)
		return
	}
	writeJSON(w, http.StatusOK, h.p.newOpView(id, o, true))
}

// listOps lists the operations of the query cell, or every operation, oldest first.
func (h *adminHandler) listOps(w http.ResponseWriter, r *http.Request) {
	cell := r.URL.Query().Get("cell")
	if _, ok := h.p.intent[cell]; cell != "" && !ok {
		adminError(w, refuse(mgmtapi.ReasonCellUnknown, ""))
		return
	}
	st := h.p.snap.Load().st
	out := []opView{}
	for _, id := range st.OpOrder {
		if o := st.Ops[id]; cell == "" || o.Cell == cell {
			out = append(out, h.p.newOpView(id, o, false))
		}
	}
	if len(out) > maxListedOps {
		out = out[len(out)-maxListedOps:]
	}
	writeJSON(w, http.StatusOK, map[string]any{"ops": out})
}

func (h *adminHandler) closeOp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.p.CloseOp(r.Context(), id); err != nil {
		adminError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "final": OpAbandoned})
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

// Limits of the API server.
const (
	apiStreams        = 4
	readHeaderTimeout = 10 * time.Second
	maxHeaderBytes    = 16 << 10
)

// connContext marks the connection for the maximum age and adds the verified API peer.
func connContext(ctx context.Context, c net.Conn) context.Context {
	ctx = connlimit.ConnContext(ctx, c)
	if v, ok := peerIDs.LoadAndDelete(connKey(c)); ok {
		ctx = context.WithValue(ctx, peerCtxKey{}, v.(peerInfo))
	}
	return ctx
}

// NewServers returns the API server, with the limits of the shared table and HTTP/2 only. The
// handler runs under connlimit.MaxAge. Serve it on a listener from ListenAPI.
func NewServers(api http.Handler, apiTLS *tls.Config) *http.Server {
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	// The API listener finishes the TLS handshake before the server sees the connection, so the
	// server reads HTTP/2 from that connection as from a plain one.
	protos.SetUnencryptedHTTP2(true)
	return &http.Server{
		Handler: connlimit.MaxAge(api), TLSConfig: apiTLS, Protocols: protos,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: apiStreams},
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: maxHeaderBytes, ConnContext: connContext,
	}
}
