package hostsvc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

// Limits of the step route.
const (
	maxStepBody = 16 << 10
	maxSpecBody = 256 << 10
	// putBurst is the size of the token bucket of each peer. One token returns every putRefill.
	putBurst  = 20
	putRefill = 3 * time.Second

	retryAfterBusy   = "60"
	retryAfterBehind = "30"
)

var stepIDShape = regexp.MustCompile(`^[0-9a-f]{32}$`)

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("hostsvc: no randomness: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// deny answers with the Denied body and a request ID. The detail goes to the log only.
func deny(w http.ResponseWriter, status int, retryAfter string) string {
	id := newRequestID()
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	writeJSON(w, status, mgmtapi.Denied{Error: mgmtapi.DeniedError, RequestID: id})
	return id
}

type bucket struct {
	tokens float64
	last   time.Time
}

type stepHandler struct {
	v   *StepVerifier
	a   *Actor
	log *slog.Logger
	now func() time.Time
	lim *lograte.Limiter

	mu      sync.Mutex
	buckets map[string]*bucket
}

// NewStepHandler serves PUT and GET of mgmtapi.StepPattern. A PUT passes the token bucket of its
// peer first, then the verifier, then the actor. Every refusal has a Denied body with a request ID.
// A verify failure, step_conflict and peer errors are 403. rate_limited and queue_full are 503 with
// Retry-After 60, spec_behind is 503 with Retry-After 30 and journal_corrupt is 503 with none.
func NewStepHandler(v *StepVerifier, a *Actor, log *slog.Logger, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	h := &stepHandler{v: v, a: a, log: log, now: now, lim: lograte.New(denialWindow, denialMaxKeys, now), buckets: map[string]*bucket{}}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT "+mgmtapi.StepPattern, h.put)
	mux.HandleFunc("GET "+mgmtapi.StepPattern, h.get)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "GET, PUT")
		h.refuse(w, r, http.StatusMethodNotAllowed, "", "method_not_allowed", nil)
	})
	return mux
}

// refuse answers, and logs the denial at most once for each reason in each window.
func (h *stepHandler) refuse(w http.ResponseWriter, r *http.Request, status int, retryAfter, reason string, err error, attrs ...any) {
	rid := deny(w, status, retryAfter)
	_, ok, suppressed, _ := h.lim.Allow(reason)
	if !ok {
		return
	}
	peer, _ := PeerID(r.Context())
	a := append([]any{"reason", reason, "status", status, "request_id", rid, "peer", peer.String(), "suppressed", suppressed}, attrs...)
	if err != nil {
		a = append(a, "error", err.Error())
	}
	h.log.Warn(reason, a...)
}

// allow takes one token from the bucket of peer.
func (h *stepHandler) allow(peer string) bool {
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.buckets[peer]
	if !ok {
		b = &bucket{tokens: putBurst, last: now}
		h.buckets[peer] = b
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(putBurst, b.tokens+float64(d)/float64(putRefill))
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (h *stepHandler) put(w http.ResponseWriter, r *http.Request) {
	peer, _ := PeerID(r.Context())
	if !h.allow(peer.String()) {
		h.refuse(w, r, http.StatusServiceUnavailable, retryAfterBusy, step.DetailRateLimited, nil)
		return
	}
	if h.a.Journal().Corrupt() {
		h.refuse(w, r, http.StatusServiceUnavailable, "", step.DetailJournalCorrupt, nil)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxStepBody))
	if err != nil {
		h.refuse(w, r, http.StatusForbidden, "", step.DetailPayloadInvalid, err)
		return
	}
	id, cell, _, err := step.Peek(body)
	if err != nil || id != r.PathValue("id") {
		h.refuse(w, r, http.StatusForbidden, "", step.DetailPayloadInvalid, err)
		return
	}
	c, err := h.v.CheckFull(body, true)
	if err != nil {
		h.checkFailed(w, r, c, body, id, cell, err)
		return
	}
	st, err := h.a.Submit(body, c.Step)
	switch {
	case errors.Is(err, ErrConflict):
		h.refuse(w, r, http.StatusForbidden, "", step.DetailStepConflict, nil, "step", id, "cell", cell)
	case errors.Is(err, ErrQueueFull):
		h.refuse(w, r, http.StatusServiceUnavailable, retryAfterBusy, step.DetailQueueFull, nil, "step", id, "cell", cell)
	case errors.Is(err, ErrJournalCorrupt):
		h.refuse(w, r, http.StatusServiceUnavailable, "", step.DetailJournalCorrupt, nil)
	case err != nil:
		h.refuse(w, r, http.StatusInternalServerError, "", "internal", err, "step", id)
	default:
		writeJSON(w, http.StatusOK, st)
	}
}

func (h *stepHandler) checkFailed(w http.ResponseWriter, r *http.Request, c Checked, body []byte, id, cell string, err error) {
	var se *step.Error
	if !errors.As(err, &se) {
		h.refuse(w, r, http.StatusInternalServerError, "", "internal", err, "step", id)
		return
	}
	if (se.Detail == step.DetailSpecBehind || se.Detail == step.DetailStepUnindexed) &&
		h.v.Spec.Index(c.Step.Cell, c.Step.ID, c.PayloadSH) == IndexResign {
		st, handled, derr := h.a.Door(c, body)
		switch {
		case handled && errors.Is(derr, ErrSpecBehind):
			h.refuse(w, r, http.StatusServiceUnavailable, retryAfterBehind, step.DetailSpecBehind, nil, "step", id, "cell", cell)
			return
		case handled && errors.Is(derr, ErrConflict):
			h.refuse(w, r, http.StatusForbidden, "", step.DetailStepConflict, nil, "step", id, "cell", cell)
			return
		case handled:
			writeJSON(w, http.StatusOK, st)
			return
		}
	}
	if se.Detail == step.DetailSpecBehind {
		h.refuse(w, r, http.StatusServiceUnavailable, retryAfterBehind, se.Detail, nil, "step", id, "cell", cell)
		return
	}
	h.refuse(w, r, http.StatusForbidden, "", se.Detail, nil, "step", id, "cell", cell)
}

func (h *stepHandler) get(w http.ResponseWriter, r *http.Request) {
	if h.a.Journal().Corrupt() {
		h.refuse(w, r, http.StatusServiceUnavailable, "", step.DetailJournalCorrupt, nil)
		return
	}
	st, ok := h.a.Status(r.PathValue("id"))
	if !ok {
		h.refuse(w, r, http.StatusNotFound, "", "step_unknown", nil)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

type specHandler struct {
	s   *SpecStore
	log *slog.Logger
	lim *lograte.Limiter
}

// NewSpecHandler serves PUT mgmtapi.HostSpecPath. The body is a spec envelope of at most 256 KiB.
// A refused spec is 403 with a Denied body, and the detail goes to the log.
func NewSpecHandler(s *SpecStore, log *slog.Logger) http.Handler {
	h := &specHandler{s: s, log: log, lim: lograte.New(denialWindow, denialMaxKeys, time.Now)}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT "+mgmtapi.HostSpecPath, h.put)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", http.MethodPut)
		h.refuse(w, r, http.StatusMethodNotAllowed, "method_not_allowed", nil)
	})
	return mux
}

func (h *specHandler) refuse(w http.ResponseWriter, r *http.Request, status int, reason string, err error) {
	rid := deny(w, status, "")
	_, ok, suppressed, _ := h.lim.Allow(reason)
	if !ok {
		return
	}
	peer, _ := PeerID(r.Context())
	a := []any{"reason", reason, "status", status, "request_id", rid, "peer", peer.String(), "suppressed", suppressed}
	if err != nil {
		a = append(a, "error", err.Error())
	}
	h.log.Warn("spec_denied", a...)
}

func (h *specHandler) put(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSpecBody))
	if err != nil {
		h.refuse(w, r, http.StatusForbidden, step.DetailPayloadInvalid, err)
		return
	}
	sp, err := h.s.Put(body)
	var se *step.Error
	switch {
	case errors.As(err, &se):
		h.refuse(w, r, http.StatusForbidden, se.Detail, nil)
	case err != nil:
		h.refuse(w, r, http.StatusInternalServerError, "internal", err)
	default:
		w.Header().Set("X-Spec-Revision", strconv.FormatUint(sp.Revision.Epoch, 10)+"."+strconv.FormatUint(sp.Revision.Counter, 10))
		writeJSON(w, http.StatusOK, sp.Revision)
	}
}
