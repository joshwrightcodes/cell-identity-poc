package gateway

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// QueueEntry is one row of the operation queue as the admin socket shows it. The envelope stays
// out.
type QueueEntry struct {
	OpID       string    `json:"opId"`
	State      string    `json:"state"`
	Fence      op.Fence  `json:"fence"`
	Holder     string    `json:"holder"`
	LeaseUntil time.Time `json:"leaseUntil,omitzero"`
	Claims     int       `json:"claims"`
	KeyEpoch   uint64    `json:"keyEpoch"`
}

// The states of a queue row.
const (
	StateQueued = "queued"
	StateLeased = "leased"
	StateDone   = "done"
)

// maxAdminRows bounds one listing.
const maxAdminRows = 2000

// QueueEntries lists the rows of cell, oldest first.
func (s *Store) QueueEntries(ctx context.Context, cell string) ([]QueueEntry, error) {
	out := []QueueEntry{}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		out = out[:0]
		now := s.now().UnixNano()
		return scanRows(tx, `SELECT op_id, done, holder, lease_until, fence_epoch, fence_counter, claims, key_epoch
			FROM queue WHERE cell = ? ORDER BY seq LIMIT ?`, func(r *sql.Rows) error {
			var e QueueEntry
			var done bool
			var until int64
			if err := r.Scan(&e.OpID, &done, &e.Holder, &until, &e.Fence.Epoch, &e.Fence.Counter, &e.Claims, &e.KeyEpoch); err != nil {
				return err
			}
			switch {
			case done:
				e.State = StateDone
			case until > now:
				e.State = StateLeased
			default:
				e.State = StateQueued
			}
			if until > 0 {
				e.LeaseUntil = fromNano(until)
			}
			out = append(out, e)
			return nil
		}, cell, maxAdminRows)
	})
	return out, err
}

// OutboxEntry is one outbox item as the admin socket shows it: the token appears only as its key
// ID and its audience, and the body never appears.
type OutboxEntry struct {
	ID       string    `json:"id"`
	Cell     string    `json:"cell"`
	Kind     string    `json:"kind"`
	OpID     string    `json:"opId,omitempty"`
	KID      string    `json:"kid"`
	Audience string    `json:"audience"`
	Size     int       `json:"size"`
	At       time.Time `json:"at"`
}

// OutboxEntries lists the outbox, oldest first.
func (s *Store) OutboxEntries(ctx context.Context) ([]OutboxEntry, error) {
	out := []OutboxEntry{}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		out = out[:0]
		return scanRows(tx, `SELECT id, cell, kind, op_id, token, size, at FROM outbox ORDER BY seq LIMIT ?`, func(r *sql.Rows) error {
			var e OutboxEntry
			var token string
			var at int64
			if err := r.Scan(&e.ID, &e.Cell, &e.Kind, &e.OpID, &token, &e.Size, &at); err != nil {
				return err
			}
			e.KID, e.Audience = tokenLabels(token)
			e.At = fromNano(at)
			out = append(out, e)
			return nil
		}, maxAdminRows)
	})
	return out, err
}

// tokenLabels reads the key ID and the audience of a compact token without checking it. A token
// that does not parse gives empty strings.
func tokenLabels(token string) (kid, aud string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ""
	}
	var head struct {
		KID string `json:"kid"`
	}
	if b, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil || json.Unmarshal(b, &head) != nil {
		return "", ""
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil && json.Unmarshal(b, &claims) == nil {
		var one string
		var many []string
		switch {
		case json.Unmarshal(claims.Aud, &one) == nil:
			aud = one
		case json.Unmarshal(claims.Aud, &many) == nil:
			aud = strings.Join(many, ",")
		}
	}
	return head.KID, aud
}

type adminHandler struct {
	st     *Store
	status func() any
	mux    *http.ServeMux
}

// NewAdminHandler serves the commands of `cellgw ctl` on the local admin socket. status gives the
// body of GET /status. A nil status gives the store status.
func NewAdminHandler(st *Store, status func() any) http.Handler {
	h := &adminHandler{st: st, status: status, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /status", h.getStatus)
	h.mux.HandleFunc("GET /queue", h.queue)
	h.mux.HandleFunc("POST /enqueue", h.enqueue)
	h.mux.HandleFunc("POST /inject", h.inject)
	h.mux.HandleFunc("GET /outbox", h.outbox)
	return h.mux
}

func adminFail(w http.ResponseWriter, code int, reason, msg string) {
	body := map[string]string{"error": msg}
	if reason != "" {
		body["reason"] = reason
	}
	writeJSON(w, code, body)
}

func (h *adminHandler) getStatus(w http.ResponseWriter, r *http.Request) {
	if h.status != nil {
		writeJSON(w, http.StatusOK, h.status())
		return
	}
	st, err := h.st.Stats(r.Context())
	if err != nil {
		adminFail(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func cellParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	vals := r.URL.Query()["cell"]
	if len(vals) != 1 || !spec.ValidName(vals[0]) {
		adminFail(w, http.StatusBadRequest, "", "cell must appear once and be a cell name")
		return "", false
	}
	return vals[0], true
}

func (h *adminHandler) queue(w http.ResponseWriter, r *http.Request) {
	cell, ok := cellParam(w, r)
	if !ok {
		return
	}
	rows, err := h.st.QueueEntries(r.Context(), cell)
	if err != nil {
		adminFail(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cell": cell, "items": rows})
}

func (h *adminHandler) enqueue(w http.ResponseWriter, r *http.Request) {
	cell, ok := cellParam(w, r)
	if !ok {
		return
	}
	replay := false
	switch v := r.URL.Query().Get("replay"); v {
	case "":
	case "1":
		replay = true
	default:
		adminFail(w, http.StatusBadRequest, "", "replay must be 1")
		return
	}
	body, bad := readBody(w, r, maxAdminBody)
	if bad != "" {
		adminFail(w, http.StatusBadRequest, "", bad)
		return
	}
	var id string
	var added bool
	var err error
	if replay {
		id, err = h.st.EnqueueReplay(r.Context(), cell, body)
		added = err == nil
	} else {
		id, added, err = h.st.Enqueue(r.Context(), cell, body)
	}
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"cell": cell, "opId": id, "added": added, "replay": replay})
	case errors.Is(err, gwapi.ErrEnvelopeConflict):
		adminFail(w, http.StatusConflict, gwapi.ReasonEnvelopeConflict, err.Error())
	case strings.HasPrefix(err.Error(), "enqueue: "):
		adminFail(w, http.StatusBadRequest, "", err.Error())
	default:
		adminFail(w, http.StatusInternalServerError, "", err.Error())
	}
}

func (h *adminHandler) inject(w http.ResponseWriter, r *http.Request) {
	body, bad := readBody(w, r, maxAdminBody)
	if bad != "" {
		adminFail(w, http.StatusBadRequest, "", bad)
		return
	}
	var it gwapi.Item
	if err := record.DecodeStrict(body, &it); err != nil {
		adminFail(w, http.StatusBadRequest, "", "body is not an item: "+err.Error())
		return
	}
	if it.Cell == "" || !spec.ValidName(it.Cell) || (it.Kind != gwapi.KindResult && it.Kind != gwapi.KindStatus && it.Kind != gwapi.KindBind) {
		adminFail(w, http.StatusBadRequest, "", "item needs a valid cell and a kind of result, status or bind")
		return
	}
	id, err := h.st.Append(r.Context(), it)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"id": id})
	case errors.Is(err, gwapi.ErrOverloaded):
		adminFail(w, http.StatusConflict, gwapi.ReasonOverloaded, err.Error())
	default:
		adminFail(w, http.StatusInternalServerError, "", err.Error())
	}
}

func (h *adminHandler) outbox(w http.ResponseWriter, r *http.Request) {
	rows, err := h.st.OutboxEntries(r.Context())
	if err != nil {
		adminFail(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows})
}
