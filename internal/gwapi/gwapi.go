// Package gwapi holds the wire types of the cell gateway: the stream frames between celld and the
// gateway, the sync and ack bodies between envd and the gateway, and the bind inbox types.
package gwapi

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// MaxFrame is the longest frame of a stream, newline included.
const MaxFrame = 64 << 10

// The frame types.
const (
	TypeHello   = "hello"
	TypeWelcome = "welcome"
	TypeClaim   = "claim"
	TypeLease   = "lease"
	TypeNone    = "none"
	TypeWork    = "work"
	TypeResult  = "result"
	TypeStatus  = "status"
	TypeAck     = "ack"
	TypeFinal   = "final"
	TypeRetry   = "retry"
	TypeRefused = "refused"
	TypePing    = "ping"
	TypePong    = "pong"
)

var frameTypes = map[string]bool{
	TypeHello: true, TypeWelcome: true, TypeClaim: true, TypeLease: true, TypeNone: true, TypeWork: true,
	TypeResult: true, TypeStatus: true, TypeAck: true, TypeFinal: true, TypeRetry: true, TypeRefused: true,
	TypePing: true, TypePong: true,
}

// The item kinds.
const (
	KindResult = "result"
	KindStatus = "status"
	KindBind   = "bind"
)

// Frame is one message of a stream. A field that a frame type does not use stays empty and is
// left out of the encoding.
type Frame struct {
	Type      string          `json:"type"`
	Token     string          `json:"token,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Pod       string          `json:"pod,omitempty"`
	LeaseID   string          `json:"leaseId,omitempty"`
	OpID      string          `json:"opId,omitempty"`
	Outcome   string          `json:"outcome,omitempty"`
	Cap       int             `json:"cap,omitempty"`
	Queued    int             `json:"queued,omitempty"`
	Fence     op.Fence        `json:"fence,omitzero"`
	LastFence op.Fence        `json:"lastFence,omitzero"`
	Envelope  json.RawMessage `json:"envelope,omitempty"`
	Until     time.Time       `json:"until,omitzero"`
	Item      *Item           `json:"item,omitempty"`
}

// Item is one report item that celld sends up through the gateway. Body holds the exact bytes that
// the proof audience covers. celld must make Body with the standard encoding/json Marshal, which
// escapes <, > and & and has no extra whitespace. Such a body is unchanged by each later Marshal, so
// every hop keeps its bytes. A body made in another way can change at a hop, and the proof then fails.
type Item struct {
	Kind  string          `json:"kind"`
	Cell  string          `json:"cell"`
	OpID  string          `json:"opId,omitempty"`
	Body  json.RawMessage `json:"body"`
	Token string          `json:"token"`
}

func (f Frame) validate() error {
	if !frameTypes[f.Type] {
		return fmt.Errorf("%w frame: unknown type %q", record.ErrDecode, f.Type)
	}
	if f.Item != nil {
		switch f.Item.Kind {
		case KindResult, KindStatus, KindBind:
		default:
			return fmt.Errorf("%w frame: unknown item kind %q", record.ErrDecode, f.Item.Kind)
		}
	}
	return nil
}

// ErrFrameTooLarge means a frame is longer than MaxFrame.
var ErrFrameTooLarge = errors.New("gateway frame is too large")

// Decoder reads newline-terminated frames from a stream.
type Decoder struct {
	r   *bufio.Reader
	buf []byte
}

// NewDecoder returns a Decoder for r. A frame is at most MaxFrame bytes, an unknown type, an
// unknown field and a duplicate field are errors, and so is data after the frame object.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: bufio.NewReaderSize(r, 4096)}
}

// Decode reads the next frame. It returns io.EOF at the end of the stream, and ErrFrameTooLarge
// when a line passes MaxFrame bytes without ending. After ErrFrameTooLarge the rest of the line
// stays in the buffer, so the caller must close the stream. Every other decode failure wraps
// record.ErrDecode.
func (d *Decoder) Decode() (Frame, error) {
	d.buf = d.buf[:0]
	for {
		chunk, err := d.r.ReadSlice('\n')
		d.buf = append(d.buf, chunk...)
		if len(d.buf) > MaxFrame {
			return Frame{}, ErrFrameTooLarge
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(d.buf) > 0 {
			break
		}
		return Frame{}, err
	}
	var f Frame
	if err := record.DecodeStrict(bytes.TrimSuffix(d.buf, []byte("\n")), &f); err != nil {
		return Frame{}, err
	}
	if err := f.validate(); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// Encode writes f as one line, in a single write, and flushes w when it is an http.Flusher. It
// does not escape HTML. A body that the standard encoding/json Marshal made already holds the
// escapes for <, > and &, so it keeps its bytes. A body with a raw < or & also keeps its bytes here,
// but a later Marshal of a ReportBatch rewrites it, so celld must not make such a body.
func Encode(w io.Writer, f Frame) error {
	if err := f.validate(); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return fmt.Errorf("encode frame: %w", err)
	}
	if buf.Len() > MaxFrame {
		return ErrFrameTooLarge
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	return nil
}

// ItemID names one outbox item, one bind and one report item: 128 random bits as 32 lowercase hex
// characters.
type ItemID string

var itemIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// NewItemID returns a random ItemID.
func NewItemID() ItemID {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("gwapi: no randomness: " + err.Error())
	}
	return ItemID(hex.EncodeToString(b[:]))
}

// Valid reports whether id has the form of an ItemID.
func (id ItemID) Valid() bool { return itemIDRE.MatchString(string(id)) }

// ParseItemID returns s as an ItemID, or an error when it has the wrong form.
func ParseItemID(s string) (ItemID, error) {
	if id := ItemID(s); id.Valid() {
		return id, nil
	}
	return "", errors.New("item ID is not 32 lowercase hex characters")
}

// OutItem is an Item with the ID that the gateway outbox gave it.
type OutItem struct {
	ID ItemID `json:"id"`
	Item
}

// The errors that a gateway store returns. ReasonOf maps each one to its reason string.
var (
	ErrLeaseLost        = errors.New("lease lost")
	ErrOverloaded       = errors.New("gateway overloaded")
	ErrEnvelopeConflict = errors.New("envelope conflicts with the stored envelope")
)

// ReasonOf returns the reason string of a sentinel in err, or the empty string.
func ReasonOf(err error) string {
	switch {
	case errors.Is(err, ErrLeaseLost):
		return ReasonLeaseLost
	case errors.Is(err, ErrOverloaded):
		return ReasonOverloaded
	case errors.Is(err, ErrEnvelopeConflict):
		return ReasonEnvelopeConflict
	}
	return ""
}

// The gateway reasons. The ones that mgmtapi or op also define have the same string.
const (
	ReasonCellUnknown      = mgmtapi.ReasonCellUnknown
	ReasonCellRevoked      = "cell_revoked"
	ReasonHelloTimeout     = "hello_timeout"
	ReasonProofMissing     = mgmtapi.ReasonProofMissing
	ReasonProofInvalid     = mgmtapi.ReasonProofInvalid
	ReasonReplicaCap       = "replica_cap"
	ReasonSuperseded       = "superseded"
	ReasonReauth           = "reauth"
	ReasonSourceMismatch   = "source_mismatch"
	ReasonNonceInvalid     = mgmtapi.ReasonNonceInvalid
	ReasonTokenInvalid     = mgmtapi.ReasonTokenInvalid
	ReasonOverloaded       = "overloaded"
	ReasonLeaseLost        = "lease_lost"
	ReasonRecordOld        = "record_old"
	ReasonEnvelopeConflict = "envelope_conflict"
)

// BindAccepted is the answer of the gateway to a bind post: the ID to poll.
type BindAccepted struct {
	ID ItemID `json:"id"`
}

// The values of BindResult.Status besides the mgmtapi bind statuses.
const (
	BindDenied  = "denied"
	BindPending = "pending"
)

// BindResult is what a cell reads when it polls a bind ID.
type BindResult struct {
	Status    string `json:"status"`
	RequestID string `json:"requestId,omitempty"`
}

// BindResultFor turns the outcome of a bind item into the status that a cell polls. An accepted
// item with a bind response gives the status of that response, a refused item gives denied with
// its request ID, and every other outcome gives pending.
func BindResultFor(o mgmtapi.ItemOutcome) BindResult {
	switch o.Outcome {
	case mgmtapi.OutcomeAccepted:
		if o.Bind != nil {
			return BindResult{Status: o.Bind.Status}
		}
	case mgmtapi.OutcomeRefused:
		return BindResult{Status: BindDenied, RequestID: o.RequestID}
	}
	return BindResult{Status: BindPending}
}

// SyncRequest is what envd sends the gateway: the signed spec, the signed records, the operation
// envelopes, the cell nonces and the local revocation entries that envd holds, sorted by cell.
type SyncRequest struct {
	SpecEnvelope json.RawMessage            `json:"specEnvelope"`
	Records      map[string]json.RawMessage `json:"records"`
	Ops          []json.RawMessage          `json:"ops"`
	Cells        []mgmtapi.CellInfo         `json:"cells"`
	Revocations  []json.RawMessage          `json:"revocations,omitempty"`
}

// SyncResponse is the answer of the gateway: the outbox items for the management plane and the
// gateway status.
type SyncResponse struct {
	Items  []OutItem             `json:"items"`
	Status mgmtapi.GatewayStatus `json:"status"`
}

// AckRequest tells the gateway what the management plane decided for items it sent up.
type AckRequest struct {
	Outcomes []mgmtapi.ItemOutcome `json:"outcomes"`
}

// Route patterns and paths of the gateway.
const (
	StreamPattern     = "/v1/cells/{cell}/stream"
	BindResultPattern = "/v1/cells/{cell}/bind/{id}"
	// NoncePattern and BindPattern are the routes where a cell asks for a bind nonce and posts a bind request.
	NoncePattern = "/v1/cells/{cell}/nonce"
	BindPattern  = "/v1/cells/{cell}/bind"

	// SyncPath is where envd posts a SyncRequest.
	SyncPath = "/v1/sync"
	// AckPath is where envd posts an AckRequest.
	AckPath = "/v1/ack"
)

// StreamPath is the path of the stream of a cell.
func StreamPath(cell string) string { return "/v1/cells/" + url.PathEscape(cell) + "/stream" }

// NoncePath is the path where a cell asks the gateway for a bind nonce.
func NoncePath(cell string) string { return "/v1/cells/" + url.PathEscape(cell) + "/nonce" }

// BindPath is the path where a cell posts a bind request to the gateway.
func BindPath(cell string) string { return "/v1/cells/" + url.PathEscape(cell) + "/bind" }

// BindResultPath is the path where a cell polls the result of a bind.
func BindResultPath(cell string, id string) string {
	return "/v1/cells/" + url.PathEscape(cell) + "/bind/" + url.PathEscape(id)
}
