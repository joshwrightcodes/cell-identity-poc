package envd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// The bounds of the revocation input. envd checks them before it reads any entry, so a hostile
// input costs no more than this.
const (
	// MaxRevocationInputs is the most entries in one read of the input.
	MaxRevocationInputs = 4 * revoke.MaxHeld
	// MaxRevocationInputBytes is the most bytes of all entries in one read of the input.
	MaxRevocationInputBytes = MaxRevocationInputs * revoke.MaxCanonicalBytes
)

// ErrRevocationInputTooLarge means a read of the input is above MaxRevocationInputs or
// MaxRevocationInputBytes. envd then takes in no entry from it and keeps the held overlay.
var ErrRevocationInputTooLarge = errors.New("revocation input is too large")

// checkInputSize returns ErrRevocationInputTooLarge for n entries of size bytes above a bound.
func checkInputSize(n, size int) error {
	if n > MaxRevocationInputs {
		return fmt.Errorf("%w: %d entries, limit %d", ErrRevocationInputTooLarge, n, MaxRevocationInputs)
	}
	if size > MaxRevocationInputBytes {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrRevocationInputTooLarge, size, MaxRevocationInputBytes)
	}
	return nil
}

// The causes that a revocation_settled line names.
const (
	settledRevoked = "revoked"
	settledRetired = "retired"
	settledStale   = "stale"
)

// RevocationSource gives envd the signed local revocation entries that the operator wrote.
type RevocationSource interface {
	// Read returns the entry envelopes in a stable order. An absent source gives no entries.
	Read(ctx context.Context) ([][]byte, error)
}

// ConfigMapRevocations reads the entries from the ConfigMap Namespace/Name, one value for each
// entry. An absent ConfigMap gives no entries, and one above the input bounds gives an error that
// wraps ErrRevocationInputTooLarge.
type ConfigMapRevocations struct {
	Client          kubernetes.Interface
	Namespace, Name string
}

// Read returns the values of the ConfigMap in the order of their keys.
func (c ConfigMapRevocations) Read(ctx context.Context) ([][]byte, error) {
	cm, err := c.Client.CoreV1().ConfigMaps(c.Namespace).Get(ctx, c.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read configmap %s/%s: %w", c.Namespace, c.Name, err)
	}
	size := 0
	for _, v := range cm.Data {
		size += len(v)
	}
	if err := checkInputSize(len(cm.Data), size); err != nil {
		return nil, fmt.Errorf("configmap %s/%s: %w", c.Namespace, c.Name, err)
	}
	out := make([][]byte, 0, len(cm.Data))
	for _, k := range slices.Sorted(maps.Keys(cm.Data)) {
		out = append(out, []byte(cm.Data[k]))
	}
	return out, nil
}

// heldEntry decodes the payload of an envelope that the overlay holds. revoke.Admit or revoke.Load
// verified the envelope and keeps it in the form that revoke.Sign writes.
func heldEntry(raw []byte) (revoke.Entry, bool) {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return revoke.Entry{}, false
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return revoke.Entry{}, false
	}
	var e revoke.Entry
	if err := json.Unmarshal(body, &e); err != nil {
		return revoke.Entry{}, false
	}
	return e, true
}

func (p *Puller) operatorKeys() []ed25519.PublicKey {
	if p.cfg.OperatorKeys == nil {
		return nil
	}
	return p.cfg.OperatorKeys()
}

// overlay runs after the spec leg of each round, also when the pull failed. It drops each stale
// entry that the store gave at start, settles the held entries against the accepted spec, takes in
// the input entries, and saves a changed overlay. It needs an accepted spec, so it does nothing
// before the first one.
func (p *Puller) overlay(ctx context.Context) {
	if len(p.state.SpecEnvelope) == 0 {
		return
	}
	ctx, span := p.cfg.Tracer.Start(ctx, "envd.overlay")
	defer span.End()
	held := p.dropStale(ctx, p.state.Revocations)
	held = p.settle(ctx, held)
	held = p.intake(ctx, held)
	p.heldGauge.Record(ctx, int64(len(held)))
	if maps.EqualFunc(held, p.state.Revocations, bytes.Equal) {
		return
	}
	if len(held) == 0 {
		held = nil
	}
	next := *p.state
	next.Revocations = held
	// The new overlay is in force before the save, so the gateway and the report get it even when
	// the save fails. The next round writes the store again.
	p.state = &next
	if err := p.cfg.Store.Save(ctx, &next); err != nil {
		fail(span, err)
		p.storeErr = mgmtapi.ReasonStoreFailed
		p.logLimited(ctx, "save failed", "save", "error", clip(err.Error()))
	}
}

// settle drops the entry of each cell that the accepted spec revokes or retires.
func (p *Puller) settle(ctx context.Context, held revoke.Held) revoke.Held {
	if len(held) == 0 {
		return held
	}
	retired := map[string]bool{}
	for name := range p.state.Marks {
		if _, listed := p.state.Cells[name]; !listed {
			retired[name] = true
		}
	}
	out := revoke.Settle(held, p.state.Cells, retired)
	for _, cell := range slices.Sorted(maps.Keys(held)) {
		if _, kept := out[cell]; kept {
			continue
		}
		cause := settledRevoked
		if retired[cell] {
			cause = settledRetired
		}
		p.logSettled(ctx, cell, held[cell], cause)
	}
	return out
}

// staleOnLoad returns, by cell, each held entry of st that revoke.Stale reports against the record
// of its cell in st. st is the state that the store gave at start, so each entry is checked against
// the spec that it was held against. revoke.Load applies no stale rule, so this stops a writer of
// the store from planting an old entry for a cell that was revoked and un-revoked since.
func staleOnLoad(st *State) map[string][]byte {
	var out map[string][]byte
	for cell, raw := range st.Revocations {
		rec, known := st.Cells[cell]
		e, decoded := heldEntry(raw)
		if !known || !decoded || !revoke.Stale(e, spec.RecordRevision(rec)) {
			continue
		}
		if out == nil {
			out = map[string][]byte{}
		}
		out[cell] = raw
	}
	return out
}

// dropStale drops the entries of staleOnLoad once, in the first overlay leg. Afterwards a loaded
// entry follows the settle rule like an entry admitted in this run.
func (p *Puller) dropStale(ctx context.Context, held revoke.Held) revoke.Held {
	if len(p.staleAtStart) == 0 {
		return held
	}
	out := maps.Clone(held)
	for _, cell := range slices.Sorted(maps.Keys(p.staleAtStart)) {
		if raw, ok := held[cell]; ok && bytes.Equal(raw, p.staleAtStart[cell]) {
			delete(out, cell)
			p.logSettled(ctx, cell, raw, settledStale)
		}
	}
	p.staleAtStart = nil
	return out
}

// intake reads the input entries and adds the ones that pass the admit rules. A failed read and an
// input above the bounds keep held as it is.
func (p *Puller) intake(ctx context.Context, held revoke.Held) revoke.Held {
	if p.cfg.Revocations == nil {
		return held
	}
	var in [][]byte
	if err := p.leg(ctx, "envd.revocations.read", func(lctx context.Context) error {
		var err error
		in, err = p.cfg.Revocations.Read(lctx)
		if err != nil {
			return err
		}
		size := 0
		for _, e := range in {
			size += len(e)
		}
		return checkInputSize(len(in), size)
	}); err != nil {
		p.logLimited(ctx, "revocation input read failed", "revocations-read", "error", clip(err.Error()))
		return held
	}
	out, refusals := revoke.Admit(held, in, p.operatorKeys(), p.cfg.Env, p.state.Cells)
	for _, cell := range slices.Sorted(maps.Keys(out)) {
		if _, before := held[cell]; before {
			continue
		}
		e, _ := heldEntry(out[cell])
		p.cfg.Log.InfoContext(ctx, "revocation_held", "cell", cell, "id", e.ID,
			"record_epoch", e.Record.Epoch, "record_counter", e.Record.Counter)
	}
	for _, r := range refusals {
		p.refusedCount.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", r.Reason)))
		// The key holds no entry ID, so the refusals take at most one key for each reason and detail.
		_, ok, suppressed, dropped := p.logs.Allow("revocation-refused/" + r.Reason + "/" + r.Detail)
		for _, h := range dropped {
			p.cfg.Log.WarnContext(ctx, "log lines held back", "key", h.Key, "suppressed", h.Suppressed)
		}
		if ok {
			p.cfg.Log.WarnContext(ctx, "revocation_refused", "reason", r.Reason, "detail", r.Detail, "cell", r.Cell,
				"id", r.ID, "suppressed", suppressed)
		}
	}
	return out
}

func (p *Puller) logSettled(ctx context.Context, cell string, raw []byte, cause string) {
	e, _ := heldEntry(raw)
	p.cfg.Log.InfoContext(ctx, "revocation_settled", "cell", cell, "id", e.ID, "cause", cause)
}

// overlayEnvelopes returns the held envelopes sorted by cell, or nil for an empty overlay.
func (p *Puller) overlayEnvelopes() []json.RawMessage {
	if len(p.state.Revocations) == 0 {
		return nil
	}
	return p.state.Revocations.Envelopes()
}
