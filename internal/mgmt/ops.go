package mgmt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

const (
	// DefaultOpTTL is the lifetime of an operation when the caller gives none.
	DefaultOpTTL = 10 * time.Minute
	// MaxOpenOps is the most open operations that one environment holds.
	MaxOpenOps = 256
	// OpHistory is the most operations that the state keeps.
	OpHistory = 500
	// opGrace is how long an operation stays served after it expires, so that a cell that is slow
	// to report can still close it.
	opGrace = 60 * time.Second

	// OpAbandoned is the final state of an operation that ended through CloseOp.
	OpAbandoned = "abandoned"
)

// The errors of CloseOp.
var (
	ErrOpUnknown    = errors.New("operation_unknown")
	ErrOpNotExpired = errors.New("operation_not_expired")
	ErrOpFinal      = errors.New("operation_final")
)

// open reports whether the operation has no final result and is not past its grace time.
func (o *OpState) open(now time.Time) bool {
	return o.Final == "" && now.Before(o.ExpiresAt.Add(opGrace))
}

// CreateOp signs an operation for a bound cell and records it. The ID is 128 random bits, and
// KeyEpoch is State.Last.Epoch at the time of signing. A reset or a lost state starts again at
// epoch 1 under a new key and loses every open operation, so a lower epoch never meets a queued
// envelope of the same ID. A zero ttl takes DefaultOpTTL. With serve false the operation is signed
// and recorded but never offered by OpenOps.
func (p *Plane) CreateOp(ctx context.Context, cell, kind string, args json.RawMessage, ttl time.Duration, serve bool) (op.Operation, []byte, error) {
	if err := ctx.Err(); err != nil {
		return op.Operation{}, nil, err
	}
	if ttl == 0 {
		ttl = DefaultOpTTL
	}
	if ttl < op.MinTTL || ttl > op.MaxTTL {
		return op.Operation{}, nil, refuse(mgmtapi.ReasonPayloadInvalid, "ttl")
	}
	if _, ok := p.intent[cell]; !ok {
		return op.Operation{}, nil, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	if kind != op.KindDemoAppend {
		return op.Operation{}, nil, refuse(mgmtapi.ReasonPayloadInvalid, "kind_unknown")
	}
	if _, err := op.ParseDemoAppend(args); err != nil {
		return op.Operation{}, nil, refuse(mgmtapi.ReasonPayloadInvalid, "args")
	}
	var (
		o   op.Operation
		env []byte
	)
	err := p.commit(func(t *txn) error {
		if t.st.Cells[cell] == nil {
			return refuse(mgmtapi.ReasonNotBound, "")
		}
		open := 0
		for _, s := range t.st.Ops {
			if s.open(t.now) {
				open++
			}
		}
		if open >= MaxOpenOps {
			return refuse(mgmtapi.ReasonRateLimited, "too_many_open_ops")
		}
		id := op.NewID()
		for t.st.Ops[id] != nil {
			id = op.NewID()
		}
		issued := t.now.UTC().Truncate(time.Second)
		o = op.Operation{
			ID: id, Env: t.p.cfg.Intent.Env, Cell: cell, Kind: kind, Version: 1, KeyEpoch: t.st.Last.Epoch,
			IssuedAt: issued, ExpiresAt: issued.Add(ttl), Args: slices.Clone(args),
		}
		var err error
		if env, err = op.Sign(o, t.key); err != nil {
			return err
		}
		t.st.Ops[id] = &OpState{
			Cell: cell, Envelopes: []string{op.EnvelopeSHA256(env)}, Envelope: env, KeyEpoch: o.KeyEpoch,
			IssuedAt: o.IssuedAt, ExpiresAt: o.ExpiresAt, Served: serve,
		}
		t.st.OpOrder = append(t.st.OpOrder, id)
		trimOps(t.st)
		t.dirty = true
		return nil
	})
	if err != nil {
		return op.Operation{}, nil, err
	}
	return o, slices.Clone(env), nil
}

// trimOps drops the oldest final operations until OpHistory remain. When none is final it drops the
// oldest operation.
func trimOps(st *State) {
	for len(st.OpOrder) > OpHistory {
		i := slices.IndexFunc(st.OpOrder, func(id string) bool { return st.Ops[id].Final != "" })
		if i < 0 {
			i = 0
		}
		delete(st.Ops, st.OpOrder[i])
		st.OpOrder = slices.Delete(st.OpOrder, i, i+1)
	}
}

// OpenOps returns the envelopes of the served operations that have no final result and are not
// past ExpiresAt plus 60 s, and one CellInfo with a fresh nonce for each intent cell. An operation
// past that time gets ExpiredAt.
func (p *Plane) OpenOps() mgmtapi.OpsBundle {
	now := p.cfg.Now()
	st := p.snap.Load().st
	if slices.ContainsFunc(st.OpOrder, func(id string) bool {
		o := st.Ops[id]
		return o.Final == "" && o.ExpiredAt.IsZero() && !o.open(now)
	}) {
		err := p.commit(func(t *txn) error {
			for _, o := range t.st.Ops {
				if o.Final == "" && o.ExpiredAt.IsZero() && !o.open(t.now) {
					o.ExpiredAt = t.now
					t.dirty = true
				}
			}
			return nil
		})
		if err != nil {
			p.logLimited(context.Background(), slog.LevelError, "expire_ops_failed", "expire_ops_failed", "error", err.Error())
		}
		st = p.snap.Load().st
	}
	b := mgmtapi.OpsBundle{Ops: []json.RawMessage{}, Cells: []mgmtapi.CellInfo{}}
	for _, id := range st.OpOrder {
		if o := st.Ops[id]; o.Served && o.open(now) {
			b.Ops = append(b.Ops, slices.Clone(json.RawMessage(o.Envelope)))
		}
	}
	for _, name := range sortedKeys(p.intent) {
		nonce, exp := p.nonces.Issue(name)
		b.Cells = append(b.Cells, mgmtapi.CellInfo{Name: name, Nonce: nonce, NonceExpiresAt: exp, Bound: st.Cells[name] != nil})
	}
	return b
}

// CloseOp ends an operation that is past ExpiresAt and has no final result with the final state
// abandoned.
func (p *Plane) CloseOp(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.commit(func(t *txn) error {
		o := t.st.Ops[id]
		switch {
		case o == nil:
			return ErrOpUnknown
		case o.Final != "":
			return ErrOpFinal
		case t.now.Before(o.ExpiresAt):
			return ErrOpNotExpired
		}
		o.Final = OpAbandoned
		if o.ExpiredAt.IsZero() {
			o.ExpiredAt = t.now
		}
		t.dirty = true
		return nil
	})
}

// resignOps signs every open operation again under the new key, with the same ID and expiry and
// the key epoch of the new revision. The new digest joins Envelopes, so a result for either
// envelope closes the operation. It runs after t.revise.
func (t *txn) resignOps() error {
	for _, id := range t.st.OpOrder {
		o := t.st.Ops[id]
		if !o.open(t.now) {
			continue
		}
		cur, err := decodeOpUnverified(o.Envelope)
		if err != nil {
			return fmt.Errorf("operation %s: %w", id, err)
		}
		cur.KeyEpoch = t.rev.Epoch
		env, err := op.Sign(cur, t.key)
		if err != nil {
			return err
		}
		o.Envelope, o.KeyEpoch = env, cur.KeyEpoch
		if d := op.EnvelopeSHA256(env); !slices.Contains(o.Envelopes, d) {
			o.Envelopes = append(o.Envelopes, d)
		}
	}
	return nil
}

// decodeOpUnverified reads an operation that the plane signed itself, from its own state.
func decodeOpUnverified(envelope []byte) (op.Operation, error) {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		return op.Operation{}, err
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return op.Operation{}, err
	}
	var o op.Operation
	return o, json.Unmarshal(body, &o)
}
