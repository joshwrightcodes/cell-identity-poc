package executor

import (
	"errors"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// check verifies the envelope and every rule that needs no cell state. It returns the operation, or
// the refusal result. It writes nothing.
func (e *Executor) check(envelope []byte, f op.Fence, sha string) (op.Operation, *op.Result) {
	o, _, err := op.Verify(envelope, e.cfg.Keys)
	if err != nil {
		reason := op.ReasonPayloadInvalid
		if errors.Is(err, record.ErrSignature) {
			reason = op.ReasonSignatureInvalid
		}
		res := e.result("", op.OutcomeRefused, reason, f, sha)
		if id, _, _, perr := op.Peek(envelope); perr == nil {
			res.PeekedID = id
		}
		return op.Operation{}, &res
	}
	refuse := func(outcome, reason string) (op.Operation, *op.Result) {
		res := e.result(o.ID, outcome, reason, f, sha)
		return op.Operation{}, &res
	}
	now := e.cfg.Now()
	switch {
	case o.Env != e.cfg.Env:
		return refuse(op.OutcomeRefused, op.ReasonEnvMismatch)
	case o.Cell != e.cfg.Cell:
		return refuse(op.OutcomeRefused, op.ReasonWrongTarget)
	case o.IssuedAt.After(now.Add(op.MaxSkew)):
		return refuse(op.OutcomeRefused, op.ReasonPayloadInvalid)
	case !now.Before(o.ExpiresAt):
		return refuse(op.OutcomeExpired, "")
	}
	if _, ok := e.cfg.Kinds[o.Kind]; !ok {
		return refuse(op.OutcomeRefused, op.ReasonKindUnknown)
	}
	if o.Kind == op.KindDemoAppend {
		if _, err := op.ParseDemoAppend(o.Args); err != nil {
			return refuse(op.OutcomeRefused, op.ReasonPayloadInvalid)
		}
	}
	return o, nil
}
