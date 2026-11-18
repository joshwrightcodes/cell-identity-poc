package executor

import (
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"context"
	"errors"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// recorded reports whether the record of the operation is in state applied or reported. It only
// reads. An applied operation answers already_applied also after its expiry, so a late redelivery
// does not race the resend of its applied result. A record that does not exist gives false and no
// error. Any other failed read gives an error, because the answer is not known.
func (e *Executor) recorded(ctx context.Context, id string) (bool, error) {
	cm, err := e.cfg.Client.CoreV1().ConfigMaps(e.cfg.Namespace).Get(ctx, recordPrefix+id, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	rec, err := decodeRecord(cm)
	if err != nil {
		return false, err
	}
	return rec.State == stateApplied || rec.State == stateReported, nil
}

// check verifies the envelope and every rule that needs no cell state. It returns the operation, or
// the refusal result. It writes nothing.
func (e *Executor) check(ctx context.Context, envelope []byte, f op.Fence, sha string) (op.Operation, *op.Result) {
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
		// A failed read is not an answer: expired is final, so a retryable local outcome stands in.
		recorded, err := e.recorded(ctx, o.ID)
		switch {
		case err != nil:
			return refuse(op.OutcomeLeaseLost, ReasonStoreError)
		case recorded:
			return refuse(op.OutcomeAlreadyApplied, "")
		}
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
	if o.Kind == op.KindBundleApply && len(o.Args) > op.MaxBundleArgsBytes {
		return refuse(op.OutcomeRefused, op.ReasonPayloadInvalid)
	}
	return o, nil
}
