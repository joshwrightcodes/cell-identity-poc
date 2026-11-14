package mgmt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

// MaxPortalCells is the most cells that one portal call names.
const MaxPortalCells = 8

var bootstrapDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PortalRequest asks for the named cells. Each cell that is not requested yet gets a request and
// one signed step, in one commit. A cell that is already requested is listed in AlreadyRequested
// and gets no new step, and a request where every cell is already requested makes no commit.
func (p *Plane) PortalRequest(ctx context.Context, cells []string, digest string) (mgmtapi.PortalResult, error) {
	cells, err := p.portalCells(ctx, cells, false)
	if err != nil {
		return mgmtapi.PortalResult{}, err
	}
	if !bootstrapDigestRE.MatchString(digest) {
		return mgmtapi.PortalResult{}, refuse(mgmtapi.ReasonBootstrapInvalid, "")
	}
	var res mgmtapi.PortalResult
	err = p.commit(func(t *txn) error {
		res = mgmtapi.PortalResult{Steps: []mgmtapi.PortalStep{}, AlreadyRequested: []string{}, Revision: t.st.Last}
		var fresh []string
		for _, c := range cells {
			if t.st.Requests[c] != nil {
				res.AlreadyRequested = append(res.AlreadyRequested, c)
			} else {
				fresh = append(fresh, c)
			}
		}
		if len(fresh) == 0 {
			return nil
		}
		if err := t.revise(); err != nil {
			return err
		}
		if t.st.Requests == nil {
			t.st.Requests = map[string]*Request{}
		}
		res.RequestID = newRequestID()
		for _, c := range fresh {
			ss, err := t.issueStep(c, digest)
			if err != nil {
				return err
			}
			t.st.Requests[c] = &Request{RequestID: res.RequestID, RequestedAt: t.now, Step: ss}
			res.Steps = append(res.Steps, mgmtapi.PortalStep{Cell: c, StepID: ss.ID})
		}
		res.Revision = t.rev
		t.dirty = true
		return p.reconcile(t)
	})
	if err != nil {
		return mgmtapi.PortalResult{}, err
	}
	return res, nil
}

// PortalWithdraw removes the requests of the named cells. A named cell that is not requested is
// skipped, and a call where no named cell is requested makes no commit. A bound cell stays in the
// state until its staged drop, but its step leaves the spec in this commit.
func (p *Plane) PortalWithdraw(ctx context.Context, cells []string) (mgmtapi.PortalResult, error) {
	cells, err := p.portalCells(ctx, cells, true)
	if err != nil {
		return mgmtapi.PortalResult{}, err
	}
	var res mgmtapi.PortalResult
	err = p.commit(func(t *txn) error {
		res = mgmtapi.PortalResult{Revision: t.st.Last}
		var gone []string
		for _, c := range cells {
			if t.st.Requests[c] != nil {
				gone = append(gone, c)
			}
		}
		if len(gone) == 0 {
			return nil
		}
		if err := t.revise(); err != nil {
			return err
		}
		for _, c := range gone {
			delete(t.st.Requests, c)
		}
		res.RequestID = newRequestID()
		res.Revision = t.rev
		t.dirty = true
		return p.reconcile(t)
	})
	if err != nil {
		return mgmtapi.PortalResult{}, err
	}
	return res, nil
}

// PortalRecreate signs a new step for a requested cell that has no open step.
func (p *Plane) PortalRecreate(ctx context.Context, cell, digest string) (mgmtapi.PortalResult, error) {
	return p.portalStep(ctx, cell, digest, func(r *Request) error {
		switch {
		case r == nil:
			return refuse(mgmtapi.ReasonNotRequested, "")
		case r.Step.open():
			return refuse(mgmtapi.ReasonStepOpen, "")
		}
		return nil
	})
}

// PortalRetry signs a new step with a new ID in place of the open step of a cell, whatever state the
// host reports for the old one. The old ID leaves the spec, so the host cancels it.
func (p *Plane) PortalRetry(ctx context.Context, cell, digest string) (mgmtapi.PortalResult, error) {
	return p.portalStep(ctx, cell, digest, func(r *Request) error {
		if r == nil || !r.Step.open() {
			return refuse(mgmtapi.ReasonNoStep, "")
		}
		return nil
	})
}

// PortalCancel drops the open step of a cell from the spec. The request stays.
func (p *Plane) PortalCancel(ctx context.Context, cell string) (mgmtapi.PortalResult, error) {
	if err := ctx.Err(); err != nil {
		return mgmtapi.PortalResult{}, err
	}
	if _, ok := p.catalog[cell]; !ok {
		return mgmtapi.PortalResult{}, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	var res mgmtapi.PortalResult
	err := p.commit(func(t *txn) error {
		r := t.st.Requests[cell]
		if r == nil || !r.Step.open() {
			return refuse(mgmtapi.ReasonNoStep, "")
		}
		if err := t.revise(); err != nil {
			return err
		}
		r.Step = nil
		t.dirty = true
		res = mgmtapi.PortalResult{RequestID: newRequestID(), Revision: t.rev}
		return p.reconcile(t)
	})
	if err != nil {
		return mgmtapi.PortalResult{}, err
	}
	return res, nil
}

// portalStep runs a recreate or a retry: check decides from the request, and the commit signs a
// new step for the cell.
func (p *Plane) portalStep(ctx context.Context, cell, digest string, check func(*Request) error) (mgmtapi.PortalResult, error) {
	if err := ctx.Err(); err != nil {
		return mgmtapi.PortalResult{}, err
	}
	if _, ok := p.catalog[cell]; !ok {
		return mgmtapi.PortalResult{}, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	if !bootstrapDigestRE.MatchString(digest) {
		return mgmtapi.PortalResult{}, refuse(mgmtapi.ReasonBootstrapInvalid, "")
	}
	var res mgmtapi.PortalResult
	err := p.commit(func(t *txn) error {
		r := t.st.Requests[cell]
		if err := check(r); err != nil {
			return err
		}
		if err := t.revise(); err != nil {
			return err
		}
		ss, err := t.issueStep(cell, digest)
		if err != nil {
			return err
		}
		r.Step = ss
		t.dirty = true
		res = mgmtapi.PortalResult{
			RequestID: newRequestID(), Revision: t.rev, Steps: []mgmtapi.PortalStep{{Cell: cell, StepID: ss.ID}},
		}
		return p.reconcile(t)
	})
	if err != nil {
		return mgmtapi.PortalResult{}, err
	}
	return res, nil
}

// portalCells checks the cell list of a request or a withdraw and returns it without duplicates. A
// withdraw also accepts a name that left the catalog while a request still holds it.
func (p *Plane) portalCells(ctx context.Context, cells []string, withdraw bool) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(cells) == 0 {
		return nil, refuse(mgmtapi.ReasonPayloadInvalid, "cells")
	}
	if len(cells) > MaxPortalCells {
		return nil, refuse(mgmtapi.ReasonTooManyCells, "")
	}
	st := p.snap.Load().st
	out := make([]string, 0, len(cells))
	for _, c := range cells {
		_, listed := p.catalog[c]
		if !listed && !(withdraw && st.Requests[c] != nil) {
			return nil, refuse(mgmtapi.ReasonCellUnknown, "")
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// issueStep signs a step for a catalog cell at the revision of the change. IssuedAt is the commit
// time in whole seconds, because a token iat has that resolution. It runs after t.revise.
func (t *txn) issueStep(cell, digest string) (*StepState, error) {
	ic, ok := t.p.catalog[cell]
	if !ok {
		return nil, refuse(mgmtapi.ReasonCellUnknown, "")
	}
	issued := t.now.UTC().Truncate(time.Second)
	body := step.Step{
		ID: t.newStepID(), Env: t.p.cfg.Intent.Env, Cell: cell, Kind: step.KindCellCreate, Version: 1,
		KeyEpoch: t.rev.Epoch, IssuedAt: issued, ExpiresAt: issued.Add(step.DefaultTTL),
		Cluster: ic.Cluster, BootstrapSHA256: digest,
	}
	ss, err := t.signStepState(body)
	if err != nil {
		return nil, err
	}
	ss.KeysAtIssue = []string{}
	if cs := t.st.Cells[cell]; cs != nil {
		for _, k := range parseKeys(cs.JWKS) {
			ss.KeysAtIssue = append(ss.KeysAtIssue, k.id)
		}
	}
	return ss, nil
}

func (t *txn) newStepID() string {
	for {
		id := step.NewID()
		used := false
		for _, r := range t.st.Requests {
			if r.Step != nil && r.Step.ID == id {
				used = true
			}
		}
		if !used {
			return id
		}
	}
}

// signStepState signs body with the key of the change and describes the envelope.
func (t *txn) signStepState(body step.Step) (*StepState, error) {
	env, err := step.Sign(body, t.key)
	if err != nil {
		return nil, fmt.Errorf("sign step: %w", err)
	}
	_, payload, err := step.Verify(env, []ed25519.PublicKey{t.key.Public().(ed25519.PublicKey)})
	if err != nil {
		return nil, fmt.Errorf("verify step: %w", err)
	}
	return &StepState{
		ID: body.ID, Envelope: env, PayloadSHA256: step.PayloadSHA256(payload), KeyEpoch: body.KeyEpoch,
		IssuedAt: body.IssuedAt, ExpiresAt: body.ExpiresAt,
	}, nil
}

// closeStep closes the open step of a cell after a bind, when the token was minted at or after the
// step was signed and the keys that the bind proved differ from the keys at signing.
func (t *txn) closeStep(cell string, iat time.Time, proved []keyInfo) {
	r := t.st.Requests[cell]
	if r == nil || !r.Step.open() {
		return
	}
	ids := make([]string, 0, len(proved))
	for _, k := range proved {
		ids = append(ids, k.id)
	}
	if stepCloses(r.Step, iat, ids) {
		r.Step.DoneAt = t.now
	}
}

// stepCloses is the close rule. proved holds the sorted key identities that the bind proved.
func stepCloses(s *StepState, iat time.Time, proved []string) bool {
	return s.open() && !iat.Before(s.IssuedAt) && !slices.Equal(s.KeysAtIssue, proved)
}

// resignSteps signs every open step again under the new key, with the same ID, issue time and
// expiry and the key epoch of the new revision. An expired open step is signed again too, because
// only a retry or a cancel ends it. It runs after t.revise.
func (t *txn) resignSteps() error {
	pub := t.key.Public().(ed25519.PublicKey)
	for _, name := range sortedKeys(t.st.Requests) {
		ss := t.st.Requests[name].Step
		if !ss.open() {
			continue
		}
		cur, err := decodeStepUnverified(ss.Envelope)
		if err != nil {
			return fmt.Errorf("step %s: %w", ss.ID, err)
		}
		cur.KeyEpoch = t.rev.Epoch
		env, err := step.Sign(cur, t.key)
		if err != nil {
			return fmt.Errorf("sign step %s: %w", ss.ID, err)
		}
		_, payload, err := step.Verify(env, []ed25519.PublicKey{pub})
		if err != nil {
			return fmt.Errorf("verify step %s: %w", ss.ID, err)
		}
		ss.Envelope, ss.PayloadSHA256, ss.KeyEpoch = env, step.PayloadSHA256(payload), cur.KeyEpoch
	}
	return nil
}

// decodeStepUnverified reads a step that the plane signed itself, from its own state.
func decodeStepUnverified(envelope []byte) (step.Step, error) {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		return step.Step{}, err
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return step.Step{}, err
	}
	var s step.Step
	return s, json.Unmarshal(body, &s)
}

// SignStep signs a test step and records nothing. It refuses a digest other than step.TestDigest,
// fills an empty ID and sets the key epoch.
func (p *Plane) SignStep(ctx context.Context, body step.Step) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if body.BootstrapSHA256 != step.TestDigest {
		return nil, refuse(mgmtapi.ReasonTestDigestOnly, "")
	}
	var env []byte
	err := p.commit(func(t *txn) error {
		if t.st.Served != 0 {
			return refuse(mgmtapi.ReasonRestoreActive, "")
		}
		if body.ID == "" {
			body.ID = step.NewID()
		}
		body.KeyEpoch = t.st.Last.Epoch
		var err error
		env, err = step.Sign(body, t.key)
		return err
	})
	if err != nil {
		return nil, err
	}
	return slices.Clone(env), nil
}
