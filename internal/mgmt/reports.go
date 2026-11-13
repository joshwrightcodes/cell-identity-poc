package mgmt

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// The kinds of a report item.
const (
	kindResult = "result"
	kindStatus = "status"
	kindBind   = "bind"
)

const (
	// maxStatusAge is the oldest `at` that a status may carry.
	maxStatusAge = 2 * time.Minute
	// maxPodsPerCell is how many pods of one cell keep a status sequence.
	maxPodsPerCell = 8
	// forgedRing is how many forged_seen records a cell keeps.
	forgedRing = 20
	// hintEvery is the shortest time between two hint checks for one cell.
	hintEvery = 60 * time.Second
	// hintCheckTimeout bounds one background hint check.
	hintCheckTimeout = 30 * time.Second
)

// bindItemTimeout is the deadline of one bind item inside a report batch. A variable so that a test
// can lower it.
var bindItemTimeout = 5 * time.Second

// bindBatchBudget is the time that the bind items of one Reports call share.
var bindBatchBudget = 8 * time.Second

var opIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ItemRefusal is the last report item that the plane refused for a cell.
type ItemRefusal struct {
	Kind   string    `json:"kind"`
	Reason string    `json:"reason"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// ForgedSeen is one result that named an operation but did not close it.
type ForgedSeen struct {
	PeekedID string    `json:"peekedId"`
	OpID     string    `json:"opId,omitempty"`
	At       time.Time `json:"at"`
}

type podStatus struct {
	name string
	seq  uint64
	at   time.Time
}

// cellRuntime is what the plane keeps in memory about the reports of one cell.
type cellRuntime struct {
	pods               map[string]*podStatus // by pod UID
	lastStatusAt       time.Time
	lastStatusPod      string
	unreported         uint64
	oldestUnreportedAt time.Time
	records            uint64
	refusal            *ItemRefusal
	forgedTotal        int
	forged             []ForgedSeen
	hintAt             time.Time
	lastHintCheck      string
}

type liveState struct {
	cells map[string]*cellRuntime
	binds map[bindKey]storedBind
}

func (l *liveState) cell(name string) *cellRuntime {
	c := l.cells[name]
	if c == nil {
		c = &cellRuntime{pods: map[string]*podStatus{}}
		l.cells[name] = c
	}
	return c
}

// snapshot copies what Status shows. The caller holds rmu.
func (l *liveState) snapshot() map[string]cellRuntime {
	out := make(map[string]cellRuntime, len(l.cells))
	for k, v := range l.cells {
		c := *v
		if v.refusal != nil {
			r := *v.refusal
			c.refusal = &r
		}
		c.pods, c.forged = nil, nil
		out[k] = c
	}
	return out
}

// fill adds the report fields of a cell to its status.
func (cs *CellStatus) fill(live cellRuntime, st *State, now time.Time) {
	cs.LastStatusAt, cs.LastStatusPod = live.lastStatusAt, live.lastStatusPod
	cs.Unreported, cs.OldestUnreportedAt, cs.Records = live.unreported, live.oldestUnreportedAt, live.records
	cs.LastRefusal, cs.ForgedSeen = live.refusal, live.forgedTotal
	cs.HintAt, cs.LastHintCheck = live.hintAt, live.lastHintCheck
	for _, id := range st.OpOrder {
		o := st.Ops[id]
		if o.Cell != cs.Name {
			continue
		}
		switch {
		case o.Final == "" && o.open(now):
			cs.OpenOps++
		case o.Final == "":
			cs.ExpiredOps++
		}
		if o.ResultAt.After(cs.LastResultAt) {
			cs.LastResultAt = o.ResultAt
		}
	}
}

// ForgedSeen returns the last forged_seen records of a cell, oldest first.
func (p *Plane) ForgedSeen(cell string) []ForgedSeen {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	if c := p.rt.cells[cell]; c != nil {
		return slices.Clone(c.forged)
	}
	return nil
}

// Wait blocks until the background hint checks have finished. The caller stops Report and Reports
// calls first, because a hint that starts while Wait runs at a zero count is not waited for.
func (p *Plane) Wait() { p.bg.Wait() }

// queueHint starts a hint key check for a bound cell, at most once per hintEvery for each cell. The
// check runs in the background.
func (p *Plane) queueHint(cell string) {
	if _, ok := p.intent[cell]; !ok || p.snap.Load().st.Cells[cell] == nil {
		return
	}
	now := p.cfg.Now()
	p.rmu.Lock()
	c := p.rt.cell(cell)
	if !c.hintAt.IsZero() && now.Sub(c.hintAt) < hintEvery {
		p.rmu.Unlock()
		return
	}
	c.hintAt = now
	p.rmu.Unlock()
	p.bg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), hintCheckTimeout)
		defer cancel()
		res, err := p.KeyCheckVia(ctx, cell, ViaHint)
		last := string(res)
		if err != nil {
			last = "error"
			p.logLimited(ctx, slog.LevelWarn, "hint_check_failed/"+cell, "hint_check_failed", "cell", cell, "error", err.Error())
		}
		p.rmu.Lock()
		p.rt.cell(cell).lastHintCheck = last
		p.rmu.Unlock()
	})
}

// Reports checks each item of a batch on its own and returns one outcome for each, in order. The
// results of the batch commit in one save.
func (p *Plane) Reports(ctx context.Context, b mgmtapi.ReportBatch) mgmtapi.ReportResult {
	out := make([]mgmtapi.ItemOutcome, len(b.Items))
	type pendingResult struct {
		i    int
		res  op.Result
		cell string
	}
	var pending []pendingResult
	binds := &bindBatch{failed: map[string]bool{}}
	defer binds.stop()
	for i, it := range b.Items {
		var o mgmtapi.ItemOutcome
		switch it.Kind {
		case kindBind:
			o = p.reportBind(ctx, it, binds)
		case kindResult, kindStatus:
			now := p.cfg.Now()
			claims, bad := p.verifyItem(it, now)
			switch {
			case bad != nil:
				o = *bad
			case it.Kind == kindStatus:
				o = p.reportStatus(it, claims, now)
			default:
				res, bad := decodeResult(it, claims)
				if bad != nil {
					o = *bad
					break
				}
				pending = append(pending, pendingResult{i: i, res: res, cell: it.Cell})
				continue
			}
		default:
			o = refused(it, mgmtapi.ReasonPayloadInvalid, "kind")
		}
		out[i] = p.noteItem(ctx, it, o)
	}
	if len(pending) == 0 {
		return mgmtapi.ReportResult{Outcomes: out}
	}

	outcomes := make([]string, len(pending))
	err := p.commit(func(t *txn) error {
		for j, pr := range pending {
			x := t.st.Ops[pr.res.OpID]
			switch {
			case pr.res.OpID == "":
				outcomes[j] = mgmtapi.OutcomeForgedSeen
			case x == nil:
				outcomes[j] = mgmtapi.OutcomeUnknownOp
			case x.Cell != pr.cell || !slices.Contains(x.Envelopes, pr.res.EnvelopeSHA256):
				outcomes[j] = mgmtapi.OutcomeForgedSeen
			case x.Final != "":
				outcomes[j] = mgmtapi.OutcomeDuplicate
			default:
				res := pr.res
				x.Result, x.ResultAt, x.Final = &res, t.now, res.Outcome
				outcomes[j] = mgmtapi.OutcomeAccepted
				t.dirty = true
			}
		}
		return nil
	})
	for j, pr := range pending {
		it := b.Items[pr.i]
		o := mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: outcomes[j]}
		switch {
		case err != nil:
			o = mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeRetry, Reason: mgmtapi.ReasonStore}
		case o.Outcome == mgmtapi.OutcomeForgedSeen:
			p.noteForged(ctx, pr.cell, pr.res)
		}
		out[pr.i] = p.noteItem(ctx, it, o)
	}
	if err != nil {
		p.logLimited(ctx, slog.LevelError, "report_commit_failed", "report_commit_failed", "error", err.Error())
	}
	return mgmtapi.ReportResult{Outcomes: out}
}

func refused(it mgmtapi.ReportItem, reason, detail string) mgmtapi.ItemOutcome {
	return mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeRefused, Reason: reason, Detail: detail}
}

// verifyItem checks the cell and the proof of a result or status item. It returns the verified
// claims, or the outcome to answer with.
func (p *Plane) verifyItem(it mgmtapi.ReportItem, now time.Time) (clusterjwt.Claims, *mgmtapi.ItemOutcome) {
	fail := func(o mgmtapi.ItemOutcome) (clusterjwt.Claims, *mgmtapi.ItemOutcome) { return clusterjwt.Claims{}, &o }
	if _, ok := p.intent[it.Cell]; !ok {
		return fail(refused(it, mgmtapi.ReasonCellUnknown, ""))
	}
	cs := p.snap.Load().st.Cells[it.Cell]
	if cs == nil {
		return fail(refused(it, mgmtapi.ReasonNotBound, ""))
	}
	rec := record.Cell{
		Name: it.Cell, Env: p.cfg.Intent.Env, Issuer: cs.Issuer, JWKS: cs.JWKS, Subjects: cs.Subjects,
	}
	claims, err := proof.Verify(rec, it.Token, proof.ReportAudience(it.Cell, it.Kind, it.Body), p.cfg.Intent.BindSubject, now)
	if err == nil {
		return claims, nil
	}
	var pe *proof.Error
	if !errors.As(err, &pe) {
		return fail(mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeRetry, Reason: mgmtapi.ReasonProofInvalid, Detail: "internal"})
	}
	switch {
	case pe.Reason == proof.ReasonMissing:
		return fail(refused(it, mgmtapi.ReasonProofMissing, ""))
	case pe.Transient():
		if pe.Detail == string(clusterjwt.UnknownKID) {
			p.retryUnknownKID.Add(context.Background(), 1, metric.WithAttributes(attribute.String("cell", it.Cell)))
			p.queueHint(it.Cell)
		}
		return fail(mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeRetry, Reason: mgmtapi.ReasonProofInvalid, Detail: pe.Detail})
	}
	return fail(refused(it, mgmtapi.ReasonProofInvalid, pe.Detail))
}

// decodeResult decodes the body of a result item and checks it against the item and the claims.
// proof.Verify does not compare the pod, so a pod named in the body is compared here.
func decodeResult(it mgmtapi.ReportItem, claims clusterjwt.Claims) (op.Result, *mgmtapi.ItemOutcome) {
	bad := func(detail string) (op.Result, *mgmtapi.ItemOutcome) {
		o := refused(it, mgmtapi.ReasonPayloadInvalid, detail)
		return op.Result{}, &o
	}
	var res op.Result
	switch err := record.DecodeStrict(it.Body, &res); {
	case err != nil:
		return bad("body")
	case res.Cell != it.Cell:
		return bad("cell")
	case res.OpID != "" && !opIDRE.MatchString(res.OpID):
		return bad("op_id")
	case !op.IsFinal(res.Outcome):
		return bad("outcome")
	case res.Pod != "" && res.Pod != claims.PodName:
		return bad("pod")
	}
	return res, nil
}

// reportStatus applies the rules of a status item: the pod in the body is the pod of the token, the
// time is recent, and the sequence of the pod rises.
func (p *Plane) reportStatus(it mgmtapi.ReportItem, claims clusterjwt.Claims, now time.Time) mgmtapi.ItemOutcome {
	var s op.Status
	switch err := record.DecodeStrict(it.Body, &s); {
	case err != nil:
		return refused(it, mgmtapi.ReasonPayloadInvalid, "body")
	case s.Cell != it.Cell:
		return refused(it, mgmtapi.ReasonPayloadInvalid, "cell")
	case s.Pod != claims.PodName || s.PodUID != claims.PodUID:
		return refused(it, mgmtapi.ReasonPayloadInvalid, "pod")
	case now.Sub(s.At) > maxStatusAge:
		return refused(it, mgmtapi.ReasonStale, "at")
	case s.At.Sub(now) > op.MaxSkew:
		return refused(it, mgmtapi.ReasonPayloadInvalid, "at_future")
	}
	p.rmu.Lock()
	defer p.rmu.Unlock()
	c := p.rt.cell(it.Cell)
	pod := c.pods[s.PodUID]
	switch {
	case pod != nil && s.Seq == pod.seq:
		return mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeDuplicate}
	case pod != nil && s.Seq < pod.seq:
		return refused(it, mgmtapi.ReasonStale, "seq")
	case pod == nil:
		if len(c.pods) >= maxPodsPerCell {
			oldest := ""
			for uid, ps := range c.pods {
				if oldest == "" || ps.at.Before(c.pods[oldest].at) {
					oldest = uid
				}
			}
			delete(c.pods, oldest)
		}
		pod = &podStatus{}
		c.pods[s.PodUID] = pod
	}
	pod.name, pod.seq, pod.at = s.Pod, s.Seq, s.At
	c.lastStatusAt, c.lastStatusPod = s.At, s.Pod
	c.unreported, c.oldestUnreportedAt, c.records = s.Unreported, s.OldestUnreportedAt, s.Records
	return mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeAccepted}
}

// bindBatch is what the bind items of one Reports call share: one time budget, and the cells whose
// key fetch already failed.
type bindBatch struct {
	ctx    context.Context
	cancel context.CancelFunc
	failed map[string]bool
}

func (b *bindBatch) stop() {
	if b.cancel != nil {
		b.cancel()
	}
}

// storedBind is the outcome of a bind that succeeded, kept for NonceTTL so that the same request,
// sent again after a cut response, gets the same answer.
type storedBind struct {
	resp    mgmtapi.BindResponse
	expires time.Time
}

type bindKey struct {
	cell, nonce string
	token       [sha256.Size]byte
}

const maxStoredBinds = 4096

func (p *Plane) storeBind(k bindKey, resp mgmtapi.BindResponse) {
	now := p.cfg.Now()
	p.rmu.Lock()
	defer p.rmu.Unlock()
	if p.rt.binds == nil {
		p.rt.binds = map[bindKey]storedBind{}
	}
	if len(p.rt.binds) >= maxStoredBinds {
		for key, v := range p.rt.binds {
			if !now.Before(v.expires) {
				delete(p.rt.binds, key)
			}
		}
		if len(p.rt.binds) >= maxStoredBinds {
			return
		}
	}
	p.rt.binds[k] = storedBind{resp: resp, expires: now.Add(p.cfg.NonceTTL)}
}

func (p *Plane) storedBind(k bindKey) (mgmtapi.BindResponse, bool) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	v, ok := p.rt.binds[k]
	if !ok || !p.cfg.Now().Before(v.expires) {
		return mgmtapi.BindResponse{}, false
	}
	return v.resp, true
}

// reportBind runs a bind item through Plane.Bind under a deadline of its own, inside the budget of
// the batch. A key fetch that does not finish in time answers retry, and the other items go on. After
// a cell failed once in a batch, its later bind items answer retry with no fetch.
func (p *Plane) reportBind(ctx context.Context, it mgmtapi.ReportItem, b *bindBatch) mgmtapi.ItemOutcome {
	retry := func(detail string) mgmtapi.ItemOutcome {
		return mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeRetry, Reason: mgmtapi.ReasonIssuerUnavailable, Detail: detail}
	}
	var req mgmtapi.BindRequest
	if err := record.DecodeStrict(it.Body, &req); err != nil {
		return refused(it, mgmtapi.ReasonPayloadInvalid, "body")
	}
	if b.ctx == nil {
		b.ctx, b.cancel = context.WithTimeout(ctx, bindBatchBudget)
	}
	switch {
	case b.failed[it.Cell]:
		return retry("batch")
	case b.ctx.Err() != nil:
		return retry("budget")
	}
	ictx, cancel := context.WithTimeout(b.ctx, bindItemTimeout)
	defer cancel()
	key := bindKey{cell: it.Cell, nonce: req.Nonce, token: sha256.Sum256([]byte(req.Token))}
	resp, err := p.Bind(ictx, it.Cell, req)
	if err == nil {
		p.storeBind(key, resp)
		return mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeAccepted, Bind: &resp}
	}
	var e *Error
	switch {
	case !errors.As(err, &e):
		return mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeRetry, Reason: mgmtapi.ReasonInternal}
	case e.Reason == mgmtapi.ReasonIssuerUnavailable || ictx.Err() != nil:
		b.failed[it.Cell] = true
		return retry(e.Detail)
	case e.Reason == mgmtapi.ReasonNonceInvalid && e.Detail == "consumed":
		if resp, ok := p.storedBind(key); ok {
			return mgmtapi.ItemOutcome{ID: it.ID, OpID: it.OpID, Outcome: mgmtapi.OutcomeAccepted, Bind: &resp}
		}
	}
	o := refused(it, e.Reason, e.Detail)
	o.RequestID = newRequestID()
	return o
}

// noteForged keeps a forged_seen result in the ring of its cell and logs it with the peeked ID.
func (p *Plane) noteForged(ctx context.Context, cell string, res op.Result) {
	peeked := res.PeekedID
	if peeked == "" {
		peeked = res.OpID
	}
	if !opIDRE.MatchString(peeked) {
		peeked = ""
	}
	now := p.cfg.Now()
	p.rmu.Lock()
	c := p.rt.cell(cell)
	c.forgedTotal++
	c.forged = append(c.forged, ForgedSeen{PeekedID: peeked, OpID: res.OpID, At: now})
	if len(c.forged) > forgedRing {
		c.forged = slices.Clone(c.forged[len(c.forged)-forgedRing:])
	}
	p.rmu.Unlock()
	p.logLimited(ctx, slog.LevelWarn, "forged_seen/"+cell, "forged_seen", "cell", cell, "peeked_id", peeked, "op_id", res.OpID)
}

// noteItem counts an item outcome and keeps the last refusal of its cell.
func (p *Plane) noteItem(ctx context.Context, it mgmtapi.ReportItem, o mgmtapi.ItemOutcome) mgmtapi.ItemOutcome {
	kind := it.Kind
	if !slices.Contains([]string{kindResult, kindStatus, kindBind}, kind) {
		kind = "unknown"
	}
	p.reportItems.Add(ctx, 1, metric.WithAttributes(
		attribute.String("kind", kind), attribute.String("outcome", o.Outcome),
		attribute.String("reason", o.Reason), attribute.String("detail", o.Detail)))
	if o.Outcome == mgmtapi.OutcomeRefused {
		if _, ok := p.intent[it.Cell]; ok {
			p.rmu.Lock()
			p.rt.cell(it.Cell).refusal = &ItemRefusal{Kind: kind, Reason: o.Reason, Detail: o.Detail, At: p.cfg.Now()}
			p.rmu.Unlock()
		}
		p.logLimited(ctx, slog.LevelInfo, "report_refused/"+kind+"/"+o.Reason+"/"+o.Detail, "report_refused",
			"kind", kind, "reason", o.Reason, "detail", o.Detail)
	}
	return o
}
