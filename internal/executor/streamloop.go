package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
)

type execOutcome struct {
	res     op.Result
	leaseID string
}

// loop serves one open stream. It runs in one goroutine and writes every frame itself. A reader
// goroutine passes the frames in, and an executor goroutine passes the result of each lease.
type loop struct {
	cfg StreamConfig
	ctx context.Context
	// parent outlives the stream: a lease that runs when the stream ends still finishes.
	parent context.Context
	w      io.Writer
	wg     sync.WaitGroup
	exec   chan execOutcome

	frames  chan gwapi.Frame
	readErr chan error

	executing, claimInFlight, wantClaim bool
	nextClaimOK, claimAt, statusAt      time.Time
	resendAt, pingAt, pongDue           time.Time
	ackDue                              []time.Time
	claimDue                            time.Time
	lastForged                          time.Time
	// held holds the operations whose result the management plane refused in this stream. The
	// periodic resend skips them, and the next stream sends them again.
	held map[string]struct{}
	// resendMore is true while a burst of resends left results unsent. The next burst starts when
	// the acks of the sent items are in.
	resendMore bool
}

func newLoop(cfg StreamConfig, ctx context.Context, w io.Writer, dec *gwapi.Decoder) *loop {
	l := &loop{cfg: cfg, ctx: ctx, w: w, exec: make(chan execOutcome, 1),
		frames: make(chan gwapi.Frame), readErr: make(chan error, 1), held: map[string]struct{}{}}
	now := cfg.Now()
	l.wantClaim = true
	l.claimAt = now.Add(cfg.ClaimEvery)
	// The deadline of the last stream carries over. A new stream sends a status at once when that deadline has passed.
	if l.statusAt = cfg.status.get(); l.statusAt.IsZero() {
		l.statusAt = now.Add(cfg.statusWait())
		cfg.status.set(l.statusAt)
	}
	l.resendAt = now // a new stream sends every result that is still unreported
	l.pingAt = now.Add(cfg.pingEvery)
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		for {
			f, err := dec.Decode()
			if err != nil {
				l.readErr <- err
				return
			}
			select {
			case l.frames <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	return l
}

func (c StreamConfig) statusWait() time.Duration {
	return time.Duration(float64(c.StatusEvery) * (1 - statusSpread + 2*statusSpread*c.Rand()))
}

// finish waits for the goroutines of the loop. The stream must be closed first.
func (l *loop) finish() {
	if l.executing {
		<-l.exec
		l.executing = false
	}
	l.wg.Wait()
}

func (l *loop) send(f gwapi.Frame) error {
	if err := gwapi.Encode(l.w, f); err != nil {
		return fmt.Errorf("write a %s frame: %w", f.Type, err)
	}
	return nil
}

func (l *loop) run(parent context.Context) error {
	l.parent = parent
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		if err := l.fire(l.cfg.Now()); err != nil {
			return err
		}
		timer.Reset(max(0, l.next().Sub(l.cfg.Now())))
		select {
		case <-parent.Done():
			return parent.Err()
		case <-l.cfg.SVIDUpdates:
			return errSVIDUpdate
		case err := <-l.readErr:
			return fmt.Errorf("read the stream: %w", err)
		case f := <-l.frames:
			if err := l.handle(f); err != nil {
				return err
			}
		case o := <-l.exec:
			l.executing, l.claimInFlight = false, false
			l.wantClaim = op.IsFinal(o.res.Outcome)
			if err := l.reportLease(o); err != nil {
				return err
			}
		case <-timer.C:
		}
	}
}

// next returns the time of the earliest event.
func (l *loop) next() time.Time {
	t := l.claimAt
	for _, c := range []time.Time{l.statusAt, l.resendAt, l.pingAt, l.pongDue} {
		if !c.IsZero() && c.Before(t) {
			t = c
		}
	}
	if !l.claimDue.IsZero() && l.claimDue.Before(t) {
		t = l.claimDue
	}
	if len(l.ackDue) > 0 && l.ackDue[0].Before(t) {
		t = l.ackDue[0]
	}
	if l.wantClaim && !l.claimInFlight && l.nextClaimOK.Before(t) {
		t = l.nextClaimOK
	}
	return t
}

func (l *loop) fire(now time.Time) error {
	c := l.cfg
	if !now.Before(l.claimAt) {
		l.wantClaim, l.claimAt = true, now.Add(c.ClaimEvery)
	}
	if l.wantClaim && !l.claimInFlight && !now.Before(l.nextClaimOK) {
		if err := l.send(gwapi.Frame{Type: gwapi.TypeClaim}); err != nil {
			return err
		}
		l.wantClaim, l.claimInFlight = false, true
		l.claimDue = now.Add(c.AckTimeout)
		l.nextClaimOK = now.Add(time.Duration(float64(time.Second) / c.ClaimsPerSecond))
	}
	if !now.Before(l.statusAt) {
		l.statusAt = now.Add(c.statusWait())
		c.status.set(l.statusAt)
		if err := l.sendStatus(); err != nil {
			return err
		}
	}
	if !now.Before(l.resendAt) {
		l.resendAt = now.Add(c.ResendEvery)
		if err := l.resendPending(""); err != nil {
			return err
		}
	}
	if !now.Before(l.pingAt) {
		l.pingAt = now.Add(c.pingEvery)
		if err := l.send(gwapi.Frame{Type: gwapi.TypePing}); err != nil {
			return err
		}
		if l.pongDue.IsZero() {
			l.pongDue = now.Add(c.PongTimeout)
		}
	}
	switch {
	case !l.pongDue.IsZero() && !now.Before(l.pongDue):
		return errors.New("no pong from the gateway")
	case !l.claimDue.IsZero() && !now.Before(l.claimDue):
		return errors.New("no answer to a claim from the gateway")
	case len(l.ackDue) > 0 && !now.Before(l.ackDue[0]):
		return errors.New("no ack from the gateway")
	}
	return nil
}

func (l *loop) handle(f gwapi.Frame) error {
	c := l.cfg
	switch f.Type {
	case gwapi.TypeLease:
		if !l.claimInFlight || l.executing {
			c.Log.WarnContext(l.ctx, "lease without a claim", "lease_id", f.LeaseID)
			return nil
		}
		l.claimDue = time.Time{}
		if len(f.Envelope) == 0 {
			l.claimInFlight = false
			return nil
		}
		l.executing = true
		ectx := c.EffectCtx
		if ectx == nil {
			ectx = l.parent
		}
		go func() { l.exec <- execOutcome{res: c.Exec.Execute(ectx, f.Envelope, f.Fence), leaseID: f.LeaseID} }()
	case gwapi.TypeNone:
		l.claimInFlight = false
		l.claimDue = time.Time{}
	case gwapi.TypeWork:
		l.wantClaim = true
	case gwapi.TypeAck:
		if len(l.ackDue) > 0 {
			l.ackDue = l.ackDue[1:]
		}
		if l.resendMore && len(l.ackDue) == 0 {
			l.resendMore, l.resendAt = false, l.cfg.Now()
		}
	case gwapi.TypePong:
		l.pongDue = time.Time{}
	case gwapi.TypePing:
		return l.send(gwapi.Frame{Type: gwapi.TypePong})
	case gwapi.TypeFinal:
		l.handleFinal(f)
	case gwapi.TypeRetry:
		return l.resendPending(f.OpID)
	case gwapi.TypeRefused:
		// A refusal for overload answers one item. Every other reason ends the stream.
		if f.Reason == gwapi.ReasonOverloaded {
			if len(l.ackDue) > 0 {
				l.ackDue = l.ackDue[1:]
			}
			c.Log.WarnContext(l.ctx, "the gateway refused an item as overloaded")
			return nil
		}
		return fmt.Errorf("the gateway refused the stream: %s", f.Reason)
	}
	return nil
}

// handleFinal ends the record of an operation when the management plane has a final verdict for it:
// it took the result, already had it, or does not know the operation. Any other verdict leaves the
// record applied, so the next stream sends the result again.
func (l *loop) handleFinal(f gwapi.Frame) {
	c := l.cfg
	switch f.Outcome {
	case mgmtapi.OutcomeAccepted, mgmtapi.OutcomeDuplicate, mgmtapi.OutcomeUnknownOp:
	default:
		if _, again := l.held[f.OpID]; !again {
			l.held[f.OpID] = struct{}{}
			c.Log.WarnContext(l.ctx, "the management plane did not take a result; it stays applied",
				"op_id", f.OpID, "outcome", f.Outcome)
		}
		return
	}
	kctx, cancel := context.WithTimeout(l.ctx, kubeTimeout)
	err := c.Exec.MarkReported(kctx, f.OpID)
	cancel()
	if err != nil && !apierrors.IsNotFound(err) {
		c.Log.WarnContext(l.ctx, "mark reported failed", "op_id", f.OpID, "error", err.Error())
	}
	c.resent.forget(f.OpID)
}

// reportLease sends the result of a lease when it is final. A local outcome stays in the log. At most
// one result with an empty operation ID goes up in forgedEvery, because a forged envelope can come
// any number of times and the executor already counts each one in ForgedSeen.
func (l *loop) reportLease(o execOutcome) error {
	res := o.res
	if !op.IsFinal(res.Outcome) {
		l.cfg.Log.WarnContext(l.ctx, "local outcome stays here", "op_id", res.OpID, "outcome", res.Outcome, "reason", res.Reason)
		return nil
	}
	if res.OpID == "" {
		now := l.cfg.Now()
		if !l.lastForged.IsZero() && now.Sub(l.lastForged) < forgedEvery {
			return nil
		}
		l.lastForged = now
	}
	return l.sendResult(res, o.leaseID)
}

// sendResult sends one result item with a new token. A failed token request is only logged, and
// the next resend tries again. A failed write ends the stream.
func (l *loop) sendResult(res op.Result, leaseID string) error {
	body, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return l.sendItem(gwapi.TypeResult, gwapi.KindResult, res.OpID, body, leaseID, res.Fence)
}

func (l *loop) sendItem(typ, kind, opID string, body []byte, leaseID string, fe op.Fence) error {
	c := l.cfg
	token, err := c.Tokens(l.ctx, proof.ReportAudience(c.Cell, kind, body))
	if err != nil {
		c.Log.WarnContext(l.ctx, "mint a report token failed", "kind", kind, "error", err.Error())
		return nil
	}
	err = l.send(gwapi.Frame{Type: typ, LeaseID: leaseID, Fence: fe,
		Item: &gwapi.Item{Kind: kind, Cell: c.Cell, OpID: opID, Body: body, Token: token}})
	if err == nil {
		l.ackDue = append(l.ackDue, c.Now().Add(c.AckTimeout))
	}
	return err
}

func (l *loop) sendStatus() error {
	body, err := json.Marshal(l.cfg.Status())
	if err != nil {
		return err
	}
	return l.sendItem(gwapi.TypeStatus, gwapi.KindStatus, "", body, "", op.Fence{})
}

// resendPending sends again each unreported result, or only the one for opID when it is not empty.
// An op goes up again at most once in minResendGap. One call sends at most maxResendBurst results,
// so that the loop reads its frames in time. The rest follow when the acks of the burst are in.
func (l *loop) resendPending(opID string) error {
	ctx, cancel := context.WithTimeout(l.ctx, kubeTimeout)
	pending, err := l.cfg.Exec.Pending(ctx)
	cancel()
	if err != nil {
		l.cfg.Log.WarnContext(l.ctx, "read the pending results failed", "error", err.Error())
		return nil
	}
	found, sent := false, 0
	for _, res := range pending {
		if opID != "" && res.OpID != opID {
			continue
		}
		if _, held := l.held[res.OpID]; held && opID == "" {
			continue
		}
		found = true
		if sent >= maxResendBurst {
			l.resendMore = true
			break
		}
		if !l.cfg.resent.allow(res.OpID, l.cfg.Now()) {
			continue
		}
		if err := l.sendResult(res, ""); err != nil {
			return err
		}
		sent++
	}
	if opID != "" && !found {
		l.cfg.Log.InfoContext(l.ctx, "retry without a pending result", "op_id", opID)
	}
	return nil
}
