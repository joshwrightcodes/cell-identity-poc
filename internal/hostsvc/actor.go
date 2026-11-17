package hostsvc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

// Errors of the actor.
var (
	// ErrQueueFull means QueueCap steps already wait.
	ErrQueueFull = errors.New("step queue is full")
	// ErrConflict means the journal holds a step with this ID and other content.
	ErrConflict = errors.New("step conflicts with the journal")
	// ErrNotFound means a cancel matched no open step.
	ErrNotFound = errors.New("no open step matches")
	// ErrSpecBehind means a re-signed envelope arrived before the spec that indexes it.
	ErrSpecBehind = errors.New("spec does not index the step yet")
)

// Defaults of ActorConfig.
const (
	DefaultMaxAttempts = 3
	DefaultQueueCap    = 8
	DefaultRetryAfter  = 5 * time.Minute
	DefaultKillAfter   = 10 * time.Second
	DefaultHeartbeat   = 30 * time.Second
	// resignHold is how long the actor waits for the re-signed envelope of a step.
	resignHold = 10 * time.Minute
)

// Attempt tells a stage which run it is. N counts the attempts of the step, from 1. StageRuns
// counts every start of this stage, including a start that ended with interrupted.
type Attempt struct{ N, StageRuns int }

// Stage is one stage of a step. Command returns the argv. Cluster returns the value of CELL, and
// nil means the cell of the step.
type Stage struct {
	Name    string
	Timeout time.Duration
	Command func(s step.Step, attempt Attempt) []string
	Cluster func(s step.Step) string
}

// ActorConfig configures an Actor. Zero numbers take the Default constants.
type ActorConfig struct {
	Journal  *Journal
	Verifier *StepVerifier
	Spec     *SpecStore
	Stages   []Stage
	// Start runs one stage. The output of the group goes to log.
	Start func(argv []string, env []string, log io.Writer) (*Group, error)
	// Env is the base environment of a child. Nil means the environment of this process.
	Env []string
	// NodeIP returns the IPv4 address of the control-plane node of a cell. When it is set, the
	// actor reads it after creating ends with success and records it in the step status.
	NodeIP func(cell string) (string, error)

	MaxAttempts, QueueCap            int
	RetryAfter, KillAfter, Heartbeat time.Duration
	Now                              func() time.Time
	Log                              *slog.Logger
	Meter                            metric.Meter
}

// Selector picks open steps for Cancel by cell or by ID.
type Selector struct{ Cell, ID string }

type runState struct {
	id     string
	cancel chan struct{}
	once   sync.Once
}

func (r *runState) stop() { r.once.Do(func() { close(r.cancel) }) }

// Actor runs the stages of verified steps one step at a time and keeps their state in a Journal.
type Actor struct {
	cfg    ActorConfig
	specCh <-chan spec.Spec
	wake   chan struct{}
	steps  metric.Int64Counter

	mu       sync.Mutex
	cur      *runState
	writeErr string // the last journal write error that was logged, empty after a success
}

// Back-off of Run after a step that made no progress because the journal could not be written.
// Tests shorten the minimum.
var (
	writeBackoffMin = time.Second
	writeBackoffMax = 30 * time.Second
)

// rootCause is the text of the innermost error, so that two failures of the same kind in different
// temporary files count as one outcome.
func rootCause(err error) string {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err.Error()
		}
		err = next
	}
}

// ResetJournal clears the journal under the lock that every actor write takes.
func (a *Actor) ResetJournal() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Journal.Reset()
}

// NewActor checks cfg, subscribes to the spec store and returns an Actor. Entries that the journal
// holds in queued run first, in order. An entry in a running state with no recorded group is marked
// failed with detail interrupted, because no stage can still run for it.
func NewActor(cfg ActorConfig) (*Actor, error) {
	switch {
	case cfg.Journal == nil || cfg.Verifier == nil || cfg.Spec == nil:
		return nil, errors.New("actor needs a journal, a verifier and a spec store")
	case len(cfg.Stages) == 0:
		return nil, errors.New("actor needs stages")
	case cfg.Start == nil:
		return nil, errors.New("actor needs a start function")
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.QueueCap <= 0 {
		cfg.QueueCap = DefaultQueueCap
	}
	if cfg.RetryAfter <= 0 {
		cfg.RetryAfter = DefaultRetryAfter
	}
	if cfg.KillAfter <= 0 {
		cfg.KillAfter = DefaultKillAfter
	}
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = DefaultHeartbeat
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Meter == nil {
		cfg.Meter = metricnoop.NewMeterProvider().Meter("hostsvc")
	}
	steps, err := cfg.Meter.Int64Counter("hostsvc.steps", metric.WithDescription("Step state changes by state."))
	if err != nil {
		return nil, err
	}
	a := &Actor{cfg: cfg, specCh: cfg.Spec.Subscribe(), wake: make(chan struct{}, 1), steps: steps}
	for _, e := range cfg.Journal.List() {
		if e.Running() && e.Pgid == 0 {
			a.update(e.Status.ID, func(e *JournalEntry) { a.setFailed(e, e.Status.Stage, step.DetailInterrupted, false) })
		}
	}
	a.signal()
	return a, nil
}

func (a *Actor) signal() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *Actor) now() time.Time { return a.cfg.Now() }

// Journal returns the journal of the actor.
func (a *Actor) Journal() *Journal { return a.cfg.Journal }

func envelopeDigest(envelope []byte) string {
	sum := sha256.Sum256(envelope)
	return hex.EncodeToString(sum[:])
}

// envelopePayload returns the signed payload of a DSSE envelope without checking the signature.
// Use it only on an envelope that this host verified before it wrote it to the journal.
func envelopePayload(envelope string) ([]byte, error) {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(envelope), &env); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(env.Payload)
}

// decodeStep reads the step of a journal envelope without checking the signature.
func decodeStep(envelope string) (step.Step, string, error) {
	payload, err := envelopePayload(envelope)
	if err != nil {
		return step.Step{}, "", err
	}
	var s step.Step
	if err := json.Unmarshal(payload, &s); err != nil {
		return step.Step{}, "", err
	}
	return s, step.PayloadSHA256(payload), nil
}

// update applies f to the entry of step id under the actor lock, and counts a change of state.
func (a *Actor) update(id string, f func(*JournalEntry)) (JournalEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.updateLocked(id, f)
}

func (a *Actor) updateLocked(id string, f func(*JournalEntry)) (JournalEntry, bool) {
	var before string
	e, ok, err := a.cfg.Journal.Update(id, func(e *JournalEntry) {
		before = e.Status.State
		f(e)
		e.Status.UpdatedAt = a.now()
	})
	switch {
	case err != nil && rootCause(err) != a.writeErr:
		a.writeErr = rootCause(err)
		a.cfg.Log.Error("journal_write_failed", "step", id, "error", err.Error())
	case err == nil && a.writeErr != "":
		a.writeErr = ""
		a.cfg.Log.Info("journal_write_recovered", "step", id)
	}
	if ok && err == nil && e.Status.State != before {
		a.steps.Add(context.Background(), 1, metric.WithAttributes(attribute.String("state", e.Status.State)))
	}
	return e, ok && err == nil
}

// Status returns the status of step id.
func (a *Actor) Status(id string) (mgmtapi.StepStatus, bool) {
	e, ok := a.cfg.Journal.Get(id)
	return e.Status, ok
}

// Statuses returns the status of every step in the journal.
func (a *Actor) Statuses() []mgmtapi.StepStatus {
	var out []mgmtapi.StepStatus
	for _, e := range a.cfg.Journal.List() {
		out = append(out, e.Status)
	}
	return out
}

// Submit stores a step that the verifier accepted, and queues it. A step with a known ID changes
// the journal only as follows. The same envelope returns the status, and a failed step whose
// RetryAt has passed queues again at its failed stage. The same step under a higher key epoch
// replaces the envelope of a queued, running or failed step and keeps its stage, attempts, RetryAt
// and group. A lower epoch returns the status. Other content, or another envelope under the same
// epoch, is ErrConflict.
func (a *Actor) Submit(envelope []byte, s step.Step) (mgmtapi.StepStatus, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	j := a.cfg.Journal
	if j.Corrupt() {
		return mgmtapi.StepStatus{}, ErrJournalCorrupt
	}
	sha := envelopeDigest(envelope)
	if e, ok := j.Get(s.ID); ok {
		return a.resubmitLocked(e, envelope, sha, s)
	}
	queued := 0
	for _, e := range j.List() {
		if e.Status.State == mgmtapi.StepQueued {
			queued++
		}
	}
	if queued >= a.cfg.QueueCap {
		return mgmtapi.StepStatus{}, ErrQueueFull
	}
	var rev spec.Revision
	if sp, ok := a.cfg.Spec.Current(); ok {
		rev = sp.Revision
	}
	e := JournalEntry{
		Status:         mgmtapi.StepStatus{ID: s.ID, Cell: s.Cell, State: mgmtapi.StepQueued, UpdatedAt: a.now()},
		EnvelopeSHA256: sha, KeyEpoch: s.KeyEpoch, Envelope: string(envelope), IssuedAt: s.IssuedAt, IndexedIn: rev,
	}
	if err := j.Put(e); err != nil {
		return mgmtapi.StepStatus{}, err
	}
	a.steps.Add(context.Background(), 1, metric.WithAttributes(attribute.String("state", mgmtapi.StepQueued)))
	j.Evict(a.indexedByNewest)
	a.signal()
	return e.Status, nil
}

func (a *Actor) indexedByNewest(id string) bool {
	_, ok := a.cfg.Spec.IndexedDigest(id)
	return ok
}

func (a *Actor) resubmitLocked(e JournalEntry, envelope []byte, sha string, s step.Step) (mgmtapi.StepStatus, error) {
	if e.EnvelopeSHA256 == sha {
		if e.Status.State == mgmtapi.StepFailed && !a.now().Before(e.Status.RetryAt) && e.Status.Attempts < a.cfg.MaxAttempts {
			e2, _ := a.updateLocked(s.ID, func(e *JournalEntry) { e.Status.State = mgmtapi.StepQueued })
			a.signal()
			return e2.Status, nil
		}
		return e.Status, nil
	}
	old, _, err := decodeStep(e.Envelope)
	if err != nil || !step.SameExceptEpoch(old, s) || s.KeyEpoch == e.KeyEpoch {
		return mgmtapi.StepStatus{}, ErrConflict
	}
	if s.KeyEpoch < e.KeyEpoch || e.Final() {
		return e.Status, nil
	}
	e2, _ := a.updateLocked(s.ID, func(e *JournalEntry) {
		e.EnvelopeSHA256, e.KeyEpoch, e.Envelope = sha, s.KeyEpoch, string(envelope)
		e.ResignSince = time.Time{}
	})
	a.cfg.Log.Info("step_resigned", "step", s.ID, "cell", s.Cell, "key_epoch", s.KeyEpoch)
	a.signal()
	return e2.Status, nil
}

// Door answers a PUT that the spec index refuses because the index holds another digest for the
// ID. It returns handled false when the journal has no such step. When the journal envelope is the
// indexed one and the PUT is the same step under a higher key epoch, it returns ErrSpecBehind and
// changes nothing. The same envelope, or a lower epoch, returns the status. Anything else is
// ErrConflict.
func (a *Actor) Door(c Checked, envelope []byte) (st mgmtapi.StepStatus, handled bool, err error) {
	e, ok := a.cfg.Journal.Get(c.Step.ID)
	if !ok {
		return mgmtapi.StepStatus{}, false, nil
	}
	if e.EnvelopeSHA256 == envelopeDigest(envelope) {
		return e.Status, true, nil
	}
	old, oldSHA, err := decodeStep(e.Envelope)
	if err != nil || !step.SameExceptEpoch(old, c.Step) || c.Step.KeyEpoch == e.KeyEpoch {
		return mgmtapi.StepStatus{}, true, ErrConflict
	}
	if c.Step.KeyEpoch < e.KeyEpoch {
		return e.Status, true, nil
	}
	if d, ok := a.cfg.Spec.IndexedDigest(c.Step.ID); ok && d == oldSHA {
		return mgmtapi.StepStatus{}, true, ErrSpecBehind
	}
	return mgmtapi.StepStatus{}, false, nil
}

// Cancel ends the open steps that sel names. A queued or failed step becomes cancelled at once. A
// running step ends through a stop of its group. It returns ErrNotFound when nothing matches.
func (a *Actor) Cancel(sel Selector) error {
	if sel.Cell == "" && sel.ID == "" {
		return ErrNotFound
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.cfg.Journal.List() {
		if e.Final() || (sel.ID != "" && e.Status.ID != sel.ID) || (sel.Cell != "" && e.Status.Cell != sel.Cell) {
			continue
		}
		n++
		a.cancelLocked(e)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (a *Actor) cancelLocked(e JournalEntry) {
	if a.cur != nil && a.cur.id == e.Status.ID {
		a.cur.stop()
		return
	}
	a.updateLocked(e.Status.ID, func(e *JournalEntry) { a.setCancelled(e) })
	a.cfg.Log.Info("step_cancelled", "step", e.Status.ID, "cell", e.Status.Cell)
}

func (a *Actor) setCancelled(e *JournalEntry) {
	e.Status.State = mgmtapi.StepCancelled
	e.Status.Reason, e.Status.Detail = step.Code, step.DetailCancelled
	e.Pgid, e.LeaderStart = 0, ""
}

// setFailed ends the stage with state failed, or failed_final at the attempt limit or for a
// closed step, because no new PUT of a closed step runs. A counted failure is an attempt. RetryAt is RetryAfter after the failure, and now
// for an end that is not an attempt.
func (a *Actor) setFailed(e *JournalEntry, stage, detail string, counted bool) {
	now := a.now()
	e.Pgid, e.LeaderStart = 0, ""
	e.Status.Stage = stage
	e.Status.Reason, e.Status.Detail = step.Code, detail
	e.Status.State = mgmtapi.StepFailed
	e.Status.RetryAt = now
	if counted {
		e.Status.Attempts++
		e.Status.RetryAt = now.Add(a.cfg.RetryAfter)
	}
	if e.Closed() || (counted && e.Status.Attempts >= a.cfg.MaxAttempts) {
		e.Status.State = mgmtapi.StepFailedFinal
		e.Status.RetryAt = time.Time{}
	}
}

func (a *Actor) setFinal(e *JournalEntry, stage, detail string) {
	e.Pgid, e.LeaderStart = 0, ""
	e.Status.State = mgmtapi.StepFailedFinal
	e.Status.Stage = stage
	e.Status.Reason, e.Status.Detail = step.Code, detail
	e.Status.RetryAt = time.Time{}
}

// handleSpec applies a spec that the store accepted to every open step. A step that the spec still
// indexes keeps its place. A step that it no longer indexes is closed when the spec holds a record
// of its cell above the revision that last indexed the step, and cancelled otherwise.
func (a *Actor) handleSpec(sp spec.Spec) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.cfg.Journal.List() {
		if e.Final() {
			continue
		}
		indexed := slices.ContainsFunc(sp.Steps, func(x spec.StepEntry) bool { return x.StepID == e.Status.ID && x.Name == e.Status.Cell })
		switch {
		case indexed:
			if e.IndexedIn != sp.Revision {
				a.updateLocked(e.Status.ID, func(e *JournalEntry) { e.IndexedIn = sp.Revision })
			}
		case e.Closed():
		case recordAbove(sp, e.Status.Cell, e.IndexedIn):
			a.cfg.Log.Info("step_closed", "step", e.Status.ID, "cell", e.Status.Cell, "revision", sp.Revision)
			a.updateLocked(e.Status.ID, func(x *JournalEntry) {
				x.ClosedIn = sp.Revision
				if x.Status.State == mgmtapi.StepQueued || x.Status.State == mgmtapi.StepFailed {
					x.Status.State, x.Status.Stage, x.Status.Reason, x.Status.Detail = mgmtapi.StepDone, "", "", ""
					x.Status.RetryAt = time.Time{}
				}
			})
		default:
			a.cfg.Log.Info("step_dropped", "step", e.Status.ID, "cell", e.Status.Cell, "revision", sp.Revision)
			a.cancelLocked(e)
		}
	}
}

func recordAbove(sp spec.Spec, cell string, rev spec.Revision) bool {
	for _, c := range sp.Cells {
		if c.Name == cell {
			return c.Revision.Compare(rev) > 0
		}
	}
	return false
}

func (a *Actor) drainSpec() {
	for {
		select {
		case sp := <-a.specCh:
			a.handleSpec(sp)
		default:
			return
		}
	}
}

// Run runs steps until ctx ends. It runs one step at a time, in (issuedAt, cell) order. When ctx
// ends during a stage, it stops the group, marks the step failed with detail interrupted and
// returns after the group has exited.
func (a *Actor) Run(ctx context.Context) error {
	var backoff time.Duration
	for {
		a.drainSpec()
		if id := a.nextQueued(); id != "" {
			a.runStep(ctx, id)
			if ctx.Err() != nil {
				return nil
			}
			if e, ok := a.cfg.Journal.Get(id); ok && e.Status.State == mgmtapi.StepQueued {
				// The step made no progress, because the journal cannot be written.
				backoff = min(max(2*backoff, writeBackoffMin), writeBackoffMax)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(backoff):
				}
			} else {
				backoff = 0
			}
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case sp := <-a.specCh:
			a.handleSpec(sp)
		case <-a.wake:
		}
	}
}

func (a *Actor) nextQueued() string {
	for _, e := range a.cfg.Journal.List() {
		if e.Status.State == mgmtapi.StepQueued {
			return e.Status.ID
		}
	}
	return ""
}

func (a *Actor) stageIndex(name string) int {
	for i, s := range a.cfg.Stages {
		if s.Name == name {
			return i
		}
	}
	return 0
}

func (a *Actor) runStep(ctx context.Context, id string) {
	rs := &runState{id: id, cancel: make(chan struct{})}
	a.mu.Lock()
	a.cur = rs
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.cur = nil
		a.mu.Unlock()
	}()
	e, ok := a.cfg.Journal.Get(id)
	if !ok {
		return
	}
	for i := a.stageIndex(e.Status.Stage); i < len(a.cfg.Stages); i++ {
		stg := a.cfg.Stages[i]
		if !a.preCheck(ctx, rs, stg) {
			return
		}
		if !a.runStage(ctx, rs, stg) {
			return
		}
	}
	a.update(id, func(e *JournalEntry) {
		e.Status.State, e.Status.Stage, e.Status.Reason, e.Status.Detail = mgmtapi.StepDone, "", "", ""
		e.Status.RetryAt = time.Time{}
		e.Pgid, e.LeaderStart = 0, ""
	})
	a.cfg.Log.Info("step_done", "step", id)
	a.cfg.Journal.Evict(a.indexedByNewest)
}

// endIfStopped ends the step when it was cancelled or the actor is stopping. It returns true when
// the step has ended.
func (a *Actor) endIfStopped(ctx context.Context, rs *runState, stage string) bool {
	select {
	case <-rs.cancel:
		a.update(rs.id, func(e *JournalEntry) { a.setCancelled(e) })
		return true
	default:
	}
	if ctx.Err() != nil {
		a.update(rs.id, func(e *JournalEntry) { a.setFailed(e, stage, step.DetailInterrupted, false) })
		return true
	}
	return false
}

// preCheck runs the checks that precede each stage. It returns false when the step has ended.
func (a *Actor) preCheck(ctx context.Context, rs *runState, stg Stage) bool {
	v := a.cfg.Verifier
	var lastBeat time.Time
	for {
		a.drainSpec()
		if a.endIfStopped(ctx, rs, stg.Name) {
			return false
		}
		e, ok := a.cfg.Journal.Get(rs.id)
		if !ok || e.Final() {
			return false
		}
		if e.Closed() {
			if err := a.checkClosed(e); err != nil {
				if !isRefusal(err) {
					a.transient(rs.id, stg.Name, err)
					return false
				}
				a.update(rs.id, func(e *JournalEntry) { a.setFinal(e, stg.Name, detailOrFailed(err)) })
				a.cfg.Log.Warn("step_run_refused", "step", rs.id, "cell", e.Status.Cell, "stage", stg.Name, "detail", detailOrFailed(err))
				return false
			}
			return true
		}
		_, sha, derr := decodeStep(e.Envelope)
		if derr == nil && a.cfg.Spec.Index(e.Status.Cell, rs.id, sha) == IndexResign {
			if !a.holdForResign(ctx, rs, e, stg, &lastBeat) {
				return false
			}
			continue
		}
		if _, err := v.Check([]byte(e.Envelope), false); err != nil {
			if !isRefusal(err) {
				a.transient(rs.id, stg.Name, err)
				return false
			}
			d := detailOrFailed(err)
			a.update(rs.id, func(e *JournalEntry) { a.setFinal(e, stg.Name, d) })
			a.cfg.Log.Warn("step_run_refused", "step", rs.id, "cell", e.Status.Cell, "stage", stg.Name, "detail", d, "error", err.Error())
			return false
		}
		return true
	}
}

func isRefusal(err error) bool {
	var se *step.Error
	return errors.As(err, &se)
}

// transient ends the stage of a step whose check failed for a reason that is not a refusal, such as
// a bootstrap digest that could not be computed. The step is failed, not final, and the cell
// controller may retry it after RetryAfter. A closed step is final, because no PUT can retry it.
func (a *Actor) transient(id, stage string, err error) {
	a.cfg.Log.Warn("step_check_failed", "step", id, "stage", stage, "error", err.Error())
	a.update(id, func(e *JournalEntry) {
		a.setFailed(e, stage, step.DetailStageFailed, false)
		if e.Status.State == mgmtapi.StepFailed {
			e.Status.RetryAt = a.now().Add(a.cfg.RetryAfter)
		}
	})
}

// detailOrFailed returns the step detail of a refusal, and stage_failed for any other error.
func detailOrFailed(err error) string {
	var se *step.Error
	if errors.As(err, &se) {
		return se.Detail
	}
	return step.DetailStageFailed
}

// checkClosed runs the checks that a closed step still needs: expiry, and the bootstrap digest.
// The newest spec no longer indexes the step, and a rotation does not sign it again.
func (a *Actor) checkClosed(e JournalEntry) error {
	s, _, err := decodeStep(e.Envelope)
	if err != nil {
		return refuse(step.DetailPayloadInvalid)
	}
	if err := step.Check(s, a.cfg.Verifier.Env, a.cfg.Verifier.now()); err != nil {
		return err
	}
	d, err := a.cfg.Verifier.bootstrapDigest(false)
	if err != nil {
		return err
	}
	if d != s.BootstrapSHA256 {
		return refuse(step.DetailBootstrapMismatch)
	}
	return nil
}

// holdForResign waits for the re-signed envelope of a step that the newest spec indexes with
// another digest. It returns true when the envelope changed, and false when the step ended.
func (a *Actor) holdForResign(ctx context.Context, rs *runState, e JournalEntry, stg Stage, lastBeat *time.Time) bool {
	now := a.now()
	if e.ResignSince.IsZero() {
		e, _ = a.update(rs.id, func(x *JournalEntry) { x.ResignSince = now; x.HeartbeatAt = now })
		a.cfg.Log.Info("step_resign_wait", "step", rs.id, "cell", e.Status.Cell, "stage", stg.Name)
		*lastBeat = now
	}
	if !now.Before(e.ResignSince.Add(resignHold)) {
		a.update(rs.id, func(x *JournalEntry) { a.setFinal(x, stg.Name, step.DetailStepUnindexed) })
		a.cfg.Log.Warn("step_run_refused", "step", rs.id, "cell", e.Status.Cell, "stage", stg.Name, "detail", step.DetailStepUnindexed)
		return false
	}
	if now.Sub(*lastBeat) >= a.cfg.Heartbeat {
		a.update(rs.id, func(x *JournalEntry) { x.HeartbeatAt = now })
		*lastBeat = now
	}
	t := time.NewTimer(resignPoll)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-rs.cancel:
	case sp := <-a.specCh:
		a.handleSpec(sp)
	case <-a.wake:
	case <-t.C:
	}
	return true
}

// resignPoll is how often a held step looks at the clock and the journal. Tests shorten it.
var resignPoll = 500 * time.Millisecond

func (a *Actor) childEnv(s step.Step, cluster string) []string {
	base := a.cfg.Env
	if base == nil {
		base = os.Environ()
	}
	drop := map[string]bool{"POC_SECRET_TOKEN_CMD": true, "CELL": true, "POC_STEP_ID": true, "POC_ENVRC_LOCAL": true,
		"CLUSTER_LOCK_WAIT": true, "POC_JOURNAL_DIR": true}
	var env []string
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			env = append(env, kv)
		}
	}
	dir, err := filepath.Abs(a.cfg.Journal.Dir())
	if err != nil {
		dir = a.cfg.Journal.Dir()
	}
	return append(env, "CELL="+cluster, "POC_STEP_ID="+s.ID, "POC_ENVRC_LOCAL=/dev/null", "CLUSTER_LOCK_WAIT=900", "POC_JOURNAL_DIR="+dir)
}

// runStage runs one stage and returns true when it succeeded.
func (a *Actor) runStage(ctx context.Context, rs *runState, stg Stage) bool {
	id := rs.id
	var entry JournalEntry
	now := a.now()
	entry, ok := a.update(id, func(e *JournalEntry) {
		if e.StageRuns == nil {
			e.StageRuns = map[string]int{}
		}
		e.StageRuns[stg.Name]++
		e.Status.State, e.Status.Stage = stg.Name, stg.Name
		e.Status.Reason, e.Status.Detail = "", ""
		e.Status.RetryAt = time.Time{}
		e.HeartbeatAt, e.ResignSince = now, time.Time{}
	})
	if !ok {
		return false
	}
	st, _, err := decodeStep(entry.Envelope)
	if err != nil {
		a.update(id, func(e *JournalEntry) { a.setFinal(e, stg.Name, step.DetailPayloadInvalid) })
		return false
	}
	attempt := Attempt{N: entry.Status.Attempts + 1, StageRuns: entry.StageRuns[stg.Name]}
	cluster := st.Cell
	if stg.Cluster != nil {
		cluster = stg.Cluster(st)
	}
	logf, err := os.OpenFile(a.cfg.Journal.LogPath(id), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		err = logf.Chmod(0o600)
	}
	if err != nil {
		a.cfg.Log.Error("step_log_failed", "step", id, "error", err.Error())
		a.update(id, func(e *JournalEntry) { a.setFailed(e, stg.Name, step.DetailStageFailed, true) })
		return false
	}
	defer logf.Close()
	fmt.Fprintf(logf, "== %s attempt %d CELL=%s at %s\n", stg.Name, attempt.N, cluster, a.now().UTC().Format(time.RFC3339))
	argv := stg.Command(st, attempt)
	a.cfg.Log.Info("stage_start", "step", id, "cell", st.Cell, "stage", stg.Name, "attempt", attempt.N, "stage_runs", attempt.StageRuns)
	g, err := a.cfg.Start(argv, a.childEnv(st, cluster), logf)
	if err != nil {
		fmt.Fprintf(logf, "start failed: %v\n", err)
		a.cfg.Log.Error("stage_start_failed", "step", id, "stage", stg.Name, "error", err.Error())
		a.update(id, func(e *JournalEntry) { a.setFailed(e, stg.Name, step.DetailStageFailed, true) })
		return false
	}
	if _, ok := a.update(id, func(e *JournalEntry) { e.Pgid, e.LeaderStart = g.Pgid, g.LeaderStart }); !ok {
		g.Stop(a.cfg.KillAfter)
		_ = g.Wait()
		a.update(id, func(e *JournalEntry) { a.setFailed(e, stg.Name, step.DetailStageFailed, true) })
		return false
	}
	cause, waitErr := a.supervise(ctx, rs, g, stg)
	fmt.Fprintf(logf, "== %s ended: %s\n", stg.Name, endText(cause, waitErr))
	var detail string
	switch {
	case cause == step.DetailCancelled:
		a.update(id, func(e *JournalEntry) { a.setCancelled(e) })
		a.cfg.Log.Info("stage_cancelled", "step", id, "stage", stg.Name)
		return false
	case cause == step.DetailInterrupted:
		a.update(id, func(e *JournalEntry) { a.setFailed(e, stg.Name, step.DetailInterrupted, false) })
		a.cfg.Log.Warn("stage_interrupted", "step", id, "stage", stg.Name)
		return false
	case cause == step.DetailTimeout:
		detail = step.DetailTimeout
	case waitErr != nil:
		detail = step.DetailStageFailed
	default:
		var nodeIP string
		if stg.Name == mgmtapi.StageCreating && a.cfg.NodeIP != nil {
			ip, err := a.cfg.NodeIP(st.Cell)
			if addr, perr := netip.ParseAddr(ip); err == nil && (perr != nil || !addr.Is4() || addr.String() != ip) {
				err = fmt.Errorf("node address %q is not a canonical IPv4 address", ip)
			}
			if err != nil {
				fmt.Fprintf(logf, "node address: %v\n", err)
				a.cfg.Log.Warn("node_ip_failed", "step", id, "cell", st.Cell, "error", err.Error())
				a.update(id, func(e *JournalEntry) { a.setFailed(e, stg.Name, step.DetailStageFailed, true) })
				return false
			}
			nodeIP = ip
		}
		a.update(id, func(e *JournalEntry) {
			e.Pgid, e.LeaderStart = 0, ""
			if nodeIP != "" {
				e.Status.NodeIP = nodeIP
			}
		})
		a.cfg.Log.Info("stage_done", "step", id, "stage", stg.Name)
		return true
	}
	a.cfg.Log.Warn("stage_failed", "step", id, "stage", stg.Name, "detail", detail)
	a.update(id, func(e *JournalEntry) { a.setFailed(e, stg.Name, detail, true) })
	return false
}

func endText(cause string, err error) string {
	switch {
	case cause != "":
		return cause
	case err != nil:
		return err.Error()
	}
	return "ok"
}

// supervise waits for the group, and stops it at the stage timeout, at a cancel and when ctx ends.
// It returns the cause of a stop, empty when the group ended on its own, and the exit error.
func (a *Actor) supervise(ctx context.Context, rs *runState, g *Group, stg Stage) (string, error) {
	var timeout <-chan time.Time
	if stg.Timeout > 0 {
		t := time.NewTimer(stg.Timeout)
		defer t.Stop()
		timeout = t.C
	}
	hb := time.NewTicker(a.cfg.Heartbeat)
	defer hb.Stop()
	cancel, done := rs.cancel, ctx.Done()
	cause := ""
	stop := func(c string) {
		if cause == "" {
			cause = c
			g.Stop(a.cfg.KillAfter)
		}
	}
	for {
		select {
		case <-g.Done():
			return cause, g.Wait()
		case <-timeout:
			timeout = nil
			stop(step.DetailTimeout)
		case <-cancel:
			cancel = nil
			stop(step.DetailCancelled)
		case <-done:
			done = nil
			stop(step.DetailInterrupted)
		case <-hb.C:
			now := a.now()
			a.update(rs.id, func(e *JournalEntry) { e.HeartbeatAt = now })
		case sp := <-a.specCh:
			a.handleSpec(sp)
		}
	}
}

// DefaultStages returns the three stages of a step. creating runs `<exe> create --cluster <cell>`,
// and adds --retry-of-create from the second start of the stage. admitting runs cmd with CELL set
// to cpCluster, and bootstrapping runs cmd with CELL set to the cell.
func DefaultStages(exe string, cmd []string, cpCluster string) []Stage {
	run := func(s step.Step, _ Attempt) []string { return slices.Clone(cmd) }
	return []Stage{
		{Name: mgmtapi.StageCreating, Timeout: 10 * time.Minute, Command: func(s step.Step, a Attempt) []string {
			argv := []string{exe, "create", "--cluster", s.Cell}
			if a.StageRuns > 1 {
				argv = append(argv, "--retry-of-create")
			}
			return argv
		}},
		{Name: mgmtapi.StageAdmitting, Timeout: 30 * time.Minute, Command: run, Cluster: func(step.Step) string { return cpCluster }},
		{Name: mgmtapi.StageBootstrapping, Timeout: 45 * time.Minute, Command: run},
	}
}
