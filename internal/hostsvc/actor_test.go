package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

type cmdRec struct {
	stage   string
	cell    string
	attempt Attempt
}

// actorEnv is a stepEnv with a journal, an actor and scripted stages. Each stage runs a shell
// script that the test sets, in a real process group.
type actorEnv struct {
	*stepEnv
	work string
	j    *Journal
	a    *Actor
	logs *syncBuf

	mu       sync.Mutex
	scripts  map[string]string
	cmds     []cmdRec
	envs     [][]string
	startErr error

	cancel context.CancelFunc
	done   chan struct{}
}

func newActorEnv(t *testing.T, tweak func(*ActorConfig)) *actorEnv {
	t.Helper()
	testtool.Need(t, "sh", "sleep")
	old := resignPoll
	resignPoll = 20 * time.Millisecond
	t.Cleanup(func() { resignPoll = old })
	ae := &actorEnv{stepEnv: newStepEnv(t), work: t.TempDir(), scripts: map[string]string{}, logs: &syncBuf{}}
	j, err := OpenJournal(filepath.Join(ae.dir, "steps"), ae.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	ae.j = j
	j.SetLogger(jsonLogger(ae.logs))
	ae.a = ae.newActor(j, tweak)
	return ae
}

func (ae *actorEnv) newActor(j *Journal, tweak func(*ActorConfig)) *Actor {
	ae.t.Helper()
	mk := func(name string, timeout time.Duration) Stage {
		return Stage{Name: name, Timeout: timeout, Cluster: func(s step.Step) string {
			if name == "admitting" {
				return "dev-cp"
			}
			return s.Cell
		}, Command: func(s step.Step, a Attempt) []string {
			ae.mu.Lock()
			defer ae.mu.Unlock()
			ae.cmds = append(ae.cmds, cmdRec{stage: name, cell: s.Cell, attempt: a})
			sc, ok := ae.scripts[name]
			if !ok {
				sc = "exit 0"
			}
			return []string{"sh", "-c", sc}
		}}
	}
	cfg := ActorConfig{
		Journal: j, Verifier: ae.ver, Spec: ae.spec,
		Stages: []Stage{mk("creating", time.Minute), mk("admitting", time.Minute), mk("bootstrapping", time.Minute)},
		Start: func(argv, env []string, log io.Writer) (*Group, error) {
			ae.mu.Lock()
			err := ae.startErr
			ae.envs = append(ae.envs, env)
			ae.mu.Unlock()
			if err != nil {
				return nil, err
			}
			return StartGroup(argv, env, log)
		},
		KillAfter: 300 * time.Millisecond, Heartbeat: 40 * time.Millisecond, Now: ae.clock.Now, Log: jsonLogger(ae.logs),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	a, err := NewActor(cfg)
	if err != nil {
		ae.t.Fatal(err)
	}
	return a
}

func (ae *actorEnv) setScript(stage, script string) {
	ae.mu.Lock()
	ae.scripts[stage] = script
	ae.mu.Unlock()
}

// start runs the actor in the background until the end of the test.
func (ae *actorEnv) start() {
	ae.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ae.cancel, ae.done = cancel, make(chan struct{})
	go func() { defer close(ae.done); _ = ae.a.Run(ctx) }()
	ae.t.Cleanup(ae.stop)
}

func (ae *actorEnv) stop() {
	if ae.cancel == nil {
		return
	}
	ae.cancel()
	select {
	case <-ae.done:
	case <-time.After(15 * time.Second):
		ae.t.Error("the actor did not stop")
	}
	ae.cancel = nil
}

func (ae *actorEnv) stagesRun() []string {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	var out []string
	for _, c := range ae.cmds {
		out = append(out, c.stage)
	}
	return out
}

func (ae *actorEnv) status(id string) mgmtapi.StepStatus {
	st, _ := ae.a.Status(id)
	return st
}

func (ae *actorEnv) waitState(id string, states ...string) mgmtapi.StepStatus {
	ae.t.Helper()
	var st mgmtapi.StepStatus
	waitUntil(ae.t, fmt.Sprintf("step %s to reach %v", id[:6], states), 15*time.Second, func() bool {
		st = ae.status(id)
		for _, s := range states {
			if st.State == s {
				return true
			}
		}
		return false
	})
	return st
}

func (ae *actorEnv) submit(s step.Step, env []byte) mgmtapi.StepStatus {
	ae.t.Helper()
	st, err := ae.a.Submit(env, s)
	if err != nil {
		ae.t.Fatalf("Submit: %v", err)
	}
	return st
}

// blocker returns a script that waits until the file exists, and a function that creates the file.
func (ae *actorEnv) blocker(name string) (script string, release func()) {
	path := filepath.Join(ae.work, name)
	return `while [ ! -e ` + path + ` ]; do sleep 0.02; done`, func() {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			ae.t.Fatal(err)
		}
	}
}

func TestActorStagesInOrder(t *testing.T) {
	ae := newActorEnv(t, nil)
	order := filepath.Join(ae.work, "order")
	for _, st := range []string{"creating", "admitting", "bootstrapping"} {
		ae.setScript(st, `echo `+st+` CELL=$CELL >> `+order)
	}
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	if st := ae.submit(s, env); st.State != mgmtapi.StepQueued {
		t.Fatalf("Submit state = %s, want queued", st.State)
	}
	st := ae.waitState(s.ID, mgmtapi.StepDone)
	if !mgmtapi.ValidStepStatus(st) || st.Attempts != 0 {
		t.Errorf("final status = %+v", st)
	}
	b, _ := os.ReadFile(order)
	want := "creating CELL=dev-cell-1\nadmitting CELL=dev-cp\nbootstrapping CELL=dev-cell-1\n"
	if string(b) != want {
		t.Errorf("stage output = %q, want %q", b, want)
	}
	log, err := os.ReadFile(ae.j.LogPath(s.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"== creating attempt 1 CELL=dev-cell-1 at 2026-11-10T12:00:00Z", "== admitting attempt 1 CELL=dev-cp at ", "== bootstrapping attempt 1 CELL=dev-cell-1 at "} {
		if !strings.Contains(string(log), h) {
			t.Errorf("step log lacks the header %q:\n%s", h, log)
		}
	}
}

func TestActorOneAtATime(t *testing.T) {
	ae := newActorEnv(t, nil)
	trace := filepath.Join(ae.work, "trace")
	ae.setScript("creating", `echo start $CELL >> `+trace+`; sleep 0.25; echo end $CELL >> `+trace)
	s1, e1 := ae.newStep("dev-cell-1", nil)
	s2, e2 := ae.newStep("dev-cell-2", nil)
	ae.putSpec([]spec.StepEntry{ae.indexOf(s1, e1), ae.indexOf(s2, e2)}, nil)
	ae.submit(s2, e2)
	ae.submit(s1, e1)
	ae.start()
	ae.waitState(s1.ID, mgmtapi.StepDone)
	ae.waitState(s2.ID, mgmtapi.StepDone)
	b, _ := os.ReadFile(trace)
	want := "start dev-cell-1\nend dev-cell-1\nstart dev-cell-2\nend dev-cell-2\n"
	if string(b) != want {
		t.Errorf("creating trace = %q, want %q", b, want)
	}
}

func TestActorIdempotentSubmit(t *testing.T) {
	ae := newActorEnv(t, nil)
	s, env := ae.indexed("dev-cell-1", nil)
	first := ae.submit(s, env)
	if again := ae.submit(s, env); again.State != mgmtapi.StepQueued || again.UpdatedAt != first.UpdatedAt {
		t.Errorf("queued resubmit = %+v, want no change from %+v", again, first)
	}
	if n := len(ae.j.List()); n != 1 {
		t.Fatalf("entries after two submits = %d, want 1", n)
	}
	ae.start()
	ae.waitState(s.ID, mgmtapi.StepDone)
	ae.submit(s, env)
	ae.submit(s, env)
	time.Sleep(150 * time.Millisecond)
	if st := ae.status(s.ID); st.State != mgmtapi.StepDone {
		t.Errorf("state after resubmitting a done step = %s", st.State)
	}
	if got := ae.stagesRun(); len(got) != 3 {
		t.Errorf("stages run = %v, want one run of each stage", got)
	}
}

// putEntry stores a journal entry for a signed step in the given state, as an earlier run left it.
func (ae *actorEnv) putEntry(s step.Step, env []byte, mod func(*JournalEntry)) {
	ae.t.Helper()
	e := JournalEntry{
		Status:         mgmtapi.StepStatus{ID: s.ID, Cell: s.Cell, State: mgmtapi.StepQueued, UpdatedAt: ae.clock.Now()},
		EnvelopeSHA256: envelopeDigest(env), KeyEpoch: s.KeyEpoch, Envelope: string(env), IssuedAt: s.IssuedAt,
	}
	if mod != nil {
		mod(&e)
	}
	if err := ae.j.Put(e); err != nil {
		ae.t.Fatal(err)
	}
}

func TestActorConflict(t *testing.T) {
	resigned := func(ae *actorEnv, s step.Step, epoch uint64) (step.Step, []byte) {
		_, priv := newKey(t)
		ae.setKeys(ae.pub)
		s2 := s
		s2.KeyEpoch = epoch
		env, err := step.Sign(s2, priv)
		if err != nil {
			t.Fatal(err)
		}
		return s2, env
	}
	t.Run("same_epoch_other_bytes", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.newStep("dev-cell-1", nil)
		ae.submit(s, env)
		s2, env2 := resigned(ae, s, 1)
		if _, err := ae.a.Submit(env2, s2); !errors.Is(err, ErrConflict) {
			t.Fatalf("Submit = %v, want ErrConflict", err)
		}
		if got, _ := ae.j.Get(s.ID); got.EnvelopeSHA256 != envelopeDigest(env) {
			t.Error("the journal envelope changed")
		}
	})
	t.Run("higher_epoch_queued", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.newStep("dev-cell-1", nil)
		ae.submit(s, env)
		s2, env2 := resigned(ae, s, 2)
		st, err := ae.a.Submit(env2, s2)
		if err != nil || st.State != mgmtapi.StepQueued {
			t.Fatalf("Submit = %+v %v", st, err)
		}
		got, _ := ae.j.Get(s.ID)
		if got.EnvelopeSHA256 != envelopeDigest(env2) || got.KeyEpoch != 2 || len(ae.j.List()) != 1 {
			t.Errorf("entry after the swap = %+v", got)
		}
	})
	t.Run("higher_epoch_failed", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.newStep("dev-cell-1", nil)
		retry := ae.clock.Now().Add(5 * time.Minute)
		ae.putEntry(s, env, func(e *JournalEntry) {
			e.Status.State, e.Status.Stage, e.Status.Attempts, e.Status.RetryAt = mgmtapi.StepFailed, "admitting", 2, retry
			e.Status.Reason, e.Status.Detail = step.Code, step.DetailStageFailed
		})
		s2, env2 := resigned(ae, s, 2)
		st, err := ae.a.Submit(env2, s2)
		if err != nil {
			t.Fatal(err)
		}
		if st.State != mgmtapi.StepFailed || st.Attempts != 2 || !st.RetryAt.Equal(retry) || st.Stage != "admitting" {
			t.Errorf("status after the swap = %+v, want failed at admitting, 2 attempts, the old RetryAt", st)
		}
		if got, _ := ae.j.Get(s.ID); got.EnvelopeSHA256 != envelopeDigest(env2) {
			t.Error("the envelope was not replaced")
		}
	})
	t.Run("higher_epoch_running", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		block, release := ae.blocker("rel")
		ae.setScript("creating", block)
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		ae.waitState(s.ID, mgmtapi.StepCreating)
		waitUntil(t, "the group", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).Pgid != 0 })
		before, _ := ae.j.Get(s.ID)
		s2, env2 := resigned(ae, s, 2)
		st, err := ae.a.Submit(env2, s2)
		if err != nil || st.State != mgmtapi.StepCreating {
			t.Fatalf("Submit = %+v %v, want the running status", st, err)
		}
		after, _ := ae.j.Get(s.ID)
		if after.EnvelopeSHA256 != envelopeDigest(env2) || after.Pgid != before.Pgid || after.Pgid == 0 {
			t.Errorf("after the swap: envelope %s pgid %d (before %d)", after.EnvelopeSHA256[:8], after.Pgid, before.Pgid)
		}
		release()
		ae.waitState(s.ID, mgmtapi.StepCreating, mgmtapi.StepAdmitting, mgmtapi.StepBootstrapping, mgmtapi.StepDone, mgmtapi.StepFailedFinal)
		if n := countStage(ae.stagesRun(), "creating"); n != 1 {
			t.Errorf("creating ran %d times, want 1", n)
		}
	})
	t.Run("higher_epoch_done", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.newStep("dev-cell-1", nil)
		ae.putEntry(s, env, func(e *JournalEntry) { e.Status.State = mgmtapi.StepDone })
		s2, env2 := resigned(ae, s, 2)
		st, err := ae.a.Submit(env2, s2)
		if err != nil || st.State != mgmtapi.StepDone {
			t.Fatalf("Submit = %+v %v, want done", st, err)
		}
		if got, _ := ae.j.Get(s.ID); got.EnvelopeSHA256 != envelopeDigest(env) {
			t.Error("a done step took the new envelope")
		}
	})
	t.Run("higher_epoch_other_cell", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.newStep("dev-cell-1", nil)
		ae.submit(s, env)
		s2, env2 := resigned(ae, s, 2)
		s2.Cell = "dev-cell-2"
		env2, _ = step.Sign(s2, ae.priv)
		if _, err := ae.a.Submit(env2, s2); !errors.Is(err, ErrConflict) {
			t.Fatalf("Submit = %v, want ErrConflict", err)
		}
	})
	t.Run("lower_epoch_after_swap", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.newStep("dev-cell-1", nil)
		ae.submit(s, env)
		s2, env2 := resigned(ae, s, 2)
		if _, err := ae.a.Submit(env2, s2); err != nil {
			t.Fatal(err)
		}
		st, err := ae.a.Submit(env, s)
		if err != nil || st.State != mgmtapi.StepQueued {
			t.Fatalf("lower epoch Submit = %+v %v, want the current status", st, err)
		}
		if got, _ := ae.j.Get(s.ID); got.EnvelopeSHA256 != envelopeDigest(env2) || got.KeyEpoch != 2 {
			t.Error("a lower epoch replaced the newer envelope")
		}
	})
}

func countStage(stages []string, name string) int {
	n := 0
	for _, s := range stages {
		if s == name {
			n++
		}
	}
	return n
}

func TestActorRetryWaits(t *testing.T) {
	ae := newActorEnv(t, nil)
	ae.setScript("admitting", "exit 1")
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	st := ae.waitState(s.ID, mgmtapi.StepFailed)
	if st.Attempts != 1 || st.Stage != "admitting" || st.Detail != step.DetailStageFailed || !st.RetryAt.Equal(ae.clock.Now().Add(5*time.Minute)) {
		t.Fatalf("failed status = %+v", st)
	}
	runs := len(ae.stagesRun())
	ae.clock.Advance(4*time.Minute + 59*time.Second)
	if again := ae.submit(s, env); again.State != mgmtapi.StepFailed {
		t.Errorf("resubmit before RetryAt = %s, want failed", again.State)
	}
	time.Sleep(150 * time.Millisecond)
	if got := len(ae.stagesRun()); got != runs {
		t.Errorf("a resubmit before RetryAt ran %d more stages", got-runs)
	}
	ae.clock.Advance(2 * time.Second)
	ae.setScript("admitting", "exit 0")
	if again := ae.submit(s, env); again.State != mgmtapi.StepQueued {
		t.Errorf("resubmit after RetryAt = %s, want queued", again.State)
	}
	ae.waitState(s.ID, mgmtapi.StepDone)
}

func TestActorRetryResumesFailedStage(t *testing.T) {
	ae := newActorEnv(t, nil)
	ae.setScript("admitting", "exit 1")
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepFailed)
	ae.clock.Advance(6 * time.Minute)
	ae.setScript("admitting", "exit 0")
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepDone)
	got := ae.stagesRun()
	want := []string{"creating", "admitting", "admitting", "bootstrapping"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("stages run = %v, want %v: the retry starts at the failed stage", got, want)
	}
	ae.mu.Lock()
	defer ae.mu.Unlock()
	if c := ae.cmds[2]; c.attempt.N != 2 || c.attempt.StageRuns != 2 {
		t.Errorf("retry attempt = %+v, want N 2 and StageRuns 2", c.attempt)
	}
}

func TestActorRetryLimit(t *testing.T) {
	ae := newActorEnv(t, nil)
	ae.setScript("creating", "exit 1")
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	for n := 1; n <= 3; n++ {
		st := ae.waitState(s.ID, mgmtapi.StepFailed, mgmtapi.StepFailedFinal)
		if st.Attempts != n {
			t.Fatalf("after attempt %d: attempts = %d (state %s)", n, st.Attempts, st.State)
		}
		if n < 3 {
			if st.State != mgmtapi.StepFailed {
				t.Fatalf("after attempt %d: state = %s, want failed", n, st.State)
			}
			ae.clock.Advance(6 * time.Minute)
			ae.submit(s, env)
			waitUntil(t, "the retry to start", 5*time.Second, func() bool { return ae.status(s.ID).State != mgmtapi.StepFailed })
		}
	}
	st := ae.status(s.ID)
	if st.State != mgmtapi.StepFailedFinal || st.Attempts != 3 || st.Detail != step.DetailStageFailed {
		t.Fatalf("after three attempts: %+v, want failed_final with 3 attempts", st)
	}
	ae.clock.Advance(time.Hour)
	ae.submit(s, env)
	time.Sleep(100 * time.Millisecond)
	if got := countStage(ae.stagesRun(), "creating"); got != 3 {
		t.Errorf("creating ran %d times, want 3", got)
	}
}

func TestActorQueueCap(t *testing.T) {
	ae := newActorEnv(t, func(c *ActorConfig) { c.QueueCap = 2 })
	var steps []step.Step
	var envs [][]byte
	for _, c := range []string{"dev-cell-1", "dev-cell-2", "dev-cell-3"} {
		s, env := ae.newStep(c, nil)
		steps, envs = append(steps, s), append(envs, env)
	}
	ae.submit(steps[0], envs[0])
	ae.submit(steps[1], envs[1])
	if _, err := ae.a.Submit(envs[2], steps[2]); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("third Submit = %v, want ErrQueueFull", err)
	}
	if st := ae.submit(steps[0], envs[0]); st.State != mgmtapi.StepQueued {
		t.Errorf("a known step at the cap: %+v", st)
	}
	if _, ok := ae.a.Status(steps[2].ID); ok {
		t.Error("a refused step is in the journal")
	}
}

func TestActorHeadOfLine(t *testing.T) {
	ae := newActorEnv(t, nil)
	trace := filepath.Join(ae.work, "trace")
	ae.setScript("creating", `echo $CELL >> `+trace)
	at := ae.clock.Now()
	same := func(s *step.Step) { s.IssuedAt = at }
	s2, e2 := ae.newStep("dev-cell-2", same)
	s1, e1 := ae.newStep("dev-cell-1", same)
	s3, e3 := ae.newStep("dev-cell-3", func(s *step.Step) { s.IssuedAt = at.Add(-time.Second) })
	ae.putSpec([]spec.StepEntry{ae.indexOf(s1, e1), ae.indexOf(s2, e2), ae.indexOf(s3, e3)}, nil)
	ae.submit(s2, e2)
	ae.submit(s1, e1)
	ae.submit(s3, e3)
	ae.start()
	for _, s := range []step.Step{s1, s2, s3} {
		ae.waitState(s.ID, mgmtapi.StepDone)
	}
	b, _ := os.ReadFile(trace)
	if got, want := string(b), "dev-cell-3\ndev-cell-1\ndev-cell-2\n"; got != want {
		t.Errorf("run order = %q, want %q (oldest issuedAt, then cell)", got, want)
	}
}

func TestActorRechecksBeforeRun(t *testing.T) {
	t.Run("expired_in_queue", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.indexed("dev-cell-1", func(s *step.Step) { s.ExpiresAt = s.IssuedAt.Add(step.MinTTL) })
		ae.submit(s, env)
		ae.clock.Advance(step.MinTTL + time.Second)
		ae.start()
		st := ae.waitState(s.ID, mgmtapi.StepFailedFinal)
		if st.Detail != step.DetailExpired || len(ae.stagesRun()) != 0 {
			t.Errorf("status %+v, stages run %v, want expired and none", st, ae.stagesRun())
		}
	})
	t.Run("digest_changed_in_queue", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.indexed("dev-cell-1", nil)
		ae.submit(s, env)
		ae.digest.Store(strings.Repeat("d", 64))
		ae.start()
		st := ae.waitState(s.ID, mgmtapi.StepFailedFinal)
		if st.Detail != step.DetailBootstrapMismatch || len(ae.stagesRun()) != 0 {
			t.Errorf("status %+v, stages run %v, want bootstrap_mismatch and none", st, ae.stagesRun())
		}
	})
	t.Run("unindexed_in_queue", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.newStep("dev-cell-1", nil)
		ae.submit(s, env)
		ae.clock.Advance(3 * time.Minute)
		ae.start()
		st := ae.waitState(s.ID, mgmtapi.StepFailedFinal)
		if st.Detail != step.DetailStepUnindexed || len(ae.stagesRun()) != 0 {
			t.Errorf("status %+v, stages run %v, want step_unindexed and none", st, ae.stagesRun())
		}
	})
	t.Run("signature_in_queue", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		s, env := ae.indexed("dev-cell-1", nil)
		ae.submit(s, env)
		newPub, _ := newKey(t)
		ae.setKeys(newPub)
		ae.start()
		st := ae.waitState(s.ID, mgmtapi.StepFailedFinal)
		if st.Detail != step.DetailSignatureInvalid || len(ae.stagesRun()) != 0 {
			t.Errorf("status %+v, stages run %v, want signature_invalid and none", st, ae.stagesRun())
		}
	})
}

func TestActorDigestBetweenStages(t *testing.T) {
	ae := newActorEnv(t, nil)
	block, release := ae.blocker("rel")
	ae.setScript("creating", block)
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepCreating)
	ae.digest.Store(strings.Repeat("e", 64))
	release()
	st := ae.waitState(s.ID, mgmtapi.StepFailedFinal)
	if st.Detail != step.DetailBootstrapMismatch || st.Stage != "admitting" {
		t.Errorf("status = %+v, want bootstrap_mismatch before admitting", st)
	}
	if got := ae.stagesRun(); strings.Join(got, ",") != "creating" {
		t.Errorf("stages run = %v, want creating only", got)
	}
}

// rotated returns the step as a later key epoch signs it under another key.
func (ae *actorEnv) rotated(s step.Step) (step.Step, []byte) {
	ae.t.Helper()
	pub, priv := newKey(ae.t)
	ae.setKeys(ae.pub, pub)
	s2 := s
	s2.KeyEpoch++
	env, err := step.Sign(s2, priv)
	if err != nil {
		ae.t.Fatal(err)
	}
	return s2, env
}

func TestRotateWhileQueued(t *testing.T) {
	ae := newActorEnv(t, nil)
	s, env := ae.indexed("dev-cell-1", nil)
	ae.submit(s, env)
	s2, env2 := ae.rotated(s)
	ae.putSpec([]spec.StepEntry{ae.indexOf(s2, env2)}, nil)
	ae.start()
	waitUntil(t, "the hold", 5*time.Second, func() bool { return strings.Contains(ae.logs.String(), "step_resign_wait") })
	time.Sleep(100 * time.Millisecond)
	if st := ae.status(s.ID); st.State != mgmtapi.StepQueued || len(ae.stagesRun()) != 0 {
		t.Fatalf("while held: %+v, stages run %v, want queued and none", st, ae.stagesRun())
	}
	if n := strings.Count(ae.logs.String(), "step_resign_wait"); n != 1 {
		t.Errorf("step_resign_wait logged %d times, want once", n)
	}
	if _, err := ae.a.Submit(env2, s2); err != nil {
		t.Fatal(err)
	}
	st := ae.waitState(s.ID, mgmtapi.StepDone)
	if st.Attempts != 0 {
		t.Errorf("attempts = %d", st.Attempts)
	}
	if got, _ := ae.j.Get(s.ID); got.KeyEpoch != 2 {
		t.Errorf("journal key epoch = %d, want 2", got.KeyEpoch)
	}
}

func TestRotateWhileRunning(t *testing.T) {
	setup := func(t *testing.T) (*actorEnv, step.Step, step.Step, []byte, func()) {
		ae := newActorEnv(t, nil)
		block, release := ae.blocker("rel")
		ae.setScript("creating", block)
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		pgBefore := ae.waitStateEntry(s.ID, mgmtapi.StepCreating)
		_ = pgBefore
		s2, env2 := ae.rotated(s)
		ae.putSpec([]spec.StepEntry{ae.indexOf(s2, env2)}, nil)
		return ae, s, s2, env2, release
	}
	t.Run("holds_at_boundary_then_swap", func(t *testing.T) {
		ae, s, s2, env2, release := setup(t)
		// The stage keeps running after the rotation spec.
		time.Sleep(100 * time.Millisecond)
		if st := ae.status(s.ID); st.State != mgmtapi.StepCreating {
			t.Fatalf("after the rotation spec: %s, want creating", st.State)
		}
		release()
		waitUntil(t, "the hold before admitting", 5*time.Second, func() bool { return strings.Contains(ae.logs.String(), "step_resign_wait") })
		hb1 := mustEntry(t, ae.j, s.ID).HeartbeatAt
		ae.clock.Advance(time.Minute)
		waitUntil(t, "a heartbeat while held", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).HeartbeatAt.After(hb1) })
		if got := ae.stagesRun(); strings.Join(got, ",") != "creating" {
			t.Fatalf("stages run while held = %v, want creating only", got)
		}
		if n := strings.Count(ae.logs.String(), "step_resign_wait"); n != 1 {
			t.Errorf("step_resign_wait logged %d times, want once", n)
		}
		if _, err := ae.a.Submit(env2, s2); err != nil {
			t.Fatal(err)
		}
		ae.waitState(s.ID, mgmtapi.StepDone)
		if got := ae.stagesRun(); strings.Join(got, ",") != "creating,admitting,bootstrapping" {
			t.Errorf("stages run = %v", got)
		}
	})
	t.Run("hold_ends_after_10_minutes", func(t *testing.T) {
		ae, s, _, _, release := setup(t)
		release()
		waitUntil(t, "the hold", 5*time.Second, func() bool { return strings.Contains(ae.logs.String(), "step_resign_wait") })
		ae.clock.Advance(10*time.Minute + time.Second)
		st := ae.waitState(s.ID, mgmtapi.StepFailedFinal)
		if st.Detail != step.DetailStepUnindexed || st.Stage != "admitting" {
			t.Errorf("status = %+v, want step_unindexed at admitting", st)
		}
	})
	t.Run("hold_ends_on_cancel", func(t *testing.T) {
		ae, s, _, _, release := setup(t)
		release()
		waitUntil(t, "the hold", 5*time.Second, func() bool { return strings.Contains(ae.logs.String(), "step_resign_wait") })
		if err := ae.a.Cancel(Selector{ID: s.ID}); err != nil {
			t.Fatal(err)
		}
		ae.waitState(s.ID, mgmtapi.StepCancelled)
	})
}

func mustEntry(t *testing.T, j *Journal, id string) JournalEntry {
	t.Helper()
	e, ok := j.Get(id)
	if !ok {
		t.Fatalf("no entry %s", id)
	}
	return e
}

// waitStateEntry waits for a state and returns the entry.
func (ae *actorEnv) waitStateEntry(id string, states ...string) JournalEntry {
	ae.t.Helper()
	ae.waitState(id, states...)
	return mustEntry(ae.t, ae.j, id)
}

func TestJournalQueuedSurvivesRestart(t *testing.T) {
	ae := newActorEnv(t, nil)
	s1, e1 := ae.newStep("dev-cell-1", nil)
	s2, e2 := ae.newStep("dev-cell-2", nil)
	ae.putSpec([]spec.StepEntry{ae.indexOf(s1, e1), ae.indexOf(s2, e2)}, nil)
	ae.submit(s1, e1)
	ae.submit(s2, e2)
	// A new process: reopen the journal and build a new actor.
	j2, err := OpenJournal(ae.j.Dir(), ae.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	ae.j = j2
	ae.a = ae.newActor(j2, nil)
	ae.start()
	ae.waitState(s1.ID, mgmtapi.StepDone)
	ae.waitState(s2.ID, mgmtapi.StepDone)
	if got := countStage(ae.stagesRun(), "creating"); got != 2 {
		t.Errorf("creating ran %d times, want 2", got)
	}
}

func TestSpecDropCancelsQueued(t *testing.T) {
	ae := newActorEnv(t, nil)
	block, release := ae.blocker("rel")
	ae.setScript("creating", block)
	s1, e1 := ae.newStep("dev-cell-1", nil)
	s2, e2 := ae.newStep("dev-cell-2", nil)
	ae.putSpec([]spec.StepEntry{ae.indexOf(s1, e1), ae.indexOf(s2, e2)}, nil)
	ae.start()
	ae.submit(s1, e1)
	ae.submit(s2, e2)
	ae.waitState(s1.ID, mgmtapi.StepCreating)
	if st := ae.status(s2.ID); st.State != mgmtapi.StepQueued {
		t.Fatalf("second step = %s, want queued", st.State)
	}
	ae.putSpec([]spec.StepEntry{ae.indexOf(s1, e1)}, nil)
	ae.waitState(s2.ID, mgmtapi.StepCancelled)
	if st := ae.status(s1.ID); st.State != mgmtapi.StepCreating {
		t.Errorf("the still indexed step = %s, want creating", st.State)
	}
	release()
	ae.waitState(s1.ID, mgmtapi.StepDone)
	if n := countStage(ae.stagesRun(), "creating"); n != 1 {
		t.Errorf("creating ran %d times, want 1: the cancelled step must not run", n)
	}
}

func TestSpecDropCancelsRunning(t *testing.T) {
	ae := newActorEnv(t, nil)
	pidFile := filepath.Join(ae.work, "sleep.pid")
	ae.setScript("creating", `trap "" TERM; sleep 600 & echo $! > `+pidFile+`; wait`)
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	sleeper := readPid(t, pidFile)
	e := mustEntry(t, ae.j, s.ID)
	ae.putSpec(nil, nil)
	st := ae.waitState(s.ID, mgmtapi.StepCancelled)
	if st.Detail != step.DetailCancelled {
		t.Errorf("status = %+v", st)
	}
	waitUntil(t, "the group to be gone", 12*time.Second, func() bool { return pidGone(sleeper) && !groupAlive(e.Pgid) })
	if got := countStage(ae.stagesRun(), "admitting"); got != 0 {
		t.Errorf("admitting ran after the cancel")
	}
}

func TestSpecDropCancelsFailed(t *testing.T) {
	ae := newActorEnv(t, nil)
	ae.setScript("admitting", "exit 1")
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepFailed)
	ae.putSpec(nil, nil)
	st := ae.waitState(s.ID, mgmtapi.StepCancelled)
	if st.Detail != step.DetailCancelled || st.Attempts != 1 {
		t.Errorf("status = %+v, want cancelled and the attempt kept", st)
	}
}

func TestSpecDropClosedStepKeepsRunning(t *testing.T) {
	// closeSpec drops the step and holds a record of its cell above the revision that indexed it.
	closeSpec := func(ae *actorEnv) {
		ae.putSpec(nil, map[string]uint64{"dev-cell-1": ae.rev + 5})
	}
	t.Run("closed_running_finishes", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		block, release := ae.blocker("rel")
		ae.setScript("creating", block)
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		ae.waitState(s.ID, mgmtapi.StepCreating)
		closeSpec(ae)
		waitUntil(t, "the step to be closed", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).Closed() })
		if st := ae.status(s.ID); st.State != mgmtapi.StepCreating {
			t.Fatalf("after the close: %s, want creating", st.State)
		}
		release()
		ae.waitState(s.ID, mgmtapi.StepDone)
		if got := strings.Join(ae.stagesRun(), ","); got != "creating,admitting,bootstrapping" {
			t.Errorf("stages run = %s: a closed step finishes its stage set", got)
		}
	})
	t.Run("closed_queued_done", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		block, release := ae.blocker("rel")
		ae.setScript("creating", block)
		s1, e1 := ae.newStep("dev-cell-2", nil)
		s2, e2 := ae.newStep("dev-cell-1", func(s *step.Step) { s.IssuedAt = s.IssuedAt.Add(time.Second) })
		ae.putSpec([]spec.StepEntry{ae.indexOf(s2, e2), ae.indexOf(s1, e1)}, nil)
		ae.start()
		ae.submit(s1, e1)
		ae.submit(s2, e2)
		ae.waitState(s1.ID, mgmtapi.StepCreating)
		ae.putSpec([]spec.StepEntry{ae.indexOf(s1, e1)}, map[string]uint64{"dev-cell-1": ae.rev + 5})
		st := ae.waitState(s2.ID, mgmtapi.StepDone)
		if st.Stage != "" || st.Detail != "" {
			t.Errorf("status = %+v, want done with no stage", st)
		}
		release()
		ae.waitState(s1.ID, mgmtapi.StepDone)
		for _, c := range ae.cmds {
			if c.cell == "dev-cell-1" {
				t.Errorf("a stage ran for the closed queued step: %+v", c)
			}
		}
	})
	t.Run("closed_stage_fails_final", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		block, release := ae.blocker("rel")
		ae.setScript("creating", block)
		ae.setScript("admitting", "exit 1")
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		ae.waitState(s.ID, mgmtapi.StepCreating)
		closeSpec(ae)
		waitUntil(t, "the close", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).Closed() })
		release()
		st := ae.waitState(s.ID, mgmtapi.StepFailedFinal, mgmtapi.StepFailed)
		if st.State != mgmtapi.StepFailedFinal || st.Stage != "admitting" || st.Detail != step.DetailStageFailed {
			t.Errorf("status = %+v, want failed_final at admitting", st)
		}
	})
	t.Run("closed_skips_index_and_signature", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		block, release := ae.blocker("rel")
		ae.setScript("creating", block)
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		ae.waitState(s.ID, mgmtapi.StepCreating)
		closeSpec(ae)
		waitUntil(t, "the close", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).Closed() })
		newPub, _ := newKey(t)
		ae.setKeys(newPub) // the old key left: a rotation does not sign a closed step again
		release()
		ae.waitState(s.ID, mgmtapi.StepDone)
	})
	t.Run("closed_expired_between_stages", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		block, release := ae.blocker("rel")
		ae.setScript("creating", block)
		s, env := ae.indexed("dev-cell-1", func(s *step.Step) { s.ExpiresAt = s.IssuedAt.Add(step.MinTTL) })
		ae.start()
		ae.submit(s, env)
		ae.waitState(s.ID, mgmtapi.StepCreating)
		closeSpec(ae)
		waitUntil(t, "the close", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).Closed() })
		ae.clock.Advance(step.MinTTL + time.Second)
		release()
		if st := ae.waitState(s.ID, mgmtapi.StepFailedFinal); st.Detail != step.DetailExpired {
			t.Errorf("status = %+v, want expired", st)
		}
	})
	t.Run("closed_digest_changed_between_stages", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		block, release := ae.blocker("rel")
		ae.setScript("creating", block)
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		ae.waitState(s.ID, mgmtapi.StepCreating)
		closeSpec(ae)
		waitUntil(t, "the close", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).Closed() })
		ae.digest.Store(strings.Repeat("f", 64))
		release()
		if st := ae.waitState(s.ID, mgmtapi.StepFailedFinal); st.Detail != step.DetailBootstrapMismatch {
			t.Errorf("status = %+v, want bootstrap_mismatch", st)
		}
	})
	t.Run("record_not_above_cancels", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		block, _ := ae.blocker("rel")
		ae.setScript("creating", block)
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		ae.waitState(s.ID, mgmtapi.StepCreating)
		// A record of the cell at the revision of the indexing spec is not above it.
		ae.putSpec(nil, map[string]uint64{"dev-cell-1": mustEntry(t, ae.j, s.ID).IndexedIn.Counter})
		ae.waitState(s.ID, mgmtapi.StepCancelled)
	})
}

func TestActorStageTimeoutKillsTrapper(t *testing.T) {
	ae := newActorEnv(t, func(c *ActorConfig) { c.Stages[0].Timeout = time.Second })
	pidFile := filepath.Join(ae.work, "sleep.pid")
	ae.setScript("creating", `trap "" TERM; sleep 600 & echo $! > `+pidFile+`; wait`)
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	sleeper := readPid(t, pidFile)
	e := mustEntry(t, ae.j, s.ID)
	st := ae.waitState(s.ID, mgmtapi.StepFailed)
	if st.Detail != step.DetailTimeout || st.Attempts != 1 || st.Stage != "creating" {
		t.Errorf("status = %+v, want failed with timeout at creating", st)
	}
	waitUntil(t, "both processes to be gone", 12*time.Second, func() bool { return pidGone(sleeper) && !groupAlive(e.Pgid) })
}

func TestActorStageEndDetails(t *testing.T) {
	check := func(t *testing.T, st mgmtapi.StepStatus, state, detail string, attempts int) {
		t.Helper()
		if st.State != state || st.Detail != detail || st.Attempts != attempts || !mgmtapi.ValidStepStatus(st) {
			t.Errorf("status = %+v (valid %v), want %s with detail %q and %d attempts", st, mgmtapi.ValidStepStatus(st), state, detail, attempts)
		}
	}
	t.Run("timeout", func(t *testing.T) {
		ae := newActorEnv(t, func(c *ActorConfig) { c.Stages[0].Timeout = 300 * time.Millisecond })
		ae.setScript("creating", "sleep 60")
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		check(t, ae.waitState(s.ID, mgmtapi.StepFailed), mgmtapi.StepFailed, step.DetailTimeout, 1)
	})
	t.Run("interrupted", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		ae.setScript("creating", "sleep 60")
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		ae.waitState(s.ID, mgmtapi.StepCreating)
		waitUntil(t, "the group", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).Pgid != 0 })
		e := mustEntry(t, ae.j, s.ID)
		ae.stop()
		check(t, ae.status(s.ID), mgmtapi.StepFailed, step.DetailInterrupted, 0)
		waitUntil(t, "the group to be gone", 5*time.Second, func() bool { return !groupAlive(e.Pgid) })
	})
	t.Run("stage_failed", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		ae.setScript("bootstrapping", "exit 7")
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		st := ae.waitState(s.ID, mgmtapi.StepFailed)
		check(t, st, mgmtapi.StepFailed, step.DetailStageFailed, 1)
		if st.Stage != "bootstrapping" {
			t.Errorf("stage = %s", st.Stage)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		ae.setScript("creating", "sleep 60")
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		ae.waitState(s.ID, mgmtapi.StepCreating)
		if err := ae.a.Cancel(Selector{Cell: "dev-cell-1"}); err != nil {
			t.Fatal(err)
		}
		check(t, ae.waitState(s.ID, mgmtapi.StepCancelled), mgmtapi.StepCancelled, step.DetailCancelled, 0)
	})
	t.Run("start_error", func(t *testing.T) {
		ae := newActorEnv(t, nil)
		ae.startErr = errors.New("no such program")
		s, env := ae.indexed("dev-cell-1", nil)
		ae.start()
		ae.submit(s, env)
		check(t, ae.waitState(s.ID, mgmtapi.StepFailed), mgmtapi.StepFailed, step.DetailStageFailed, 1)
	})
}

func TestActorChildEnv(t *testing.T) {
	base := []string{"PATH=" + os.Getenv("PATH"), "POC_SECRET_TOKEN_CMD=cat /secret", "CELL=wrong", "POC_ENVRC_LOCAL=/etc/passwd", "KEEP=1"}
	ae := newActorEnv(t, func(c *ActorConfig) { c.Env = base })
	for _, st := range []string{"creating", "admitting", "bootstrapping"} {
		ae.setScript(st, `env | sort > `+filepath.Join(ae.work, st+".env"))
	}
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepDone)
	for stage, cell := range map[string]string{"creating": "dev-cell-1", "admitting": "dev-cp", "bootstrapping": "dev-cell-1"} {
		b, err := os.ReadFile(filepath.Join(ae.work, stage+".env"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(b), "\n")
		has := func(l string) bool {
			for _, x := range lines {
				if x == l {
					return true
				}
			}
			return false
		}
		for _, want := range []string{"CELL=" + cell, "POC_STEP_ID=" + s.ID, "POC_ENVRC_LOCAL=/dev/null", "CLUSTER_LOCK_WAIT=900", "KEEP=1"} {
			if !has(want) {
				t.Errorf("%s: env lacks %s", stage, want)
			}
		}
		for _, l := range lines {
			if strings.HasPrefix(l, "POC_SECRET_TOKEN_CMD") || l == "CELL=wrong" || l == "POC_ENVRC_LOCAL=/etc/passwd" {
				t.Errorf("%s: env holds %s", stage, l)
			}
		}
		if !has("POC_JOURNAL_DIR=" + ae.j.Dir()) {
			t.Errorf("%s: env lacks POC_JOURNAL_DIR", stage)
		}
	}
}

func TestStepLogMode0600(t *testing.T) {
	ae := newActorEnv(t, nil)
	ae.setScript("creating", "echo line")
	s, env := ae.newStep("dev-cell-1", nil)
	ae.putSpec([]spec.StepEntry{ae.indexOf(s, env)}, nil)
	// A log that exists with a wider mode is narrowed.
	if err := os.WriteFile(ae.j.LogPath(s.ID), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepDone)
	fi, err := os.Stat(ae.j.LogPath(s.ID))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("step log: %v mode %v, want 0600", err, fi)
	}
	b, _ := os.ReadFile(ae.j.LogPath(s.ID))
	if !strings.HasPrefix(string(b), "old\n== creating attempt 1") || !strings.Contains(string(b), "line\n") {
		t.Errorf("log = %q, want the old text, a header and the output appended", b)
	}
}

func TestActorHeartbeat(t *testing.T) {
	ae := newActorEnv(t, nil)
	block, release := ae.blocker("rel")
	ae.setScript("creating", block)
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepCreating)
	first := mustEntry(t, ae.j, s.ID).HeartbeatAt
	ae.clock.Advance(30 * time.Second)
	waitUntil(t, "a heartbeat", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).HeartbeatAt.After(first) })
	release()
	ae.waitState(s.ID, mgmtapi.StepDone)
}

func TestCreateStageTimeoutNoSecondCreate(t *testing.T) {
	testtool.Need(t, "sh", "sleep")
	work := t.TempDir()
	calls := filepath.Join(work, "calls")
	counter := filepath.Join(work, "n")
	script := filepath.Join(work, "fake-hostsvc")
	body := "#!/bin/sh\necho \"$@\" >> " + calls + "\nn=$(cat " + counter + " 2>/dev/null || echo 0)\necho $((n+1)) > " + counter + "\nif [ \"$n\" = 0 ]; then sleep 600; fi\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ae := newActorEnv(t, func(c *ActorConfig) {
		c.Stages = DefaultStages(script, []string{"true"}, "dev-cp")
		c.Stages[0].Timeout = 500 * time.Millisecond
	})
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	waitUntil(t, "the group", 5*time.Second, func() bool { return mustEntry(t, ae.j, s.ID).Pgid != 0 })
	e := mustEntry(t, ae.j, s.ID)
	st := ae.waitState(s.ID, mgmtapi.StepFailed)
	if st.Detail != step.DetailTimeout || st.Stage != "creating" {
		t.Fatalf("status = %+v, want a timeout at creating", st)
	}
	waitUntil(t, "the create child to be killed", 12*time.Second, func() bool { return !groupAlive(e.Pgid) })
	ae.clock.Advance(6 * time.Minute)
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepDone)
	b, _ := os.ReadFile(calls)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || lines[0] != "create --cluster dev-cell-1" || lines[1] != "create --cluster dev-cell-1 --retry-of-create" {
		t.Errorf("create calls = %q, want one plain call, then one retry call (no second create in the first attempt)", lines)
	}
}

func TestInterruptedCreateDeletesHalfBuiltCluster(t *testing.T) {
	testtool.Need(t, "sh", "sleep")
	work := t.TempDir()
	calls := filepath.Join(work, "calls")
	script := filepath.Join(work, "fake-hostsvc")
	body := "#!/bin/sh\necho \"$@\" >> " + calls + "\nif [ ! -e " + filepath.Join(work, "second") + " ]; then sleep 600; fi\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ae := newActorEnv(t, func(c *ActorConfig) { c.Stages = DefaultStages(script, []string{"true"}, "dev-cp") })
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepCreating)
	waitUntil(t, "the create call", 5*time.Second, func() bool { b, _ := os.ReadFile(calls); return len(b) > 0 })
	ae.stop() // the host service stops while the create child runs
	if st := ae.status(s.ID); st.State != mgmtapi.StepFailed || st.Detail != step.DetailInterrupted || st.Attempts != 0 {
		t.Fatalf("after the stop: %+v", st)
	}
	if err := os.WriteFile(filepath.Join(work, "second"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A new run of the host service: the interrupted step is queued again, with no attempt used.
	j2, err := OpenJournal(ae.j.Dir(), ae.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	ae.j = j2
	ae.a = ae.newActor(j2, func(c *ActorConfig) { c.Stages = DefaultStages(script, []string{"true"}, "dev-cp") })
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepDone)
	b, _ := os.ReadFile(calls)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || lines[0] != "create --cluster dev-cell-1" || lines[1] != "create --cluster dev-cell-1 --retry-of-create" {
		t.Errorf("create calls = %q: the run after an interrupted create must carry --retry-of-create", lines)
	}
}

func TestActorCountsStates(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	ae := newActorEnv(t, func(c *ActorConfig) { c.Meter = mp.Meter("m") })
	ae.setScript("bootstrapping", "exit 1")
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepFailed)
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for state, want := range map[string]int64{"queued": 1, "creating": 1, "admitting": 1, "bootstrapping": 1, "failed": 1, "done": 0} {
		if got := sumFor(t, rm, "hostsvc.steps", "state", state); got != want {
			t.Errorf("hostsvc.steps{state=%s} = %d, want %d", state, got, want)
		}
	}
	if _, err := NewActor(ActorConfig{}); err == nil {
		t.Error("NewActor accepted an empty config")
	}
}
