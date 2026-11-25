package cellctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/envd"
	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

const ns = "cell-controller-system"

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

type call struct {
	op, id string
	at     time.Time
}

type hostStep struct {
	st  mgmtapi.StepStatus
	env []byte
}

// fakeHost is a host service that keeps steps by ID. It refuses to run two calls at once.
type fakeHost struct {
	t   *testing.T
	clk *clock

	mu       sync.Mutex
	calls    []call
	steps    map[string]*hostStep
	created  map[string]int
	inflight int
	// err, when set, answers every call.
	err error
	// putErr and getErr answer the calls of one step.
	putErr, getErr map[string]error
	// advance moves a step to its next state at each Get.
	advance bool
	// onCreate changes the status of a step when the host service first accepts it.
	onCreate map[string]func(*mgmtapi.StepStatus)
	// doneOnCreate makes every new step done at once, so that it holds nothing back.
	doneOnCreate bool
}

func newHost(t *testing.T, clk *clock) *fakeHost {
	return &fakeHost{t: t, clk: clk, steps: map[string]*hostStep{}, created: map[string]int{},
		putErr: map[string]error{}, getErr: map[string]error{}}
}

var progress = []string{mgmtapi.StepQueued, mgmtapi.StepCreating, mgmtapi.StepAdmitting, mgmtapi.StepBootstrapping, mgmtapi.StepDone}

func stageOf(state string) string {
	switch state {
	case mgmtapi.StepCreating, mgmtapi.StepAdmitting, mgmtapi.StepBootstrapping:
		return state
	}
	return ""
}

func (h *fakeHost) enter(op, id string) func() {
	h.mu.Lock()
	h.inflight++
	if h.inflight != 1 {
		h.t.Errorf("%d host calls in flight", h.inflight)
	}
	h.calls = append(h.calls, call{op, id, h.clk.now})
	return func() { h.inflight--; h.mu.Unlock() }
}

func (h *fakeHost) Put(_ context.Context, id string, env []byte) (mgmtapi.StepStatus, error) {
	defer h.enter("put", id)()
	if h.err != nil {
		return mgmtapi.StepStatus{}, h.err
	}
	if err := h.putErr[id]; err != nil {
		return mgmtapi.StepStatus{}, err
	}
	s, ok := h.steps[id]
	if !ok {
		_, cell, _, err := step.Peek(env)
		if err != nil {
			h.t.Errorf("host got a bad envelope: %v", err)
		}
		s = &hostStep{st: mgmtapi.StepStatus{ID: id, Cell: cell, State: mgmtapi.StepQueued, UpdatedAt: h.clk.now}}
		h.steps[id] = s
		h.created[id]++
		if h.doneOnCreate {
			s.st.State = mgmtapi.StepDone
		}
		if f := h.onCreate[id]; f != nil {
			f(&s.st)
		}
	}
	if !bytes.Equal(s.env, env) {
		s.env = bytes.Clone(env)
	} else if s.st.State == mgmtapi.StepFailed && !h.clk.now.Before(s.st.RetryAt) {
		s.st.State = mgmtapi.StepQueued
	}
	return s.st, nil
}

func (h *fakeHost) Get(_ context.Context, id string) (mgmtapi.StepStatus, error) {
	defer h.enter("get", id)()
	if h.err != nil {
		return mgmtapi.StepStatus{}, h.err
	}
	if err := h.getErr[id]; err != nil {
		return mgmtapi.StepStatus{}, err
	}
	s, ok := h.steps[id]
	if !ok {
		return mgmtapi.StepStatus{}, &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcDenied, Status: 404}
	}
	if h.advance {
		if i := slices.Index(progress, s.st.State); i >= 0 && i < len(progress)-1 {
			s.st.State = progress[i+1]
			s.st.Stage = stageOf(s.st.State)
		}
	}
	return s.st, nil
}

// set changes the state of a step at the host.
func (h *fakeHost) set(id string, f func(*mgmtapi.StepStatus)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.steps[id]
	if !ok {
		h.t.Fatalf("host has no step %s", id)
	}
	f(&s.st)
}

func (h *fakeHost) callsOf(op, id string) []call {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []call
	for _, c := range h.calls {
		if (op == "" || c.op == op) && (id == "" || c.id == id) {
			out = append(out, c)
		}
	}
	return out
}

type harness struct {
	t    *testing.T
	w    *world
	clk  *clock
	host *fakeHost
	kube *fake.Clientset
	c    *Controller
	logs *bytes.Buffer
}

func newHarness(t *testing.T, w *world, mod ...func(*Config)) *harness {
	t.Helper()
	clk := &clock{now: t0}
	h := &harness{t: t, w: w, clk: clk, host: newHost(t, clk), kube: fake.NewClientset(), logs: &bytes.Buffer{}}
	cfg := Config{Env: "dev", Namespace: ns, StepsName: "cell-steps", StatusName: "step-status", Client: h.kube,
		Keys: w.keys, Host: h.host, Now: clk.Now, Rand: func() float64 { return 0.5 },
		Log: slog.New(slog.NewJSONHandler(h.logs, nil))}
	for _, m := range mod {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.c = c
	return h
}

// restart replaces the controller with a new one on the same cluster and host service.
func (h *harness) restart() {
	c, err := New(h.c.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	h.c = c
}

func (h *harness) setSteps(data map[string]string) {
	h.t.Helper()
	cms := h.kube.CoreV1().ConfigMaps(ns)
	cm, err := cms.Get(h.t.Context(), "cell-steps", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(h.t.Context(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cell-steps", Namespace: ns}, Data: data}, metav1.CreateOptions{})
	} else if err == nil {
		cm.Data = data
		_, err = cms.Update(h.t.Context(), cm, metav1.UpdateOptions{})
	}
	if err != nil {
		h.t.Fatal(err)
	}
}

// runFor runs rounds at the wake times of the controller until d has passed on the fake clock.
func (h *harness) runFor(d time.Duration) {
	h.t.Helper()
	end := h.clk.now.Add(d)
	for {
		h.c.round(h.t.Context())
		next := h.clk.now.Add(h.c.wait())
		if next.After(end) {
			h.clk.now = end
			return
		}
		h.clk.now = next
	}
}

type report struct {
	At    time.Time            `json:"at"`
	Steps []mgmtapi.StepStatus `json:"steps"`
}

func (h *harness) cm() *corev1.ConfigMap {
	h.t.Helper()
	cm, err := h.kube.CoreV1().ConfigMaps(ns).Get(h.t.Context(), "step-status", metav1.GetOptions{})
	if err != nil {
		h.t.Fatalf("step-status: %v", err)
	}
	return cm
}

func (h *harness) report() report {
	h.t.Helper()
	var r report
	if err := json.Unmarshal([]byte(h.cm().Data[StatusKey]), &r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *harness) statusOf(id string) (mgmtapi.StepStatus, bool) {
	for _, s := range h.report().Steps {
		if s.ID == id {
			return s, true
		}
	}
	return mgmtapi.StepStatus{}, false
}

func busy(after time.Duration) error {
	return &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcBusy, Status: 503, RetryAfter: after}
}

func unavailable() error {
	return &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcUnavailable}
}

func TestControllerRefusalsMakeNoHostCall(t *testing.T) {
	w := newWorld(t)
	for _, row := range refusalRows(t, w) {
		if row.name == "good" {
			continue
		}
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t, w)
			if row.mark.Counter > 1 {
				h.setSteps(w.data(row.mark.Counter))
				h.runFor(0)
			}
			d, wanted := row.build()
			h.setSteps(d)
			h.runFor(time.Minute)
			for _, wn := range wanted {
				if wn.id != "" && len(h.host.callsOf("", wn.id)) != 0 {
					t.Errorf("host calls for the refused step: %+v", h.host.callsOf("", wn.id))
				}
				if wn.id == "" {
					continue
				}
				st, ok := h.statusOf(wn.id)
				if !ok || st.State != mgmtapi.StepRefused || st.Reason != step.Code || st.Detail != wn.detail {
					t.Errorf("status %+v (found %v), want refused %s", st, ok, wn.detail)
				}
			}
			if row.name == "unindexed_step" {
				// The good step of the same read still goes through.
				if n := len(h.host.callsOf("put", "")); n != 1 {
					t.Errorf("%d puts, want 1", n)
				}
			} else if n := len(h.host.callsOf("", "")); n != 0 {
				t.Errorf("%d host calls: %+v", n, h.host.callsOf("", ""))
			}
		})
	}
}

func TestControllerPutsThenPolls(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w)
	h.host.advance = true
	h.setSteps(w.data(2, a))
	h.runFor(3 * time.Minute)

	calls := h.host.callsOf("", a.s.ID)
	if len(calls) == 0 || calls[0].op != "put" || !calls[0].at.Equal(t0) {
		t.Fatalf("calls %+v", calls)
	}
	var puts, gets int
	for i, c := range calls {
		if c.op == "put" {
			puts++
		} else {
			gets++
		}
		if i > 0 && c.at.Sub(calls[i-1].at) != 10*time.Second {
			t.Errorf("call %d came %s after the one before", i, c.at.Sub(calls[i-1].at))
		}
	}
	if puts != 1 || gets != 4 {
		t.Errorf("%d puts and %d gets, want 1 and 4 (queued to done)", puts, gets)
	}
	if st, _ := h.statusOf(a.s.ID); st.State != mgmtapi.StepDone {
		t.Errorf("status %+v", st)
	}
}

func TestControllerOneInFlight(t *testing.T) {
	w := newWorld(t)
	a, b, c := w.item("dev-cell-3", 0), w.item("dev-cell-1", time.Second), w.item("dev-cell-2", time.Second)
	h := newHarness(t, w)
	h.host.advance = true
	h.setSteps(w.data(2, a, b, c))
	h.runFor(5 * time.Minute)
	var order []string
	for _, cl := range h.host.callsOf("put", "") {
		order = append(order, cl.id)
	}
	if !slices.Equal(order, []string{a.s.ID, b.s.ID, c.s.ID}) {
		t.Errorf("put order %v, want issuedAt then cell", order)
	}
}

func TestControllerSendsNextWhileHeadWaits(t *testing.T) {
	w := newWorld(t)
	a, b := w.item("dev-cell-1", 0), w.item("dev-cell-2", time.Second)
	h := newHarness(t, w)
	h.host.onCreate = map[string]func(*mgmtapi.StepStatus){a.s.ID: func(s *mgmtapi.StepStatus) {
		s.State, s.Stage, s.Attempts, s.RetryAt = mgmtapi.StepFailed, mgmtapi.StageCreating, 1, t0.Add(5*time.Minute)
	}}
	h.setSteps(w.data(2, a, b))
	h.runFor(4 * time.Minute)
	if puts := h.host.callsOf("put", b.s.ID); len(puts) != 1 || !puts[0].at.Equal(t0) {
		t.Errorf("puts of the next step: %+v", puts)
	}
	if puts := h.host.callsOf("put", a.s.ID); len(puts) != 1 {
		t.Errorf("the head step was sent again before its RetryAt: %+v", puts)
	} // At its RetryAt the head goes out again, although the next step is open at the host service.
	h.runFor(2 * time.Minute)
	if puts := h.host.callsOf("put", a.s.ID); len(puts) != 2 {
		t.Errorf("the head step was not sent again at its RetryAt: %+v", puts)
	}
}

func TestControllerResumesAfterRestart(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w)
	h.setSteps(w.data(2, a))
	h.runFor(0)
	h.host.set(a.s.ID, func(s *mgmtapi.StepStatus) { s.State, s.Stage = mgmtapi.StepAdmitting, mgmtapi.StageAdmitting })
	h.restart()
	h.runFor(0)
	if h.host.created[a.s.ID] != 1 {
		t.Errorf("host made the step %d times", h.host.created[a.s.ID])
	}
	if puts := h.host.callsOf("put", a.s.ID); len(puts) != 2 {
		t.Errorf("%d puts, want one before and one after the restart", len(puts))
	}
	if st, _ := h.statusOf(a.s.ID); st.State != mgmtapi.StepAdmitting {
		t.Errorf("status after the restart %+v", st)
	}
	h.host.set(a.s.ID, func(s *mgmtapi.StepStatus) { s.State, s.Stage = mgmtapi.StepDone, "" })
	h.runFor(15 * time.Second)
	if st, _ := h.statusOf(a.s.ID); st.State != mgmtapi.StepDone {
		t.Errorf("the restarted controller does not poll: %+v", st)
	}
}

func TestControllerHostDown(t *testing.T) {
	for _, reason := range []string{mgmtapi.ReasonHostsvcUnavailable, mgmtapi.ReasonHostsvcUntrusted} {
		t.Run(reason, func(t *testing.T) {
			w := newWorld(t)
			a := w.item("dev-cell-1", 0)
			var n int
			h := newHarness(t, w, func(c *Config) {
				c.Rand = func() float64 { n++; return float64(n%2) * 0.99 }
			})
			h.host.err = &mgmtapi.HostError{Reason: reason}
			h.setSteps(w.data(2, a))
			h.runFor(30 * time.Minute)

			calls := h.host.callsOf("", "")
			// More than 34 failures in a row would overflow a back-off that is not capped in its loop.
			if len(calls) < 40 {
				t.Fatalf("%d calls in 30 minutes", len(calls))
			}
			base := time.Second
			for i := 1; i < len(calls); i++ {
				gap := calls[i].at.Sub(calls[i-1].at)
				if gap < time.Second || gap > 30*time.Second || gap < base/2 || gap > base {
					t.Errorf("gap %d is %s, want %s to %s", i, gap, max(base/2, time.Second), base)
				}
				base = min(base*2, 30*time.Second)
			}
			st, ok := h.statusOf(a.s.ID)
			if !ok || st.LastHostError == nil || st.LastHostError.Reason != reason {
				t.Fatalf("status %+v", st)
			}
			// At is the start of the outage, so the rule "older than 2 minutes" fires while the outage lasts.
			if !st.LastHostError.At.Equal(t0) || h.clk.now.Sub(st.LastHostError.At) < 2*time.Minute {
				t.Errorf("lastHostError.At %s, want the first failure at %s", st.LastHostError.At, t0)
			}
			if !mgmtapi.ValidStepStatus(st) {
				t.Errorf("status %+v is not valid", st)
			}

			h.host.err = nil
			h.runFor(time.Minute)
			st, _ = h.statusOf(a.s.ID)
			if st.State != mgmtapi.StepQueued || st.LastHostError != nil {
				t.Errorf("after recovery %+v, want queued with no lastHostError", st)
			}
			if h.host.created[a.s.ID] != 1 {
				t.Errorf("created %d times", h.host.created[a.s.ID])
			}
		})
	}
}

func TestControllerHonoursRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after time.Duration
	}{
		{"rate_60s", 60 * time.Second},
		{"queue_60s", 60 * time.Second},
		{"spec_behind_30s", 30 * time.Second},
		{"short_5s", 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			a := w.item("dev-cell-1", 0)
			h := newHarness(t, w)
			h.host.err = busy(tc.after)
			h.setSteps(w.data(2, a))
			h.runFor(0)
			h.runFor(tc.after - time.Second)
			if n := len(h.host.callsOf("", "")); n != 1 {
				t.Fatalf("%d calls before the Retry-After passed", n)
			}
			h.host.err = nil
			h.runFor(2 * time.Second)
			calls := h.host.callsOf("", "")
			if len(calls) != 2 || !calls[1].at.Equal(t0.Add(tc.after)) {
				t.Fatalf("calls %+v, want the second at %s", calls, tc.after)
			}
			if st, _ := h.statusOf(a.s.ID); st.State != mgmtapi.StepQueued {
				t.Errorf("status %+v", st)
			}
		})
	}
}

func TestControllerDeniedStops(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w)
	h.host.putErr[a.s.ID] = &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcDenied, Status: 403, RequestID: "0123456789abcdef"}
	h.setSteps(w.data(2, a))
	h.runFor(5 * time.Minute)
	if n := len(h.host.callsOf("", a.s.ID)); n != 1 {
		t.Errorf("%d calls for a denied step", n)
	}
	st, _ := h.statusOf(a.s.ID)
	if st.State != mgmtapi.StepRefused || st.Reason != mgmtapi.ReasonHostsvcDenied || st.RequestID != "0123456789abcdef" ||
		st.LastHostError == nil || st.LastHostError.Reason != mgmtapi.ReasonHostsvcDenied {
		t.Errorf("status %+v", st)
	}
	if !mgmtapi.ValidStepStatus(st) {
		t.Errorf("status %+v is not valid", st)
	}
}

func TestControllerResendsResignedStep(t *testing.T) {
	for _, state := range []string{"denied", mgmtapi.StepQueued, mgmtapi.StepAdmitting} {
		t.Run(state, func(t *testing.T) {
			w := newWorld(t)
			a := w.item("dev-cell-1", 0)
			h := newHarness(t, w)
			if state == "denied" {
				h.host.putErr[a.s.ID] = &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcDenied, Status: 403, RequestID: "0123456789abcdef"}
			}
			h.setSteps(w.data(2, a))
			h.runFor(30 * time.Second)
			if state != "denied" {
				h.host.set(a.s.ID, func(s *mgmtapi.StepStatus) { s.State, s.Stage = state, stageOf(state) })
			}
			delete(h.host.putErr, a.s.ID)

			// A rotation signs the same step again under the next key epoch.
			again := a.s
			again.KeyEpoch = 2
			re := w.sign(again)
			if bytes.Equal(re.env, a.env) {
				t.Fatal("the resigned envelope has the same bytes")
			}
			h.setSteps(w.data(3, re))
			h.runFor(30 * time.Second)

			puts := h.host.callsOf("put", a.s.ID)
			if len(puts) != 2 {
				t.Fatalf("%d puts, want 2: %+v", len(puts), puts)
			}
			if !bytes.Equal(h.host.steps[a.s.ID].env, re.env) {
				t.Error("the host did not get the new envelope")
			}
			if st, _ := h.statusOf(a.s.ID); st.State == mgmtapi.StepRefused {
				t.Errorf("a new envelope did not clear the denial: %+v", st)
			}
		})
	}
}

func TestControllerRetriesFailedAtRetryAt(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w)
	h.setSteps(w.data(2, a))
	h.runFor(0)
	retry := t0.Add(5 * time.Minute)
	h.host.set(a.s.ID, func(s *mgmtapi.StepStatus) {
		s.State, s.Stage, s.Attempts, s.RetryAt = mgmtapi.StepFailed, mgmtapi.StageAdmitting, 1, retry
	})
	h.runFor(4*time.Minute + 55*time.Second)
	if n := len(h.host.callsOf("put", a.s.ID)); n != 1 {
		t.Fatalf("%d puts before RetryAt", n)
	}
	if st, _ := h.statusOf(a.s.ID); st.State != mgmtapi.StepFailed || !st.RetryAt.Equal(retry) {
		t.Errorf("status while it waits %+v", st)
	}
	h.runFor(15 * time.Second)
	puts := h.host.callsOf("put", a.s.ID)
	if len(puts) != 2 || puts[1].at.Before(retry) || puts[1].at.After(retry.Add(time.Second)) {
		t.Fatalf("puts %+v, want the second at %s", puts, retry)
	}
	if st, _ := h.statusOf(a.s.ID); st.State != mgmtapi.StepQueued {
		t.Errorf("status after the retry %+v", st)
	}
}

func TestControllerPollsDroppedStepToFinal(t *testing.T) {
	for _, tc := range []struct {
		name string
		// host changes the host service after the drop.
		host func(h *fakeHost, id string)
		// wantState is the last status that the report shows, "" when the entry just ends.
		wantState string
	}{
		{"dropped_failed_becomes_cancelled", func(h *fakeHost, id string) {
			h.set(id, func(s *mgmtapi.StepStatus) { s.State, s.Detail = mgmtapi.StepCancelled, step.DetailCancelled })
		}, mgmtapi.StepCancelled},
		{"dropped_unknown_404", func(h *fakeHost, id string) {
			h.mu.Lock()
			delete(h.steps, id)
			h.mu.Unlock()
		}, ""},
		{"dropped_running_finishes", func(h *fakeHost, id string) {
			h.set(id, func(s *mgmtapi.StepStatus) { s.State, s.Stage = mgmtapi.StepDone, "" })
		}, mgmtapi.StepDone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			a, b := w.item("dev-cell-1", 0), w.item("dev-cell-2", time.Second)
			h := newHarness(t, w)
			h.setSteps(w.data(2, a, b))
			h.runFor(0)
			h.host.set(a.s.ID, func(s *mgmtapi.StepStatus) {
				s.State, s.Stage, s.Attempts, s.RetryAt = mgmtapi.StepFailed, mgmtapi.StageCreating, 1, t0.Add(time.Minute)
			})
			h.setSteps(w.data(3, b))
			// The step is failed and its RetryAt passes, but the spec no longer holds it.
			h.runFor(3 * time.Minute)
			if n := len(h.host.callsOf("put", a.s.ID)); n != 1 {
				t.Errorf("%d puts of a dropped step", n)
			}
			if n := len(h.host.callsOf("get", a.s.ID)); n < 10 {
				t.Errorf("%d polls of a dropped step in 3 minutes, want one every 10 s", n)
			}
			tc.host(h.host, a.s.ID)
			before := len(h.host.callsOf("", a.s.ID))
			h.runFor(time.Minute)
			if len(h.host.callsOf("get", a.s.ID)) > before+1 {
				t.Errorf("the poll of a dropped step does not end")
			}
			h.runFor(time.Minute)
			if got := len(h.host.callsOf("", a.s.ID)); got > before+1 {
				t.Errorf("calls kept coming after the final state: %d", got-before)
			}
			st, ok := h.statusOf(a.s.ID)
			if tc.wantState != "" && (!ok || st.State != tc.wantState) {
				t.Errorf("status %+v (found %v), want %s", st, ok, tc.wantState)
			}
			wantEntries := 2
			if tc.wantState == "" {
				wantEntries = 1
			}
			if len(h.c.entries) != wantEntries {
				t.Errorf("%d entries are kept, want %d", len(h.c.entries), wantEntries)
			}
		})
	}
}

func TestControllerPutsAgainWhenHostForgets(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w)
	h.setSteps(w.data(2, a))
	h.runFor(0)
	h.host.mu.Lock()
	delete(h.host.steps, a.s.ID)
	h.host.mu.Unlock()
	h.runFor(30 * time.Second)
	if n := len(h.host.callsOf("put", a.s.ID)); n != 2 {
		t.Errorf("%d puts, want 2 for a step that the spec still indexes", n)
	}
}

func writeKey(t *testing.T, dir, name string, key []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(encodeKey(key)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestControllerTwoKeys(t *testing.T) {
	w1, w2, rogue := newWorld(t), newWorld(t), newWorld(t)
	// A ConfigMap volume: files are links through ..data into a dot directory.
	dir := t.TempDir()
	vol := filepath.Join(dir, "..2026_11_14_10_00_00.1")
	if err := os.Mkdir(vol, 0o755); err != nil {
		t.Fatal(err)
	}
	writeKey(t, vol, "spec.pub", w1.pub)
	writeKey(t, vol, "next.pub", w2.pub)
	for _, l := range [][2]string{{"..2026_11_14_10_00_00.1", "..data"}, {"..data/spec.pub", "spec.pub"}, {"..data/next.pub", "next.pub"}} {
		if err := os.Symlink(l[0], filepath.Join(dir, l[1])); err != nil {
			t.Fatal(err)
		}
	}
	h := newHarness(t, w1, func(c *Config) { c.Keys = hostsvc.KeysFromDir(dir) })
	h.host.doneOnCreate = true

	a := w1.item("dev-cell-1", 0)
	h.setSteps(w1.data(2, a))
	h.runFor(11 * time.Second)
	b := w2.item("dev-cell-2", time.Second)
	h.setSteps(w2.data(3, b))
	h.runFor(11 * time.Second)
	c := rogue.item("dev-cell-3", 2*time.Second)
	h.setSteps(rogue.data(4, c))
	h.runFor(11 * time.Second)

	if n := len(h.host.callsOf("put", a.s.ID)); n != 1 {
		t.Errorf("%d puts of the step under spec.pub", n)
	}
	if n := len(h.host.callsOf("put", b.s.ID)); n != 1 {
		t.Errorf("%d puts of the step under next.pub", n)
	}
	if n := len(h.host.callsOf("put", c.s.ID)); n != 0 {
		t.Errorf("%d puts of a step under no pinned key", n)
	}
}

func TestControllerWritesStatus(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w)
	h.setSteps(w.data(2, a))
	h.runFor(0)
	if got := h.cm().Labels["poc.internal/made-by"]; got != "cell-controller" {
		t.Errorf("the created ConfigMap has label %q", got)
	}
	h.runFor(40 * time.Second)

	cm := h.cm()
	if cm.Labels["poc.internal/made-by"] != "cell-controller" {
		t.Errorf("labels %v", cm.Labels)
	}
	if len(cm.Data) != 1 || cm.Data[StatusKey] == "" || len(cm.BinaryData) != 0 {
		t.Fatalf("data keys %v", cm.Data)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(cm.Data[StatusKey]), &top); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, 2)
	for k := range top {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"at", "steps"}) {
		t.Errorf("status.json keys %v", keys)
	}
	var at time.Time
	if err := json.Unmarshal(top["at"], &at); err != nil || at.IsZero() {
		t.Errorf("at %s: %v", top["at"], err)
	}
	if !strings.HasPrefix(string(top["steps"]), "[{") {
		t.Errorf("steps %s", top["steps"])
	}

	var managers []string
	for _, act := range h.kube.Actions() {
		switch a := act.(type) {
		case ktesting.CreateActionImpl:
			managers = append(managers, a.CreateOptions.FieldManager)
		case ktesting.UpdateActionImpl:
			managers = append(managers, a.UpdateOptions.FieldManager)
		}
	}
	// h.setSteps writes with no manager. Every write of the controller names cell-controller.
	var named int
	for _, m := range managers {
		if m == "cell-controller" {
			named++
		}
	}
	if named == 0 {
		t.Errorf("no write names the field manager: %v", managers)
	}
	for _, act := range h.kube.Actions() {
		if act.GetResource().Resource != "configmaps" || (act.GetVerb() != "create" && act.GetVerb() != "update") {
			continue
		}
		var name, fm string
		switch a := act.(type) {
		case ktesting.CreateActionImpl:
			name, fm = a.Object.(*corev1.ConfigMap).Name, a.CreateOptions.FieldManager
		case ktesting.UpdateActionImpl:
			name, fm = a.Object.(*corev1.ConfigMap).Name, a.UpdateOptions.FieldManager
		}
		if name == "step-status" && fm != "cell-controller" {
			t.Errorf("a write of step-status uses field manager %q", fm)
		}
	}

	// envd reads the same document.
	steps, when, err := envd.NewConfigMapStepStatus(h.kube, ns, "step-status").Read(t.Context())
	if err != nil || len(steps) != 1 || when.IsZero() || steps[0].ID != a.s.ID {
		t.Errorf("envd reads %+v, %v, %v", steps, when, err)
	}
}

func TestControllerWritesIntoExistingConfigMap(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w)
	// A ConfigMap that a person made: no label and other keys.
	if _, err := h.kube.CoreV1().ConfigMaps(ns).Create(t.Context(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "step-status", Namespace: ns, Labels: map[string]string{"other": "x"}},
		Data:       map[string]string{"old": "data"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.setSteps(w.data(2, a))
	h.runFor(0)
	cm := h.cm()
	if cm.Labels["poc.internal/made-by"] != "cell-controller" || cm.Labels["other"] != "x" {
		t.Errorf("labels %v", cm.Labels)
	}
	if len(cm.Data) != 1 || cm.Data[StatusKey] == "" {
		t.Errorf("data keys %v", cm.Data)
	}
}

func TestControllerWritesNoMoreThan32(t *testing.T) {
	w := newWorld(t)
	var items []item
	for i := range 40 {
		items = append(items, w.item(fmt.Sprintf("dev-cell-%02d", i), time.Duration(i)*time.Millisecond))
	}
	h := newHarness(t, w)
	h.setSteps(w.data(2, items...))
	h.runFor(time.Second)
	if n := len(h.report().Steps); n != 32 {
		t.Errorf("%d entries", n)
	}
}

func TestControllerHeartbeat(t *testing.T) {
	for _, interval := range []time.Duration{10 * time.Second, 2 * time.Minute} {
		t.Run(interval.String(), func(t *testing.T) { testHeartbeat(t, interval) })
	}
}

func testHeartbeat(t *testing.T, interval time.Duration) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w, func(c *Config) { c.Interval = interval })
	// A done step needs no poll, so only the heartbeat wakes the controller between reads.
	h.host.onCreate = map[string]func(*mgmtapi.StepStatus){a.s.ID: func(s *mgmtapi.StepStatus) { s.State = mgmtapi.StepDone }}
	h.setSteps(w.data(2, a))

	var slept []time.Duration
	var stale []string
	end := t0.Add(5 * time.Minute)
	h.c.cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d)
		h.clk.now = h.clk.now.Add(d)
		if age := h.clk.now.Sub(h.report().At); age > 30*time.Second {
			stale = append(stale, fmt.Sprintf("at %s the status is %s old", h.clk.now.Sub(t0), age))
		}
		if !h.clk.now.Before(end) {
			return context.Canceled
		}
		return nil
	}
	if err := h.c.Run(t.Context()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	if len(stale) != 0 {
		t.Errorf("status older than 30 s: %v", stale)
	}
	for _, d := range slept {
		if d > 30*time.Second {
			t.Errorf("slept %s", d)
		}
	}
	if st, _ := h.statusOf(a.s.ID); st.State != mgmtapi.StepDone {
		t.Errorf("status %+v", st)
	}
	if !h.c.Ready() {
		t.Error("not ready")
	}
}

func TestControllerReadyIgnoresHost(t *testing.T) {
	w := newWorld(t)
	h := newHarness(t, w)
	h.host.err = unavailable()
	h.setSteps(w.data(2, w.item("dev-cell-1", 0)))
	if h.c.Ready() {
		t.Fatal("ready before the first read")
	}
	h.runFor(0)
	if len(h.host.callsOf("", "")) == 0 {
		t.Fatal("the host service was not called")
	}
	if !h.c.Ready() {
		t.Fatal("not ready after reading the steps ConfigMap while the host service is down")
	}
}

func TestControllerSpecRefusalShowsOnLastIndex(t *testing.T) {
	for _, hostUp := range []bool{false, true} {
		name := "step_unsent_host_down"
		if hostUp {
			name = "step_known_to_host"
		}
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			a := w.item("dev-cell-1", 0)
			h := newHarness(t, w)
			if !hostUp {
				h.host.err = unavailable()
			}
			h.setSteps(w.data(2, a))
			h.runFor(15 * time.Second)

			bad := w.data(3, a)
			bad[SpecKey] = w.specEnv(3, w.rogue, w.entry(a))
			h.setSteps(bad)
			h.runFor(15 * time.Second)
			before := len(h.host.callsOf("", ""))
			h.host.err = nil
			h.runFor(time.Minute)
			if puts := h.host.callsOf("put", ""); hostUp && len(puts) != 1 {
				t.Errorf("%d puts, want only the first", len(puts))
			}
			if hostUp && len(h.host.callsOf("get", a.s.ID)) < 5 {
				t.Errorf("the step is not polled while its spec is refused")
			}
			if !hostUp && len(h.host.callsOf("", "")) != before {
				t.Errorf("%d host calls after the spec was refused", len(h.host.callsOf("", ""))-before)
			}
			st, ok := h.statusOf(a.s.ID)
			if !ok || st.State != mgmtapi.StepRefused || st.Reason != step.Code || st.Detail != step.DetailSignatureInvalid || !mgmtapi.ValidStepStatus(st) {
				t.Fatalf("status %+v", st)
			}
			if n := strings.Count(h.logs.String(), `"msg":"spec refused"`); n != 1 {
				t.Errorf("%d spec refusal logs in a minute, want 1", n)
			}

			// A later spec that verifies clears the refusal.
			h.setSteps(w.data(4, a))
			h.runFor(15 * time.Second)
			if st, _ := h.statusOf(a.s.ID); st.State != mgmtapi.StepQueued {
				t.Errorf("status after the good spec %+v", st)
			}
		})
	}
}

func TestControllerStepRefusalShowsOverHostStatus(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w)
	h.setSteps(w.data(2, a))
	h.runFor(15 * time.Second)
	// A compromised dev-cp swaps the envelope for one under another key.
	rogue, err := step.Sign(a.s, w.rogue)
	if err != nil {
		t.Fatal(err)
	}
	d := w.data(3, a)
	d[a.s.Cell+StepSuffix] = string(rogue)
	h.setSteps(d)
	h.runFor(time.Minute)
	if n := len(h.host.callsOf("put", a.s.ID)); n != 1 {
		t.Errorf("%d puts", n)
	}
	if n := len(h.host.callsOf("get", a.s.ID)); n < 5 {
		t.Errorf("%d polls while the step is refused", n)
	}
	st, _ := h.statusOf(a.s.ID)
	if st.State != mgmtapi.StepRefused || st.Detail != step.DetailSignatureInvalid {
		t.Errorf("status %+v", st)
	}
}

func TestControllerHoldsNextStepWhileHeadRuns(t *testing.T) {
	w := newWorld(t)
	a, b := w.item("dev-cell-1", 0), w.item("dev-cell-2", time.Second)
	h := newHarness(t, w)
	h.setSteps(w.data(2, a, b))
	h.runFor(2 * time.Minute)
	if n := len(h.host.callsOf("put", b.s.ID)); n != 0 {
		t.Fatalf("the next step was sent while the head runs: %d puts", n)
	}
	if st, _ := h.statusOf(b.s.ID); st.State != mgmtapi.StepQueued {
		t.Errorf("held step %+v", st)
	}
	h.host.set(a.s.ID, func(s *mgmtapi.StepStatus) { s.State, s.Stage = mgmtapi.StepDone, "" })
	h.runFor(30 * time.Second)
	puts := h.host.callsOf("put", b.s.ID)
	if len(puts) != 1 {
		t.Fatalf("%d puts of the next step after the head ended", len(puts))
	}
}

func TestControllerBusyDelaysPutsNotPolls(t *testing.T) {
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	h := newHarness(t, w)
	h.setSteps(w.data(2, a))
	h.runFor(15 * time.Second)

	// A rotation signs the step again. The host service is busy for the new Put.
	again := a.s
	again.KeyEpoch = 2
	re := w.sign(again)
	h.host.putErr[a.s.ID] = busy(60 * time.Second)
	h.setSteps(w.data(3, re))
	gets := len(h.host.callsOf("get", a.s.ID))
	h.runFor(55 * time.Second)
	if n := len(h.host.callsOf("put", a.s.ID)); n != 2 {
		t.Errorf("%d puts inside the Retry-After window, want the first and one busy", n)
	}
	if n := len(h.host.callsOf("get", a.s.ID)) - gets; n < 4 {
		t.Errorf("%d polls in 55 s while Puts wait, want one every 10 s", n)
	}
	delete(h.host.putErr, a.s.ID)
	h.runFor(15 * time.Second)
	if n := len(h.host.callsOf("put", a.s.ID)); n != 3 {
		t.Errorf("%d puts after the window", n)
	}
}

func TestControllerReportKeepsRealStepsFirst(t *testing.T) {
	w := newWorld(t)
	good := w.item("dev-cell-1", 0)
	d := w.data(2, good)
	for i := range 40 {
		stray := w.item(fmt.Sprintf("dev-cell-%02d", i+10), 0)
		d[stray.s.Cell+StepSuffix] = string(stray.env)
	}
	h := newHarness(t, w)
	h.setSteps(d)
	h.runFor(time.Second)
	steps := h.report().Steps
	if len(steps) != 32 {
		t.Fatalf("%d entries", len(steps))
	}
	var found bool
	for _, st := range steps {
		found = found || st.ID == good.s.ID
	}
	if !found {
		t.Error("the step in the spec is not in the report")
	}
}

func TestControllerNoHostErrorOnRefusalOnlyEntries(t *testing.T) {
	w := newWorld(t)
	good, stray := w.item("dev-cell-1", 0), w.item("dev-cell-2", 0)
	d := w.data(2, good)
	d[stray.s.Cell+StepSuffix] = string(stray.env)
	h := newHarness(t, w)
	h.host.err = unavailable()
	h.setSteps(d)
	h.runFor(30 * time.Second)
	st, ok := h.statusOf(stray.s.ID)
	if !ok || st.State != mgmtapi.StepRefused || st.LastHostError != nil {
		t.Errorf("refusal-only entry %+v", st)
	}
	if st, _ := h.statusOf(good.s.ID); st.LastHostError == nil {
		t.Errorf("step in the spec has no lastHostError: %+v", st)
	}
}

func TestControllerCounters(t *testing.T) {
	w := newWorld(t)
	a, b := w.item("dev-cell-1", 0), w.item("dev-cell-2", time.Second)
	reader := metric.NewManualReader()
	h := newHarness(t, w, func(c *Config) { c.Meter = metric.NewMeterProvider(metric.WithReader(reader)).Meter("t") })
	h.host.advance = true
	d := w.data(2, a)
	delete(d, b.s.Cell+StepSuffix)
	d[b.s.Cell+StepSuffix] = string(b.env) // b is not indexed
	h.setSteps(d)
	h.runFor(2 * time.Minute)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				for _, kv := range dp.Attributes.ToSlice() {
					got[m.Name+"/"+string(kv.Key)+"="+kv.Value.AsString()] += dp.Value
				}
			}
		}
	}
	for k, want := range map[string]int64{
		"cellctl.steps/state=queued": 1, "cellctl.steps/state=done": 1, "cellctl.steps/state=creating": 1,
		"cellctl.refusals/detail=step_unindexed": 1,
	} {
		if got[k] != want {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], want, got)
		}
	}
}

func TestNewChecksConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("an empty Config was accepted")
	}
	w := newWorld(t)
	h := newHarness(t, w)
	cfg := h.c.cfg
	if cfg.Interval != 10*time.Second || cfg.PollEvery != 10*time.Second || cfg.Heartbeat != 30*time.Second ||
		cfg.MinBackoff != time.Second || cfg.MaxBackoff != 30*time.Second {
		t.Errorf("defaults %+v", cfg)
	}
}

type gaugeKey struct{ state, stage string }

func collect(t *testing.T, reader *metric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	return rm
}

func openSteps(rm metricdata.ResourceMetrics) map[gaugeKey]int64 {
	got := map[gaugeKey]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok || m.Name != "cellctl.steps.open" {
				continue
			}
			for _, dp := range g.DataPoints {
				st, _ := dp.Attributes.Value("state")
				sg, _ := dp.Attributes.Value("stage")
				got[gaugeKey{st.AsString(), sg.AsString()}] += dp.Value
			}
		}
	}
	return got
}

type stageDP struct {
	stage, result string
	count         uint64
	sum           float64
}

func stageDurations(rm metricdata.ResourceMetrics) []stageDP {
	var got []stageDP
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok || m.Name != "cellctl.step.stage.duration" {
				continue
			}
			for _, dp := range h.DataPoints {
				sg, _ := dp.Attributes.Value("stage")
				r, _ := dp.Attributes.Value("result")
				got = append(got, stageDP{sg.AsString(), r.AsString(), dp.Count, dp.Sum})
			}
		}
	}
	return got
}

func stageHarness(t *testing.T) (*harness, *metric.ManualReader, item) {
	t.Helper()
	w := newWorld(t)
	a := w.item("dev-cell-1", 0)
	reader := metric.NewManualReader()
	h := newHarness(t, w, func(c *Config) { c.Meter = metric.NewMeterProvider(metric.WithReader(reader)).Meter("t") })
	h.setSteps(w.data(2, a))
	return h, reader, a
}

// setStage moves the step at the host service and lets the controller poll it.
func (h *harness) setStage(id, state, stage string) {
	h.host.set(id, func(s *mgmtapi.StepStatus) { s.State, s.Stage = state, stage })
	h.runFor(h.c.cfg.PollEvery)
}

func TestNoStageDurationForFirstPoll(t *testing.T) {
	h, reader, a := stageHarness(t)
	h.runFor(time.Second)
	h.setStage(a.s.ID, mgmtapi.StepCreating, mgmtapi.StageCreating)
	if got := stageDurations(collect(t, reader)); len(got) != 0 {
		t.Errorf("durations after the first poll of a stage: %+v", got)
	}
}

func TestStageDurationOnChange(t *testing.T) {
	h, reader, a := stageHarness(t)
	h.runFor(time.Second)
	h.setStage(a.s.ID, mgmtapi.StepCreating, mgmtapi.StageCreating)
	h.runFor(30 * time.Second)
	h.setStage(a.s.ID, mgmtapi.StepAdmitting, mgmtapi.StageAdmitting)
	got := stageDurations(collect(t, reader))
	if len(got) != 1 || got[0].stage != "creating" || got[0].result != "next" || got[0].count != 1 || got[0].sum < 30 || got[0].sum > 60 {
		t.Errorf("durations %+v", got)
	}
}

func TestStageDurationOnFinal(t *testing.T) {
	h, reader, a := stageHarness(t)
	h.runFor(time.Second)
	h.setStage(a.s.ID, mgmtapi.StepBootstrapping, mgmtapi.StageBootstrapping)
	h.runFor(20 * time.Second)
	h.setStage(a.s.ID, mgmtapi.StepDone, "")
	h.runFor(time.Minute)
	got := stageDurations(collect(t, reader))
	if len(got) != 1 || got[0].stage != "bootstrapping" || got[0].result != "done" || got[0].count != 1 {
		t.Errorf("durations %+v", got)
	}
}

func TestStageDurationOnRefused(t *testing.T) {
	h, reader, a := stageHarness(t)
	h.runFor(time.Second)
	h.setStage(a.s.ID, mgmtapi.StepCreating, mgmtapi.StageCreating)
	h.host.getErr[a.s.ID] = &mgmtapi.HostError{Reason: mgmtapi.ReasonHostsvcDenied, Status: 403, RequestID: "0123456789abcdef"}
	h.runFor(30 * time.Second)
	got := stageDurations(collect(t, reader))
	if len(got) != 1 || got[0].stage != "creating" || got[0].result != "refused" || got[0].count != 1 {
		t.Errorf("durations %+v", got)
	}
}

func TestStepsOpenByState(t *testing.T) {
	h, reader, a := stageHarness(t)
	h.runFor(time.Second)
	if got := openSteps(collect(t, reader)); got[gaugeKey{"queued", ""}] != 1 || len(got) != 1 {
		t.Errorf("queued: %v", got)
	}
	h.setStage(a.s.ID, mgmtapi.StepAdmitting, mgmtapi.StageAdmitting)
	if got := openSteps(collect(t, reader)); got[gaugeKey{"admitting", "admitting"}] != 1 || len(got) != 1 {
		t.Errorf("admitting: %v", got)
	}
	h.setStage(a.s.ID, mgmtapi.StepDone, "")
	if got := openSteps(collect(t, reader)); len(got) != 0 {
		t.Errorf("final step is open: %v", got)
	}
}
