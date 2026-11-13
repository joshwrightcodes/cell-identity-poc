package clusterjwt

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const hintHCL = "hint_configmap = \"poc-system/cell-key-hints\"\n"

type hintCall struct {
	cell string
	at   time.Time
}

// fakeHints records each hint. A non-nil block holds every call until it closes.
type fakeHints struct {
	calls chan hintCall
	block chan struct{}
}

func newFakeHints() *fakeHints { return &fakeHints{calls: make(chan hintCall, 64)} }

func (h *fakeHints) Hint(ctx context.Context, cell string, at time.Time) error {
	if h.block != nil {
		select {
		case <-h.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	h.calls <- hintCall{cell, at}
	return nil
}

// next returns the next call, or fails when none arrives.
func (h *fakeHints) next(t *testing.T) hintCall {
	t.Helper()
	select {
	case c := <-h.calls:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no hint was written")
		return hintCall{}
	}
}

func (h *fakeHints) none(t *testing.T) {
	t.Helper()
	select {
	case c := <-h.calls:
		t.Fatalf("unexpected hint for %q", c.cell)
	default:
	}
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type hintFixture struct {
	*fixture
	hints     *fakeHints
	clock     *testClock
	processed chan struct{}
}

func newHintFixture(t *testing.T, o fixtureOptions) *hintFixture {
	t.Helper()
	h := &hintFixture{hints: newFakeHints(), clock: &testClock{t: testNow}, processed: make(chan struct{}, 64)}
	o.clock, o.hints = h.clock.now, h.hints
	o.afterHint = func() { h.processed <- struct{}{} }
	o.extraHCL += "\n" + hintHCL
	h.fixture = newFixture(t, o)
	return h
}

// processedOne waits until the writing goroutine has handled one queued cell.
func (h *hintFixture) processedOne(t *testing.T) {
	t.Helper()
	select {
	case <-h.processed:
	case <-time.After(5 * time.Second):
		t.Fatal("the hint goroutine did not handle the cell")
	}
}

func (h *hintFixture) unknownKID(t *testing.T, cell string) {
	t.Helper()
	_, err := h.attest(cell, func(nonce string) string {
		s := h.keys.good()
		s.Audience = []string{"spire-" + testEnv + "/" + nonce}
		s.KID = "other"
		return s.token(t)
	})
	wantDenied(t, err, UnknownKID)
}

func TestUnknownKidWritesHint(t *testing.T) {
	h := newHintFixture(t, fixtureOptions{})
	h.unknownKID(t, "dev-cell-1")
	got := h.hints.next(t)
	if got.cell != "dev-cell-1" || !got.at.Equal(testNow) {
		t.Fatalf("hint = %+v, want dev-cell-1 at %v", got, testNow)
	}
}

func TestHintOffWithoutConfigMap(t *testing.T) {
	hints := newFakeHints()
	processed := make(chan struct{}, 4)
	f := newFixture(t, fixtureOptions{hints: hints, afterHint: func() { processed <- struct{}{} }})
	_, err := f.attest("dev-cell-1", func(nonce string) string {
		s := f.keys.good()
		s.Audience = []string{"spire-" + testEnv + "/" + nonce}
		s.KID = "other"
		return s.token(t)
	})
	wantDenied(t, err, UnknownKID)
	select {
	case <-processed:
		t.Fatal("the hint goroutine handled a cell with hints off")
	case <-time.After(100 * time.Millisecond):
	}
	hints.none(t)
}

func TestHintWriteRateLimited(t *testing.T) {
	h := newHintFixture(t, fixtureOptions{})
	h.unknownKID(t, "dev-cell-1")
	h.processedOne(t)
	h.hints.next(t)

	// The same cell within the interval, and another cell within one second, write nothing.
	h.clock.advance(500 * time.Millisecond)
	h.unknownKID(t, "dev-cell-1")
	h.processedOne(t)
	h.unknownKID(t, "dev-cell-2")
	h.processedOne(t)
	h.hints.none(t)

	// Another cell after one second writes.
	h.clock.advance(time.Second)
	h.unknownKID(t, "dev-cell-2")
	h.processedOne(t)
	if got := h.hints.next(t); got.cell != "dev-cell-2" {
		t.Fatalf("hint for %q, want dev-cell-2", got.cell)
	}

	// The first cell stays limited until its interval ends.
	h.clock.advance(57 * time.Second)
	h.unknownKID(t, "dev-cell-1")
	h.processedOne(t)
	h.hints.none(t)
	h.clock.advance(2 * time.Second)
	h.unknownKID(t, "dev-cell-1")
	h.processedOne(t)
	if got := h.hints.next(t); got.cell != "dev-cell-1" {
		t.Fatalf("hint for %q, want dev-cell-1", got.cell)
	}
}

func TestNoHintForUnknownCellOrRevoked(t *testing.T) {
	h := newHintFixture(t, fixtureOptions{cells: []string{"dev-cell-1", "dev-cell-2"}, revoked: map[string]bool{"dev-cell-2": true}})
	_, err := h.attest("dev-cell-3", h.goodToken)
	wantDenied(t, err, UnknownCell)
	_, err = h.attest("dev-cell-2", h.goodToken)
	wantDenied(t, err, Revoked)
	// A hint queue keeps its order, so the first hint to arrive shows that none came before it.
	h.unknownKID(t, "dev-cell-1")
	h.processedOne(t)
	if got := h.hints.next(t); got.cell != "dev-cell-1" {
		t.Fatalf("hint for %q, want dev-cell-1", got.cell)
	}
	h.hints.none(t)
}

func TestNoHintForOtherReasons(t *testing.T) {
	h := newHintFixture(t, fixtureOptions{})
	other := newKeys(t)
	cases := map[string]struct {
		want   Reason
		mutate func(s *spec)
	}{
		"bad_signature":  {BadSignature, func(s *spec) { s.Key = other.rsa }},
		"wrong_audience": {WrongAudience, func(s *spec) { s.Audience = []string{"spire-" + testEnv + "/not-the-nonce"} }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := h.attest("dev-cell-1", func(nonce string) string {
				s := h.keys.good()
				s.Audience = []string{"spire-" + testEnv + "/" + nonce}
				c.mutate(&s)
				return s.token(t)
			})
			wantDenied(t, err, c.want)
		})
	}
	_, err := h.attest("dev-cell-1", func(string) string { return "not-a-jwt" })
	if err == nil {
		t.Fatal("expected a denial")
	}
	h.unknownKID(t, "dev-cell-2")
	h.processedOne(t)
	if got := h.hints.next(t); got.cell != "dev-cell-2" {
		t.Fatalf("hint for %q, want dev-cell-2", got.cell)
	}
	h.hints.none(t)
}

func TestHintNeverBlocksAttest(t *testing.T) {
	hints := newFakeHints()
	hints.block = make(chan struct{})
	h := &hintFixture{hints: hints, clock: &testClock{t: testNow}, processed: make(chan struct{}, 64)}
	h.fixture = newFixture(t, fixtureOptions{clock: h.clock.now, hints: hints, extraHCL: hintHCL})
	t.Cleanup(func() { close(hints.block) })
	start := time.Now()
	// One hint is in the blocked writer and sixteen fill the queue. The rest are dropped.
	for i := 0; i < 40; i++ {
		h.unknownKID(t, "dev-cell-1")
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("40 attestations took %v", d)
	}
	if n := strings.Count(h.logs.String(), "hint dropped"); n != 1 {
		t.Fatalf("%d drop log lines, want 1 in one minute", n)
	}
}

func TestHintPatchShape(t *testing.T) {
	at := time.Date(2026, 11, 14, 9, 30, 0, 0, time.FixedZone("x", 3600))
	kube := fake.NewSimpleClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "poc-system", Name: "cell-key-hints"}})
	var patches []k8stesting.PatchAction
	kube.PrependReactor("*", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if pa, ok := a.(k8stesting.PatchAction); ok {
			patches = append(patches, pa)
		}
		return false, nil, nil
	})
	w := newConfigMapHints(kube.CoreV1(), "poc-system", "cell-key-hints", hclog.NewNullLogger())
	if err := w.Hint(context.Background(), "dev-cell-1", at); err != nil {
		t.Fatal(err)
	}
	if len(patches) != 1 {
		t.Fatalf("%d patches, want 1", len(patches))
	}
	p := patches[0]
	const want = `{"data":{"dev-cell-1":"{\"at\":\"2026-11-14T08:30:00Z\"}"}}`
	if p.GetPatchType() != types.MergePatchType || string(p.GetPatch()) != want || p.GetName() != "cell-key-hints" || p.GetNamespace() != "poc-system" {
		t.Fatalf("patch = %s %s %s/%s, want merge patch %s", p.GetPatchType(), p.GetPatch(), p.GetNamespace(), p.GetName(), want)
	}
	cm, err := kube.CoreV1().ConfigMaps("poc-system").Get(context.Background(), "cell-key-hints", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := cm.Data["dev-cell-1"]; got != `{"at":"2026-11-14T08:30:00Z"}` {
		t.Fatalf("data = %q", got)
	}
}

func TestHintNeverCreatesConfigMap(t *testing.T) {
	kube := fake.NewSimpleClientset()
	logs := &syncBuffer{}
	log := hclog.New(&hclog.LoggerOptions{Level: hclog.Debug, Output: logs})
	w := newConfigMapHints(kube.CoreV1(), "poc-system", "cell-key-hints", log)
	now := testNow
	w.(*configMapHints).now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		err := w.Hint(context.Background(), "dev-cell-1", now)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("error = %v, want NotFound", err)
		}
	}
	for _, a := range kube.Actions() {
		if a.GetVerb() == "create" {
			t.Fatalf("unexpected %s", a.GetVerb())
		}
	}
	if n := strings.Count(logs.String(), "hints_configmap_missing"); n != 1 {
		t.Fatalf("%d missing lines, want 1 in a minute", n)
	}
	now = now.Add(61 * time.Second)
	_ = w.Hint(context.Background(), "dev-cell-1", now)
	if n := strings.Count(logs.String(), "hints_configmap_missing"); n != 2 {
		t.Fatalf("%d missing lines after a minute, want 2", n)
	}
}

func TestHintConfigValidation(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	base := f.base
	cases := []struct {
		name  string
		extra string
		ok    bool
	}{
		{"off", "", true},
		{"on", hintHCL, true},
		{"minimum interval", hintHCL + "hint_min_interval = \"10s\"\n", true},
		{"interval alone is checked", "hint_min_interval = \"9s\"\n", false},
		{"below minimum", hintHCL + "hint_min_interval = \"9s\"\n", false},
		{"not a duration", hintHCL + "hint_min_interval = \"soon\"\n", false},
		{"no name", "hint_configmap = \"poc-system\"\n", false},
		{"three parts", "hint_configmap = \"a/b/c\"\n", false},
		{"empty namespace", "hint_configmap = \"/b\"\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := &configv1.ConfigureRequest{CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: testTrustDomain}, HclConfiguration: base + c.extra}
			p := New()
			p.newHints = func(string) (HintWriter, error) { return newFakeHints(), nil }
			t.Cleanup(func() { _ = p.Close() })
			_, cerr := p.Configure(context.Background(), req)
			v, _ := p.Validate(context.Background(), &configv1.ValidateRequest{CoreConfiguration: req.CoreConfiguration, HclConfiguration: req.HclConfiguration})
			if (cerr == nil) != c.ok || v.GetValid() != c.ok {
				t.Fatalf("Configure error %v, Validate valid %v, want ok = %v", cerr, v.GetValid(), c.ok)
			}
		})
	}
}
