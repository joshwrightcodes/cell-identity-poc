package envd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	testNS   = "spire-system"
	testName = "cell-records"
)

var configMaps = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}

// syncBuffer is a log sink that a test reads while the puller writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) lines() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(b.buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			panic("log line is not JSON: " + l)
		}
		out = append(out, m)
	}
	return out
}

func (b *syncBuffer) count(msg string) int {
	n := 0
	for _, m := range b.lines() {
		if m["msg"] == msg {
			n++
		}
	}
	return n
}

func newLog(w io.Writer) *slog.Logger { return slog.New(slog.NewJSONHandler(w, nil)) }

func TestStoreRoundTrip(t *testing.T) {
	f := newFx(t)
	cur, _ := f.base()
	c := fake.NewClientset()
	s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	if err := s.Save(t.Context(), cur); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflectEqual(got, cur) {
		t.Fatalf("loaded %+v, want %+v", got, cur)
	}
	cm, err := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"a.dsse.json", "b.dsse.json", "c.dsse.json", "spec-envelope.json"}
	gotKeys := slices.Sorted(maps.Keys(cm.Data))
	if !slices.Equal(gotKeys, wantKeys) {
		t.Errorf("data keys %v, want %v", gotKeys, wantKeys)
	}
	wantAnn := map[string]string{
		"poc.internal/spec-epoch":      "1",
		"poc.internal/spec-counter":    "5",
		"poc.internal/spec-key-sha256": KeyFingerprint(f.keys()),
	}
	if !maps.Equal(cm.Annotations, wantAnn) {
		t.Errorf("annotations %v, want %v", cm.Annotations, wantAnn)
	}
}

func TestStoreLoadAbsent(t *testing.T) {
	f := newFx(t)
	s := NewConfigMapStore(fake.NewClientset(), testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	got, err := s.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflectEqual(got, Empty()) {
		t.Fatalf("got %+v", got)
	}
}

// guardResourceVersion makes the fake API server answer Conflict to an update whose resourceVersion
// differs from the stored one, and bump the version on each accepted update.
func guardResourceVersion(c *fake.Clientset) {
	var mu sync.Mutex
	c.PrependReactor("update", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		in := a.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		stored, err := c.Tracker().Get(configMaps, in.Namespace, in.Name)
		if err != nil {
			return false, nil, nil
		}
		have := stored.(*corev1.ConfigMap).ResourceVersion
		if in.ResourceVersion != have {
			return true, nil, apierrors.NewConflict(configMaps.GroupResource(), in.Name, errors.New("resourceVersion differs"))
		}
		n, _ := strconv.Atoi(have)
		in.ResourceVersion = strconv.Itoa(n + 1)
		return false, nil, nil
	})
}

func TestStoreSaveUsesResourceVersion(t *testing.T) {
	f := newFx(t)
	cur, items := f.base()
	c := fake.NewClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testName, ResourceVersion: "7"}})
	guardResourceVersion(c)
	s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))

	if err := s.Save(t.Context(), cur); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := s.Save(t.Context(), cur); err != nil {
		t.Fatalf("second save: %v", err)
	}

	stored, err := c.Tracker().Get(configMaps, testNS, testName)
	if err != nil {
		t.Fatal(err)
	}
	outside := stored.(*corev1.ConfigMap).DeepCopy()
	outside.ResourceVersion = "100"
	outside.Labels = map[string]string{"edited": "outside"}
	if err := c.Tracker().Update(configMaps, outside, testNS); err != nil {
		t.Fatal(err)
	}
	next, _, err := Accept(cur, f.bundle(rev(1, 6), append(slices.Clone(items), f.item(f.cell("d", rev(1, 6), false))), []spec.Retired{{Name: "r", Revision: rev(1, 3)}}), testEnv, f.keys())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(t.Context(), next); err != nil {
		t.Fatalf("save after outside update: %v", err)
	}
	got, err := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Annotations["poc.internal/spec-counter"] != "6" || got.Labels["edited"] != "outside" {
		t.Errorf("annotations %v labels %v", got.Annotations, got.Labels)
	}
}

func TestStoreResetsOnlyOnPinChange(t *testing.T) {
	f := newFx(t)
	cur, _ := f.base()
	c := fake.NewClientset()
	old := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	if err := old.Save(t.Context(), cur); err != nil {
		t.Fatal(err)
	}

	var logs syncBuffer
	same := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(&logs))
	got, err := same.Load(t.Context())
	if err != nil || len(got.Cells) != 3 || logs.count("state_reset") != 0 {
		t.Fatalf("same pin: cells=%d err=%v resets=%d", len(got.Cells), err, logs.count("state_reset"))
	}

	rotated := newFx(t)
	moved := NewConfigMapStore(c, testNS, testName, testEnv, rotated.keys(), newLog(&logs))
	got, err = moved.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflectEqual(got, Empty()) {
		t.Errorf("got %+v, want Empty()", got)
	}
	if n := logs.count("state_reset"); n != 1 {
		t.Errorf("state_reset lines: %d, want 1", n)
	}
}

func TestStoreUnverifiableKeepsNotReady(t *testing.T) {
	f := newFx(t)
	cur, _ := f.base()
	c := fake.NewClientset()
	s := NewConfigMapStore(c, testNS, testName, testEnv, f.keys(), newLog(io.Discard))
	if err := s.Save(t.Context(), cur); err != nil {
		t.Fatal(err)
	}
	cm, _ := c.CoreV1().ConfigMaps(testNS).Get(t.Context(), testName, metav1.GetOptions{})
	cm.Data[SpecKey] = string(tamper(t, []byte(cm.Data[SpecKey]), func(p []byte) []byte { return slices.Concat([]byte(" "), p) }))
	if _, err := c.CoreV1().ConfigMaps(testNS).Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Load(t.Context()); !errors.Is(err, ErrStateUnverifiable) || !strings.Contains(err.Error(), "state_unverifiable") {
		t.Fatalf("Load error = %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer srv.Close()
	clk := newClock(3)
	p := NewPuller(PullerConfig{Client: srv.Client(), BaseURL: srv.URL, Env: testEnv, Keys: f.keys(), Store: s, Log: newLog(io.Discard), Now: clk.Now, Sleep: clk.Sleep})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	clk.cancel = cancel
	_ = p.Run(ctx)
	if p.Ready() {
		t.Fatal("puller is Ready with an unverifiable state")
	}
	rec := httptest.NewRecorder()
	HealthHandler(p).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz %d", rec.Code)
	}
	if clk.count() < 3 {
		t.Fatalf("puller did not retry the load: %d sleeps", clk.count())
	}
}
