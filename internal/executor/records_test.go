package executor

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

func mustGet(t *testing.T, r *rig, name string) *corev1.ConfigMap {
	t.Helper()
	cm, err := r.client.CoreV1().ConfigMaps(DefaultNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return cm
}

func seedRecord(t *testing.T, r *rig, id string, rec storedRecord) {
	t.Helper()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: recordPrefix + id, Namespace: DefaultNamespace, Labels: recordLabels()},
		Data:       map[string]string{recordKey: encodeRecord(rec)},
	}
	if _, err := r.client.CoreV1().ConfigMaps(DefaultNamespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestStoreFull(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	for i := 0; i < maxRecords; i++ {
		seedRecord(t, r, fmt.Sprintf("%032x", i+1), storedRecord{State: stateClaimed, UpdatedAt: r.clock.Now()})
	}
	res := e.Execute(ctx, r.sign(r.operation(testKind, `{}`)), fence(1, 1))
	if res.Outcome != op.OutcomeStoreFull || res.Reason != op.ReasonStoreFull {
		t.Fatalf("result = %+v", res)
	}
	if n := r.cnt.count(); n != 0 {
		t.Fatalf("count = %d", n)
	}
	if n, _ := e.Count(ctx); n != maxRecords {
		t.Fatalf("records = %d", n)
	}
	// An operation that already has an applied record still answers while the store is full.
	o := r.operation(testKind, `{}`)
	done := op.Result{OpID: o.ID, Outcome: op.OutcomeApplied, At: r.clock.Now()}
	if err := r.client.CoreV1().ConfigMaps(DefaultNamespace).Delete(ctx, recordPrefix+fmt.Sprintf("%032x", 1), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	seedRecord(t, r, o.ID, storedRecord{State: stateApplied, Result: &done})
	res = e.Execute(ctx, r.sign(o), fence(1, 2))
	if res.Outcome != op.OutcomeAlreadyApplied {
		t.Fatalf("full store, known op = %+v", res)
	}
}

func TestGCKeepsRetention(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	now := r.clock.Now()
	day := op.RecordRetention
	claimedKeep := day + op.MaxTTL
	for id, rec := range map[string]storedRecord{
		"a": {State: stateReported, UpdatedAt: now.Add(-day - time.Nanosecond)},
		"b": {State: stateReported, UpdatedAt: now.Add(-day)},
		"c": {State: stateApplied, UpdatedAt: now.Add(-48 * time.Hour)},
		"d": {State: stateClaimed, UpdatedAt: now.Add(-claimedKeep - time.Nanosecond)},
		"e": {State: stateClaimed, UpdatedAt: now.Add(-claimedKeep)},
		"f": {State: stateClaimed, UpdatedAt: now.Add(-time.Hour)},
	} {
		seedRecord(t, r, id, rec)
	}
	if err := e.GC(ctx); err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, cm := range r.records() {
		left = append(left, cm.Name)
	}
	if fmt.Sprint(left) != "[op-b op-c op-e op-f]" {
		t.Fatalf("records left = %v", left)
	}
}

func TestPendingOldestFirst(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	var ids []string
	for i := 0; i < 3; i++ {
		o := r.operation(testKind, `{}`)
		ids = append(ids, o.ID)
		if res := e.Execute(ctx, r.sign(o), fence(1, uint64(i+1))); res.Outcome != op.OutcomeApplied {
			t.Fatalf("%+v", res)
		}
		r.clock.Advance(time.Second)
	}
	if err := e.MarkReported(ctx, ids[1]); err != nil {
		t.Fatal(err)
	}
	p, err := e.Pending(ctx)
	if err != nil || len(p) != 2 || p[0].OpID != ids[0] || p[1].OpID != ids[2] {
		t.Fatalf("pending = %+v, %v", p, err)
	}
}

func TestRecordLabels(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	o := r.operation(op.KindDemoAppend, `{"line":"x"}`)
	e.Execute(ctx, r.sign(o), fence(1, 1))
	for _, name := range []string{recordPrefix + o.ID, demoLogName} {
		cm := mustGet(t, r, name)
		if cm.Labels[labelMadeBy] != "celld" {
			t.Errorf("%s labels = %v", name, cm.Labels)
		}
	}
	if mustGet(t, r, recordPrefix+o.ID).Labels[labelRecord] != "true" {
		t.Errorf("record lacks %s", labelRecord)
	}
}

// A resend from another pod names that pod, and the record keeps the pod that applied the operation.
func TestPendingNamesThisPod(t *testing.T) {
	r := newRig(t)
	a := r.executor("uid-a")
	o := r.operation(testKind, `{}`)
	if res := a.Execute(ctx, r.sign(o), fence(1, 1)); res.Outcome != op.OutcomeApplied {
		t.Fatalf("%+v", res)
	}
	b := r.executor("uid-b")
	p, err := b.Pending(ctx)
	if err != nil || len(p) != 1 {
		t.Fatalf("pending = %+v, %v", p, err)
	}
	if p[0].Pod != b.cfg.Pod || p[0].Pod == a.cfg.Pod {
		t.Fatalf("pod %q, want %q (applier %q)", p[0].Pod, b.cfg.Pod, a.cfg.Pod)
	}
	rec, err := decodeRecord(mustGet(t, r, recordPrefix+o.ID))
	if err != nil || rec.Result == nil || rec.Result.Pod != a.cfg.Pod {
		t.Fatalf("record keeps %+v, %v; want pod %q", rec.Result, err, a.cfg.Pod)
	}
}
