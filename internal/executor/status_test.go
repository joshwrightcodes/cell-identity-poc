package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundleapply"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

func TestStatusFields(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-1")
	expiry := r.clock.Now().Add(30 * time.Minute)
	status := NewStatus("cell-1", "celld-uid-1", "uid-1", "v1", func() time.Time { return expiry }, e)

	first := status()
	if first.Cell != "cell-1" || first.Pod != "celld-uid-1" || first.PodUID != "uid-1" || first.Version != "v1" {
		t.Fatalf("identity fields %+v", first)
	}
	if !first.SVIDExpiresAt.Equal(expiry) || !first.At.Equal(r.clock.Now()) {
		t.Fatalf("times %+v", first)
	}
	if first.Records != 0 || first.Unreported != 0 || !first.OldestUnreportedAt.IsZero() {
		t.Fatalf("empty executor %+v", first)
	}

	a := r.operation(testKind, "{}")
	if res := e.Execute(t.Context(), r.sign(a), fence(1, 1)); res.Outcome != op.OutcomeApplied {
		t.Fatalf("result %+v", res)
	}
	r.clock.Advance(time.Minute)
	b := r.operation(testKind, "{}")
	e.Execute(t.Context(), r.sign(b), fence(1, 2))
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged, err := op.Sign(r.operation(testKind, "{}"), other)
	if err != nil {
		t.Fatal(err)
	}
	if res := e.Execute(t.Context(), forged, fence(1, 3)); res.Reason != op.ReasonSignatureInvalid {
		t.Fatalf("forged result %+v", res)
	}
	if err := e.MarkReported(t.Context(), b.ID); err != nil {
		t.Fatal(err)
	}

	got := status()
	if got.Applied != 2 || got.Refused != 1 || got.ForgedSeen != 1 {
		t.Fatalf("counts %+v", got)
	}
	if got.Records != 2 || got.Unreported != 1 {
		t.Fatalf("records %d unreported %d, want 2 and 1", got.Records, got.Unreported)
	}
	if want := r.clock.Now().Add(-time.Minute); !got.OldestUnreportedAt.Equal(want) {
		t.Fatalf("oldest unreported %v, want %v", got.OldestUnreportedAt, want)
	}
}

func TestStatusSeqRises(t *testing.T) {
	r := newRig(t)
	status := NewStatus("cell-1", "p", "u", "v", func() time.Time { return time.Time{} }, r.executor("uid-1"))
	var last uint64
	for i := range 5 {
		s := status()
		if s.Seq <= last {
			t.Fatalf("call %d: seq %d after %d, want a rising value", i, s.Seq, last)
		}
		last = s.Seq
	}
}

// slowStatus is a bundle applier that records how much of the status deadline is left when its
// read starts.
type slowStatus struct {
	left       time.Duration
	noDeadline bool
}

func (s *slowStatus) Apply(context.Context, string, string, []byte) (bundleapply.Outcome, error) {
	return bundleapply.Outcome{}, nil
}

func (s *slowStatus) Status(ctx context.Context) (*op.BundleStatus, error) {
	dl, ok := ctx.Deadline()
	if !ok {
		s.noDeadline = true
		return nil, errors.New("no deadline")
	}
	s.left = time.Until(dl)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestStatusReadsShareOneDeadline(t *testing.T) {
	r := newRig(t)
	const budget = 400 * time.Millisecond
	r.client.PrependReactor("list", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		time.Sleep(100 * time.Millisecond)
		return false, nil, nil
	})
	e := r.executor("uid-1")
	s := &slowStatus{}
	e.bundle = s
	e.statusTimeout = budget
	start := time.Now()
	st := NewStatus("cell-1", "p", "u", "v", func() time.Time { return time.Time{} }, e)()
	took := time.Since(start)
	if st.Bundle != nil {
		t.Errorf("bundle = %+v", st.Bundle)
	}
	if took > budget+200*time.Millisecond {
		t.Errorf("status took %s with a budget of %s", took, budget)
	}
	if s.noDeadline {
		t.Fatal("the bundle read had no deadline")
	}
	if s.left > budget-150*time.Millisecond {
		t.Errorf("the bundle read had %s left, want the time of the earlier reads taken from %s", s.left, budget)
	}
}
