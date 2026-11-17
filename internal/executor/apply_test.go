package executor

import (
	"fmt"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

func TestDemoLogCapped(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	var ids []string
	for i := 0; i < demoLogLines+5; i++ {
		o := r.operation(op.KindDemoAppend, fmt.Sprintf(`{"line":"line %d"}`, i))
		ids = append(ids, o.ID)
		if res := e.Execute(ctx, r.sign(o), fence(1, uint64(i+1))); res.Outcome != op.OutcomeApplied {
			t.Fatalf("op %d: %+v", i, res)
		}
	}
	lines := strings.Split(mustGet(t, r, demoLogName).Data[demoLogKey], "\n")
	if len(lines) != demoLogLines {
		t.Fatalf("%d lines", len(lines))
	}
	if !strings.HasPrefix(lines[0], ids[5]+" ") || !strings.HasPrefix(lines[len(lines)-1], ids[len(ids)-1]+" ") {
		t.Errorf("first %q, last %q", lines[0], lines[len(lines)-1])
	}
}

func TestDemoAppendSkipsKnownID(t *testing.T) {
	r := newRig(t)
	e := r.executor("uid-a")
	o := r.operation(op.KindDemoAppend, `{"line":"x"}`)
	for i := 0; i < 2; i++ {
		if err := applyDemoAppend(ctx, e, o); err != nil {
			t.Fatal(err)
		}
	}
	if got := mustGet(t, r, demoLogName).Data[demoLogKey]; got != o.ID+" x" {
		t.Fatalf("log = %q", got)
	}
}
