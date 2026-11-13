package mgmt

import (
	"errors"
	"testing"
)

func TestRestoreUnknownRevisionWrapsTheSentinel(t *testing.T) {
	r := newRig(t)
	err := r.plane.Restore(99)
	if !errors.Is(err, ErrRevisionUnknown) {
		t.Fatalf("Restore(99): %v", err)
	}
	if err := r.plane.IfSeq(r.status().Seq).Restore(99); !errors.Is(err, ErrRevisionUnknown) {
		t.Fatalf("guarded Restore(99): %v", err)
	}
}
