package testtool

import (
	"fmt"
	"testing"
)

type recorder struct{ skipped, failed string }

func (r *recorder) Helper()                           {}
func (r *recorder) Skipf(format string, args ...any)  { r.skipped = fmt.Sprintf(format, args...) }
func (r *recorder) Fatalf(format string, args ...any) { r.failed = fmt.Sprintf(format, args...) }

func TestNeed(t *testing.T) {
	for _, tc := range []struct {
		ci, want string
	}{{"", "skip"}, {"true", "fail"}} {
		t.Run("CI="+tc.ci, func(t *testing.T) {
			t.Setenv("CI", tc.ci)
			r := &recorder{}
			Need(r, "sh", "no-such-tool-for-the-test")
			switch {
			case tc.want == "skip" && (r.skipped == "" || r.failed != ""):
				t.Fatalf("want a skip, got skip %q and failure %q", r.skipped, r.failed)
			case tc.want == "fail" && r.failed == "":
				t.Fatalf("want a failure under CI=true, got skip %q", r.skipped)
			}
		})
	}
	r := &recorder{}
	Need(r, "sh")
	if r.skipped != "" || r.failed != "" {
		t.Fatalf("a tool on PATH gave skip %q and failure %q", r.skipped, r.failed)
	}
}
