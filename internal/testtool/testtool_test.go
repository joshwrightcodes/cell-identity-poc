package testtool

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
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

func TestSlowWrapper(t *testing.T) {
	Need(t, "bash", "printf")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "printf"), []byte(SlowWrapper("printf", "slow")), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, time.Duration) {
		t.Helper()
		start := time.Now()
		out, err := exec.Command(filepath.Join(dir, "printf"), args...).Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out), time.Since(start)
	}
	if out, d := run(`%s\n`, "slow", "b"); out != "slow\nb\n" || d < 400*time.Millisecond {
		t.Errorf("a matching call printed %q in %v, want both lines with a pause after each", out, d)
	}
	if out, d := run(`%s\n`, "fast", "b"); out != "fast\nb\n" || d > 300*time.Millisecond {
		t.Errorf("another call printed %q in %v, want the output of the tool at once", out, d)
	}
}
