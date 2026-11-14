package hostsvc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

func (ae *actorEnv) adminHandler() http.Handler { return NewAdminHandler(ae.a, ae.j) }

func adminDo(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestAdminSteps(t *testing.T) {
	ae := newActorEnv(t, nil)
	s, env := ae.indexed("dev-cell-1", nil)
	ae.submit(s, env)
	rec := adminDo(ae.adminHandler(), "GET", "/steps")
	var out struct {
		Steps   []mgmtapi.StepStatus `json:"steps"`
		Corrupt bool                 `json:"corrupt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 {
		t.Fatalf("%d %s %v", rec.Code, rec.Body.String(), err)
	}
	if len(out.Steps) != 1 || out.Steps[0].ID != s.ID || out.Steps[0].State != mgmtapi.StepQueued || out.Corrupt {
		t.Errorf("answer = %+v", out)
	}
	if strings.Contains(rec.Body.String(), "\n  ") {
		t.Error("the answer is not compact")
	}
}

func TestAdminCancel(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := ae.adminHandler()
	s1, e1 := ae.newStep("dev-cell-1", nil)
	s2, e2 := ae.newStep("dev-cell-2", nil)
	ae.putSpec(nil, nil)
	ae.submit(s1, e1)
	ae.submit(s2, e2)
	if rec := adminDo(h, "POST", "/cancel?step="+s1.ID); rec.Code != 200 {
		t.Fatalf("cancel by step: %d %s", rec.Code, rec.Body.String())
	}
	if st := ae.status(s1.ID); st.State != mgmtapi.StepCancelled || st.Detail != step.DetailCancelled {
		t.Errorf("step 1 = %+v", st)
	}
	if st := ae.status(s2.ID); st.State != mgmtapi.StepQueued {
		t.Errorf("step 2 = %s, want it untouched", st.State)
	}
	if rec := adminDo(h, "POST", "/cancel?cell=dev-cell-2"); rec.Code != 200 {
		t.Fatalf("cancel by cell: %d", rec.Code)
	}
	if st := ae.status(s2.ID); st.State != mgmtapi.StepCancelled {
		t.Errorf("step 2 = %s", st.State)
	}
	for name, target := range map[string]string{
		"nothing_open": "/cancel?cell=dev-cell-2", "no_selector": "/cancel", "both_selectors": "/cancel?cell=a&step=" + s1.ID,
	} {
		if rec := adminDo(h, "POST", target); rec.Code < 400 {
			t.Errorf("%s: status %d, want an error", name, rec.Code)
		}
	}
	if rec := adminDo(h, "GET", "/cancel?step="+s1.ID); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /cancel = %d, want 405", rec.Code)
	}
}

func TestAdminCancelRunning(t *testing.T) {
	ae := newActorEnv(t, nil)
	ae.setScript("creating", "sleep 60")
	s, env := ae.indexed("dev-cell-1", nil)
	ae.start()
	ae.submit(s, env)
	ae.waitState(s.ID, mgmtapi.StepCreating)
	if rec := adminDo(ae.adminHandler(), "POST", "/cancel?cell=dev-cell-1"); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	ae.waitState(s.ID, mgmtapi.StepCancelled)
}

func TestAdminResetJournal(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := ae.adminHandler()
	s, env := ae.indexed("dev-cell-1", nil)
	ae.submit(s, env)
	if rec := adminDo(h, "POST", "/reset-journal"); rec.Code != 200 {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	if len(ae.j.List()) != 0 {
		t.Error("entries survived the reset")
	}
	ae.putEntry(s, env, func(e *JournalEntry) { e.Status.State = mgmtapi.StepAdmitting })
	if rec := adminDo(h, "POST", "/reset-journal"); rec.Code != http.StatusConflict {
		t.Errorf("reset while a stage runs: %d, want 409", rec.Code)
	}
}

func TestAdminLog(t *testing.T) {
	ae := newActorEnv(t, nil)
	h := ae.adminHandler()
	id := strings.Repeat("a", 32)
	if err := os.WriteFile(ae.j.LogPath(id), []byte("line one\nline two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := adminDo(h, "GET", "/log?step="+id)
	if rec.Code != 200 || rec.Body.String() != "line one\nline two\n" {
		t.Errorf("log = %d %q", rec.Code, rec.Body.String())
	}
	if rec := adminDo(h, "GET", "/log?step="+strings.Repeat("b", 32)); rec.Code != 404 {
		t.Errorf("unknown step log = %d", rec.Code)
	}
	for _, bad := range []string{"", "../x", strings.Repeat("A", 32), "abc"} {
		if rec := adminDo(h, "GET", "/log?step="+bad); rec.Code != 400 {
			t.Errorf("step %q = %d, want 400", bad, rec.Code)
		}
	}
	// Follow ends at once for a step that is not in the journal.
	if rec := adminDo(h, "GET", "/log?step="+id+"&follow=1"); rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "line one") {
		t.Errorf("follow of a finished step = %d %q", rec.Code, rec.Body.String())
	}
}

func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "admin.sock")
}

func TestAdminSocketMode(t *testing.T) {
	path := shortSocket(t)
	before := syscall.Umask(0o022)
	syscall.Umask(before)
	ln, err := ListenAdmin(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket: %v mode %v, want a socket with 0600", err, fi)
	}
	after := syscall.Umask(before)
	syscall.Umask(after)
	if after != before {
		t.Errorf("umask after ListenAdmin = %o, want %o restored", after, before)
	}
	ln.Close()
	// A stale socket file is replaced.
	if ln, err = ListenAdmin(path); err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	ln.Close()
	// A path that is not a socket is refused and left alone.
	file := filepath.Join(filepath.Dir(path), "regular")
	if err := os.WriteFile(file, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenAdmin(file); err == nil {
		t.Error("ListenAdmin took a regular file")
	}
	if b, _ := os.ReadFile(file); string(b) != "keep" {
		t.Error("the regular file changed")
	}
	if err := os.Symlink(file, filepath.Join(filepath.Dir(path), "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenAdmin(filepath.Join(filepath.Dir(path), "link")); err == nil {
		t.Error("ListenAdmin took a symbolic link")
	}
}

func TestAdminLogFollowOutlivesTimeout(t *testing.T) {
	oldD, oldP := adminWriteDeadline, adminFollowPoll
	adminWriteDeadline, adminFollowPoll = 150*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { adminWriteDeadline, adminFollowPoll = oldD, oldP })
	ae := newActorEnv(t, nil)
	s, env := ae.newStep("dev-cell-1", nil)
	ae.putEntry(s, env, func(e *JournalEntry) { e.Status.State = mgmtapi.StepAdmitting })
	path := shortSocket(t)
	ln, err := ListenAdmin(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewAdminServer(ae.adminHandler())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	if err := os.WriteFile(ae.j.LogPath(s.ID), []byte("start\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The writer appends for about 1 s, far past the 150 ms deadline of one write.
	go func() {
		f, _ := os.OpenFile(ae.j.LogPath(s.ID), os.O_APPEND|os.O_WRONLY, 0o600)
		defer f.Close()
		for i := range 10 {
			time.Sleep(100 * time.Millisecond)
			_, _ = f.WriteString("tick " + string(rune('0'+i)) + "\n")
		}
		_, _, _ = ae.j.Update(s.ID, func(e *JournalEntry) { e.Status.State = mgmtapi.StepDone })
	}()
	c := NewAdminClient(path)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, err := c.Do(ctx, "GET", "/log?step="+s.ID+"&follow=1")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	b, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("follow ended with %v after %q", err, b)
	}
	if !strings.HasPrefix(string(b), "start\n") || !strings.HasSuffix(string(b), "tick 9\n") {
		t.Errorf("followed log = %q, want every line up to tick 9", b)
	}
	// The same server answers an ordinary request after the follow.
	if out, err := c.Do(ctx, "GET", "/steps"); err != nil {
		t.Errorf("steps after a follow: %v", err)
	} else {
		out.Close()
	}
}

func TestAdminClientError(t *testing.T) {
	path := shortSocket(t)
	if _, err := NewAdminClient(path).Do(context.Background(), "GET", "/steps"); err == nil || !strings.Contains(err.Error(), "admin socket") {
		t.Errorf("no server: %v", err)
	}
	ae := newActorEnv(t, nil)
	ln, _ := ListenAdmin(path)
	srv := NewAdminServer(ae.adminHandler())
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	if _, err := NewAdminClient(path).Do(context.Background(), "POST", "/cancel?cell=none"); err == nil || !strings.Contains(err.Error(), "no open step") {
		t.Errorf("cancel of nothing: %v", err)
	}
}
