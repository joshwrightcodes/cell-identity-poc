package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type testSource struct {
	x509svid.Source
	*x509bundle.Bundle
}

func testDeps(t *testing.T) deps {
	ca := spiffetest.NewCA(t, "dev.env.poc.internal")
	return deps{svids: func(context.Context) (svidSource, func(), error) {
		return testSource{ca.Source(t, "spiffe://dev.env.poc.internal/cp/gateway"), ca.Bundle()}, func() {}, nil
	}}
}

func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func keyFile(t *testing.T, dir string) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "spec.pub")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, priv
}

func serveArgs(dir, key string, extra ...string) []string {
	return append([]string{"serve", "--data-dir", filepath.Join(dir, "data"), "--stream-listen", "127.0.0.1:0", "--bind-listen", "127.0.0.1:0",
		"--envd-listen", "127.0.0.1:0", "--health-listen", "127.0.0.1:0", "--admin-socket", filepath.Join(dir, "a.sock"),
		"--env", "dev", "--envd-id", "spiffe://dev.env.poc.internal/envd", "--spec-key-file", key, "--cell-node", "dev-cell-1=127.0.0.1"}, extra...)
}

func oneJSONLine(t *testing.T, out string) map[string]any {
	t.Helper()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("output %q is not one line", out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output %q is not JSON: %v", out, err)
	}
	return m
}

func TestServeRequiresFlags(t *testing.T) {
	dir := shortDir(t)
	key, _ := keyFile(t, dir)
	full := serveArgs(dir, key)
	run := func(args []string) (int, string) {
		var out bytes.Buffer
		return execute(context.Background(), args, strings.NewReader(""), &out, testDeps(t)), out.String()
	}
	for _, flag := range []string{"--env", "--envd-id", "--spec-key-file", "--cell-node"} {
		t.Run("missing"+flag, func(t *testing.T) {
			var args []string
			for i := 0; i < len(full); i++ {
				if full[i] == flag {
					i++
					continue
				}
				args = append(args, full[i])
			}
			code, out := run(args)
			m := oneJSONLine(t, out)
			if code != 2 || !strings.Contains(m["error"].(string), flag) {
				t.Fatalf("exit %d, output %s", code, out)
			}
		})
	}
	for name, args := range map[string][]string{
		"bad_cell_node":  append(append([]string{}, full...), "--cell-node", "x"),
		"bad_cell_ip":    append(append([]string{}, full...), "--cell-node", "dev-cell-2=nope"),
		"dup_cell":       append(append([]string{}, full...), "--cell-node", "dev-cell-1=10.0.0.1"),
		"replica_cap_0":  append(append([]string{}, full...), "--replica-cap", "0"),
		"bad_envd_id":    append(append([]string{}, full...), "--envd-id", "nope"),
		"extra_argument": append(append([]string{}, full...), "stray"),
		"unknown_flag":   append(append([]string{}, full...), "--nope"),
	} {
		t.Run(name, func(t *testing.T) {
			code, out := run(args)
			oneJSONLine(t, out)
			if code != 2 {
				t.Fatalf("exit %d, output %s", code, out)
			}
		})
	}
	t.Run("bad_key_file", func(t *testing.T) {
		bad := filepath.Join(dir, "bad.pub")
		_ = os.WriteFile(bad, []byte("not base64!"), 0o600)
		code, out := run(serveArgs(dir, bad))
		oneJSONLine(t, out)
		if code != 2 {
			t.Fatalf("exit %d, output %s", code, out)
		}
	})
	if code, out := run(nil); code != 2 {
		oneJSONLine(t, out)
		t.Fatalf("no command: exit %d", code)
	}
	if code, out := run([]string{"nope"}); code != 2 || oneJSONLine(t, out)["error"] == nil {
		t.Fatalf("unknown command: exit %d, output %s", code, out)
	}
}

// running starts serve and waits for the listening line.
type running struct {
	out    *lockedBuffer
	cancel context.CancelFunc
	done   chan int
	fields map[string]any
	dir    string
}

func startServe(t *testing.T) *running {
	t.Helper()
	dir := shortDir(t)
	key, _ := keyFile(t, dir)
	out := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{out: out, cancel: cancel, done: make(chan int, 1), dir: dir}
	go func() { r.done <- execute(ctx, serveArgs(dir, key), strings.NewReader(""), out, testDeps(t)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(15 * time.Second):
			t.Error("serve does not stop")
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range strings.Split(out.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "listening" {
				r.fields = m
				return r
			}
		}
		select {
		case code := <-r.done:
			t.Fatalf("serve ended with %d: %s", code, out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("serve did not listen: %s", out.String())
	return nil
}

func TestLogsAreJSON(t *testing.T) {
	r := startServe(t)
	resp, err := http.Get("http://" + r.fields["health"].(string) + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp.Body.Close()
	r.cancel()
	select {
	case code := <-r.done:
		r.done <- code
		if code != 0 {
			t.Fatalf("serve exit %d", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve does not stop")
	}
	lines := strings.Split(strings.TrimSpace(r.out.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("output %q", r.out.String())
	}
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil || m["msg"] == nil || m["level"] == nil {
			t.Fatalf("log line %q is not a JSON log record: %v", l, err)
		}
	}
	if !strings.Contains(r.out.String(), `"msg":"stopped"`) {
		t.Fatalf("no stopped line: %s", r.out.String())
	}
}

func TestAdminCommandsPrintOneLine(t *testing.T) {
	r := startServe(t)
	sock := filepath.Join(r.dir, "a.sock")
	_, priv := keyFile(t, r.dir)
	envelope, err := op.Sign(op.Operation{ID: strings.Repeat("a", 32), Env: "dev", Cell: "dev-cell-1", Kind: op.KindDemoAppend, Version: 1, KeyEpoch: 1,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), Args: json.RawMessage(`{"line":"x"}`)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	ctl := func(stdin string, args ...string) (int, string) {
		var out bytes.Buffer
		code := execute(context.Background(), append([]string{"ctl", "--socket", sock}, args...), strings.NewReader(stdin), &out, deps{})
		return code, out.String()
	}
	for name, c := range map[string]struct {
		stdin string
		args  []string
		field string
	}{
		"status":  {"", []string{"status"}, "epoch"},
		"queue":   {"", []string{"queue", "--cell", "dev-cell-1"}, "items"},
		"enqueue": {string(envelope), []string{"enqueue", "--cell", "dev-cell-1"}, "opId"},
		"replay":  {string(envelope), []string{"enqueue", "--cell", "dev-cell-1", "--replay"}, "replay"},
		"inject":  {`{"kind":"status","cell":"dev-cell-1","body":{},"token":"t"}`, []string{"inject"}, "id"},
		"outbox":  {"", []string{"outbox"}, "items"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out := ctl(c.stdin, c.args...)
			m := oneJSONLine(t, out)
			if code != 0 || m[c.field] == nil {
				t.Fatalf("exit %d, output %s", code, out)
			}
		})
	}
	code, out := ctl("", "queue", "--cell", "dev-cell-1")
	if m := oneJSONLine(t, out); code != 0 || len(m["items"].([]any)) != 1 {
		t.Fatalf("queue after enqueue: %d %s", code, out)
	}
	for name, c := range map[string]struct {
		stdin string
		args  []string
		code  int
	}{
		"queue_needs_cell":  {"", []string{"queue"}, 2},
		"unknown_command":   {"", []string{"nope"}, 2},
		"replay_on_queue":   {"", []string{"queue", "--cell", "dev-cell-1", "--replay"}, 2},
		"enqueue_garbage":   {"garbage", []string{"enqueue", "--cell", "dev-cell-1"}, 1},
		"inject_bad_item":   {`{"kind":"x"}`, []string{"inject"}, 1},
		"cell_on_status":    {"", []string{"status", "--cell", "x"}, 2},
		"stdin_above_1_mib": {strings.Repeat("a", maxCtlInput+1), []string{"inject"}, 2},
	} {
		t.Run(name, func(t *testing.T) {
			code, out := ctl(c.stdin, c.args...)
			m := oneJSONLine(t, out)
			if code != c.code || m["level"] != "ERROR" || m["error"] == nil {
				t.Fatalf("exit %d, output %s", code, out)
			}
		})
	}
	// A missing socket is one error line too.
	var out2 bytes.Buffer
	if code := execute(context.Background(), []string{"ctl", "--socket", filepath.Join(r.dir, "none.sock"), "status"}, strings.NewReader(""), &out2, deps{}); code != 1 {
		t.Fatalf("missing socket: exit %d", code)
	}
	oneJSONLine(t, out2.String())
}

func TestListenAdminModes(t *testing.T) {
	dir := shortDir(t)
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	sock := filepath.Join(dir, "run", "admin.sock")
	ln, err := listenAdmin(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for path, want := range map[string]os.FileMode{filepath.Dir(sock): 0o700, sock: 0o600} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: mode %v, %v; want %v", path, fi, err, want)
		}
	}
	if got := syscall.Umask(0o022); got != 0o022 {
		t.Fatalf("the process umask is %o after listenAdmin", got)
	}
}
