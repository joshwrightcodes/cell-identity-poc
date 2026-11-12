package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

type stubKeys struct{}

func (stubKeys) Keys(_ context.Context, cell string) (mgmtapi.ClusterKeys, error) {
	return mgmtapi.ClusterKeys{Name: cell, Issuer: "https://" + cell + ".test", JWKS: json.RawMessage(`{"keys":[]}`)}, nil
}

func TestAdminCommandsPrintOneLine(t *testing.T) {
	f := newFixture(t)
	in, err := mgmt.LoadIntent(f.args["intent"])
	must(t, err)
	plane, err := mgmt.NewPlane(mgmt.Config{
		Intent: in, KeyPath: filepath.Join(f.dir, "data", "ed25519.key"), Keys: stubKeys{},
		Store: &mgmt.FileStore{Path: filepath.Join(f.dir, "data", "state.json")},
	})
	must(t, err)
	var published atomic.Int32
	publish := func(context.Context, ed25519.PublicKey) error { published.Add(1); return nil }
	sock := filepath.Join(f.sockDir, "c.sock")
	ln, err := listenAdmin(sock)
	must(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go serveAdmin(ctx, ln, mgmt.NewAdminHandler(plane, publish))
	info, err := os.Stat(sock)
	must(t, err)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", info.Mode())
	}

	ctl := func(args ...string) (int, string) {
		var out bytes.Buffer
		code := execute(ctx, append([]string{"ctl", "--socket", sock}, args...), &out, f.deps())
		return code, out.String()
	}
	oneLine := func(args ...string) map[string]any {
		t.Helper()
		code, out := ctl(args...)
		if code != 0 || strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
			t.Fatalf("ctl %v: exit %d output %q", args, code, out)
		}
		var m map[string]any
		must(t, json.Unmarshal([]byte(out), &m))
		return m
	}
	st := oneLine("status")
	if st["env"] != "dev" || st["seq"] == nil || st["seq"].(float64) == 0 {
		t.Fatalf("status %v", st)
	}
	if recs := oneLine("records"); len(recs) != 0 {
		t.Fatalf("records %v", recs)
	}
	pk := oneLine("pubkey")
	if len(pk) != 1 || pk["spec.pub"] == "" {
		t.Fatalf("pubkey %v", pk)
	}
	if k := oneLine("keys", "--cell", "dev-cell-1"); k["issuer"] != "https://dev-cell-1.test" {
		t.Fatalf("keys %v", k)
	}
	if k := oneLine("keycheck", "--cell", "dev-cell-1"); k["result"] != "not_bound" {
		t.Fatalf("keycheck %v", k)
	}
	if r := oneLine("restore", "--revision", "latest"); r["restoreActive"] != false {
		t.Fatalf("restore %v", r)
	}

	// A stale --expect-seq is a conflict and an error line, and changes nothing.
	seq := st["seq"].(float64)
	code, out := ctl("--expect-seq", "0", "rotate-key")
	lines := jsonLines(t, out)
	if code != 1 || len(lines) != 1 || !strings.Contains(lines[0]["error"].(string), "conflict") || published.Load() != 0 {
		t.Fatalf("stale rotate: %d %q", code, out)
	}
	if after := oneLine("status"); after["seq"] != st["seq"] {
		t.Fatalf("seq moved from %v to %v", st["seq"], after["seq"])
	}
	rot := oneLine("--expect-seq", itoa(int(seq)), "rotate-key")
	if rot["spec.pub"] == pk["spec.pub"] || published.Load() != 1 {
		t.Fatalf("rotate %v, published %d", rot, published.Load())
	}
	if now := oneLine("pubkey"); now["spec.pub"] != rot["spec.pub"] {
		t.Fatal("pubkey after the rotation")
	}

	for name, args := range map[string][]string{
		"no_command": {}, "unknown": {"nope"}, "keys_without_cell": {"keys"},
		"restore_without_revision": {"restore"}, "bad_expect": {"--expect-seq", "x", "status"},
	} {
		code, out := ctl(args...)
		if code == 0 || len(jsonLines(t, out)) != 1 {
			t.Errorf("%s: exit %d output %q", name, code, out)
		}
	}
	var absent bytes.Buffer
	exit := execute(ctx, []string{"ctl", "--socket", filepath.Join(f.sockDir, "absent.sock"), "status"}, &absent, f.deps())
	if exit != 1 || len(jsonLines(t, absent.String())) != 1 {
		t.Fatalf("absent socket: %d %q", exit, absent.String())
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func newAdminRig(t *testing.T, publish func(context.Context, ed25519.PublicKey) error) (func(args ...string) (int, string), *mgmt.Plane) {
	t.Helper()
	f := newFixture(t)
	in, err := mgmt.LoadIntent(f.args["intent"])
	must(t, err)
	plane, err := mgmt.NewPlane(mgmt.Config{
		Intent: in, KeyPath: filepath.Join(f.dir, "data", "ed25519.key"), Keys: stubKeys{},
		Store: &mgmt.FileStore{Path: filepath.Join(f.dir, "data", "state.json")},
	})
	must(t, err)
	sock := filepath.Join(f.sockDir, "c.sock")
	ln, err := listenAdmin(sock)
	must(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go serveAdmin(ctx, ln, mgmt.NewAdminHandler(plane, publish))
	return func(args ...string) (int, string) {
		var out bytes.Buffer
		code := execute(ctx, append([]string{"ctl", "--socket", sock}, args...), &out, f.deps())
		return code, out.String()
	}, plane
}

// A stale --expect-seq stops every guarded command through ctl, and changes nothing.
func TestCtlExpectSeqGuardsEveryChange(t *testing.T) {
	ctl, plane := newAdminRig(t, func(context.Context, ed25519.PublicKey) error { return nil })
	before := plane.Status().Seq
	pub := plane.PublicKey()
	for _, args := range [][]string{
		{"--expect-seq", "0", "keycheck", "--cell", "dev-cell-1"},
		{"--expect-seq", "0", "restore", "--revision", "1"},
		{"--expect-seq", "0", "restore", "--revision", "latest"},
		{"--expect-seq", "0", "rotate-key"},
	} {
		code, out := ctl(args...)
		lines := jsonLines(t, out)
		if code != 1 || len(lines) != 1 || lines[0]["reason"] != "conflict" {
			t.Errorf("%v: exit %d, output %q", args, code, out)
		}
	}
	if plane.Status().Seq != before || !plane.PublicKey().Equal(pub) || plane.Status().RestoreActive {
		t.Fatal("a stale command changed state")
	}
	// A GET command refuses the flag.
	for _, c := range []string{"status", "records", "pubkey"} {
		if code, out := ctl("--expect-seq", "1", c); code != 2 || len(jsonLines(t, out)) != 1 {
			t.Errorf("%s with --expect-seq: exit %d output %q", c, code, out)
		}
	}
}

func TestCtlPrintsReasonAndRotated(t *testing.T) {
	ctl, _ := newAdminRig(t, func(context.Context, ed25519.PublicKey) error { return errors.New("api down") })
	code, out := ctl("restore", "--revision", "99")
	lines := jsonLines(t, out)
	if code != 1 || len(lines) != 1 || lines[0]["reason"] != "not_found" {
		t.Fatalf("restore of an unknown revision: %d %q", code, out)
	}
	code, out = ctl("rotate-key")
	lines = jsonLines(t, out)
	if code != 1 || len(lines) != 1 || lines[0]["rotated"] != true || !strings.Contains(lines[0]["error"].(string), "api down") {
		t.Fatalf("rotate with a failing publish: %d %q", code, out)
	}
}

func TestListenAdminDirectory(t *testing.T) {
	base, err := os.MkdirTemp("", "ad")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	// A directory that mgmtd creates has mode 0700.
	ln, err := listenAdmin(filepath.Join(base, "new", "a.sock"))
	must(t, err)
	ln.Close()
	if info, _ := os.Stat(filepath.Join(base, "new")); info.Mode().Perm() != 0o700 {
		t.Fatalf("created directory mode %v", info.Mode().Perm())
	}
	// A directory that group or others can write is refused.
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777} {
		dir := filepath.Join(base, "open"+mode.String())
		must(t, os.Mkdir(dir, 0o700))
		must(t, os.Chmod(dir, mode))
		if _, err := listenAdmin(filepath.Join(dir, "a.sock")); err == nil {
			t.Errorf("directory mode %v was accepted", mode)
		}
	}
	// A directory with mode 0755 that the process owns is fine.
	dir := filepath.Join(base, "ok")
	must(t, os.Mkdir(dir, 0o700))
	must(t, os.Chmod(dir, 0o755))
	ln, err = listenAdmin(filepath.Join(dir, "a.sock"))
	must(t, err)
	ln.Close()
}
