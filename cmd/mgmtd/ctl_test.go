package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
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
