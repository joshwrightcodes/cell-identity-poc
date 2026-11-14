package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
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
	requestCell(t, plane)
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
	code, out := ctl("--expect-seq", "0", "rotate-key", "--emergency")
	lines := jsonLines(t, out)
	if code != 1 || len(lines) != 1 || !strings.Contains(lines[0]["error"].(string), "conflict") || published.Load() != 0 {
		t.Fatalf("stale rotate: %d %q", code, out)
	}
	if after := oneLine("status"); after["seq"] != st["seq"] {
		t.Fatalf("seq moved from %v to %v", st["seq"], after["seq"])
	}
	rot := oneLine("--expect-seq", itoa(int(seq)), "rotate-key", "--emergency")
	if rot["spec.pub"] == pk["spec.pub"] || published.Load() != 1 {
		t.Fatalf("rotate %v, published %d", rot, published.Load())
	}
	if now := oneLine("pubkey"); now["spec.pub"] != rot["spec.pub"] {
		t.Fatal("pubkey after the rotation")
	}

	for name, args := range map[string][]string{
		"no_command": {}, "unknown": {"nope"}, "keys_without_cell": {"keys"},
		"restore_without_revision": {"restore"}, "bad_expect": {"--expect-seq", "x", "status"},
		"rotate_two_modes": {"rotate-key", "--stage", "--commit"}, "rotate_stage_emergency": {"rotate-key", "--stage", "--emergency"},
		"flag_of_another_command": {"keycheck", "--cell", "dev-cell-1", "--stage"}, "op_flag_on_status": {"status", "--line", "x"},
		"revision_on_keys": {"keys", "--cell", "dev-cell-1", "--revision", "1"}, "line_on_op_get": {"op", "get", "--line", "x", "--id", "a"},
		"op_without_command": {"op"}, "op_unknown": {"op", "nope"}, "op_create_without_line": {"op", "create", "--cell", "dev-cell-1"},
		"op_get_without_id": {"op", "get"}, "op_get_two_ids": {"op", "get", "a", "b"}, "op_list_with_id": {"op", "list", "x"},
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
	requestCell(t, plane)
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
		{"--expect-seq", "0", "rotate-key", "--stage"},
		{"--expect-seq", "0", "rotate-key", "--emergency"},
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
	code, out = ctl("rotate-key", "--emergency")
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

// The admin directory must belong to the process, unless it has the sticky bit.
func TestListenAdminRefusesAForeignDirectory(t *testing.T) {
	base, err := os.MkdirTemp("", "fo")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir := filepath.Join(base, "d")
	must(t, os.Mkdir(dir, 0o700))
	oldEuid := euid
	euid = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { euid = oldEuid })
	if _, err := listenAdmin(filepath.Join(dir, "a.sock")); err == nil {
		t.Fatal("a directory of another uid was accepted")
	}
	must(t, os.Chmod(dir, 0o700|os.ModeSticky))
	ln, err := listenAdmin(filepath.Join(dir, "a.sock"))
	if err != nil {
		t.Fatalf("a sticky directory was refused: %v", err)
	}
	ln.Close()
}

// A directory that changes between the check and the bind is refused.
func TestListenAdminRechecksTheDirectory(t *testing.T) {
	base, err := os.MkdirTemp("", "re")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir := filepath.Join(base, "d")
	must(t, os.Mkdir(dir, 0o700))
	afterListen = func() {
		must(t, os.Rename(dir, filepath.Join(base, "moved")))
		must(t, os.Mkdir(dir, 0o700))
	}
	t.Cleanup(func() { afterListen = nil })
	if ln, err := listenAdmin(filepath.Join(dir, "a.sock")); err == nil {
		ln.Close()
		t.Fatal("a swapped directory was accepted")
	}
}

// ctl refuses a socket that another user owns, and a path that is not a socket.
func TestCtlRefusesAForeignSocket(t *testing.T) {
	ctl, _ := newAdminRig(t, nil)
	if code, out := ctl("status"); code != 0 {
		t.Fatalf("own socket: %d %s", code, out)
	}
	oldEuid := euid
	euid = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { euid = oldEuid })
	code, out := ctl("status")
	lines := jsonLines(t, out)
	if code != 1 || len(lines) != 1 || !strings.Contains(lines[0]["error"].(string), "owned by uid") {
		t.Fatalf("foreign socket: %d %q", code, out)
	}
}

// bindFixture binds dev-cell-1 and serves the admin socket of that plane.
func bindFixture(t *testing.T, f *fixture) (func(args ...string) (int, string), *mgmt.Plane) {
	t.Helper()
	plane := seedBoundState(t, f)
	sock := filepath.Join(f.sockDir, "b.sock")
	ln, err := listenAdmin(sock)
	must(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go serveAdmin(ctx, ln, mgmt.NewAdminHandler(plane, func(context.Context, ed25519.PublicKey) error { return nil }))
	return func(args ...string) (int, string) {
		var out bytes.Buffer
		code := execute(ctx, append([]string{"ctl", "--socket", sock}, args...), &out, f.deps())
		return code, out.String()
	}, plane
}

// requestCell asks for dev-cell-1 through the portal, as the cell fixtures of the catalog need.
func requestCell(t *testing.T, plane *mgmt.Plane) {
	t.Helper()
	_, err := plane.PortalRequest(t.Context(), []string{"dev-cell-1"}, strings.Repeat("a", 64))
	must(t, err)
}

// seedRequestedState leaves a state with dev-cell-1 requested and not bound in the data directory
// of f, where a serve then finds it.
func seedRequestedState(t *testing.T, f *fixture) {
	t.Helper()
	in, err := mgmt.LoadIntent(f.args["intent"])
	must(t, err)
	plane, err := mgmt.NewPlane(mgmt.Config{
		Intent: in, KeyPath: filepath.Join(f.dir, "data", "ed25519.key"), Keys: stubKeys{},
		Store: &mgmt.FileStore{Path: filepath.Join(f.dir, "data", "state.json")},
	})
	must(t, err)
	requestCell(t, plane)
}

// seedBoundState binds dev-cell-1 with a token that a stub key source accepts, and leaves the state
// and the signing key in the data directory of f, where a serve then finds a record.
func seedBoundState(t *testing.T, f *fixture) *mgmt.Plane {
	t.Helper()
	signer := kubetoken.NewSigner(t, "kid-1", jose.ES256)
	in, err := mgmt.LoadIntent(f.args["intent"])
	must(t, err)
	plane, err := mgmt.NewPlane(mgmt.Config{
		Intent: in, KeyPath: filepath.Join(f.dir, "data", "ed25519.key"), Keys: signerKeys{signer},
		Store: &mgmt.FileStore{Path: filepath.Join(f.dir, "data", "state.json")},
	})
	must(t, err)
	requestCell(t, plane)
	nonce, err := plane.Nonce("dev-cell-1")
	must(t, err)
	tok := signer.Token(t, kubetoken.Claims{
		Issuer: "https://dev-cell-1.test", Namespace: "cell-identity-system", ServiceAccount: "celld", PodName: "celld-0", PodUID: "uid",
		NodeName: "n", Audience: []string{mgmtapi.BindAudience("dev-cell-1", nonce.Nonce)}, IssuedAt: time.Now(),
	})
	if resp, err := plane.Bind(t.Context(), "dev-cell-1", mgmtapi.BindRequest{Nonce: nonce.Nonce, Token: tok}); err != nil || resp.Status != mgmtapi.StatusBound {
		t.Fatalf("bind: %+v %v", resp, err)
	}
	return plane
}

type signerKeys struct{ s *kubetoken.Signer }

func (k signerKeys) Keys(_ context.Context, cell string) (mgmtapi.ClusterKeys, error) {
	return mgmtapi.ClusterKeys{Name: cell, Issuer: "https://" + cell + ".test", JWKS: k.s.JWKS()}, nil
}

func ctlLine(t *testing.T, ctl func(...string) (int, string), args ...string) map[string]any {
	t.Helper()
	code, out := ctl(args...)
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("ctl %v: exit %d output %q", args, code, out)
	}
	var m map[string]any
	must(t, json.Unmarshal([]byte(out), &m))
	return m
}

func TestOpCommandsPrintOneLine(t *testing.T) {
	ctl, plane := bindFixture(t, newFixture(t))
	created := ctlLine(t, ctl, "op", "create", "--cell", "dev-cell-1", "--line", "hello world", "--ttl", "5m")
	id, _ := created["id"].(string)
	if len(id) != 32 || created["cell"] != "dev-cell-1" || created["state"] != "open" || created["served"] != true || created["envelope"] == nil {
		t.Fatalf("create %v", created)
	}
	// get takes the ID as an argument or as a flag, and shows the same op.
	for _, args := range [][]string{{"op", "get", id}, {"op", "get", "--id", id}} {
		got := ctlLine(t, ctl, args...)
		if got["id"] != id || got["state"] != "open" || got["cell"] != "dev-cell-1" || got["kind"] != "demo.append" || got["envelope"] == nil {
			t.Fatalf("get %v: %v", args, got)
		}
	}
	list := ctlLine(t, ctl, "op", "list", "--cell", "dev-cell-1")
	if ops, _ := list["ops"].([]any); len(ops) != 1 || ops[0].(map[string]any)["id"] != id || ops[0].(map[string]any)["envelope"] != nil {
		t.Fatalf("list %v", list)
	}
	if all := ctlLine(t, ctl, "op", "list"); len(all["ops"].([]any)) != 1 {
		t.Fatalf("list of all %v", all)
	}
	// An op that has not expired does not close, and the error is one line with a reason.
	code, out := ctl("op", "close", id)
	lines := jsonLines(t, out)
	if code != 1 || len(lines) != 1 || lines[0]["reason"] != "operation_not_expired" {
		t.Fatalf("close of an open op: exit %d output %q", code, out)
	}
	code, out = ctl("op", "get", strings.Repeat("0", 32))
	lines = jsonLines(t, out)
	if code != 1 || len(lines) != 1 || lines[0]["reason"] != "operation_unknown" {
		t.Fatalf("get of an unknown op: exit %d output %q", code, out)
	}
	code, out = ctl("op", "create", "--cell", "dev-cell-1", "--line", "x", "--ttl", "soon")
	if lines = jsonLines(t, out); code != 1 || len(lines) != 1 {
		t.Fatalf("create with a bad ttl: exit %d output %q", code, out)
	}
	code, out = ctl("op", "create", "--cell", "dev-cell-1", "--line", "x\ny")
	if lines = jsonLines(t, out); code != 1 || len(lines) != 1 || lines[0]["reason"] != "payload_invalid" {
		t.Fatalf("create with a control character: exit %d output %q", code, out)
	}
	if got := len(plane.OpenOps().Ops); got != 1 {
		t.Fatalf("%d served ops, want 1", got)
	}
}

// ctl op sign records and signs an op, and OpenOps never serves it.
func TestCtlOpSignNotServed(t *testing.T) {
	ctl, plane := bindFixture(t, newFixture(t))
	signed := ctlLine(t, ctl, "op", "sign", "--cell", "dev-cell-1", "--line", "forged by a test")
	id, _ := signed["id"].(string)
	if len(id) != 32 || signed["served"] != false || signed["envelope"] == nil {
		t.Fatalf("sign %v", signed)
	}
	if got := len(plane.OpenOps().Ops); got != 0 {
		t.Fatalf("a signed op was served: %d ops", got)
	}
	got := ctlLine(t, ctl, "op", "get", id)
	if got["served"] != false || got["state"] != "open" {
		t.Fatalf("get of a signed op %v", got)
	}
	// The envelope that sign prints is the one that get prints, and it verifies under the signing key.
	env, err := json.Marshal(signed["envelope"])
	must(t, err)
	genv, _ := json.Marshal(got["envelope"])
	if !bytes.Equal(env, genv) {
		t.Fatalf("sign and get print different envelopes:\n%s\n%s", env, genv)
	}
	if _, _, err := op.Verify(env, []ed25519.PublicKey{plane.PublicKey()}); err != nil {
		t.Fatalf("the envelope does not verify under the signing key: %v", err)
	}
	// create serves.
	ctlLine(t, ctl, "op", "create", "--cell", "dev-cell-1", "--line", "served")
	if got := len(plane.OpenOps().Ops); got != 1 {
		t.Fatalf("%d served ops after create, want 1", got)
	}
}

func TestRotateKeyStageThenCommit(t *testing.T) {
	var mu sync.Mutex
	var published []ed25519.PublicKey
	ctl, plane := newAdminRig(t, func(_ context.Context, pub ed25519.PublicKey) error {
		mu.Lock()
		defer mu.Unlock()
		published = append(published, pub)
		return nil
	})
	old := plane.PublicKey()
	staged := ctlLine(t, ctl, "rotate-key", "--stage")
	next, ok := plane.StagedPublicKey()
	if !ok || staged["staged"] != true || staged["next.pub"] != base64.StdEncoding.EncodeToString(next) || !plane.PublicKey().Equal(old) {
		t.Fatalf("stage %v, staged %v", staged, ok)
	}
	if code, out := ctl("--expect-seq", "0", "rotate-key", "--commit"); code != 1 || jsonLines(t, out)[0]["reason"] != "conflict" {
		t.Fatalf("stale commit: %d %q", code, out)
	}
	if !plane.PublicKey().Equal(old) {
		t.Fatal("a stale commit rotated")
	}
	committed := ctlLine(t, ctl, "rotate-key", "--commit")
	if committed["spec.pub"] != base64.StdEncoding.EncodeToString(next) || !plane.PublicKey().Equal(next) {
		t.Fatalf("commit %v", committed)
	}
	if code, out := ctl("rotate-key", "--commit"); code != 1 || jsonLines(t, out)[0]["reason"] != "not_staged" {
		t.Fatalf("a second commit: %d %q", code, out)
	}
	mu.Lock()
	n := len(published)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("%d publishes, want 2", n)
	}
}

// The bare rotate-key is the emergency rotation of M4: the same answer, and a staged key goes.
func TestCtlBareRotateKeyIsEmergency(t *testing.T) {
	ctl, plane := newAdminRig(t, func(context.Context, ed25519.PublicKey) error { return nil })
	old := plane.PublicKey()
	got := ctlLine(t, ctl, "rotate-key")
	if got["spec.pub"] != base64.StdEncoding.EncodeToString(plane.PublicKey()) || plane.PublicKey().Equal(old) || got["signed"] == nil || got["seq"] == nil || len(got) != 3 {
		t.Fatalf("bare rotate-key: %v", got)
	}
	ctlLine(t, ctl, "rotate-key", "--stage")
	staged, _ := plane.StagedPublicKey()
	em := ctlLine(t, ctl, "rotate-key", "--emergency")
	if _, ok := plane.StagedPublicKey(); ok || em["spec.pub"] == base64.StdEncoding.EncodeToString(staged) || len(em) != 3 {
		t.Fatalf("emergency rotate-key: %v", em)
	}
	ctlLine(t, ctl, "rotate-key", "--stage")
	if bare := ctlLine(t, ctl, "rotate-key"); len(bare) != 3 {
		t.Fatalf("bare rotate-key after a stage: %v", bare)
	}
	if _, ok := plane.StagedPublicKey(); ok {
		t.Fatal("the bare rotate-key left a staged key")
	}
}
