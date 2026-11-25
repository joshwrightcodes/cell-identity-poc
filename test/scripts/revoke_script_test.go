package scripts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// revokeKubectl is opKubectl with the patch verb that scripts/revoke.sh uses: a merge patch of data, where a null value deletes a key.
// STUB_PIN_WRITE_FAIL fails it, as it fails every other write.
var revokeKubectl = strings.Replace(opKubectl, `  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;`, `  patch)
    [[ "$2" == configmap && " $* " == *" --type=merge "* && " $* " == *" --field-manager=operator "* ]] || { echo "unexpected kubectl patch: $*" >&2; exit 2; }
    f="$STUB_DIR/k/$ctx/$ns/$3.json"
    [[ -f "$f" ]] || { echo "Error from server (NotFound): configmaps \"$3\" not found" >&2; exit 1; }
    [[ -z "${STUB_PIN_WRITE_FAIL:-}" ]] || { echo "Error from server (Forbidden)" >&2; exit 1; }
    p=""
    for ((i = 1; i < $#; i++)); do [[ "${!i}" == -p ]] && { j=$((i + 1)); p="${!j}"; }; done
    jq -c --argjson p "$p" '.data = (((.data // {}) + ($p.data // {})) | with_entries(select(.value != null)))' "$f" >"$f.new" && mv "$f.new" "$f"
    echo "wrote $ctx $ns/$3 $(jq -c .data "$f")" >>"$STUB_DIR/calls" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;`, 1)

// revokeRig is an opRig with a key in the secret manager, the record of two cells in dev-cp and the patch verb in the kubectl stub.
type revokeRig struct {
	*opRig
	key  ed25519.PrivateKey
	name string
}

func newRevokeRig(t *testing.T) *revokeRig {
	t.Helper()
	r := &revokeRig{opRig: newOpRig(t), key: opNewKey(t), name: "poc/operator/20260101T000000Z"}
	if err := os.WriteFile(filepath.Join(r.bin, "kubectl"), []byte(revokeKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	r.installKey(r.key, r.name)
	r.setRecords(nil, map[string]cellRecord{"dev-cell-1": {1, 4, false}, "dev-cell-2": {2, 5, false}})
	return r
}

// cellRecord is the revision and the revoked flag of the record of a cell in ConfigMap cell-records.
type cellRecord struct {
	epoch, counter uint64
	revoked        bool
}

// setRecords writes ConfigMap cell-records of dev-cp: the records of the cells, and the overlay of the held envelopes.
func (r *revokeRig) setRecords(held []string, cells map[string]cellRecord) {
	r.t.Helper()
	raw := make([]json.RawMessage, 0, len(held))
	for _, e := range held {
		raw = append(raw, json.RawMessage(e))
	}
	heldJSON, _ := json.Marshal(raw)
	data := map[string]string{"local-revocations.json": string(heldJSON), "spec-envelope.json": "{}"}
	for name, c := range cells {
		payload, _ := json.Marshal(map[string]any{"name": name, "epoch": c.epoch, "counter": c.counter, "revoked": c.revoked})
		env, _ := json.Marshal(map[string]any{"payloadType": "x", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{}})
		data[name+".dsse.json"] = string(env)
	}
	r.put("kind-dev-cp", "spire-system", "cell-records", data)
}

// sign makes an entry envelope with the key of the rig.
func (r *revokeRig) sign(cell string, epoch, counter uint64, issued time.Time) (id, envelope string) {
	r.t.Helper()
	sum := sha256.Sum256([]byte(cell))
	id = hex.EncodeToString(sum[:8])
	b, err := revoke.Sign(revoke.Entry{ID: id, Env: "dev", Cell: cell, Record: spec.Revision{Epoch: epoch, Counter: counter}, IssuedAt: issued.UTC().Truncate(time.Second)}, r.key)
	if err != nil {
		r.t.Fatal(err)
	}
	return id, string(b)
}

// runRevoke runs scripts/revoke.sh with the arguments and checks that no seed of the secret manager leaked.
func (r *revokeRig) runRevoke(env []string, args ...string) (stdout, stderr string, code int) {
	r.t.Helper()
	path, err := filepath.Abs("../../scripts/revoke.sh")
	if err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{path}, args...)...)
	cmd.Env = r.env(env...)
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			r.t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	r.assertNoSeed(out.String(), errBuf.String())
	return out.String(), errBuf.String(), code
}

func (r *revokeRig) calls() string {
	b, _ := os.ReadFile(filepath.Join(r.stub, "calls"))
	return string(b)
}

func (r *revokeRig) inputs() map[string]string {
	return r.data("kind-dev-cp", "envd-system", "local-revocations")
}

// revokeResult is the line that revoke -- local prints.
type revokeResult struct {
	ID     string `json:"id"`
	Cell   string `json:"cell"`
	Record struct{ Epoch, Counter uint64 }
}

func parseRevokeResult(t *testing.T, out string) revokeResult {
	t.Helper()
	var res revokeResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil {
		t.Fatalf("standard output %q is no JSON object: %v", out, err)
	}
	return res
}

// TestRevokeLocalPipesSeed: local reads the seed of the key that key.env names through the read command, signs the revision of the
// record that envd holds, and writes the entry with the field manager operator. The seed reaches no output, file or call argument
// (the rig checks it), and the entry verifies against the public key.
func TestRevokeLocalPipesSeed(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	out, stderr, code := r.runRevoke(nil, "local", "--cell", "dev-cell-2")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, stderr)
	}
	res := parseRevokeResult(t, out)
	if res.Cell != "dev-cell-2" || res.Record.Epoch != 2 || res.Record.Counter != 5 {
		t.Errorf("result %+v, want dev-cell-2 at the record revision 2.5 that cell-records holds", res)
	}
	envelope := r.inputs()[res.ID+".json"]
	if envelope == "" || len(r.inputs()) != 1 {
		t.Fatalf("ConfigMap local-revocations holds %v, want the one key %s.json", r.inputs(), res.ID)
	}
	e, err := revoke.Verify([]byte(envelope), []ed25519.PublicKey{r.key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatalf("the entry does not verify: %v", err)
	}
	if e.ID != res.ID || e.Env != "dev" || e.Cell != "dev-cell-2" || e.Record != (spec.Revision{Epoch: 2, Counter: 5}) {
		t.Errorf("entry %+v, want id %s, env dev, dev-cell-2 at 2.5", e, res.ID)
	}
	calls := r.calls()
	if !strings.Contains(calls, "secret-read "+r.name+"\n") {
		t.Errorf("calls lack the read of %s:\n%s", r.name, calls)
	}
	if strings.Contains(calls, "secret-write") {
		t.Errorf("revoke wrote to the secret manager:\n%s", calls)
	}
	for _, verb := range []string{"create", "patch"} {
		for line := range strings.SplitSeq(calls, "\n") {
			if strings.HasPrefix(line, "kubectl ") && strings.Contains(line, " "+verb+" ") && !strings.Contains(line, "--field-manager=operator") {
				t.Errorf("a %s without the field manager operator: %s", verb, line)
			}
		}
	}
}

// TestRevokeLocalSignsHeldRevisionOnly: the record revision comes from cell-records and from nowhere else. A revoked record, an
// absent record and a bad cell name stop before the secret manager is read and write nothing.
func TestRevokeLocalSignsHeldRevisionOnly(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	r.setRecords(nil, map[string]cellRecord{"dev-cell-1": {1, 4, false}, "dev-cell-2": {7, 11, false}})
	out, _, code := r.runRevoke(nil, "local", "--cell", "dev-cell-1")
	if res := parseRevokeResult(t, out); code != 0 || res.Record.Epoch != 1 || res.Record.Counter != 4 {
		t.Fatalf("exit %d, %+v, want the revision 1.4 of dev-cell-1 and no other", code, res)
	}
	for name, tc := range map[string]struct {
		cells map[string]cellRecord
		args  []string
		want  string
	}{
		"revoked":  {map[string]cellRecord{"dev-cell-2": {2, 5, true}}, []string{"local", "--cell", "dev-cell-2"}, "revoked already"},
		"absent":   {map[string]cellRecord{"dev-cell-1": {1, 4, false}}, []string{"local", "--cell", "dev-cell-2"}, "holds no record of dev-cell-2"},
		"bad name": {map[string]cellRecord{"dev-cell-2": {2, 5, false}}, []string{"local", "--cell", "Dev_Cell"}, "not a DNS label"},
		"no cell":  {map[string]cellRecord{"dev-cell-2": {2, 5, false}}, []string{"local"}, "usage"},
	} {
		r2 := newRevokeRig(t)
		r2.setRecords(nil, tc.cells)
		out, _, code := r2.runRevoke(nil, tc.args...)
		if code != 1 || !strings.Contains(out, tc.want) {
			t.Errorf("%s: exit %d, output %q, want exit 1 with %q", name, code, out, tc.want)
		}
		if strings.Contains(r2.calls(), "secret-read") || r2.inputs() != nil {
			t.Errorf("%s: the script read the secret manager or wrote an entry:\n%s", name, r2.calls())
		}
	}
}

// TestRevokeLocalAppendsLog: each local run appends its envelope, as written to the ConfigMap, to build/operator/revocations.log. A run
// that fails to apply appends nothing.
func TestRevokeLocalAppendsLog(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	logPath := filepath.Join(r.build, "operator", "revocations.log")
	var ids []string
	for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
		out, stderr, code := r.runRevoke(nil, "local", "--cell", cell)
		if code != 0 {
			t.Fatalf("%s: exit %d\n%s\n%s", cell, code, out, stderr)
		}
		ids = append(ids, parseRevokeResult(t, out).ID)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("the log holds %d lines, want 2:\n%s", len(lines), b)
	}
	for i, id := range ids {
		if lines[i] != r.inputs()[id+".json"] {
			t.Errorf("line %d of the log differs from the entry %s in the ConfigMap", i+1, id)
		}
	}
	r.setRecords(nil, map[string]cellRecord{"dev-cell-1": {1, 4, false}, "dev-cell-2": {2, 5, false}})
	_, _, code := r.runRevoke([]string{"STUB_PIN_WRITE_FAIL=1"}, "local", "--cell", "dev-cell-1")
	after, _ := os.ReadFile(logPath)
	if code != 1 || !bytes.Equal(after, b) {
		t.Errorf("a failed apply: exit %d, log changed %v, want exit 1 and an unchanged log", code, !bytes.Equal(after, b))
	}
}

// TestRevokeLocalKeyNameFallback: the key name comes from key.env, and from spec.name of operator-pub when key.env is absent. Without
// either, the script stops before it reads the secret manager.
func TestRevokeLocalKeyNameFallback(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	envFile := filepath.Join(r.build, "operator", "key.env")
	// key.env wins over spec.name.
	r.put("kind-management", "mgmt-system", "operator-pub", map[string]string{"spec.pub": opPub(r.key), "spec.name": "poc/operator/other"})
	if _, _, code := r.runRevoke(nil, "local", "--cell", "dev-cell-1"); code != 0 {
		t.Fatalf("with key.env: exit %d", code)
	}
	if !strings.Contains(r.calls(), "secret-read "+r.name+"\n") || strings.Contains(r.calls(), "poc/operator/other") {
		t.Errorf("with key.env the read must name %s:\n%s", r.name, r.calls())
	}
	// Without key.env, spec.name decides.
	if err := os.Remove(envFile); err != nil {
		t.Fatal(err)
	}
	spare := "poc/operator/20270101T000000Z"
	if err := os.WriteFile(filepath.Join(r.stub, "secrets", strings.ReplaceAll(spare, "/", "_")), []byte(revoke.FormatSeed(r.key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.put("kind-management", "mgmt-system", "operator-pub", map[string]string{"spec.pub": opPub(r.key), "spec.name": spare})
	if out, stderr, code := r.runRevoke(nil, "local", "--cell", "dev-cell-2"); code != 0 {
		t.Fatalf("without key.env: exit %d\n%s\n%s", code, out, stderr)
	}
	if !strings.Contains(r.calls(), "secret-read "+spare+"\n") {
		t.Errorf("without key.env the read must name %s:\n%s", spare, r.calls())
	}
	// Without a name, no read happens.
	r.put("kind-management", "mgmt-system", "operator-pub", map[string]string{"spec.pub": opPub(r.key)})
	before := strings.Count(r.calls(), "secret-read")
	out, _, code := r.runRevoke(nil, "local", "--cell", "dev-cell-1")
	if code != 1 || !strings.Contains(out, "names the remote key") || strings.Count(r.calls(), "secret-read") != before {
		t.Errorf("no name: exit %d, output %q, want exit 1 and no read", code, out)
	}
}

// TestRevokeLocalFailureLeaksNothing: a refused read stops the run with a fixed text and writes nothing. The text never quotes the
// read command (the rig checks the seed too).
func TestRevokeLocalFailureLeaksNothing(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	out, _, code := r.runRevoke([]string{"STUB_READ_FAIL=1"}, "local", "--cell", "dev-cell-2")
	if code != 1 || !strings.Contains(out, "failed. Nothing was written") || strings.Contains(out, "refused") {
		t.Errorf("exit %d, output %q, want a fixed error that does not quote the read command", code, out)
	}
	if r.inputs() != nil {
		t.Errorf("a failed read wrote %v", r.inputs())
	}
}

// TestRevokeReapply: reapply writes every entry of the log to the ConfigMap, also into a ConfigMap that is absent, and a second run
// changes nothing. A line that is no envelope stops the run before any write.
func TestRevokeReapply(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	id1, e1 := r.sign("dev-cell-1", 1, 4, time.Now())
	id2, e2 := r.sign("dev-cell-2", 2, 5, time.Now())
	logPath := filepath.Join(r.build, "operator", "revocations.log")
	if err := os.WriteFile(logPath, []byte(e1+"\n\n"+e2+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for run := 1; run <= 2; run++ {
		out, stderr, code := r.runRevoke(nil, "reapply")
		if code != 0 || !strings.Contains(out, `"reapplied":2`) {
			t.Fatalf("run %d: exit %d, output %q\n%s", run, code, out, stderr)
		}
		got := r.inputs()
		if len(got) != 2 || got[id1+".json"] != e1 || got[id2+".json"] != e2 {
			t.Fatalf("run %d: ConfigMap holds %v, want both entries as the log holds them", run, got)
		}
	}
	// An entry that is in the ConfigMap and not in the log stays.
	r.put("kind-dev-cp", "envd-system", "local-revocations", map[string]string{"keep.json": "{}"})
	if _, _, code := r.runRevoke(nil, "reapply"); code != 0 || len(r.inputs()) != 3 {
		t.Errorf("reapply removed a key that the log does not hold: exit %d, keys %v", code, r.inputs())
	}
	// A bad line stops the run.
	r2 := newRevokeRig(t)
	if err := os.WriteFile(filepath.Join(r2.build, "operator", "revocations.log"), []byte(e1+"\nnot an envelope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, code := r2.runRevoke(nil, "reapply")
	if code != 1 || !strings.Contains(out, "no entry envelope") || r2.inputs() != nil {
		t.Errorf("a bad line: exit %d, output %q, inputs %v, want exit 1 and no write", code, out, r2.inputs())
	}
	// No log.
	r3 := newRevokeRig(t)
	if out, _, code := r3.runRevoke(nil, "reapply"); code != 1 || !strings.Contains(out, "revocations.log") {
		t.Errorf("no log: exit %d, output %q", code, out)
	}
}

// listed reads the lines of revoke -- list into a map from key to state.
func listed(t *testing.T, out string) map[string]string {
	t.Helper()
	states := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var e struct{ Key, State string }
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %q is no JSON: %v", line, err)
		}
		states[e.Key] = e.State
	}
	return states
}

// TestRevokeClean: list gives each input entry its state: settled (the record is revoked, or the cell has none), stale (the record of
// the cell is newer), held (envd holds it), pending, invalid. clean deletes the stale and the settled keys and keeps the others.
func TestRevokeClean(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	now := time.Now()
	idHeld, held := r.sign("dev-cell-1", 1, 4, now)
	idPending, pending := r.sign("dev-cell-2", 2, 5, now)
	idStale, stale := r.sign("dev-cell-3", 3, 1, now)
	idSettled, settled := r.sign("dev-cell-4x", 1, 1, now)
	idGone, gone := r.sign("dev-cell-55555", 1, 1, now)
	if len(map[string]bool{idHeld: true, idPending: true, idStale: true, idSettled: true, idGone: true}) != 5 {
		t.Fatal("the ids of the fixtures collide")
	}
	// envd holds two more entries that Settle keeps: one whose cell has a newer record that is not revoked, and one whose cell has no record.
	idHeldNewer, heldNewer := r.sign("dev-cell-6", 1, 1, now)
	idHeldGone, heldGone := r.sign("dev-cell-7", 1, 1, now)
	r.setRecords([]string{held, heldNewer, heldGone}, map[string]cellRecord{"dev-cell-1": {1, 4, false}, "dev-cell-2": {2, 5, false}, "dev-cell-3": {3, 2, false},
		"dev-cell-4x": {1, 1, true}, "dev-cell-6": {1, 6, false}})
	r.put("kind-dev-cp", "envd-system", "local-revocations", map[string]string{
		idHeld + ".json": held, idPending + ".json": pending, idStale + ".json": stale, idSettled + ".json": settled, idGone + ".json": gone, "junk.json": "{",
		idHeldNewer + ".json": heldNewer, idHeldGone + ".json": heldGone,
	})
	out, stderr, code := r.runRevoke(nil, "list")
	if code != 0 {
		t.Fatalf("list: exit %d\n%s\n%s", code, out, stderr)
	}
	want := map[string]string{idHeld + ".json": "held", idPending + ".json": "pending", idStale + ".json": "stale", idSettled + ".json": "settled",
		idGone + ".json": "settled", "junk.json": "invalid", idHeldNewer + ".json": "held", idHeldGone + ".json": "held"}
	got := listed(t, out)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("state of %s is %q, want %q", k, got[k], v)
		}
	}
	out, stderr, code = r.runRevoke(nil, "clean")
	if code != 0 {
		t.Fatalf("clean: exit %d\n%s\n%s", code, out, stderr)
	}
	var res struct {
		Removed []string `json:"removed"`
		Kept    int      `json:"kept"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &res); err != nil {
		t.Fatal(err)
	}
	slices.Sort(res.Removed)
	wantRemoved := []string{idStale, idSettled, idGone}
	slices.Sort(wantRemoved)
	if !slices.Equal(res.Removed, wantRemoved) || res.Kept != 5 {
		t.Errorf("clean removed %v and kept %d, want %v and 5", res.Removed, res.Kept, wantRemoved)
	}
	left := r.inputs()
	if len(left) != 5 || left[idHeld+".json"] == "" || left[idPending+".json"] == "" || left["junk.json"] == "" || left[idHeldNewer+".json"] == "" || left[idHeldGone+".json"] == "" {
		t.Errorf("ConfigMap holds %v, want the held (also with a newer record or no record), the pending and the invalid key", left)
	}
	// With no ConfigMap, clean removes nothing and writes nothing.
	r2 := newRevokeRig(t)
	out, _, code = r2.runRevoke(nil, "clean")
	if code != 0 || !strings.Contains(out, `"removed":[]`) || r2.inputs() != nil {
		t.Errorf("no ConfigMap: exit %d, output %q, inputs %v", code, out, r2.inputs())
	}
}

// TestRotateCutRefusalNamesHealAll: the refusal of a rotation during a cut names the command that heals every cut.
func TestRotateCutRefusalNamesHealAll(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	out, _, code := r.run([]string{"STUB_CUT=dev-cp-control-plane:iptables"}, "rotate")
	if code != 1 || !strings.Contains(out, "mise run partition -- heal --all") {
		t.Errorf("exit %d, output %q, want exit 1 and the command partition -- heal --all", code, out)
	}
}

// TestRevokeReapplyWritesLiveEntriesOnly: reapply skips the entries that envd would refuse (stale, settled, no record), writes the
// pending ones, refuses a log line with no 16 hex id, and refuses a write that would pass the 64 keys that envd takes in.
func TestRevokeReapplyWritesLiveEntriesOnly(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	now := time.Now()
	idLive, live := r.sign("dev-cell-2", 2, 5, now)
	_, stale := r.sign("dev-cell-3", 3, 1, now)
	_, settled := r.sign("dev-cell-4x", 1, 1, now)
	_, gone := r.sign("dev-cell-55555", 1, 1, now)
	r.setRecords(nil, map[string]cellRecord{"dev-cell-2": {2, 5, false}, "dev-cell-3": {3, 2, false}, "dev-cell-4x": {1, 1, true}})
	logPath := filepath.Join(r.build, "operator", "revocations.log")
	if err := os.WriteFile(logPath, []byte(strings.Join([]string{live, stale, settled, gone}, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := r.runRevoke(nil, "reapply")
	if code != 0 || !strings.Contains(out, `"reapplied":1`) || !strings.Contains(out, `"skipped":3`) {
		t.Fatalf("exit %d, output %q\n%s", code, out, stderr)
	}
	if got := r.inputs(); len(got) != 1 || got[idLive+".json"] != live {
		t.Errorf("ConfigMap holds %v, want the live entry alone", got)
	}
	// A line whose id is not 16 hex characters stops the run.
	payload, _ := json.Marshal(map[string]any{"id": "short", "cell": "dev-cell-2"})
	bad, _ := json.Marshal(map[string]any{"payloadType": "x", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{}})
	r2 := newRevokeRig(t)
	if err := os.WriteFile(filepath.Join(r2.build, "operator", "revocations.log"), []byte(live+"\n"+string(bad)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, _, code := r2.runRevoke(nil, "reapply"); code != 1 || !strings.Contains(out, "16 hex id") || r2.inputs() != nil {
		t.Errorf("a bad id: exit %d, output %q, inputs %v", code, out, r2.inputs())
	}
	// The ConfigMap holds 64 keys already: a new entry would make 65.
	r3 := newRevokeRig(t)
	_, e := r3.sign("dev-cell-2", 2, 5, now)
	if err := os.WriteFile(filepath.Join(r3.build, "operator", "revocations.log"), []byte(e+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	full := map[string]string{}
	for i := range 64 {
		full[fmt.Sprintf("k%02d.json", i)] = "{"
	}
	r3.put("kind-dev-cp", "envd-system", "local-revocations", full)
	if out, _, code := r3.runRevoke(nil, "reapply"); code != 1 || !strings.Contains(out, "at most 64") || len(r3.inputs()) != 64 {
		t.Errorf("65 keys: exit %d, output %q, keys %d", code, out, len(r3.inputs()))
	}
}
