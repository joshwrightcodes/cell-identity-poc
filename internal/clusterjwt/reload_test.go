package clusterjwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	envspec "github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// cmDir writes a directory in the layout that kubelet gives a ConfigMap volume: one timestamped
// directory per version, a ..data link to the current one, and one link per key.
type cmDir struct {
	t    *testing.T
	root string
	gen  int
	// keepOld leaves the previous version directory in place, as kubelet does for a short time.
	keepOld bool
}

func (d *cmDir) write(files map[string][]byte) {
	d.t.Helper()
	d.gen++
	version := fmt.Sprintf("..2026_11_12_00_00_%02d.%d", d.gen, d.gen)
	if err := os.Mkdir(filepath.Join(d.root, version), 0o755); err != nil {
		d.t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(d.root, version, name), data, 0o600); err != nil {
			d.t.Fatal(err)
		}
	}
	old, _ := os.Readlink(filepath.Join(d.root, "..data"))
	d.swap(version)
	for name := range files {
		link := filepath.Join(d.root, name)
		if _, err := os.Lstat(link); err != nil {
			if err := os.Symlink(filepath.Join("..data", name), link); err != nil {
				d.t.Fatal(err)
			}
		}
	}
	entries, err := os.ReadDir(d.root)
	if err != nil {
		d.t.Fatal(err)
	}
	for _, e := range entries {
		if _, keep := files[e.Name()]; !keep && !strings.HasPrefix(e.Name(), "..") {
			if err := os.Remove(filepath.Join(d.root, e.Name())); err != nil {
				d.t.Fatal(err)
			}
		}
	}
	if old != "" && !d.keepOld {
		if err := os.RemoveAll(filepath.Join(d.root, old)); err != nil {
			d.t.Fatal(err)
		}
	}
}

// swap points ..data at version, as kubelet does, with an atomic rename of a new link.
func (d *cmDir) swap(version string) {
	d.t.Helper()
	tmp := filepath.Join(d.root, "..data_tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(version, tmp); err != nil {
		d.t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(d.root, "..data")); err != nil {
		d.t.Fatal(err)
	}
}

func signSpec(t *testing.T, key ed25519.PrivateKey, env string, epoch, counter uint64, cells []envspec.Entry, retired []envspec.Retired) []byte {
	t.Helper()
	cells = slices.Clone(cells)
	retired = slices.Clone(retired)
	slices.SortFunc(cells, func(a, b envspec.Entry) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(retired, func(a, b envspec.Retired) int { return strings.Compare(a.Name, b.Name) })
	out, err := envspec.Sign(envspec.Spec{Env: env, Revision: envspec.Revision{Epoch: epoch, Counter: counter}, Cells: cells, Retired: retired}, key)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// recordAt returns a signed record of the cell at the counter, and its entry in a spec. change edits
// the record before it is signed.
func (f *fixture) recordAt(name string, counter uint64, change ...func(*record.Cell)) ([]byte, envspec.Entry) {
	f.t.Helper()
	rec := f.keys.record(f.t)
	rec.Name, rec.Epoch, rec.Counter = name, 1, counter
	for _, c := range change {
		c(&rec)
	}
	env, err := record.Sign(rec, f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	body, _ := json.Marshal(rec)
	return env, envspec.Entry{Name: name, Revision: envspec.RecordRevision(rec), RecordSHA256: envspec.RecordDigest(body)}
}

func (f *fixture) specAt(counter uint64, cells []envspec.Entry, retired ...envspec.Retired) []byte {
	f.t.Helper()
	return signSpec(f.t, f.priv, testEnv, 1, counter, cells, retired)
}

// publish replaces the whole content of the directory with a new version.
func (f *fixture) publish(specEnv []byte, recs map[string][]byte) {
	f.t.Helper()
	files := map[string][]byte{specFile: specEnv}
	for name, env := range recs {
		files[name+recordSuffix] = env
	}
	f.cm.write(files)
}

// reload ticks the plugin and waits until the reload that the tick started has ended.
func (f *fixture) reload() {
	f.t.Helper()
	select {
	case f.tick <- time.Now():
	case <-time.After(5 * time.Second):
		f.t.Fatal("the reload goroutine did not take the tick")
	}
	select {
	case <-f.reloaded:
	case <-time.After(5 * time.Second):
		f.t.Fatal("the reload did not end")
	}
}

func (f *fixture) cells() []string {
	var out []string
	for name := range f.plugin.st.Load().records {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func (f *fixture) wantCells(want ...string) {
	f.t.Helper()
	if got := f.cells(); !slices.Equal(got, want) {
		f.t.Fatalf("cells = %v, want %v\n%s", got, want, f.logs.String())
	}
}

func (f *fixture) wantLog(substr string) {
	f.t.Helper()
	if !strings.Contains(f.logs.String(), substr) {
		f.t.Fatalf("log lacks %q:\n%s", substr, f.logs.String())
	}
}

func (f *fixture) wantUnknown(cell string) {
	f.t.Helper()
	_, err := f.attest(cell, f.goodToken)
	wantDenied(f.t, err, UnknownCell)
}

func (f *fixture) wantAttests(cell string) {
	f.t.Helper()
	if _, err := f.attest(cell, f.goodToken); err != nil {
		f.t.Fatalf("attest %s: %v\n%s", cell, err, f.logs.String())
	}
}

func TestReloadPicksUpNewRecord(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, cells: []string{"dev-cell-1"}})
	f.wantUnknown("dev-cell-2")
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, e2 := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	f.reload()
	f.wantAttests("dev-cell-2")
	f.wantLog(`"@message":"records reloaded"`)
	f.wantLog(`"cells":["dev-cell-1","dev-cell-2"]`)
}

func TestReloadLogsOnlyWhenTheSetChanges(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, e2 := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	f.reload()
	f.reload()
	if n := strings.Count(f.logs.String(), `"@message":"records reloaded"`); n != 0 {
		t.Fatalf("%d reload lines for an unchanged record set:\n%s", n, f.logs.String())
	}
}

func TestReloadRemovesCell(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	f.wantAttests("dev-cell-2")
	r1, e1 := f.recordAt("dev-cell-1", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1}), map[string][]byte{"dev-cell-1": r1})
	f.reload()
	f.wantCells("dev-cell-1")
	f.wantUnknown("dev-cell-2")
	f.wantAttests("dev-cell-1")
}

func TestReloadKeepsStateOnReadError(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	before := f.plugin.st.Load()
	gone := f.cm.root + ".gone"
	if err := os.Rename(f.cm.root, gone); err != nil {
		t.Fatal(err)
	}
	f.reload()
	if f.plugin.st.Load() != before {
		t.Fatal("an unreadable directory replaced the state")
	}
	f.wantLog(`"@message":"records_unreadable"`)
	f.wantAttests("dev-cell-1")
	if err := os.Rename(gone, f.cm.root); err != nil {
		t.Fatal(err)
	}
}

func TestReloadKeepsLimiter(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, cells: []string{"dev-cell-1"}})
	old := f.plugin.st.Load()
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, e2 := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	f.reload()
	now := f.plugin.st.Load()
	if now == old || len(now.records) != 2 {
		t.Fatal("the reload did not swap the state")
	}
	if now.limit != old.limit || now.gate != old.gate {
		t.Fatal("a reload must keep the limiter and the gate")
	}
}

func TestReloadIntervalConfig(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	hcl := func(extra string) string {
		return fmt.Sprintf("env = \"dev\"\ntrust_domain = %q\nrecords_dir = %q\nrecord_public_keys = [%q]\n%s\n",
			testTrustDomain, dir, base64.StdEncoding.EncodeToString(pub), extra)
	}
	core := &configv1.CoreConfiguration{TrustDomain: testTrustDomain}
	for _, tc := range []struct {
		name, extra string
		valid       bool
		want        time.Duration
	}{
		{"default", "", true, 10 * time.Second},
		{"off", `reload_interval = "0s"`, true, 0},
		{"one second", `reload_interval = "1s"`, true, time.Second},
		{"below one second", `reload_interval = "999ms"`, false, 0},
		{"negative", `reload_interval = "-1s"`, false, 0},
		{"not a duration", `reload_interval = "soon"`, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := New()
			v, err := p.Validate(context.Background(), &configv1.ValidateRequest{CoreConfiguration: core, HclConfiguration: hcl(tc.extra)})
			if err != nil || v.GetValid() != tc.valid {
				t.Fatalf("Validate = %v, %v, want valid %v", v, err, tc.valid)
			}
			_, err = p.Configure(context.Background(), &configv1.ConfigureRequest{CoreConfiguration: core, HclConfiguration: hcl(tc.extra)})
			if (err == nil) != tc.valid {
				t.Fatalf("Configure error = %v, want valid %v", err, tc.valid)
			}
			if tc.valid && p.st.Load().reloadEvery != tc.want {
				t.Fatalf("reloadEvery = %v, want %v", p.st.Load().reloadEvery, tc.want)
			}
		})
	}
}

func TestReloadIntervalOffStartsNoReload(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, extraHCL: `reload_interval = "0s"`})
	select {
	case f.tick <- time.Now():
		t.Fatal("a plugin with reload_interval 0s took a tick")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestReloadFollowsConfigMapLayout(t *testing.T) {
	t.Run("new_version", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{ticker: true, cells: []string{"dev-cell-1"}})
		for i, name := range []string{"dev-cell-2", "dev-cell-3"} {
			var cells []envspec.Entry
			recs := map[string][]byte{}
			for _, n := range []string{"dev-cell-1", "dev-cell-2", "dev-cell-3"}[:i+2] {
				r, e := f.recordAt(n, 1)
				cells, recs[n] = append(cells, e), r
			}
			f.publish(f.specAt(uint64(i+2), cells), recs)
			f.reload()
			f.wantAttests(name)
		}
	})
	t.Run("one_version_per_load", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{ticker: true, cells: []string{"dev-cell-1"}})
		r1, e1 := f.recordAt("dev-cell-1", 1)
		f.publish(f.specAt(2, []envspec.Entry{e1}), map[string][]byte{"dev-cell-1": r1})
		r2, e2 := f.recordAt("dev-cell-1", 2)
		newVersion := "..2026_11_12_00_00_99.99"
		if err := os.Mkdir(filepath.Join(f.cm.root, newVersion), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{specFile: f.specAt(3, []envspec.Entry{e2}), "dev-cell-1" + recordSuffix: r2} {
			if err := os.WriteFile(filepath.Join(f.cm.root, newVersion, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// The ConfigMap changes while the plugin reads, so the files of one load must all come from
		// the version that the plugin resolved first.
		f.plugin.afterResolve = func() { f.cm.swap(newVersion) }
		f.reload()
		f.plugin.afterResolve = nil
		if got := f.plugin.st.Load().records["dev-cell-1"].Counter; got != 1 {
			t.Fatalf("counter = %d: the load mixed two ConfigMap versions\n%s", got, f.logs.String())
		}
		f.reload()
		if got := f.plugin.st.Load().records["dev-cell-1"].Counter; got != 2 {
			t.Fatalf("counter = %d after the next reload, want 2", got)
		}
	})
}

func TestReloadKeepsHigherRevision(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, mutate: func(rec *record.Cell) { rec.Counter = 3 }})
	r1, e1 := f.recordAt("dev-cell-1", 2)
	r2, e2 := f.recordAt("dev-cell-2", 3)
	f.publish(f.specAt(5, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	f.reload()
	if got := f.plugin.st.Load().records["dev-cell-1"].Counter; got != 3 {
		t.Fatalf("counter = %d, want 3\n%s", got, f.logs.String())
	}
	f.wantLog(`"@message":"record_older_ignored"`)
	f.wantAttests("dev-cell-1")
}

func TestReloadDropThenOlderRefused(t *testing.T) {
	// dropped applies a spec that drops dev-cell-2 and retires it at its revision.
	dropped := func(t *testing.T) (f *fixture, r1, r2 []byte, e1, e2 envspec.Entry) {
		f = newFixture(t, fixtureOptions{ticker: true})
		r1, e1 = f.recordAt("dev-cell-1", 1)
		r2, e2 = f.recordAt("dev-cell-2", 1)
		f.publish(f.specAt(3, []envspec.Entry{e1}, envspec.Retired{Name: "dev-cell-2", Revision: e2.Revision}), map[string][]byte{"dev-cell-1": r1})
		f.reload()
		f.wantCells("dev-cell-1")
		f.wantUnknown("dev-cell-2")
		return f, r1, r2, e1, e2
	}
	t.Run("older_spec", func(t *testing.T) {
		f, r1, r2, e1, e2 := dropped(t)
		before := f.plugin.st.Load()
		f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
		f.reload()
		f.wantLog(`"@message":"spec_older_ignored"`)
		if f.plugin.st.Load() != before {
			t.Fatal("an older spec changed the state")
		}
		f.wantUnknown("dev-cell-2")
	})
	t.Run("newer_spec_old_record", func(t *testing.T) {
		f, r1, r2, e1, e2 := dropped(t)
		f.publish(f.specAt(4, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
		f.reload()
		f.wantCells("dev-cell-1")
		f.wantUnknown("dev-cell-2")
		f.wantLog(`"@message":"record_retired"`)
	})
	t.Run("newer_record_after_retired", func(t *testing.T) {
		f, r1, _, e1, _ := dropped(t)
		r2, e2 := f.recordAt("dev-cell-2", 2)
		f.publish(f.specAt(4, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
		f.reload()
		f.wantAttests("dev-cell-2")
	})
}

func TestReloadRefusesUnindexedRecord(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, cells: []string{"dev-cell-1"}})
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, _ := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	f.reload()
	f.wantCells("dev-cell-1")
	f.wantUnknown("dev-cell-2")
	f.wantLog(`"@message":"record_unindexed"`)
}

func TestReloadRefusesRecordThatDiffersFromItsEntry(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, cells: []string{"dev-cell-1"}})
	r1, _ := f.recordAt("dev-cell-1", 2)
	_, other := f.recordAt("dev-cell-1", 2, func(c *record.Cell) { c.Subjects = nil })
	f.publish(f.specAt(2, []envspec.Entry{other}), map[string][]byte{"dev-cell-1": r1})
	f.reload()
	if rec, ok := f.plugin.st.Load().records["dev-cell-1"]; ok {
		t.Fatalf("a cell whose entry has no matching record is active at counter %d", rec.Counter)
	}
	f.wantLog(`"@message":"record_mismatch"`)
	f.wantUnknown("dev-cell-1")
}

// The accepted spec replaced the record, so a record below the entry must not serve the cell, whatever
// the reason that the new record is missing.
func TestReloadWithheldRecordDoesNotKeepTheOldOne(t *testing.T) {
	revoke := func(c *record.Cell) { c.Revoked = true }
	for _, tc := range []struct {
		name string
		file func(f *fixture, old []byte) []byte
	}{
		{"old_file", func(f *fixture, old []byte) []byte { return old }},
		{"absent_file", func(f *fixture, old []byte) []byte { return nil }},
		{"corrupt_file", func(f *fixture, old []byte) []byte { return []byte("{}") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, fixtureOptions{ticker: true})
			old, _ := f.recordAt("dev-cell-1", 1)
			_, revoked := f.recordAt("dev-cell-1", 2, revoke)
			r2, e2 := f.recordAt("dev-cell-2", 1)
			recs := map[string][]byte{"dev-cell-2": r2}
			if file := tc.file(f, old); file != nil {
				recs["dev-cell-1"] = file
			}
			f.publish(f.specAt(2, []envspec.Entry{revoked, e2}), recs)
			f.reload()
			if rec, ok := f.plugin.st.Load().records["dev-cell-1"]; ok {
				t.Fatalf("the replaced record (counter %d, revoked %v) still serves the cell\n%s", rec.Counter, rec.Revoked, f.logs.String())
			}
			f.wantUnknown("dev-cell-1")
			f.wantAttests("dev-cell-2")
			f.wantLog(`"@message":"record_missing"`)
		})
	}
}

func TestReloadRefusesOlderSpec(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	r1, e1 := f.recordAt("dev-cell-1", 1)
	f.publish(f.specAt(5, []envspec.Entry{e1}), map[string][]byte{"dev-cell-1": r1})
	f.reload()
	f.wantCells("dev-cell-1")
	before := f.plugin.st.Load()
	r2, e2 := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(4, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	f.reload()
	if f.plugin.st.Load() != before {
		t.Fatal("a spec below the spec mark changed the state")
	}
	f.wantLog(`"@message":"spec_older_ignored"`)
	f.wantUnknown("dev-cell-2")
}

func TestReloadRefusesEqualRevisionConflict(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	before := f.plugin.st.Load().digests["dev-cell-2"]
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, e2 := f.recordAt("dev-cell-2", 1, func(c *record.Cell) { c.Revoked = true })
	f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	f.reload()
	f.wantLog(`"@message":"record_conflict"`)
	st := f.plugin.st.Load()
	if rec, ok := st.records["dev-cell-2"]; ok {
		t.Fatalf("a record that the accepted spec does not index serves the cell (digest kept %v, revoked %v)", st.digests["dev-cell-2"] == before, rec.Revoked)
	}
	f.wantUnknown("dev-cell-2")
}

func TestReloadKeepsRecordOnUnreadableFile(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	r1, e1 := f.recordAt("dev-cell-1", 2)
	_, e2 := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1})
	if err := os.Symlink("missing-target", filepath.Join(f.cm.root, "..data", "dev-cell-2"+recordSuffix)); err != nil {
		t.Fatal(err)
	}
	f.reload()
	st := f.plugin.st.Load()
	if st.records["dev-cell-1"].Counter != 2 {
		t.Fatal("the readable record did not load")
	}
	if _, ok := st.records["dev-cell-2"]; !ok {
		t.Fatalf("the unreadable file dropped the record of an indexed cell\n%s", f.logs.String())
	}
	f.wantLog("dev-cell-2.dsse.json")
	f.wantAttests("dev-cell-2")
}

func TestReloadDoesNotLoseConfigure(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, cells: []string{"dev-cell-1"}})
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, e2 := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	calls := 0
	f.plugin.afterLoad = func() {
		calls++
		if calls == 1 {
			f.reconfigure(t, `challenge_timeout = "7s"`)
		}
	}
	f.reload()
	st := f.plugin.st.Load()
	if st.timeout != 7*time.Second {
		t.Fatalf("timeout = %v: the reload overwrote the Configure that ran during it", st.timeout)
	}
	if len(st.records) != 2 {
		t.Fatalf("records = %v: the reload did not retry from the new state", f.cells())
	}
	if calls != 2 {
		t.Fatalf("the reload loaded %d times, want 2", calls)
	}
}

func TestReloadAbsentSpecGivesNoRecords(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	r1, _ := f.recordAt("dev-cell-1", 1)
	f.cm.write(map[string][]byte{"dev-cell-1" + recordSuffix: r1})
	f.reload()
	f.wantCells()
	f.wantUnknown("dev-cell-1")
	f.wantLog(`"@message":"spec_absent"`)
}

func TestReloadLogsARefusalOnce(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, cells: []string{"dev-cell-1"}})
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, _ := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	for range 3 {
		f.reload()
	}
	if n := strings.Count(f.logs.String(), `"@message":"record_unindexed"`); n != 1 {
		t.Fatalf("%d record_unindexed lines for one unchanged file, want 1", n)
	}
}

// restart returns a new plugin that Configures from the same files and settings as f.
func (f *fixture) restart() (*Plugin, *syncBuffer) {
	f.t.Helper()
	logs := &syncBuffer{}
	p := New()
	p.now = func() time.Time { return testNow }
	p.log = hclog.New(&hclog.LoggerOptions{Level: hclog.Debug, Output: logs, JSONFormat: true})
	f.t.Cleanup(func() { _ = p.Close() })
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: testTrustDomain},
		HclConfiguration:  f.base,
	})
	if err != nil {
		f.t.Fatalf("configure after restart: %v", err)
	}
	return p, logs
}

func TestReloadRestartKeepsMarks(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, marks: true})
	oldR1, oldE1 := f.recordAt("dev-cell-1", 1)
	oldR2, oldE2 := f.recordAt("dev-cell-2", 1)
	newR1, newE1 := f.recordAt("dev-cell-1", 2, func(c *record.Cell) { c.Revoked = true })
	f.publish(f.specAt(2, []envspec.Entry{newE1, oldE2}), map[string][]byte{"dev-cell-1": newR1, "dev-cell-2": oldR2})
	f.reload()
	if rec := f.plugin.st.Load().records["dev-cell-1"]; !rec.Revoked {
		t.Fatal("the revocation did not load")
	}
	// A writer replays the spec from before the revocation.
	f.publish(f.specAt(1, []envspec.Entry{oldE1, oldE2}), map[string][]byte{"dev-cell-1": oldR1, "dev-cell-2": oldR2})
	f.reload()
	f.wantLog(`"@message":"spec_older_ignored"`)

	p, logs := f.restart()
	if rec, ok := p.st.Load().records["dev-cell-1"]; ok && !rec.Revoked {
		t.Fatalf("after a restart the replayed spec brought back the revoked cell\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "spec_older_ignored") {
		t.Fatalf("the replayed spec was not refused as older after the restart:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), f.marksPath) {
		t.Fatalf("the refusal does not name the marks file as the source of the mark:\n%s", logs.String())
	}
}

func TestMarksFileIsWrittenBeforeTheStateSwap(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, marks: true})
	fi, err := os.Stat(f.marksPath)
	if err != nil {
		t.Fatalf("the first Configure wrote no marks file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("marks file mode = %v, want 0600", fi.Mode().Perm())
	}
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, e2 := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(7, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	var seen []byte
	before := f.plugin.st.Load()
	f.plugin.afterLoad = func() {
		if f.plugin.st.Load() == before {
			seen, _ = os.ReadFile(f.marksPath)
		}
	}
	f.reload()
	if !strings.Contains(string(seen), `"counter":7`) {
		t.Fatalf("the marks file lacked the raised spec mark when the state was about to swap: %q", seen)
	}
	if entries, _ := os.ReadDir(filepath.Dir(f.marksPath)); len(entries) != 1 {
		t.Fatalf("temporary files remain beside the marks file: %v", entries)
	}
}

func TestMarksFileCorruptFailsClosed(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":       "not json",
		"truncated":     `{"spec":{"epoch":1,"counter":`,
		"unknown_field": `{"spec":{"epoch":1,"counter":1},"cells":{},"retired":[],"extra":1}`,
		"zero_spec":     `{"spec":{"epoch":0,"counter":0},"cells":{},"retired":[]}`,
		"empty":         ``,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, fixtureOptions{marks: true})
			if err := os.WriteFile(f.marksPath, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			p, logs := f.restart()
			if n := len(p.st.Load().records); n != 0 {
				t.Fatalf("%d records served with a corrupt marks file", n)
			}
			if !strings.Contains(logs.String(), `"@message":"marks_unreadable"`) {
				t.Fatalf("no marks_unreadable log:\n%s", logs.String())
			}
			if got, _ := os.ReadFile(f.marksPath); string(got) != content {
				t.Fatal("the plugin overwrote a corrupt marks file")
			}
		})
	}
}

func TestMarksFileAbsentIsAFirstStart(t *testing.T) {
	f := newFixture(t, fixtureOptions{marks: true})
	if err := os.Remove(f.marksPath); err != nil {
		t.Fatal(err)
	}
	p, _ := f.restart()
	if n := len(p.st.Load().records); n != 2 {
		t.Fatalf("%d records after a first start, want 2", n)
	}
	if _, err := os.Stat(f.marksPath); err != nil {
		t.Fatalf("a first start wrote no marks file: %v", err)
	}
}

// unwritable makes the directory of the marks file read-only until the test ends or restore runs.
func (f *fixture) unwritable() (restore func()) {
	f.t.Helper()
	dir := filepath.Dir(f.marksPath)
	if err := os.Chmod(dir, 0o500); err != nil {
		f.t.Fatal(err)
	}
	restore = func() { _ = os.Chmod(dir, 0o700) }
	f.t.Cleanup(restore)
	return restore
}

func (f *fixture) cellRecord(name string) (record.Cell, bool) {
	rec, ok := f.plugin.st.Load().records[name]
	return rec, ok
}

// While the marks file cannot be written, a change that admits a record or raises a mark waits.
func TestMarksUnwritableHoldsAdmissions(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, marks: true})
	before := f.plugin.st.Load()
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, e2 := f.recordAt("dev-cell-2", 1)
	r3, e3 := f.recordAt("dev-cell-3", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1, e2, e3}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2, "dev-cell-3": r3})
	f.unwritable()
	f.reload()
	if f.plugin.st.Load() != before {
		t.Fatal("a change that admits a record changed the state although the marks could not be saved")
	}
	f.plugin.markMu.Lock()
	mark := f.plugin.specMark
	f.plugin.markMu.Unlock()
	if mark.Counter != 1 {
		t.Fatalf("the in-memory spec mark rose to %v although it was not saved", mark)
	}
	f.wantLog(`"@message":"marks_unwritable"`)
	f.wantUnknown("dev-cell-3")
}

// Probe RR2: a revocation needs no persisted mark to be safe, so it applies, and the process keeps it
// against a replay while the file cannot be written.
func TestMarksUnwritableStillRevokes(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, marks: true})
	oldR1, oldE1 := f.recordAt("dev-cell-1", 1)
	oldR2, oldE2 := f.recordAt("dev-cell-2", 1)
	revR1, revE1 := f.recordAt("dev-cell-1", 2, func(c *record.Cell) { c.Revoked = true })
	restore := f.unwritable()
	f.publish(f.specAt(2, []envspec.Entry{revE1, oldE2}), map[string][]byte{"dev-cell-1": revR1, "dev-cell-2": oldR2})
	f.reload()
	if rec, ok := f.cellRecord("dev-cell-1"); !ok || !rec.Revoked {
		t.Fatalf("the revocation did not apply while the marks file was unwritable\n%s", f.logs.String())
	}
	_, err := f.attest("dev-cell-1", f.goodToken)
	wantDenied(t, err, Revoked)
	f.wantAttests("dev-cell-2")
	f.wantLog(`"@message":"marks_unwritable"`)

	f.publish(f.specAt(1, []envspec.Entry{oldE1, oldE2}), map[string][]byte{"dev-cell-1": oldR1, "dev-cell-2": oldR2})
	f.reload()
	if rec, ok := f.cellRecord("dev-cell-1"); ok && !rec.Revoked {
		t.Fatal("a replay brought the revoked cell back while the marks file was unwritable")
	}

	restore()
	f.publish(f.specAt(2, []envspec.Entry{revE1, oldE2}), map[string][]byte{"dev-cell-1": revR1, "dev-cell-2": oldR2})
	f.reload()
	if b, _ := os.ReadFile(f.marksPath); !strings.Contains(string(b), `"counter":2`) {
		t.Fatalf("the marks were not saved after the file became writable: %s", b)
	}
}

func TestMarksUnwritableIsLoggedOnce(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, marks: true})
	if err := os.Remove(f.marksPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.marksPath, 0o700); err != nil {
		t.Fatal(err)
	}
	r1, e1 := f.recordAt("dev-cell-1", 1)
	r2, e2 := f.recordAt("dev-cell-2", 1)
	r3, e3 := f.recordAt("dev-cell-3", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1, e2, e3}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2, "dev-cell-3": r3})
	for range 4 {
		f.reload()
	}
	if n := strings.Count(f.logs.String(), `"@message":"marks_unwritable"`); n != 1 {
		t.Fatalf("%d marks_unwritable lines in one window, want 1", n)
	}
}

// writeMarks puts a marks file in place for the plugin of f.
func (f *fixture) writeMarks(d marksDoc) {
	f.t.Helper()
	if d.Env == "" {
		d.Env = testEnv
	}
	if d.KeySHA256 == "" {
		d.KeySHA256 = keyFingerprint([]ed25519.PublicKey{f.pub})
	}
	b, _ := json.Marshal(d)
	if err := os.WriteFile(f.marksPath, b, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func TestMarksFileCellAndRetiredMarksSurviveRestart(t *testing.T) {
	f := newFixture(t, fixtureOptions{marks: true})
	f.writeMarks(marksDoc{
		Spec:    envspec.Revision{Epoch: 1, Counter: 1},
		Cells:   map[string]envspec.Revision{"dev-cell-1": {Epoch: 1, Counter: 5}, "dev-cell-2": {Epoch: 1, Counter: 1}},
		Retired: []string{"dev-cell-2"},
	})
	p, logs := f.restart()
	for _, want := range []string{`"@message":"record_older_ignored"`, `"@message":"record_retired"`} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log lacks %s:\n%s", want, logs.String())
		}
	}
	if n := len(p.st.Load().records); n != 0 {
		t.Fatalf("%d records served below the persisted marks", n)
	}
}

func TestMarksFileOfAnotherEnvOrKeyFailsClosed(t *testing.T) {
	for name, d := range map[string]marksDoc{
		"other_env": {Env: "prod"},
		"other_key": {KeySHA256: strings.Repeat("ab", 32)},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, fixtureOptions{marks: true})
			d.Spec = envspec.Revision{Epoch: 1, Counter: 1}
			d.Cells = map[string]envspec.Revision{}
			f.writeMarks(d)
			p, logs := f.restart()
			if n := len(p.st.Load().records); n != 0 {
				t.Fatalf("%d records served with a marks file of another environment or key", n)
			}
			if l := logs.String(); !strings.Contains(l, `"@message":"marks_foreign"`) || !strings.Contains(l, f.marksPath) {
				t.Fatalf("no marks_foreign line with the path:\n%s", l)
			}
		})
	}
}

func TestMarksFileEmptyWarnsOnce(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.reconfigure(t, "")
	f.reconfigure(t, "")
	if n := strings.Count(f.logs.String(), `"@message":"marks_memory_only"`); n != 1 {
		t.Fatalf("%d marks_memory_only warnings, want 1", n)
	}
}

func TestConfigureReloadsAgainstTheCurrentState(t *testing.T) {
	t.Run("older_spec", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{ticker: true})
		_, e1 := f.recordAt("dev-cell-1", 1)
		r1, _ := f.recordAt("dev-cell-1", 1)
		f.publish(f.specAt(5, []envspec.Entry{e1}), map[string][]byte{"dev-cell-1": r1})
		f.reload()
		f.wantCells("dev-cell-1")
		r2, e2 := f.recordAt("dev-cell-2", 1)
		f.publish(f.specAt(3, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
		f.reconfigure(t, `challenge_timeout = "9s"`)
		f.wantCells("dev-cell-1")
	})
	t.Run("equal_revision_conflict", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{ticker: true})
		want := f.plugin.st.Load().digests["dev-cell-2"]
		r1, e1 := f.recordAt("dev-cell-1", 1)
		r2, e2 := f.recordAt("dev-cell-2", 1, func(c *record.Cell) { c.Issuer = "https://other.example" })
		f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
		f.reconfigure(t, `challenge_timeout = "9s"`)
		if got, ok := f.plugin.st.Load().digests["dev-cell-2"]; ok {
			t.Fatalf("a Configure kept or accepted a record that conflicts at an equal revision (kept original %v)", got == want)
		}
	})
}

func TestReloadReconfigureAppliesTheInterval(t *testing.T) {
	t.Run("test_ticker", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{ticker: true})
		f.reconfigure(t, `reload_interval = "0s"`)
		r1, e1 := f.recordAt("dev-cell-1", 1)
		f.publish(f.specAt(2, []envspec.Entry{e1}), map[string][]byte{"dev-cell-1": r1})
		f.tick <- time.Now()
		time.Sleep(200 * time.Millisecond)
		if len(f.reloaded) != 0 || len(f.cells()) != 2 {
			t.Fatal("a plugin reconfigured to 0s kept reloading")
		}
		f.reconfigure(t, `reload_interval = "1s"`)
		f.reload()
		f.wantCells("dev-cell-1")
	})
	t.Run("real_ticker", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{})
		f.reconfigure(t, `reload_interval = "10s"`)
		if got := time.Duration(f.plugin.tickEvery.Load()); got != 10*time.Second {
			t.Fatalf("interval in effect = %v, want 10s", got)
		}
		f.reconfigure(t, `reload_interval = "3s"`)
		if got := time.Duration(f.plugin.tickEvery.Load()); got != 3*time.Second {
			t.Fatalf("interval in effect = %v, want 3s", got)
		}
		f.reconfigure(t, `reload_interval = "0s"`)
		if got := f.plugin.tickEvery.Load(); got != 0 {
			t.Fatalf("interval in effect = %v, want 0", got)
		}
		f.wantLog(`"reload_interval":"0s"`)
	})
}

func waitLoops(t *testing.T, p *Plugin, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for p.loops.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%d reload goroutines, want %d", p.loops.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestReloadGoroutineLifecycle(t *testing.T) {
	t.Run("one_for_many_configures_and_close_ends_it", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{extraHCL: `reload_interval = "10s"`})
		f.reconfigure(t, `reload_interval = "10s"`)
		f.reconfigure(t, `reload_interval = "10s"`)
		waitLoops(t, f.plugin, 1)
		if err := f.plugin.Close(); err != nil {
			t.Fatal(err)
		}
		waitLoops(t, f.plugin, 0)
		if err := f.plugin.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	})
	t.Run("stop_channel_ends_it", func(t *testing.T) {
		stop := make(chan struct{})
		p := newWithTicker(make(chan time.Time), stop)
		p.applyInterval(time.Second)
		waitLoops(t, p, 1)
		close(stop)
		waitLoops(t, p, 0)
	})
}

func TestReloadForeignEnvSpecRaisesNoMark(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	before := f.plugin.st.Load()
	r1, e1 := f.recordAt("dev-cell-1", 1)
	f.publish(signSpec(t, f.priv, "prod", 1, 99, []envspec.Entry{e1}, nil), map[string][]byte{"dev-cell-1": r1})
	f.reload()
	f.wantLog(`"@message":"spec_env_mismatch"`)
	if f.plugin.st.Load() != before {
		t.Fatal("a spec for another environment changed the state")
	}
	r2, e2 := f.recordAt("dev-cell-2", 1)
	f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	f.reload()
	f.wantCells("dev-cell-1", "dev-cell-2")
	f.plugin.markMu.Lock()
	defer f.plugin.markMu.Unlock()
	if f.plugin.specMark.Counter != 2 {
		t.Fatalf("spec mark = %v, want counter 2", f.plugin.specMark)
	}
}

func TestReloadInvalidSpecKeepsState(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for name, make := range map[string]func(f *fixture) []byte{
		"foreign_key": func(f *fixture) []byte { return signSpec(f.t, other, testEnv, 1, 9, nil, nil) },
		"garbage":     func(f *fixture) []byte { return []byte("garbage") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, fixtureOptions{ticker: true})
			before := f.plugin.st.Load()
			f.publish(make(f), nil)
			f.reload()
			f.wantLog(`"@message":"spec_invalid"`)
			if f.plugin.st.Load() != before {
				t.Fatal("an invalid spec changed the state")
			}
			f.wantAttests("dev-cell-1")
		})
	}
}

func TestValidateDoesNotRaiseMarks(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	r1, e1 := f.recordAt("dev-cell-1", 1)
	f.publish(f.specAt(9, []envspec.Entry{e1}), map[string][]byte{"dev-cell-1": r1})
	v, err := f.plugin.Validate(context.Background(), &configv1.ValidateRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: testTrustDomain}, HclConfiguration: f.base})
	if err != nil || !v.GetValid() {
		t.Fatalf("Validate = %v, %v", v, err)
	}
	f.plugin.markMu.Lock()
	defer f.plugin.markMu.Unlock()
	if f.plugin.specMark.Counter != 1 || len(f.plugin.marks) != 2 {
		t.Fatalf("Validate raised the marks: spec %v, cells %v", f.plugin.specMark, f.plugin.marks)
	}
}

func TestConfigureFailsOnUnreadableSpec(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(dir, specFile)); err != nil {
		t.Fatal(err)
	}
	p := New()
	t.Cleanup(func() { _ = p.Close() })
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: testTrustDomain},
		HclConfiguration: fmt.Sprintf("env = \"dev\"\ntrust_domain = %q\nrecords_dir = %q\nrecord_public_keys = [%q]\nreload_interval = \"0s\"\n",
			testTrustDomain, dir, base64.StdEncoding.EncodeToString(pub)),
	})
	if err == nil {
		t.Fatal("Configure accepted a spec that it cannot read")
	}
}

func TestReloadLogsUnsignedTextShortened(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	for i, kind := range []string{"A", "B"} {
		body := fmt.Sprintf(`{"payloadType":%q,"payload":"","signatures":[]}`, strings.Repeat(kind, 100_000))
		f.publish([]byte(body), nil)
		f.reload()
		for _, line := range strings.Split(f.logs.String(), "\n") {
			if len(line) > 2000 {
				t.Fatalf("log line of %d bytes after reload %d", len(line), i+1)
			}
		}
	}
	if n := strings.Count(f.logs.String(), `"@message":"spec_invalid"`); n != 2 {
		t.Fatalf("%d spec_invalid lines, want one for each distinct reason", n)
	}
}

func TestReloadUnreadableIsLoggedOncePerWindow(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	gone := f.cm.root + ".gone"
	if err := os.Rename(f.cm.root, gone); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		f.reload()
	}
	if n := strings.Count(f.logs.String(), `"@message":"records_unreadable"`); n != 1 {
		t.Fatalf("%d records_unreadable lines, want 1", n)
	}
	if err := os.Rename(gone, f.cm.root); err != nil {
		t.Fatal(err)
	}
}

// A path that blocks a read must not block a Configure, so the load reads every file before it takes
// the lock of the marks.
func TestLoadReadsFilesWithoutHoldingTheMarksLock(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	var free bool
	f.plugin.afterResolve = func() {
		free = f.plugin.markMu.TryLock()
		if free {
			f.plugin.markMu.Unlock()
		}
	}
	f.reload()
	f.plugin.afterResolve = nil
	if !free {
		t.Fatal("the load held the marks lock while it read the directory")
	}
}

// Probe RR4: a Configure that resolved the old ConfigMap version while a reload applied a revocation
// must not store records below the persisted marks, and a later replay must not bring them back.
func TestConfigureDuringReloadKeepsTheRevocation(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, marks: true})
	f.cm.keepOld = true
	oldR1, oldE1 := f.recordAt("dev-cell-1", 1)
	oldR2, oldE2 := f.recordAt("dev-cell-2", 1)
	revR1, revE1 := f.recordAt("dev-cell-1", 2, func(c *record.Cell) { c.Revoked = true })
	f.plugin.afterResolve = func() {
		f.plugin.afterResolve = nil
		f.publish(f.specAt(2, []envspec.Entry{revE1, oldE2}), map[string][]byte{"dev-cell-1": revR1, "dev-cell-2": oldR2})
		f.plugin.reload()
	}
	f.reconfigure(t, `challenge_timeout = "9s"`)
	f.plugin.afterResolve = nil
	if rec, ok := f.cellRecord("dev-cell-1"); ok && !rec.Revoked {
		t.Fatalf("Configure stored a record below the persisted mark\n%s", f.logs.String())
	}
	for range 3 {
		f.publish(f.specAt(1, []envspec.Entry{oldE1, oldE2}), map[string][]byte{"dev-cell-1": oldR1, "dev-cell-2": oldR2})
		f.reload()
	}
	if rec, ok := f.cellRecord("dev-cell-1"); ok && !rec.Revoked {
		t.Fatal("a replayed spec kept the stale record in place")
	}
	f.wantUnknownOrRevoked("dev-cell-1")
}

func (f *fixture) wantUnknownOrRevoked(cell string) {
	f.t.Helper()
	if _, err := f.attest(cell, f.goodToken); err == nil {
		f.t.Fatalf("%s attests", cell)
	}
}

// A reload that swaps its state in after a Configure loaded, and before the Configure stores, must not
// be overwritten by the older load of that Configure.
func TestConfigureThatLosesTheSwapRetries(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true, marks: true})
	oldR2, oldE2 := f.recordAt("dev-cell-2", 1)
	revR1, revE1 := f.recordAt("dev-cell-1", 2, func(c *record.Cell) { c.Revoked = true })
	calls := 0
	f.plugin.beforeStore = func() {
		calls++
		if calls == 1 {
			f.publish(f.specAt(2, []envspec.Entry{revE1, oldE2}), map[string][]byte{"dev-cell-1": revR1, "dev-cell-2": oldR2})
			f.plugin.reload()
		}
	}
	f.reconfigure(t, `challenge_timeout = "9s"`)
	f.plugin.beforeStore = nil
	rec, ok := f.cellRecord("dev-cell-1")
	if !ok || !rec.Revoked {
		t.Fatalf("a Configure overwrote the state that a reload swapped in (present %v)\n%s", ok, f.logs.String())
	}
	if calls != 2 {
		t.Fatalf("the Configure stored after %d attempts, want 2", calls)
	}
	if f.plugin.st.Load().timeout != 9*time.Second {
		t.Fatal("the retried Configure lost its settings")
	}
}

// A Configure that runs after a reload loaded and raised the marks, but before that reload swapped its
// state, finds a base below the marks. A replayed older spec then leaves nothing to repair it, so the
// base must be filtered against the marks.
func TestConfigureBaseBelowMarksIsNotKept(t *testing.T) {
	setup := func(t *testing.T) (f *fixture, replay func()) {
		f = newFixture(t, fixtureOptions{ticker: true, marks: true})
		oldR1, oldE1 := f.recordAt("dev-cell-1", 1)
		oldR2, oldE2 := f.recordAt("dev-cell-2", 1)
		replay = func() {
			f.publish(f.specAt(1, []envspec.Entry{oldE1, oldE2}), map[string][]byte{"dev-cell-1": oldR1, "dev-cell-2": oldR2})
		}
		return f, replay
	}
	run := func(t *testing.T, f *fixture, replay func()) {
		calls := 0
		f.plugin.afterLoad = func() {
			calls++
			if calls == 1 {
				replay()
				f.reconfigure(t, `challenge_timeout = "9s"`)
			}
		}
		f.reload()
		f.plugin.afterLoad = nil
	}
	t.Run("revoked_cell", func(t *testing.T) {
		f, replay := setup(t)
		revR1, revE1 := f.recordAt("dev-cell-1", 2, func(c *record.Cell) { c.Revoked = true })
		r2, e2 := f.recordAt("dev-cell-2", 1)
		f.publish(f.specAt(2, []envspec.Entry{revE1, e2}), map[string][]byte{"dev-cell-1": revR1, "dev-cell-2": r2})
		run(t, f, replay)
		if rec, ok := f.cellRecord("dev-cell-1"); ok && !rec.Revoked {
			t.Fatalf("a record below the persisted mark serves the cell\n%s", f.logs.String())
		}
	})
	t.Run("retired_cell", func(t *testing.T) {
		f, replay := setup(t)
		r1, e1 := f.recordAt("dev-cell-1", 1)
		_, e2 := f.recordAt("dev-cell-2", 1)
		f.publish(f.specAt(2, []envspec.Entry{e1}, envspec.Retired{Name: "dev-cell-2", Revision: e2.Revision}), map[string][]byte{"dev-cell-1": r1})
		run(t, f, replay)
		if _, ok := f.cellRecord("dev-cell-2"); ok {
			t.Fatalf("a retired cell serves again\n%s", f.logs.String())
		}
	})
}
