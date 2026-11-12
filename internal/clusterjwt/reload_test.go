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
	if old != "" {
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
	if got := f.plugin.st.Load().records["dev-cell-1"].Counter; got != 1 {
		t.Fatalf("a record with another digest than its entry loaded (counter %d)", got)
	}
	f.wantLog(`"@message":"record_mismatch"`)
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
	r2, e2 := f.recordAt("dev-cell-2", 1, func(c *record.Cell) { c.Issuer = "https://other.example" })
	f.publish(f.specAt(2, []envspec.Entry{e1, e2}), map[string][]byte{"dev-cell-1": r1, "dev-cell-2": r2})
	f.reload()
	f.wantLog(`"@message":"record_conflict"`)
	st := f.plugin.st.Load()
	if st.digests["dev-cell-2"] != before || st.records["dev-cell-2"].Issuer == "https://other.example" {
		t.Fatal("a second record at the same revision replaced the first")
	}
	f.wantAttests("dev-cell-2")
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
