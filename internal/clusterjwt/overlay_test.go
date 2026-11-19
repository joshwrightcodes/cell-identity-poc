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
	"runtime"
	"strings"
	"testing"

	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	envspec "github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

func newOperatorKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func operatorHCL(pubs ...ed25519.PublicKey) string {
	var q []string
	for _, p := range pubs {
		q = append(q, fmt.Sprintf("%q", base64.StdEncoding.EncodeToString(p)))
	}
	return "operator_public_keys = [" + strings.Join(q, ", ") + "]\n"
}

func signEntry(t *testing.T, key ed25519.PrivateKey, env, cell string) []byte {
	t.Helper()
	env2, err := revoke.Sign(revoke.Entry{
		ID: "0123456789abcdef", Env: env, Cell: cell,
		Record: envspec.Revision{Epoch: 1, Counter: 1}, IssuedAt: testNow,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return env2
}

// putOverlay rewrites the records directory with the same files and one overlay file that holds the
// envelopes. A nil raw removes the file.
func (f *fixture) putOverlay(raw []byte) {
	f.t.Helper()
	files := map[string][]byte{}
	entries, err := os.ReadDir(f.cm.root)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "..") || e.Name() == overlayFile {
			continue
		}
		data, err := os.ReadFile(filepath.Join(f.cm.root, e.Name()))
		if err != nil {
			f.t.Fatal(err)
		}
		files[e.Name()] = data
	}
	if raw != nil {
		files[overlayFile] = raw
	}
	f.cm.write(files)
}

func envelopes(t *testing.T, in ...[]byte) []byte {
	t.Helper()
	list := make([]json.RawMessage, len(in))
	for i, e := range in {
		list[i] = e
	}
	out, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *fixture) wantRevoked(cell, source string) {
	f.t.Helper()
	_, err := f.attest(cell, f.goodToken)
	wantDenied(f.t, err, Revoked)
	f.wantLog(`"source":"` + source + `"`)
}

func overlayFixture(t *testing.T) (*fixture, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := newOperatorKey(t)
	f := newFixture(t, fixtureOptions{ticker: true, extraHCL: operatorHCL(pub)})
	return f, priv
}

func TestAttestOverlayRevoked(t *testing.T) {
	f, op := overlayFixture(t)
	f.wantAttests("dev-cell-1")
	f.putOverlay(envelopes(t, signEntry(t, op, testEnv, "dev-cell-1")))
	f.reload()
	f.wantRevoked("dev-cell-1", "overlay")
	f.wantAttests("dev-cell-2")
	f.wantLog(`"overlay":1`)
}

func TestConfigureAppliesOverlay(t *testing.T) {
	pub, op := newOperatorKey(t)
	f := newFixture(t, fixtureOptions{})
	f.putOverlay(envelopes(t, signEntry(t, op, testEnv, "dev-cell-1")))
	f.reconfigure(t, operatorHCL(pub))
	f.wantRevoked("dev-cell-1", "overlay")
	f.wantAttests("dev-cell-2")
}

func junkArray(n int) []byte {
	return []byte("[" + strings.Repeat("0,", n-1) + "0]")
}

func TestOverlayJunkIsBounded(t *testing.T) {
	cases := map[string][]byte{
		"too many bytes": []byte(`["` + strings.Repeat("a", maxOverlayBytes) + `"]`),
		"junk array":     junkArray(500_000),
		"too many items": junkArray(maxOverlayItems + 1),
		"null":           []byte("null"),
		"trailing close": []byte("[]]"),
		"trailing value": []byte("[] []"),
		"object":         []byte("{}"),
	}
	for name, junk := range cases {
		t.Run(name, func(t *testing.T) {
			f, op := overlayFixture(t)
			f.putOverlay(envelopes(t, signEntry(t, op, testEnv, "dev-cell-1")))
			f.reload()
			f.putOverlay(junk)
			f.reload()
			if _, held := f.plugin.st.Load().overlay["dev-cell-1"]; !held {
				t.Fatal("a junk file dropped the held entry")
			}
			f.wantLog("overlay_unreadable")
			if n := strings.Count(f.logs.String(), "overlay_"); n > 3 {
				t.Fatalf("%d overlay log lines, want at most 3", n)
			}
		})
	}
}

func TestOverlayRefusalsAreSummarised(t *testing.T) {
	f, _ := overlayFixture(t)
	f.putOverlay(junkArray(maxOverlayItems))
	f.reload()
	if n := strings.Count(f.logs.String(), "overlay_entries_refused"); n != 1 {
		t.Fatalf("%d summary lines, want 1:\n%s", n, f.logs.String())
	}
	f.wantLog(fmt.Sprintf(`"count":%d`, maxOverlayItems))
	if st := f.plugin.st.Load(); st.overlayRefused != maxOverlayItems {
		t.Fatalf("refused = %d, want %d", st.overlayRefused, maxOverlayItems)
	}
}

func TestReadRevokedHostileOverlayStaysSmall(t *testing.T) {
	pub, _ := newOperatorKey(t)
	f := newFixture(t, fixtureOptions{})
	f.putOverlay(junkArray(500_000))
	conf := writeServerConf(t, f, f.cm.root, operatorHCL(pub))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := ReadRevoked(conf); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if used := after.TotalAlloc - before.TotalAlloc; used > 8<<20 {
		t.Fatalf("ReadRevoked allocated %d bytes for a hostile file", used)
	}
}

func TestOverlayUnsignedIgnored(t *testing.T) {
	f, _ := overlayFixture(t)
	_, other := newOperatorKey(t)
	f.putOverlay(envelopes(t, signEntry(t, other, testEnv, "dev-cell-1")))
	f.reload()
	f.wantAttests("dev-cell-1")
	f.wantLog("overlay_entries_refused")
	f.wantLog(revoke.DetailSignature)
	if st := f.plugin.st.Load(); st.overlayRefused != 1 || len(st.overlay) != 0 {
		t.Fatalf("refused = %d, held = %d, want 1 and 0", st.overlayRefused, len(st.overlay))
	}
}

func TestOverlayOtherEnvIgnored(t *testing.T) {
	f, op := overlayFixture(t)
	f.putOverlay(envelopes(t, signEntry(t, op, "prod", "dev-cell-1")))
	f.reload()
	f.wantAttests("dev-cell-1")
	f.wantLog(revoke.DetailEnv)
	if st := f.plugin.st.Load(); st.overlayRefused != 1 {
		t.Fatalf("refused = %d, want 1", st.overlayRefused)
	}
}

func TestOverlayNarrowsOnly(t *testing.T) {
	f, op := overlayFixture(t)
	f.putOverlay(envelopes(t, signEntry(t, op, testEnv, "dev-cell-9")))
	f.reload()
	f.wantCells("dev-cell-1", "dev-cell-2")
	f.wantUnknown("dev-cell-9")
	f.wantAttests("dev-cell-1")
	f.wantAttests("dev-cell-2")
}

func TestOverlayUnreadableKeepsHeld(t *testing.T) {
	f, op := overlayFixture(t)
	f.putOverlay(envelopes(t, signEntry(t, op, testEnv, "dev-cell-1")))
	f.reload()
	f.putOverlay([]byte(`{"not":"an array"}`))
	f.reload()
	f.wantLog("overlay_unreadable")
	if _, held := f.plugin.st.Load().overlay["dev-cell-1"]; !held {
		t.Fatal("an unreadable file dropped the held entry")
	}
	f.putOverlay(nil)
	f.reload()
	f.wantAttests("dev-cell-1")
}

func TestOverlayNeedsOperatorKeys(t *testing.T) {
	f := newFixture(t, fixtureOptions{ticker: true})
	_, op := newOperatorKey(t)
	f.putOverlay(envelopes(t, signEntry(t, op, testEnv, "dev-cell-1")))
	f.reload()
	f.wantAttests("dev-cell-1")
	f.wantLog("overlay_ignored")
}

func TestConfigOperatorKeys(t *testing.T) {
	a, _ := newOperatorKey(t)
	b, _ := newOperatorKey(t)
	c, _ := newOperatorKey(t)
	f := newFixture(t, fixtureOptions{})
	ok := map[string]string{"none": "", "one": operatorHCL(a), "two": operatorHCL(a, b), "empty list": "operator_public_keys = []\n"}
	for name, extra := range ok {
		t.Run(name, func(t *testing.T) { f.reconfigure(t, extra) })
	}
	if st := f.reconfigure(t, operatorHCL(a, b)); len(st.operatorKeys) != 2 {
		t.Fatalf("operator keys = %d, want 2", len(st.operatorKeys))
	}
	bad := map[string]string{
		"three":     operatorHCL(a, b, c),
		"duplicate": operatorHCL(a, a),
		"empty key": `operator_public_keys = ["` + base64.StdEncoding.EncodeToString(a) + `", ""]` + "\n",
		"not a key": `operator_public_keys = ["AAAA"]` + "\n",
	}
	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := f.cfg.Configure(context.Background(), &configv1.ConfigureRequest{CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: testTrustDomain}, HclConfiguration: f.base + extra})
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// writeServerConf writes a SPIRE server configuration with the cluster_jwt plugin_data of the fixture.
func writeServerConf(t *testing.T, f *fixture, dir string, extra string) string {
	t.Helper()
	conf := fmt.Sprintf(`server {
  trust_domain = %q
}
plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
    }
  }
  NodeAttestor "cluster_jwt" {
    plugin_cmd = "/run/spire/plugins/cluster-jwt-server"
    plugin_data {
      env = %q
      trust_domain = %q
      records_dir = %q
      record_public_keys = [%q]
      reload_interval = "10s"
      %s
    }
  }
}
`, testTrustDomain, testEnv, testTrustDomain, dir, base64.StdEncoding.EncodeToString(f.pub), extra)
	path := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadRevokedSources(t *testing.T) {
	pub, op := newOperatorKey(t)
	f := newFixture(t, fixtureOptions{})
	// dev-cell-4 has no record and an overlay entry, so it stays out. dev-cell-5 is retired.
	recs := map[string][]byte{}
	var entries []envspec.Entry
	for _, name := range []string{"dev-cell-1", "dev-cell-2", "dev-cell-3"} {
		env, entry := f.recordAt(name, 1, func(r *record.Cell) { r.Revoked = name == "dev-cell-1" })
		recs[name], entries = env, append(entries, entry)
	}
	f.publish(f.specAt(2, entries, envspec.Retired{Name: "dev-cell-5", Revision: envspec.Revision{Epoch: 1, Counter: 2}}), recs)
	f.putOverlay(envelopes(t,
		signEntry(t, op, testEnv, "dev-cell-2"),
		signEntry(t, op, testEnv, "dev-cell-4"),
		signEntry(t, op, "prod", "dev-cell-3"),
	))
	conf := writeServerConf(t, f, f.cm.root, operatorHCL(pub))
	got, err := ReadRevoked(conf)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"dev-cell-1": SourceRecord, "dev-cell-2": SourceOverlay, "dev-cell-5": SourceRetired}
	if len(got.Cells) != len(want) {
		t.Fatalf("cells = %v, want %v", got.Cells, want)
	}
	for cell, src := range want {
		if got.Cells[cell] != src {
			t.Fatalf("cells = %v, want %v", got.Cells, want)
		}
	}
	if got.Spec != (envspec.Revision{Epoch: 1, Counter: 2}) {
		t.Fatalf("spec = %+v, want 1.2", got.Spec)
	}
}

func TestReadRevokedNoSpec(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	conf := writeServerConf(t, f, f.cm.root, "")
	if _, err := ReadRevoked(conf); err != nil {
		t.Fatalf("with a spec: %v", err)
	}
	empty := t.TempDir()
	if _, err := ReadRevoked(writeServerConf(t, f, empty, "")); err == nil {
		t.Fatal("an absent spec gave no error")
	}
	// A spec that another key signed does not verify.
	_, other := newOperatorKey(t)
	if err := os.WriteFile(filepath.Join(empty, specFile), signSpec(t, other, testEnv, 1, 1, nil, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRevoked(writeServerConf(t, f, empty, "")); err == nil {
		t.Fatal("a spec that does not verify gave no error")
	}
	if _, err := ReadRevoked(filepath.Join(t.TempDir(), "absent.conf")); err == nil {
		t.Fatal("an absent configuration gave no error")
	}
}
