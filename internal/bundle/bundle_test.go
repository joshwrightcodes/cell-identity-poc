package bundle_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

func hexDigest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func comp(name string, wave int) map[string]any {
	return map[string]any{"name": name, "wave": wave, "namespace": "default", "digest": hexDigest('a')}
}

func raw(t testing.TB, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func many(n int) []map[string]any {
	out := make([]map[string]any, 0, n)
	for i := range n {
		out = append(out, comp(fmt.Sprintf("c%02d", i), 0))
	}
	return out
}

func TestParseComponentsRules(t *testing.T) {
	with := func(k string, v any) []map[string]any {
		c := comp("a", 0)
		c[k] = v
		return []map[string]any{c}
	}
	entries := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"group": "apps", "kind": "Deployment"}
		}
		return out
	}
	noWave := []map[string]any{{"name": "a", "namespace": "default", "digest": hexDigest('a')}}
	for _, tc := range []struct {
		name string
		in   any
		want string // empty means the input is valid; otherwise a fragment of the error
	}{
		{"valid", []map[string]any{comp("a", 0), comp("b", 3)}, ""},
		{"wave_minus_10", []map[string]any{comp("a", -10)}, ""},
		{"wave_20", []map[string]any{comp("a", 20)}, ""},
		{"32_components", many(32), ""},
		{"name_40_chars", []map[string]any{comp(strings.Repeat("a", 40), 0)}, ""},
		{"ignore_8_entries", with("ignoreDifferences", entries(8)), ""},
		{"ignore_known_keys", with("ignoreDifferences", []any{map[string]any{
			"group": "g", "kind": "k", "name": "n", "namespace": "ns",
			"jsonPointers": []string{"/a"}, "jqPathExpressions": []string{".a"}, "managedFieldsManagers": []string{"m"},
		}}), ""},
		{"wave_zero_given", []map[string]any{comp("a", 0)}, ""},
		{"name_upper", []map[string]any{comp("Abc", 0)}, "is not a DNS label"},
		{"name_41_chars", []map[string]any{comp(strings.Repeat("a", 41), 0)}, "is not a DNS label"},
		{"name_empty", []map[string]any{comp("", 0)}, "is not a DNS label"},
		{"name_root", []map[string]any{comp("root", 0)}, "taken by the root bundle"},
		{"names_out_of_order", []map[string]any{comp("b", 0), comp("a", 0)}, `name "a" is not above "b"`},
		{"duplicate_name", []map[string]any{comp("a", 0), comp("a", 1)}, `name "a" is not above "a"`},
		{"wave_21", []map[string]any{comp("a", 21)}, "wave 21"},
		{"wave_minus_11", []map[string]any{comp("a", -11)}, "wave -11"},
		{"wave_missing", noWave, "has no wave"},
		{"digest_63_hex", with("digest", "sha256:"+strings.Repeat("a", 63)), "digest of"},
		{"digest_65_hex", with("digest", "sha256:"+strings.Repeat("a", 65)), "digest of"},
		{"digest_no_prefix", with("digest", strings.Repeat("a", 64)), "digest of"},
		{"digest_upper", with("digest", "sha256:"+strings.Repeat("A", 64)), "digest of"},
		{"namespace_bad", with("namespace", "Not_A_Label"), "namespace"},
		{"ignore_unknown_key", with("ignoreDifferences", []any{map[string]any{"group": "g", "extra": 1}}), "ignoreDifferences of"},
		{"ignore_9_entries", with("ignoreDifferences", entries(9)), "9 entries"},
		{"ignore_empty_list", with("ignoreDifferences", []any{}), "0 entries"},
		{"ignore_empty_entry", with("ignoreDifferences", []any{map[string]any{}}), "empty entry"},
		{"ignore_catch_all", with("ignoreDifferences", []any{map[string]any{"kind": "Deployment", "jqPathExpressions": []string{".a", "."}}}), "catch-all"},
		{"ignore_not_a_list", with("ignoreDifferences", map[string]any{"group": "g"}), "ignoreDifferences of"},
		{"ignore_entry_not_object", with("ignoreDifferences", []any{"x"}), "ignoreDifferences of"},
		{"zero_components", []map[string]any{}, "0 components"},
		{"33_components", many(33), "33 components"},
		{"unknown_field", with("extra", true), "extra"},
		{"not_a_list", map[string]any{"name": "a"}, "components:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bundle.ParseComponents(raw(t, tc.in))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				if len(got) == 0 {
					t.Fatal("no components")
				}
				return
			}
			if !errors.Is(err, record.ErrDecode) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want ErrDecode with %q, got %v", tc.want, err)
			}
		})
	}
}

func TestParseComponentsKeepsFields(t *testing.T) {
	in := `[{"name":"a","wave":-2,"namespace":"x","digest":"` + hexDigest('b') + `","ignoreDifferences": [ {"group":"g"} ]}]`
	got, err := bundle.ParseComponents(json.RawMessage(in))
	if err != nil {
		t.Fatal(err)
	}
	want := bundle.Component{Name: "a", Wave: -2, Namespace: "x", Digest: hexDigest('b'), IgnoreDifferences: json.RawMessage(`[{"group":"g"}]`)}
	if len(got) != 1 || got[0].Name != want.Name || got[0].Wave != want.Wave || got[0].Namespace != want.Namespace ||
		got[0].Digest != want.Digest || string(got[0].IgnoreDifferences) != string(want.IgnoreDifferences) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestContentIgnoresVersion(t *testing.T) {
	cs := []bundle.Component{{Name: "a", Wave: 1, Namespace: "n", Digest: hexDigest('a')}}
	a := bundle.ContentSHA256(bundle.Set{Version: bundle.Version{Epoch: 1, Counter: 1}, Components: cs})
	b := bundle.ContentSHA256(bundle.Set{Version: bundle.Version{Epoch: 9, Counter: 9}, Components: cs})
	if a != b {
		t.Fatalf("version changed the content digest: %s %s", a, b)
	}
	if len(a) != 64 || strings.ToLower(a) != a {
		t.Fatalf("digest %q is not lowercase hex SHA-256", a)
	}
	cs2 := []bundle.Component{{Name: "a", Wave: 1, Namespace: "n", Digest: hexDigest('b')}}
	if c := bundle.ContentSHA256(bundle.Set{Components: cs2}); c == a {
		t.Fatal("a component digest did not change the content digest")
	}
	cs3 := []bundle.Component{{Name: "a", Wave: 2, Namespace: "n", Digest: hexDigest('a')}}
	if c := bundle.ContentSHA256(bundle.Set{Components: cs3}); c == a {
		t.Fatal("a wave did not change the content digest")
	}
}

func TestVersionCompare(t *testing.T) {
	v := func(e, c uint64) bundle.Version { return bundle.Version{Epoch: e, Counter: c} }
	for _, tc := range []struct {
		a, b bundle.Version
		want int
	}{
		{v(1, 1), v(1, 1), 0},
		{v(1, 2), v(1, 1), 1},
		{v(1, 1), v(1, 2), -1},
		{v(2, 1), v(1, 99), 1},
		{v(1, 99), v(2, 1), -1},
	} {
		if got := tc.a.Compare(tc.b); got != tc.want {
			t.Errorf("%v.Compare(%v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	b, _ := json.Marshal(v(3, 4))
	if string(b) != `{"epoch":3,"counter":4}` {
		t.Errorf("wire form %s", b)
	}
}
