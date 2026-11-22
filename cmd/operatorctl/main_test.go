package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
)

var testNow = time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)

func run(args []string, stdin string) (string, int) {
	var out bytes.Buffer
	code := execute(args, strings.NewReader(stdin), &out, func() time.Time { return testNow })
	return out.String(), code
}

// errorLine checks that out is one JSON error line of operatorctl and returns it.
func errorLine(t *testing.T, out string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one error line, got %q", out)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("the error line %q is no JSON: %v", lines[0], err)
	}
	if rec["level"] != "ERROR" || rec["msg"] != "operatorctl failed" {
		t.Fatalf("error line %v, want level ERROR and msg %q", rec, "operatorctl failed")
	}
	return rec
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubLine(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)) + "\n"
}

var seedLineRE = regexp.MustCompile(`^OPERATOR-ED25519-SEED:[A-Za-z0-9+/]{43}=\n$`)

// TestKeygenWritesSeedLine: keygen prints exactly one seed line on standard output and writes the public key, one standard base64
// line, to the public file. pub derives the same public key from the seed line. keygen refuses a public file that exists and an
// absent --public-file, and then prints no seed.
func TestKeygenWritesSeedLine(t *testing.T) {
	dir := t.TempDir()
	pubFile := filepath.Join(dir, "new.pub")
	out, code := run([]string{"keygen", "--public-file", pubFile}, "")
	if code != 0 || !seedLineRE.MatchString(out) {
		t.Fatalf("keygen: exit %d, output %q; want exit 0 and one seed line", code, out)
	}
	key, err := revoke.ParseSeed(strings.NewReader(out))
	if err != nil {
		t.Fatalf("the seed line does not parse: %v", err)
	}
	b, err := os.ReadFile(pubFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != pubLine(key) {
		t.Fatalf("the public file holds %q, want %q", b, pubLine(key))
	}
	if st, err := os.Stat(pubFile); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("the public file has mode %v (%v), want 0644", st.Mode().Perm(), err)
	}
	pub, code := run([]string{"pub"}, out)
	if code != 0 || pub != pubLine(key) {
		t.Fatalf("pub: exit %d, output %q; want %q", code, pub, pubLine(key))
	}

	again, code := run([]string{"keygen", "--public-file", pubFile}, "")
	if code == 0 || strings.Contains(again, revoke.SeedPrefix) {
		t.Fatalf("keygen over an existing public file: exit %d, output %q; want a failure with no seed", code, again)
	}
	errorLine(t, again)
	if b2, _ := os.ReadFile(pubFile); !bytes.Equal(b2, b) {
		t.Fatalf("keygen changed an existing public file")
	}
	none, code := run([]string{"keygen"}, "")
	if code == 0 || strings.Contains(none, revoke.SeedPrefix) {
		t.Fatalf("keygen with no --public-file: exit %d, output %q; want a failure with no seed", code, none)
	}
	errorLine(t, none)

	other, _ := run([]string{"keygen", "--public-file", filepath.Join(dir, "other.pub")}, "")
	if other == out {
		t.Fatal("two runs of keygen printed the same seed")
	}
}

// TestSignVerifyRoundTrip: sign reads the seed on standard input and prints a DSSE envelope of a local revocation entry. verify reads
// the envelope on standard input, checks it against the keys file and prints one JSON line with the entry and the SHA-256 of the
// key that verified it.
func TestSignVerifyRoundTrip(t *testing.T) {
	key := newKey(t)
	next := newKey(t)
	seed := revoke.FormatSeed(key) + "\n"
	env, code := run([]string{"sign", "--env", "dev", "--cell", "dev-cell-2", "--record", "3.17"}, seed)
	if code != 0 {
		t.Fatalf("sign: exit %d: %s", code, env)
	}
	if strings.Count(env, "\n") != 1 || !strings.HasSuffix(env, "\n") {
		t.Fatalf("sign printed %q, want one line", env)
	}
	if strings.Contains(env, base64.StdEncoding.EncodeToString(key.Seed())) {
		t.Fatal("the envelope holds the seed")
	}
	e, err := revoke.Verify([]byte(strings.TrimSpace(env)), []ed25519.PublicKey{key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatalf("revoke.Verify: %v", err)
	}
	if e.Env != "dev" || e.Cell != "dev-cell-2" || e.Record.Epoch != 3 || e.Record.Counter != 17 || !e.IssuedAt.Equal(testNow) ||
		!regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(e.ID) {
		t.Fatalf("entry %+v, want env dev, cell dev-cell-2, record 3.17, issuedAt %s and a 16 hex id", e, testNow)
	}

	dir := t.TempDir()
	keys := filepath.Join(dir, "keys.pub")
	if err := os.WriteFile(keys, []byte(pubLine(next)+pubLine(key)), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run([]string{"verify", "--keys", keys}, env)
	if code != 0 {
		t.Fatalf("verify: exit %d: %s", code, out)
	}
	var got struct {
		ID        string `json:"id"`
		Env       string `json:"env"`
		Cell      string `json:"cell"`
		Record    struct{ Epoch, Counter uint64 }
		IssuedAt  time.Time `json:"issuedAt"`
		KeySHA256 string    `json:"keySHA256"`
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("verify printed %q, want one line", out)
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("verify printed %q: %v", out, err)
	}
	if got.ID != e.ID || got.Env != "dev" || got.Cell != "dev-cell-2" || got.Record.Epoch != 3 || got.Record.Counter != 17 ||
		!got.IssuedAt.Equal(testNow) || got.KeySHA256 != revoke.KeySHA256(key.Public().(ed25519.PublicKey)) {
		t.Fatalf("verify printed %+v, want entry %+v signed by the second key", got, e)
	}

	// Another key does not verify the envelope.
	if err := os.WriteFile(keys, []byte(pubLine(next)), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = run([]string{"verify", "--keys", keys}, env)
	if code == 0 {
		t.Fatalf("verify against another key: exit 0, output %q", out)
	}
	rec := errorLine(t, out)
	if rec["reason"] != revoke.ReasonInvalid || rec["detail"] != revoke.DetailSignature {
		t.Fatalf("error line %v, want reason %s and detail %s", rec, revoke.ReasonInvalid, revoke.DetailSignature)
	}

	for _, bad := range [][]string{
		{"sign", "--env", "dev", "--cell", "dev-cell-2", "--record", "0.1"},
		{"sign", "--env", "dev", "--cell", "dev-cell-2", "--record", "1"},
		{"sign", "--env", "dev", "--cell", "dev-cell-2", "--record", "1.x"},
		{"sign", "--env", "dev", "--cell", "Dev_Cell", "--record", "1.1"},
		{"sign", "--env", "", "--cell", "dev-cell-2", "--record", "1.1"},
		{"sign", "--cell", "dev-cell-2", "--record", "1.1"},
		{"sign", "--env", "dev", "--cell", "dev-cell-2", "--record", "1.1", "extra"},
		{"verify"},
		{"verify", "--keys", filepath.Join(dir, "absent")},
		{"pub", "--keys", keys},
		{"unknown"},
		{},
	} {
		out, code := run(bad, seed)
		if code == 0 {
			t.Errorf("%v: exit 0, output %q; want a failure", bad, out)
			continue
		}
		errorLine(t, out)
	}
}

// TestOperatorctlErrorsCarryNoInput: each failure prints one JSON error line that holds no byte of standard input. The inputs hold a
// marker, or a seed, that must not appear in the line.
func TestOperatorctlErrorsCarryNoInput(t *testing.T) {
	const marker = "zq9MARKERzq9"
	key := newKey(t)
	seed := revoke.FormatSeed(key)
	body := strings.TrimPrefix(seed, revoke.SeedPrefix)
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys.pub")
	if err := os.WriteFile(keys, []byte(pubLine(key)), 0o644); err != nil {
		t.Fatal(err)
	}
	signed := func(payloadType string, payload string) string {
		env, err := record.SignEnvelope(payloadType, []byte(payload), key)
		if err != nil {
			t.Fatal(err)
		}
		return string(env)
	}
	goodEntry := `{"id":"0123456789abcdef","env":"dev","cell":"dev-cell-1","record":{"epoch":1,"counter":2},"issuedAt":"2026-11-20T09:30:00Z"}`
	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
	}{
		{"pub_marker", []string{"pub"}, marker + "\n"},
		{"pub_prefix_marker", []string{"pub"}, revoke.SeedPrefix + marker + "\n"},
		{"pub_seed_then_marker", []string{"pub"}, seed + "\n" + marker + "\n"},
		{"pub_seed_trailing_space", []string{"pub"}, seed + " \n"},
		{"pub_seed_lowercase_prefix", []string{"pub"}, strings.ToLower(revoke.SeedPrefix) + body + "\n"},
		{"pub_long", []string{"pub"}, strings.Repeat(marker, 40)},
		{"pub_empty", []string{"pub"}, ""},
		{"sign_marker", []string{"sign", "--env", "dev", "--cell", "dev-cell-1", "--record", "1.1"}, marker + "\n"},
		{"sign_seed_bad_cell", []string{"sign", "--env", "dev", "--cell", "Dev_Cell", "--record", "1.1"}, seed + "\n"},
		{"sign_seed_bad_record", []string{"sign", "--env", "dev", "--cell", "dev-cell-1", "--record", "x"}, seed + "\n"},
		{"sign_seed_twice", []string{"sign", "--env", "dev", "--cell", "dev-cell-1", "--record", "1.1"}, seed + "\n" + seed + "\n"},
		{"verify_not_json", []string{"verify", "--keys", keys}, marker},
		{"verify_unknown_field", []string{"verify", "--keys", keys}, `{"` + marker + `":1}`},
		{"verify_payload_type", []string{"verify", "--keys", keys}, signed("application/"+marker, goodEntry)},
		{"verify_entry_unknown_field", []string{"verify", "--keys", keys}, signed(revoke.PayloadType, `{"`+marker+`":1}`)},
		{"verify_entry_bad_cell", []string{"verify", "--keys", keys}, signed(revoke.PayloadType, strings.Replace(goodEntry, "dev-cell-1", marker, 1))},
		{"verify_too_large", []string{"verify", "--keys", keys}, strings.Repeat(marker, revoke.MaxEntryBytes/len(marker)+2)},
		{"verify_seed", []string{"verify", "--keys", keys}, seed + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := run(tc.args, tc.stdin)
			if code == 0 {
				t.Fatalf("exit 0, output %q; want a failure", out)
			}
			errorLine(t, out)
			for _, bad := range []string{marker, "MARKER", body, body[:12], revoke.SeedPrefix, strings.ToLower(revoke.SeedPrefix)} {
				if strings.Contains(out, bad) {
					t.Fatalf("the error line %q holds input bytes %q", out, bad)
				}
			}
		})
	}
}
