package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

func TestRunPrintsVerifiableConfigMap(t *testing.T) {
	facts := func(string) (hostsvc.Facts, error) {
		return hostsvc.Facts{Name: "dev-cell-1", Issuer: "https://10.0.0.1:6443", JWKS: json.RawMessage(`{"keys":[{"kty":"RSA"}]}`)}, nil
	}
	var out bytes.Buffer
	if err := run([]string{"--cluster", "dev-cell-1", "--subject", "celld/celld"}, &out, facts); err != nil {
		t.Fatal(err)
	}
	var recLine, pubLine string
	for _, l := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(l, "  record.dsse.json: "); ok {
			recLine = v
		}
		if v, ok := strings.CutPrefix(l, "  signer.pub: "); ok {
			pubLine = v
		}
	}
	var env, pubB64 string
	if err := json.Unmarshal([]byte(recLine), &env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(pubLine), &pubB64); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	c, err := record.Verify([]byte(env), []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "dev-cell-1" || c.Env != "dev" || len(c.Subjects) != 1 {
		t.Fatalf("unexpected cell %+v", c)
	}
}

func TestRunRejectsBadSubject(t *testing.T) {
	err := run([]string{"--cluster", "x", "--subject", "nope"}, &bytes.Buffer{}, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
}

// captureStderr returns a function that reports what the code under test wrote to os.Stderr.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = f
	t.Cleanup(func() { os.Stderr = old })
	return func() string {
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

func TestFailureIsOneJSONLineOnStdoutAndNothingOnStderr(t *testing.T) {
	cases := map[string][]string{
		"bogus flag":      {"--bogus"},
		"help":            {"-h"},
		"missing cluster": {},
		"bad subject":     {"--cluster", "x", "--subject", "nope"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			stderr := captureStderr(t)
			var out bytes.Buffer
			if code := execute(args, &out, nil); code == 0 {
				t.Fatal("expected a non-zero exit code")
			}
			lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
			if len(lines) != 1 {
				t.Fatalf("want one line on stdout, got %q", out.String())
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
				t.Fatalf("stdout is not JSON: %v", err)
			}
			if m["level"] != "ERROR" || m["error"] == "" || m["error"] == nil {
				t.Fatalf("unexpected error line %v", m)
			}
			if got := stderr(); got != "" {
				t.Fatalf("stderr = %q", got)
			}
		})
	}
}

func TestFactsFailureIsJSONOnStdout(t *testing.T) {
	stderr := captureStderr(t)
	var out bytes.Buffer
	facts := func(string) (hostsvc.Facts, error) { return hostsvc.Facts{}, errors.New("no such cluster") }
	if code := execute([]string{"--cluster", "x"}, &out, facts); code != 1 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out.String(), "no such cluster") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("stdout = %q", out.String())
	}
	if stderr() != "" {
		t.Fatal("stderr must stay empty")
	}
}

func TestSuccessPrintsOnlyData(t *testing.T) {
	stderr := captureStderr(t)
	facts := func(string) (hostsvc.Facts, error) {
		return hostsvc.Facts{Name: "dev-cell-1", Issuer: "https://10.0.0.1:6443", JWKS: json.RawMessage(`{"keys":[{"kty":"RSA"}]}`)}, nil
	}
	var out bytes.Buffer
	if code := execute([]string{"--cluster", "dev-cell-1"}, &out, facts); code != 0 {
		t.Fatalf("code = %d, out %q", code, out.String())
	}
	if !strings.HasPrefix(out.String(), "apiVersion: v1\n") || stderr() != "" {
		t.Fatalf("stdout = %q, stderr = %q", out.String(), stderr())
	}
}
