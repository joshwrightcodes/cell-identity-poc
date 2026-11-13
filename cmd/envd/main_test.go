package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/otel/metric/noop"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/joshwrightcodes/cell-identity-poc/internal/envd"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type signer struct {
	t    *testing.T
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	jwks json.RawMessage
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cp, _, _ := ed25519.GenerateKey(rand.Reader)
	raw, err := (&jose.JSONWebKey{Key: cp, KeyID: "k", Algorithm: "EdDSA", Use: "sig"}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []json.RawMessage{raw}})
	return &signer{t: t, pub: pub, priv: priv, jwks: jwks}
}

func (s *signer) keyFile() string {
	p := filepath.Join(s.t.TempDir(), "spec.pub")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(s.pub)+"\n"), 0o600); err != nil {
		s.t.Fatal(err)
	}
	return p
}

// bundle signs a spec of one cell "a" at the revision counter c.
func (s *signer) bundle(c uint64) mgmtapi.SpecBundle {
	s.t.Helper()
	rec, err := record.Sign(record.Cell{Name: "a", Env: "dev", Issuer: "https://a.example", JWKS: s.jwks,
		Subjects: []record.Subject{{Namespace: "n", ServiceAccount: "s"}}, Epoch: 1, Counter: c}, s.priv)
	if err != nil {
		s.t.Fatal(err)
	}
	_, payload, err := record.VerifyWithPayload(rec, []ed25519.PublicKey{s.pub})
	if err != nil {
		s.t.Fatal(err)
	}
	raw, err := spec.Sign(spec.Spec{Env: "dev", Revision: spec.Revision{Epoch: 1, Counter: c}, Cells: []spec.Entry{
		{Name: "a", Revision: spec.Revision{Epoch: 1, Counter: c}, RecordSHA256: spec.RecordDigest(payload)}}}, s.priv)
	if err != nil {
		s.t.Fatal(err)
	}
	return mgmtapi.SpecBundle{Spec: raw, Records: map[string]json.RawMessage{"a": rec}}
}

func (s *signer) stdin(b mgmtapi.SpecBundle) io.Reader {
	raw, _ := json.Marshal(b)
	return bytes.NewReader(raw)
}

func fakeDeps(kube kubernetes.Interface, started *int) deps {
	return deps{
		telemetry: func(_ context.Context, stdout io.Writer) (*telemetry.T, error) {
			*started++
			return &telemetry.T{Log: slog.New(slog.NewJSONHandler(stdout, nil)), Meter: noop.NewMeterProvider().Meter("t"),
				Shutdown: func(context.Context) error { return nil }}, nil
		},
		kube: func() (kubernetes.Interface, error) { return kube, nil },
	}
}

func oneLine(t *testing.T, out string) map[string]any {
	t.Helper()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("output is not one line: %q", out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output is not JSON: %q", out)
	}
	return m
}

func TestCheckModePrintsOneLine(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	keyFile := s.keyFile()
	client := fake.NewClientset()
	store := envd.NewConfigMapStore(client, "spire-system", "cell-records", "dev", []ed25519.PublicKey{s.pub}, slog.New(slog.DiscardHandler))
	cur, _, err := envd.Accept(envd.Empty(), s.bundle(5), "dev", []ed25519.PublicKey{s.pub})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(t.Context(), cur); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()

	args := []string{"check", "--spec-key-file", keyFile, "--env", "dev", "--current-configmap", "spire-system/cell-records"}
	for _, tc := range []struct {
		name  string
		in    mgmtapi.SpecBundle
		code  int
		check func(t *testing.T, m map[string]any)
	}{
		{"accepted", s.bundle(6), 0, func(t *testing.T, m map[string]any) {
			if m["result"] != "accepted" || m["revision"].(map[string]any)["counter"] != float64(6) {
				t.Errorf("got %v", m)
			}
		}},
		{"unchanged", s.bundle(5), 0, func(t *testing.T, m map[string]any) {
			if m["result"] != "unchanged" || m["revision"].(map[string]any)["counter"] != float64(5) {
				t.Errorf("got %v", m)
			}
		}},
		{"older", s.bundle(4), 1, func(t *testing.T, m map[string]any) {
			if m["result"] != "refused" || m["reason"] != "revision_old" || len(m) != 2 {
				t.Errorf("got %v", m)
			}
		}},
		{"foreign_key", other.bundle(6), 1, func(t *testing.T, m map[string]any) {
			if m["result"] != "refused" || m["reason"] != "signature_invalid" {
				t.Errorf("got %v", m)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			started := 0
			code := execute(t.Context(), args, s.stdin(tc.in), &out, fakeDeps(client, &started))
			if code != tc.code {
				t.Fatalf("exit %d, want %d, output %q", code, tc.code, out.String())
			}
			tc.check(t, oneLine(t, out.String()))
			if started != 0 {
				t.Error("check started telemetry")
			}
			for _, a := range client.Actions() {
				if a.GetVerb() != "get" {
					t.Errorf("check made a %s call", a.GetVerb())
				}
			}
		})
	}

	t.Run("bad_input_is_an_error_line", func(t *testing.T) {
		var out bytes.Buffer
		started := 0
		code := execute(t.Context(), args, strings.NewReader("not json"), &out, fakeDeps(client, &started))
		m := oneLine(t, out.String())
		if code != 1 || m["msg"] != "envd failed" || m["level"] != "ERROR" {
			t.Fatalf("exit %d, line %v", code, m)
		}
	})
}

func TestEnvdRequiresFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"no_mode", nil, []string{"usage"}},
		{"unknown_mode", []string{"serve"}, []string{"unknown mode"}},
		{"run", []string{"run"}, []string{"--env", "--expect-id", "--output-configmap", "--peer-bundle", "--peer-trust-domain", "--spec-key-file", "--upstream"}},
		{"check", []string{"check"}, []string{"--current-configmap", "--env", "--spec-key-file"}},
		{"extra_argument", []string{"check", "--env", "dev", "x"}, []string{"unexpected argument"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			started := 0
			code := execute(t.Context(), tc.args, strings.NewReader(""), &out, fakeDeps(fake.NewClientset(), &started))
			if code != exitConfig {
				t.Fatalf("exit %d", code)
			}
			m := oneLine(t, out.String())
			msg, _ := m["error"].(string)
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q lacks %q", msg, w)
				}
			}
			if started != 0 {
				t.Error("telemetry started")
			}
		})
	}
}

func TestLogsAreJSON(t *testing.T) {
	s := newSigner(t)
	td := spiffetest.NewCA(t, "mgmt.poc.internal")
	dir := t.TempDir()
	bundlePEM, err := td.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(dir, "peer.pem")
	if err := os.WriteFile(peer, bundlePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientset()
	started := 0
	d := fakeDeps(client, &started)
	envCA := spiffetest.NewCA(t, "dev.env.poc.internal")
	d.svids = func(context.Context) (x509svid.Source, func(), error) {
		return envCA.Source(t, "spiffe://dev.env.poc.internal/envd"), func() {}, nil
	}
	args := []string{"run", "--upstream", "127.0.0.1:1", "--expect-id", "spiffe://mgmt.poc.internal/api",
		"--peer-bundle", peer, "--peer-trust-domain", "mgmt.poc.internal", "--spec-key-file", s.keyFile(),
		"--env", "dev", "--output-configmap", "spire-system/cell-records", "--interval", "50ms", "--health-listen", "127.0.0.1:0"}

	var out syncBuffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() { done <- execute(ctx, args, strings.NewReader(""), &out, d) }()

	var health string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range strings.Split(out.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "envd started" {
				health, _ = m["health"].(string)
			}
		}
		if health != "" && strings.Contains(out.String(), "pull failed") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if health == "" {
		t.Fatalf("envd did not start: %q", out.String())
	}
	var status int
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + health + "/healthz")
		if err == nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
		}
		if status == http.StatusOK {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status != http.StatusOK {
		t.Errorf("healthz %d while management is unreachable", status)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Errorf("not a JSON line: %q", l)
		}
		if m["msg"] == nil || m["level"] == nil || m["time"] == nil {
			t.Errorf("line lacks time, level or msg: %q", l)
		}
	}
	if !strings.Contains(lines[len(lines)-1], `"msg":"stopped"`) {
		t.Errorf("last line %q", lines[len(lines)-1])
	}
}

func TestRunRefusesExpectIDOutsideTrustDomain(t *testing.T) {
	s := newSigner(t)
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	pem, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(t.TempDir(), "peer.pem")
	if err := os.WriteFile(peer, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	args := func(id string) []string {
		return []string{"--upstream", "x:1", "--expect-id", id, "--peer-bundle", peer, "--peer-trust-domain", "mgmt.poc.internal",
			"--spec-key-file", s.keyFile(), "--env", "dev", "--output-configmap", "a/b"}
	}
	if _, err := parseRun(args("spiffe://mgmt.poc.internal/api")); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err := parseRun(args("spiffe://other.poc.internal/api")); err == nil || !strings.Contains(err.Error(), "--expect-id") {
		t.Fatalf("expect-id outside the trust domain: %v", err)
	}
}

func TestHealthServerLimits(t *testing.T) {
	srv := newHealthServer(http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("limits %v %v %v %v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}
