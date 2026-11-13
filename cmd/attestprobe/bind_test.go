package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

// bindServer plays the bind listener of the cell gateway for one test. Bind post number n gets the
// ID of n, and the poll of that ID gets the result of n.
type bindServer struct {
	addr       string
	bundlePath string
	mu         sync.Mutex
	nonces     int
	nonceReply func(cell string) mgmtapi.NonceResponse
	binds      []mgmtapi.BindRequest
	methods    []string
	postStatus func(n int) (int, any)
	result     func(n int) gwapi.BindResult
}

func bindID(n int) gwapi.ItemID { return gwapi.ItemID(fmt.Sprintf("%032x", n)) }

func newBindServer(t *testing.T) *bindServer {
	t.Helper()
	ca := spiffetest.NewCA(t, "dev.env.poc.internal")
	pem, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s := &bindServer{bundlePath: filepath.Join(t.TempDir(), "bundle.pem")}
	if err := os.WriteFile(s.bundlePath, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	s.postStatus = func(n int) (int, any) { return 202, gwapi.BindAccepted{ID: bindID(n)} }
	s.result = func(int) gwapi.BindResult { return gwapi.BindResult{Status: mgmtapi.StatusBound} }
	cfg := tlsconfig.TLSServerConfig(ca.Source(t, "spiffe://dev.env.poc.internal/cp/gateway"))
	cfg.MinVersion, cfg.NextProtos = tls.VersionTLS13, []string{"h2"}
	reply := func(w http.ResponseWriter, code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+mgmtapi.NoncePattern, func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.methods = append(s.methods, r.Method+" "+r.URL.Path)
		s.nonces++
		s.mu.Unlock()
		if s.nonceReply != nil {
			reply(w, 200, s.nonceReply(r.PathValue("cell")))
			return
		}
		reply(w, 200, mgmtapi.NonceResponse{Nonce: "n1", Audience: mgmtapi.BindAudience(r.PathValue("cell"), "n1")})
	})
	mux.HandleFunc("POST "+mgmtapi.BindPattern, func(w http.ResponseWriter, r *http.Request) {
		var req mgmtapi.BindRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		s.methods = append(s.methods, r.Method+" "+r.URL.Path)
		s.binds = append(s.binds, req)
		n := len(s.binds) - 1
		s.mu.Unlock()
		code, v := s.postStatus(n)
		reply(w, code, v)
	})
	mux.HandleFunc("GET "+gwapi.BindResultPattern, func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.methods = append(s.methods, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		var n int
		if _, err := fmt.Sscanf(r.PathValue("id"), "%032x", &n); err != nil {
			reply(w, 404, map[string]string{"error": "unknown"})
			return
		}
		reply(w, 200, s.result(n))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	srv := &http.Server{Handler: mux, Protocols: protos}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	s.addr = ln.Addr().String()
	return s
}

func (s *bindServer) args(extra ...string) []string {
	return append([]string{
		"--target", "gw-bind", "--upstream", s.addr, "--expect-id", "spiffe://dev.env.poc.internal/cp/gateway",
		"--trust-bundle", s.bundlePath, "--cell", "dev-cell-1",
	}, extra...)
}

func runProbe(t *testing.T, td *testDeps, args []string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := execute(context.Background(), args, &out, td.deps)
	return code, out.String()
}

func TestAttestprobeGatewayVariants(t *testing.T) {
	pod := testPod()
	for _, tc := range []struct {
		variant  string
		audience func(nonce string) func(*testing.T, string)
	}{
		{"good", func(n string) func(*testing.T, string) { return equalTo(mgmtapi.BindAudience("dev-cell-1", n)) }},
		{"attest-audience", func(n string) func(*testing.T, string) { return equalTo("spire-dev/" + n) }},
		{"other-nonce", func(n string) func(*testing.T, string) {
			return func(t *testing.T, got string) {
				t.Helper()
				rest, ok := strings.CutPrefix(got, "mgmt-bind/dev-cell-1/")
				if !ok || rest == n || len(rest) < 32 {
					t.Fatalf("audience %q, want mgmt-bind/dev-cell-1/<another nonce>", got)
				}
			}
		}},
	} {
		t.Run(tc.variant, func(t *testing.T) {
			s := newBindServer(t)
			td := newTestDeps(t)
			code, out := runProbe(t, td, s.args("--variant", tc.variant, "--env", "dev"))
			want := "nonce:n1 " + mgmtapi.BindAudience("dev-cell-1", "n1") + "\nbound:bound\n"
			if code != 0 || out != want {
				t.Fatalf("exit %d, output %q, want %q", code, out, want)
			}
			if len(*td.tokens) != 1 {
				t.Fatalf("%d token requests, want 1", len(*td.tokens))
			}
			req := (*td.tokens)[0]
			tc.audience("n1")(t, req.Spec.Audiences[0])
			if req.Spec.ExpirationSeconds == nil || *req.Spec.ExpirationSeconds != 600 {
				t.Fatalf("ExpirationSeconds %v, want 600", req.Spec.ExpirationSeconds)
			}
			if ref := req.Spec.BoundObjectRef; ref == nil || ref.Name != pod.name || string(ref.UID) != pod.uid {
				t.Fatalf("bound object %+v", ref)
			}
			if len(s.binds) != 1 || s.binds[0].Nonce != "n1" || s.binds[0].Token != "token-1" {
				t.Fatalf("bind requests %+v", s.binds)
			}
			wantReqs := []string{"GET " + gwapi.NoncePath("dev-cell-1"), "POST " + gwapi.BindPath("dev-cell-1"), "GET " + gwapi.BindResultPath("dev-cell-1", string(bindID(0)))}
			if !slices.Equal(s.methods, wantReqs) {
				t.Fatalf("requests %v, want %v", s.methods, wantReqs)
			}
		})
	}
}

func TestAttestprobeBindReuseNonce(t *testing.T) {
	s := newBindServer(t)
	s.result = func(n int) gwapi.BindResult {
		if n == 0 {
			return gwapi.BindResult{Status: mgmtapi.StatusBound}
		}
		return gwapi.BindResult{Status: gwapi.BindDenied, RequestID: "00000000000000aa"}
	}
	td := newTestDeps(t)
	code, out := runProbe(t, td, s.args("--variant", "good", "--reuse-nonce"))
	want := "nonce:n1 mgmt-bind/dev-cell-1/n1\nbound:bound\ndenied:00000000000000aa\n"
	if code != 0 || out != want {
		t.Fatalf("exit %d, output %q, want %q", code, out, want)
	}
	if s.nonces != 1 || len(s.binds) != 2 || s.binds[0] != s.binds[1] {
		t.Fatalf("%d nonce requests, binds %+v, want one nonce and two identical binds", s.nonces, s.binds)
	}
}

func TestAttestprobeBindNonceOnly(t *testing.T) {
	s := newBindServer(t)
	td := newTestDeps(t)
	code, out := runProbe(t, td, s.args("--nonce-only"))
	if code != 0 || out != "nonce:n1 mgmt-bind/dev-cell-1/n1\n" {
		t.Fatalf("exit %d, output %q", code, out)
	}
	if len(s.binds) != 0 || len(*td.tokens) != 0 {
		t.Fatalf("%d binds and %d tokens, want none", len(s.binds), len(*td.tokens))
	}
}

func TestAttestprobeBindWithNonceAndTokenFile(t *testing.T) {
	s := newBindServer(t)
	td := newTestDeps(t)
	code, out := runProbe(t, td, s.args("--variant", "good", "--nonce", "given", "--token-file", "/run/attestprobe/token"))
	if code != 0 || out != "bound:bound\n" {
		t.Fatalf("exit %d, output %q", code, out)
	}
	if s.nonces != 0 || len(s.binds) != 1 || s.binds[0].Nonce != "given" || s.binds[0].Token != "file-token" {
		t.Fatalf("%d nonce requests, binds %+v", s.nonces, s.binds)
	}
	if len(*td.tokens) != 0 {
		t.Fatalf("%d token requests, want none", len(*td.tokens))
	}
}

func TestAttestprobeBindDeniedIsAResult(t *testing.T) {
	s := newBindServer(t)
	s.result = func(int) gwapi.BindResult {
		return gwapi.BindResult{Status: gwapi.BindDenied, RequestID: "0123456789abcdef"}
	}
	code, out := runProbe(t, newTestDeps(t), s.args("--variant", "good"))
	if code != 0 || out != "nonce:n1 mgmt-bind/dev-cell-1/n1\ndenied:0123456789abcdef\n" {
		t.Fatalf("exit %d, output %q", code, out)
	}
}

func TestAttestprobeBindFailureIsOneJSONLine(t *testing.T) {
	s := newBindServer(t)
	s.postStatus = func(int) (int, any) { return 503, map[string]string{"error": "busy"} }
	code, out := runProbe(t, newTestDeps(t), s.args("--variant", "good"))
	if code != 1 || strings.Count(out, "\n") != 1 || strings.Contains(out, "nonce:") {
		t.Fatalf("exit %d, output %q, want one JSON error line and no data", code, out)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(out), &line); err != nil || line["level"] != "ERROR" {
		t.Fatalf("output %q (%v)", out, err)
	}
}

func TestAttestprobeBindRefusesBadFlags(t *testing.T) {
	s := newBindServer(t)
	for name, extra := range map[string][]string{
		"no variant":              {},
		"unknown variant":         {"--variant", "spire"},
		"nonce without file":      {"--variant", "good", "--nonce", "x"},
		"file without nonce":      {"--variant", "good", "--token-file", "/run/attestprobe/token"},
		"nonce-only with nonce":   {"--nonce-only", "--nonce", "x", "--token-file", "/run/attestprobe/token"},
		"nonce-only with reuse":   {"--nonce-only", "--reuse-nonce"},
		"attest-audience no env":  {"--variant", "attest-audience"},
		"unexpected argument":     {"--variant", "good", "extra"},
		"unknown target":          nil,
		"retired target":          nil,
		"spire variant in target": {"--variant", "wrong-audience"},
	} {
		t.Run(name, func(t *testing.T) {
			args := s.args(extra...)
			if name == "unknown target" {
				args = append([]string{"--target", "other"}, args[2:]...)
			}
			if name == "retired target" {
				args = append([]string{"--target", "mgmt-bind"}, args[2:]...)
			}
			if code, out := runProbe(t, newTestDeps(t), args); code != 1 || strings.Count(out, "\n") != 1 {
				t.Fatalf("exit %d, output %q", code, out)
			}
		})
	}
}

func TestAttestprobeBindRefusesWrongServerID(t *testing.T) {
	s := newBindServer(t)
	args := s.args("--variant", "good")
	for i, a := range args {
		if a == "--expect-id" {
			args[i+1] = "spiffe://dev.env.poc.internal/cp/other"
		}
	}
	td := newTestDeps(t)
	if code, out := runProbe(t, td, args); code != 1 || len(s.binds) != 0 || s.nonces != 0 {
		t.Fatalf("exit %d, output %q, nonces %d, binds %d", code, out, s.nonces, len(s.binds))
	}
}

func TestAttestprobeDefaultTargetIsSpire(t *testing.T) {
	cfg, err := parse(append([]string{"--variant", "good"}, baseArgs...), podEnv(nil))
	if err != nil || cfg.target != "spire" {
		t.Fatalf("target %q, err %v", cfg.target, err)
	}
}

func TestAttestprobeBindChecksTheNonceAnswer(t *testing.T) {
	s := newBindServer(t)
	s.nonceReply = func(cell string) mgmtapi.NonceResponse {
		return mgmtapi.NonceResponse{Nonce: "ab\nbound:bound", Audience: mgmtapi.BindAudience(cell, "ab\nbound:bound")}
	}
	code, out := runProbe(t, newTestDeps(t), s.args("--nonce-only"))
	if code != 1 || strings.Count(out, "\n") != 1 || strings.Contains(out, "nonce:") || len(s.binds) != 0 {
		t.Fatalf("exit %d, output %q", code, out)
	}
}

func TestAttestprobeBindRefusesUnknownStatus(t *testing.T) {
	s := newBindServer(t)
	s.result = func(int) gwapi.BindResult { return gwapi.BindResult{Status: "pwned"} }
	if code, out := runProbe(t, newTestDeps(t), s.args("--variant", "good")); code != 1 || strings.Contains(out, "bound:") {
		t.Fatalf("exit %d, output %q", code, out)
	}
}
