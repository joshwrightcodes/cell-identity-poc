package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

// jsonLines parses every line of out as a JSON object and fails if any line is not one.
func jsonLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("line is not a JSON object: %q: %v", l, err)
		}
		lines = append(lines, m)
	}
	return lines
}

func TestFailureIsOneJSONErrorLine(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"facts"},
		{"facts", "--nope"},
		{"facts", "-h"},
		{"up", "--x"},
		{"down", "--help"},
		{"facts", "--cluster", "nope", "--topology", "does-not-exist.yaml"},
	} {
		var out strings.Builder
		stderr := captureStderr(t)
		code := execute(context.Background(), args, &out)
		if got := stderr(); got != "" {
			t.Errorf("%v: wrote to stderr: %q", args, got)
		}
		if code == 0 {
			t.Errorf("%v: exit code 0, want non-zero", args)
		}
		lines := jsonLines(t, out.String())
		if len(lines) != 1 {
			t.Fatalf("%v: %d lines, want 1: %q", args, len(lines), out.String())
		}
		if msg, _ := lines[0]["error"].(string); msg == "" {
			t.Errorf("%v: no error field: %v", args, lines[0])
		}
	}
}

func TestLogsAreCompactJSON(t *testing.T) {
	var out strings.Builder
	execute(context.Background(), []string{"bogus"}, &out)
	if strings.Contains(out.String(), "\n  ") {
		t.Errorf("log is not compact: %q", out.String())
	}
}

// captureStderr redirects os.Stderr to a pipe and returns a function that restores it and
// returns what was written.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	return func() string {
		os.Stderr = orig
		_ = w.Close()
		b, _ := io.ReadAll(r)
		_ = r.Close()
		return string(b)
	}
}

// newCAFor is a root CA of trust domain td with the URI SAN that SPIRE roots carry.
func newCAFor(t *testing.T, td string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://" + td)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "root " + td}, URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

// gitRepo makes a repository with the files that the bootstrap digest reads, and returns its path.
func gitRepo(t *testing.T) string {
	t.Helper()
	testtool.Need(t, "git")
	root := t.TempDir()
	for p, c := range map[string]string{"go.mod": "module x\n", "cmd/a/main.go": "package main\n", "build/images.env": "A=1\n"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "go.mod", "cmd/a/main.go"}, {"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "x"}} {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	return root
}

func TestBootstrapDigestCommand(t *testing.T) {
	root := gitRepo(t)
	var out strings.Builder
	if code := execute(context.Background(), []string{"bootstrap-digest", "--root", root}, &out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	lines := jsonLines(t, out.String())
	sum, n, err := hostsvc.BootstrapDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0]["bootstrapSHA256"] != sum || lines[0]["files"] != float64(n) || len(lines[0]) != 2 {
		t.Errorf("output = %q, want one line with bootstrapSHA256 %s and files %d only", out.String(), sum, n)
	}
	if !strings.HasSuffix(out.String(), "\n") || strings.Count(out.String(), "\n") != 1 {
		t.Errorf("output is not one line: %q", out.String())
	}
	out.Reset()
	if code := execute(context.Background(), []string{"bootstrap-digest", "--root", t.TempDir()}, &out); code == 0 {
		t.Error("exit 0 outside a repository")
	}
	if l := jsonLines(t, out.String()); len(l) != 1 || l[0]["error"] == nil {
		t.Errorf("failure output = %q, want one JSON error line", out.String())
	}
}

func TestCreateCommandNeedsStep(t *testing.T) {
	dir := t.TempDir()
	j, err := hostsvc.OpenJournal(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 16)
	if err := j.Put(hostsvc.JournalEntry{
		Status: mgmtapi.StepStatus{ID: id, Cell: "dev-cell-2", State: mgmtapi.StepAdmitting}, Envelope: "{}", EnvelopeSHA256: "x",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POC_STEP_ID", "")
	for name, tc := range map[string]struct {
		stepID, cell string
	}{
		"no_step_id":     {"", "dev-cell-1"},
		"other_cell":     {id, "dev-cell-1"},
		"not_creating":   {id, "dev-cell-2"},
		"not_in_journal": {strings.Repeat("cd", 16), "dev-cell-1"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("POC_STEP_ID", tc.stepID)
			var out strings.Builder
			code := execute(context.Background(), []string{"create", "--cluster", tc.cell, "--journal-dir", dir, "--topology", topologyFile}, &out)
			if code == 0 {
				t.Fatal("create ran without a matching step")
			}
			if l := jsonLines(t, out.String()); len(l) != 1 || l[0]["error"] == nil {
				t.Errorf("output = %q, want one JSON error line", out.String())
			}
		})
	}
	t.Run("needs_cluster", func(t *testing.T) {
		var out strings.Builder
		if code := execute(context.Background(), []string{"create", "--topology", topologyFile}, &out); code == 0 {
			t.Error("create without --cluster")
		}
	})
}

// stepHost is a serve process with the step stack, a fake create program and a repository.
type stepHost struct {
	*running
	dir, journal, sock, repo, keys string
	mgmtCA, devCA                  *testCA
	devBundle                      string
	pub                            ed25519.PublicKey
	priv                           ed25519.PrivateKey
	createLog                      string
}

func startStepHost(t *testing.T, fakeCreate string, extra ...string) *stepHost {
	t.Helper()
	testtool.Need(t, "git", "sh")
	h := &stepHost{dir: t.TempDir(), repo: gitRepo(t), mgmtCA: newMgmtCA(t)}
	h.devCA = newCAFor(t, hostsvc.StepClientTrustDomain)
	short, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	h.sock = filepath.Join(short, "admin.sock")
	h.journal = filepath.Join(h.dir, "steps")
	h.keys = filepath.Join(h.dir, "keys")
	if err := os.Mkdir(h.keys, 0o755); err != nil {
		t.Fatal(err)
	}
	if h.pub, h.priv, err = ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.keys, "spec.pub"), []byte(base64.StdEncoding.EncodeToString(h.pub)), 0o644); err != nil {
		t.Fatal(err)
	}
	h.devBundle = filepath.Join(h.dir, "dev-root.crt")
	if err := os.WriteFile(h.devBundle, h.devCA.pem(), 0o600); err != nil {
		t.Fatal(err)
	}
	h.createLog = filepath.Join(h.dir, "create.log")
	script := filepath.Join(h.dir, "fake-hostsvc")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"$@\" >> "+h.createLog+"\n"+fakeCreate+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := selfExecutable
	selfExecutable = func() (string, error) { return script, nil }
	t.Cleanup(func() { selfExecutable = old })
	// The create stage of a step reads the node address of the new cluster. These tests create no cluster, so the lookup
	// answers with a fixed address and does not depend on Docker or a live kind cluster.
	oldNodeIP := nodeIPLookup
	nodeIPLookup = func(string) (string, error) { return "172.18.0.9", nil }
	t.Cleanup(func() { nodeIPLookup = oldNodeIP })
	args := append([]string{
		"--step-client-bundle", h.devBundle, "--step-keys-dir", h.keys, "--journal-dir", h.journal,
		"--repo-root", h.repo, "--admin-socket", h.sock, "--bootstrap-cmd", "true",
	}, extra...)
	h.running = startServe(t, writeBundle(t, h.mgmtCA), args...)
	return h
}

func (h *stepHost) client(t *testing.T, ca *testCA, id string) *hostsvc.KeyClient {
	t.Helper()
	var pinned [32]byte
	// The pin is the leaf that the serving line reports.
	m := jsonLines(t, lineWith(t, h.out, `"msg":"serving"`))[0]
	b, _ := hex.DecodeString(m["cert_sha256"].(string))
	copy(pinned[:], b)
	cert := ca.svid(t, id)
	kc, err := hostsvc.NewKeyClient(hostsvc.KeyClientConfig{
		Addr: h.addr, ServerName: hostsvc.KeyServerHost, Pin: pinned[:], SVIDs: certSource{cert}, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return kc
}

func (h *stepHost) stepClient(t *testing.T) *hostsvc.StepClient {
	t.Helper()
	return h.stepClientAs(t, h.devCA, defaultStepClientID)
}

// stepClientAs returns a step client with a certificate of ca for id.
func (h *stepHost) stepClientAs(t *testing.T, ca *testCA, id string) *hostsvc.StepClient {
	t.Helper()
	m := jsonLines(t, lineWith(t, h.out, `"msg":"serving"`))[0]
	b, _ := hex.DecodeString(m["cert_sha256"].(string))
	sc, err := hostsvc.NewStepClient(hostsvc.KeyClientConfig{
		Addr: h.addr, ServerName: hostsvc.KeyServerHost, Pin: b, SVIDs: certSource{ca.svid(t, id)}, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

type certSource struct{ c tls.Certificate }

func (s certSource) GetX509SVID() (*x509svid.SVID, error) {
	leaf, err := x509.ParseCertificate(s.c.Certificate[0])
	if err != nil {
		return nil, err
	}
	id, err := x509svid.IDFromCert(leaf)
	if err != nil {
		return nil, err
	}
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{leaf}, PrivateKey: s.c.PrivateKey.(crypto.Signer)}, nil
}

// signedStep returns a step for dev-cell-1 that the host accepts, with a spec that indexes it.
func (h *stepHost) signedStep(t *testing.T) (step.Step, []byte, []byte) {
	t.Helper()
	topo, err := topology.Load(topologyFile)
	if err != nil {
		t.Fatal(err)
	}
	cl, _ := topo.Cluster("dev-cell-1")
	sum, _, err := hostsvc.BootstrapDigest(h.repo)
	if err != nil {
		t.Fatal(err)
	}
	s := step.Step{
		ID: step.NewID(), Env: "dev", Cell: "dev-cell-1", Kind: step.KindCellCreate, Version: 1, KeyEpoch: 1,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		Cluster:         step.ClusterRef{PodSubnet: cl.PodSubnet, ServiceSubnet: cl.ServiceSubnet, Issuer: cl.Issuer},
		BootstrapSHA256: sum,
	}
	env, err := step.Sign(s, h.priv)
	if err != nil {
		t.Fatal(err)
	}
	payload := struct{ Payload string }{}
	_ = json.Unmarshal(env, &payload)
	raw, _ := base64.StdEncoding.DecodeString(payload.Payload)
	specEnv, err := spec.Sign(spec.Spec{Env: "dev", Revision: spec.Revision{Epoch: 1, Counter: 1},
		Steps: []spec.StepEntry{{Name: s.Cell, StepID: s.ID, StepSHA256: step.PayloadSHA256(raw)}}}, h.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, env, specEnv
}

func TestServeStepFlags(t *testing.T) {
	ca := newMgmtCA(t)
	good := writeBundle(t, ca)
	keysDir := t.TempDir()
	for name, args := range map[string][]string{
		"step_id_in_mgmt_td":   {"--step-client-id", "spiffe://mgmt.poc.internal/cp/cell-controller"},
		"step_id_no_path":      {"--step-client-id", "spiffe://dev.env.poc.internal"},
		"step_id_other_td":     {"--step-client-id", "spiffe://other.poc.internal/cp/cell-controller"},
		"step_id_bad":          {"--step-client-id", "nope"},
		"keys_without_journal": {"--step-keys-dir", keysDir},
		"journal_needs_keys":   {"--journal-dir", t.TempDir()},
		"empty_bootstrap_cmd":  {"--journal-dir", t.TempDir(), "--step-keys-dir", keysDir, "--bootstrap-cmd", " "},
		"bad_env":              {"--journal-dir", t.TempDir(), "--step-keys-dir", keysDir, "--env", "Dev"},
	} {
		t.Run(name, func(t *testing.T) {
			var out strings.Builder
			full := append([]string{"serve", "--listen", "127.0.0.1:0", "--client-bundle", good, "--topology", topologyFile}, args...)
			// A serve that wrongly starts stops at the timeout with exit 0, so the row fails.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if code := execute(ctx, full, &out); code == 0 {
				t.Fatal("serve started")
			}
			if l := jsonLines(t, out.String()); len(l) != 1 || l[0]["error"] == nil {
				t.Errorf("output = %q, want one JSON error line", out.String())
			}
		})
	}
	t.Run("bundle_absent_starts", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "dev-root.crt")
		r := startServe(t, good, "--step-client-bundle", missing, "--step-keys-dir", keysDir, "--journal-dir", t.TempDir(),
			"--admin-socket", shortSock(t), "--repo-root", t.TempDir())
		m := jsonLines(t, lineWith(t, r.out, `"msg":"serving"`))[0]
		if v, ok := m["dev_root_sha256"]; !ok || v != "" {
			t.Errorf("dev_root_sha256 = %v, want an empty string while the file is absent", v)
		}
	})
	t.Run("step_id_in_dev_td_with_path", func(t *testing.T) {
		startServe(t, good, "--step-client-id", "spiffe://dev.env.poc.internal/cp/other")
	})
}

func shortSock(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "admin.sock")
}

func TestServeLogsBinarySHA(t *testing.T) {
	ca := newMgmtCA(t)
	dev := newCAFor(t, hostsvc.StepClientTrustDomain)
	devFile := writeFile(t, "dev-root.crt", dev.pem())
	r := startServe(t, writeBundle(t, ca), "--step-client-bundle", devFile)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	m := jsonLines(t, lineWith(t, r.out, `"msg":"serving"`))[0]
	if m["binary_sha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("binary_sha256 = %v, want %x", m["binary_sha256"], sum)
	}
	devSum := sha256.Sum256(dev.cert.Raw)
	if m["dev_root_sha256"] != hex.EncodeToString(devSum[:]) {
		t.Errorf("dev_root_sha256 = %v, want %x", m["dev_root_sha256"], devSum)
	}
	mgmtSum := sha256.Sum256(ca.cert.Raw)
	if m["root_sha256"] != hex.EncodeToString(mgmtSum[:]) {
		t.Errorf("root_sha256 = %v: it must stay the management root", m["root_sha256"])
	}
}

func TestServeRunsStep(t *testing.T) {
	h := startStepHost(t, "exit 0")
	_, env, specEnv := h.signedStep(t)
	ctx := context.Background()
	if err := h.client(t, h.mgmtCA, defaultClientID).PutSpec(ctx, specEnv); err != nil {
		t.Fatalf("PutSpec: %v", err)
	}
	sc := h.stepClient(t)
	st, err := sc.Put(ctx, env)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	waitFor(t, "the step to finish", 20*time.Second, func() bool {
		st, err = sc.Get(ctx, st.ID)
		return err == nil && st.State == mgmtapi.StepDone
	})
	b, _ := os.ReadFile(h.createLog)
	if strings.TrimSpace(string(b)) != "create --cluster dev-cell-1" {
		t.Errorf("create program calls = %q, want one plain call", b)
	}
	// The spec route is for the management plane only, and the step route for the cell controller only.
	if err := func() error { _, err := h.stepClientAs(t, h.mgmtCA, defaultClientID).Get(ctx, st.ID); return err }(); err == nil {
		t.Error("the management plane read a step")
	}
}

func TestCtlCommandsPrintOneLine(t *testing.T) {
	h := startStepHost(t, "exit 0")
	s, env, specEnv := h.signedStep(t)
	ctx := context.Background()
	if err := h.client(t, h.mgmtCA, defaultClientID).PutSpec(ctx, specEnv); err != nil {
		t.Fatal(err)
	}
	sc := h.stepClient(t)
	if _, err := sc.Put(ctx, env); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the step to finish", 20*time.Second, func() bool {
		st, err := sc.Get(ctx, s.ID)
		return err == nil && st.State == mgmtapi.StepDone
	})
	ctl := func(args ...string) (string, int) {
		var out strings.Builder
		code := execute(ctx, append([]string{"ctl"}, append(args, "--admin-socket", h.sock)...), &out)
		return out.String(), code
	}
	out, code := ctl("steps")
	lines := jsonLines(t, out)
	if code != 0 || len(lines) != 1 || strings.Count(out, "\n") != 1 {
		t.Fatalf("ctl steps = %d %q, want one line", code, out)
	}
	steps, _ := lines[0]["steps"].([]any)
	if len(steps) != 1 || steps[0].(map[string]any)["state"] != "done" || steps[0].(map[string]any)["id"] != s.ID {
		t.Errorf("steps = %v", lines[0])
	}
	if out, code := ctl("log", "--step", s.ID); code != 0 || !strings.Contains(out, "== creating attempt 1 CELL=dev-cell-1") {
		t.Errorf("ctl log = %d %q", code, out)
	}
	for name, args := range map[string][]string{
		"cancel_nothing_open": {"cancel", "--cell", "dev-cell-1"},
		"cancel_no_selector":  {"cancel"},
		"cancel_both":         {"cancel", "--cell", "x", "--step", s.ID},
		"log_no_step":         {"log"},
		"unknown_command":     {"explode"},
	} {
		t.Run(name, func(t *testing.T) {
			out, code := ctl(args...)
			if l := jsonLines(t, out); code == 0 || len(l) != 1 || l[0]["error"] == nil {
				t.Errorf("ctl %v = %d %q, want one JSON error line and a failure", args, code, out)
			}
		})
	}
	out, code = ctl("reset-journal")
	if l := jsonLines(t, out); code == 0 || len(l) != 1 || l[0]["error"] == nil || !strings.Contains(out, "healthy") {
		t.Errorf("reset-journal of a healthy journal = %d %q, want one JSON error line", code, out)
	}
	out, _ = ctl("steps")
	if l := jsonLines(t, out); len(l[0]["steps"].([]any)) != 1 {
		t.Errorf("steps after the refused reset = %q", out)
	}
	var out2 strings.Builder
	if code := execute(ctx, []string{"ctl"}, &out2); code == 0 {
		t.Error("ctl with no command succeeded")
	}
	out2.Reset()
	if code := execute(ctx, []string{"ctl", "steps", "--admin-socket", filepath.Join(t.TempDir(), "none.sock")}, &out2); code == 0 {
		t.Error("ctl without a server succeeded")
	}
}

func TestServeStopEndsChild(t *testing.T) {
	h := startStepHost(t, "echo $$ > $POC_JOURNAL_DIR/child.pid\nsleep 60")
	pidFile := filepath.Join(h.journal, "child.pid")
	s, env, specEnv := h.signedStep(t)
	ctx := context.Background()
	if err := h.client(t, h.mgmtCA, defaultClientID).PutSpec(ctx, specEnv); err != nil {
		t.Fatal(err)
	}
	if _, err := h.stepClient(t).Put(ctx, env); err != nil {
		t.Fatal(err)
	}
	var pid int
	waitFor(t, "the create child", 20*time.Second, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil && pid > 1
	})
	t.Cleanup(func() { // by group id, never by name, and only while the group lives
		if syscall.Kill(-pid, 0) == nil {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("the child is not running: %v", err)
	}
	start := time.Now()
	h.finish(t)
	if d := time.Since(start); d > 12*time.Second {
		t.Errorf("serve took %s to stop", d)
	}
	waitFor(t, "the child group to be gone", 12*time.Second, func() bool { return syscall.Kill(-pid, 0) != nil })
	data, err := os.ReadFile(filepath.Join(h.journal, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct {
			Status mgmtapi.StepStatus `json:"status"`
			Pgid   int                `json:"pgid"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Entries) != 1 {
		t.Fatalf("journal = %s %v", data, err)
	}
	e := doc.Entries[0]
	if e.Status.ID != s.ID || e.Status.State != mgmtapi.StepFailed || e.Status.Detail != "interrupted" || e.Status.Attempts != 0 || e.Pgid != 0 {
		t.Errorf("entry after the stop = %+v pgid %d, want failed with detail interrupted and no attempt", e.Status, e.Pgid)
	}
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// wiringRuntime is a runtime with one existing cluster that records deletes.
type wiringRuntime struct {
	clusters map[string]bool
	deleted  []string
}

func (w *wiringRuntime) List() ([]string, error) {
	var out []string
	for n := range w.clusters {
		out = append(out, n)
	}
	return out, nil
}
func (w *wiringRuntime) Create(*v1alpha4.Cluster) error { return errors.New("create is not expected") }
func (w *wiringRuntime) Delete(n string) error {
	w.deleted = append(w.deleted, n)
	delete(w.clusters, n)
	return nil
}
func (w *wiringRuntime) Kubeconfig(string) (string, error) { return "kubeconfig", nil }
func (w *wiringRuntime) NodeIP(string) (string, error)     { return "172.18.0.5", nil }

type wiringMarker struct{}

func (wiringMarker) Has(context.Context, string) (bool, error) { return false, nil }
func (wiringMarker) Write(context.Context, string) error       { return nil }

// TestCreateCommandWiresCreateRecords runs `create --retry-of-create` with the production record
// store: the step recorded the cluster, so the command must delete it. Without the records and the
// step ID in the service, the command deletes nothing.
func TestCreateCommandWiresCreateRecords(t *testing.T) {
	dir := t.TempDir()
	j, err := hostsvc.OpenJournal(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 16)
	if err := j.Put(hostsvc.JournalEntry{Status: mgmtapi.StepStatus{ID: id, Cell: "dev-cell-1", State: mgmtapi.StepCreating}, Envelope: "{}", EnvelopeSHA256: "x"}); err != nil {
		t.Fatal(err)
	}
	for name, recorded := range map[string]bool{"recorded_by_this_step": true, "not_recorded": false} {
		t.Run(name, func(t *testing.T) {
			if recorded {
				if err := (hostsvc.FileCreateRecords{Dir: dir}).Record(id, "dev-cell-1"); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = os.Remove(filepath.Join(dir, id+".create"))
			}
			rt := &wiringRuntime{clusters: map[string]bool{"dev-cell-1": true}}
			old := newService
			newService = func(topo *topology.Topology) *hostsvc.Service {
				s := hostsvc.New(rt, topo)
				s.Marker = wiringMarker{}
				s.Docker = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("docker is not expected") }
				s.APIWait, s.APIPoll = 10*time.Millisecond, 5*time.Millisecond
				return s
			}
			t.Cleanup(func() { newService = old })
			t.Setenv("POC_STEP_ID", id)
			var out strings.Builder
			execute(context.Background(), []string{"create", "--cluster", "dev-cell-1", "--retry-of-create", "--journal-dir", dir, "--topology", topologyFile}, &out)
			if got := len(rt.deleted) == 1; got != recorded {
				t.Errorf("deleted %v with recorded=%v, want a delete only for a recorded cluster (output %s)", rt.deleted, recorded, out.String())
			}
		})
	}
}
