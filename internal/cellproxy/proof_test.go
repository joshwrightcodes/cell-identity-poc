package cellproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/satoken"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

const proofPattern = `^spiffe://dev\.env\.poc\.internal/(?:cell/[a-z0-9-]+|cp)/(?:otel|mesh-view|argocd-agent)$`

// testProofCheck makes the proof check of a server whose roles all send tokens of testSubject.
func testProofCheck(reg RegistrySource) *ProofCheck {
	return &ProofCheck{Registry: reg, Subjects: map[string]record.Subject{
		"argocd-agent": testSubject, "otel": testSubject, "mesh-view": testSubject, "celld": testSubject,
	}}
}

// testTokens signs a token of subject for the cell, with the audience that the caller asks for.
func testTokens(t testing.TB, signer *kubetoken.Signer, cellName string, subject record.Subject) satoken.TokenFunc {
	return func(_ context.Context, audience string) (string, error) {
		return signer.Token(t, kubetoken.Claims{
			Issuer: "https://" + cellName + ":6443", Namespace: subject.Namespace, ServiceAccount: subject.ServiceAccount,
			PodName: "celld-0", PodUID: "uid-1", NodeName: "n1", Audience: []string{audience},
		}), nil
	}
}

// proofFor is the ProofFunc of the SPIFFE ID id, with a token of testSubject under testSigner.
func proofFor(t testing.TB, id string) ProofFunc {
	src, err := ParseSource(spiffeIDOf(id))
	if err != nil {
		t.Fatal(err)
	}
	return NewProofWriter(testTokens(t, testSigner, src.Cell, testSubject), src.Cell, src.Role)
}

// proofServer runs a server with the proof check and returns its address and logs, and the two CAs.
func proofServer(t *testing.T, cfg ServerConfig, b Backend, reg RegistrySource) (string, *syncBuffer, *testCA, *testCA) {
	t.Helper()
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	out := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(out, nil))
	cfg.TLS = ServerTLS(source(mgmt.svid(t, principalID)), env.bundle(), regexp.MustCompile(proofPattern), reg, log)
	if cfg.Proof == nil {
		cfg.Proof = testProofCheck(reg)
	}
	addr, _, _ := serveOn(t, NewServer(cfg, b, log), out, env)
	return addr, out, env, mgmt
}

// dialWithProof dials addr as id and sends the frame that frameFor returns for the connection.
func dialWithProof(t *testing.T, addr string, env *testCA, id string, frameFor func(*tls.Conn) []byte) *tls.Conn {
	t.Helper()
	c := dialHeld(t, addr, clientConfig(t, env, id))
	if frameFor != nil {
		if _, err := c.Write(frameFor(c)); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// frameOf is the frame of a token of signer and subject for cell and role on c.
func frameOf(t *testing.T, signer *kubetoken.Signer, subject record.Subject, cellName, role string) func(*tls.Conn) []byte {
	return func(c *tls.Conn) []byte {
		binding, err := proof.Binding(c.ConnectionState())
		if err != nil {
			t.Fatal(err)
		}
		tok, _ := testTokens(t, signer, cellName, subject)(context.Background(), proof.StreamAudience(cellName, role, binding))
		return frameBytes(t, tok)
	}
}

func frameBytes(t *testing.T, token string) []byte {
	var buf bytes.Buffer
	if err := proof.WriteFrame(&buf, token); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func cellID(role string) string { return "spiffe://dev.env.poc.internal/cell/dev-cell-1/" + role }

func refusalError(t *testing.T, out *syncBuffer, reason Reason) string {
	t.Helper()
	l := waitForLog(t, out, "proof refused", reason, "")
	s, _ := l["error"].(string)
	return s
}

func TestServerRequiresProofForCellSources(t *testing.T) {
	rogue := kubetoken.NewSigner(t, "ec-1", jose.ES256)
	cases := []struct {
		name   string
		frame  func(*testing.T) func(*tls.Conn) []byte
		reason Reason
		detail string
	}{
		{"none", func(*testing.T) func(*tls.Conn) []byte { return nil }, ProofMissing, ""},
		{"rogue_key", func(t *testing.T) func(*tls.Conn) []byte { return frameOf(t, rogue, testSubject, "dev-cell-1", "otel") }, ProofInvalid, "bad_signature"},
		{"good", func(t *testing.T) func(*tls.Conn) []byte {
			return frameOf(t, testSigner, testSubject, "dev-cell-1", "otel")
		}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &holdBackend{sources: make(chan Source, 4)}
			reg := testRegistry(t)
			addr, out, env, _ := proofServer(t, ServerConfig{Proof: &ProofCheck{Registry: reg, Subjects: testProofCheck(reg).Subjects, Timeout: 300 * time.Millisecond}}, b, reg)
			dialWithProof(t, addr, env, cellID("otel"), tc.frame(t))
			if tc.reason == "" {
				if src := waitSource(t, b.sources, out); src.Cell != "dev-cell-1" || src.Role != "otel" {
					t.Fatalf("source is %+v", src)
				}
				return
			}
			if got := refusalError(t, out, tc.reason); !strings.Contains(got, tc.detail) {
				t.Fatalf("error %q does not hold %q", got, tc.detail)
			}
			noSource(t, b.sources)
		})
	}
}

func TestServerSkipsProofForEnvironment(t *testing.T) {
	b := &holdBackend{sources: make(chan Source, 4)}
	addr, out, env, _ := proofServer(t, ServerConfig{}, b, testRegistry(t))
	dialWithProof(t, addr, env, "spiffe://dev.env.poc.internal/cp/otel", nil)
	if src := waitSource(t, b.sources, out); src.Plane != PlaneEnvironment {
		t.Fatalf("source is %+v", src)
	}
}

func TestProofBoundToConnection(t *testing.T) {
	b := &holdBackend{sources: make(chan Source, 4)}
	addr, out, env, _ := proofServer(t, ServerConfig{}, b, testRegistry(t))
	frame := frameOf(t, testSigner, testSubject, "dev-cell-1", "otel")
	a := dialHeld(t, addr, clientConfig(t, env, cellID("otel")))
	replay := frame(a)
	// The token of connection a goes to a second connection of the same source.
	dialWithProof(t, addr, env, cellID("otel"), func(*tls.Conn) []byte { return replay })
	if got := refusalError(t, out, ProofInvalid); !strings.Contains(got, "wrong_audience") {
		t.Fatalf("error %q, want wrong_audience", got)
	}
	noSource(t, b.sources)
	if _, err := a.Write(replay); err != nil {
		t.Fatal(err)
	}
	waitSource(t, b.sources, out)
}

func TestProofWrongRoleSubject(t *testing.T) {
	other := record.Subject{Namespace: "observability-system", ServiceAccount: "otel-uplink"}
	rc := cell("dev-cell-1", false)
	rc.Subjects = append(rc.Subjects, other)
	pub, priv := signerKey(t)
	reg, err := LoadRegistry(writeRegistry(t, []ed25519.PublicKey{pub}, priv, rc))
	if err != nil {
		t.Fatal(err)
	}
	subjects := map[string]record.Subject{"otel": other, "mesh-view": testSubject}
	run := func(t *testing.T, role string, subject record.Subject) (*syncBuffer, *holdBackend) {
		b := &holdBackend{sources: make(chan Source, 4)}
		addr, out, env, _ := proofServer(t, ServerConfig{Proof: &ProofCheck{Registry: reg, Subjects: subjects, Timeout: time.Second}}, b, reg)
		dialWithProof(t, addr, env, cellID(role), frameOf(t, testSigner, subject, "dev-cell-1", role))
		return out, b
	}
	t.Run("subject_of_another_role", func(t *testing.T) {
		out, b := run(t, "mesh-view", other)
		if got := refusalError(t, out, ProofInvalid); !strings.Contains(got, "subject_mismatch") {
			t.Fatalf("error %q, want subject_mismatch", got)
		}
		noSource(t, b.sources)
	})
	t.Run("role_with_no_subject", func(t *testing.T) {
		out, b := run(t, "argocd-agent", testSubject)
		if got := refusalError(t, out, ProofInvalid); !strings.Contains(got, "no_subject") {
			t.Fatalf("error %q, want no_subject", got)
		}
		noSource(t, b.sources)
	})
	t.Run("right_subject", func(t *testing.T) {
		out, b := run(t, "otel", other)
		waitSource(t, b.sources, out)
	})
}

func TestProofRotatedKeyAfterReload(t *testing.T) {
	pub, priv := signerKey(t)
	old := cell("dev-cell-1", false)
	dir := writeRegistry(t, []ed25519.PublicKey{pub}, priv, old)
	signerFile := filepath.Join(t.TempDir(), "signers.pub")
	copyFile(t, filepath.Join(dir, "signers.pub"), signerFile)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	w, err := WatchRegistry(ctx, dir, signerFile, 20*time.Millisecond, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	b := &holdBackend{sources: make(chan Source, 8)}
	addr, out, env, _ := proofServer(t, ServerConfig{}, b, w)
	rotated := kubetoken.NewSigner(t, "ec-2", jose.ES256)

	dialWithProof(t, addr, env, cellID("otel"), frameOf(t, rotated, testSubject, "dev-cell-1", "otel"))
	if got := refusalError(t, out, ProofInvalid); !strings.Contains(got, "unknown_kid") {
		t.Fatalf("error %q, want unknown_kid", got)
	}

	next := old
	next.JWKS, next.Counter = rotated.JWKS(), 2
	rewriteRegistry(t, dir, []ed25519.PublicKey{pub}, priv, next)
	deadline := time.Now().Add(5 * time.Second)
	for {
		dialWithProof(t, addr, env, cellID("otel"), frameOf(t, rotated, testSubject, "dev-cell-1", "otel"))
		select {
		case <-b.sources:
			return
		case <-time.After(150 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rotated key stayed refused after the reload:\n%s", out.String())
		}
	}
}

func TestProofReadDeadline(t *testing.T) {
	b := &holdBackend{sources: make(chan Source, 8)}
	reg := testRegistry(t)
	addr, out, env, _ := proofServer(t, ServerConfig{MaxHandshakes: 2, MaxConnsPerSource: 2}, b, reg)
	// Two clients of one source finish the TLS handshake and send no proof, so they hold the slots of the source.
	silentTLS := []*tls.Conn{dialHeld(t, addr, clientConfig(t, env, cellID("otel"))), dialHeld(t, addr, clientConfig(t, env, cellID("otel")))}
	time.Sleep(200 * time.Millisecond)
	// Two more connections hold every handshake slot.
	silentTCP := []net.Conn{dialTCP(t, addr), dialTCP(t, addr)}
	t.Cleanup(func() {
		for _, c := range silentTCP {
			_ = c.Close()
		}
	})
	start := time.Now()
	good := func(t *testing.T) bool {
		t.Helper()
		c, err := tls.Dial("tcp", addr, clientConfig(t, env, cellID("mesh-view")))
		if err != nil {
			return false
		}
		defer func() { _ = c.Close() }()
		binding, err := proof.Binding(c.ConnectionState())
		if err != nil {
			t.Fatal(err)
		}
		tok, _ := testTokens(t, testSigner, "dev-cell-1", testSubject)(context.Background(), proof.StreamAudience("dev-cell-1", "mesh-view", binding))
		if _, err := c.Write(frameBytes(t, tok)); err != nil {
			return false
		}
		select {
		case src := <-b.sources:
			return src.Role == "mesh-view"
		case <-time.After(300 * time.Millisecond):
			return false
		}
	}
	for !good(t) {
		if time.Since(start) > 7*time.Second {
			t.Fatalf("a good client of another source did not connect within 7 s:\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	for i, c := range silentTLS {
		if !closedWithin(c, 4*time.Second) {
			t.Fatalf("silent client %d still holds its connection %s after the start", i, time.Since(start))
		}
	}
}

func TestProofFrameTooLarge(t *testing.T) {
	b := &holdBackend{sources: make(chan Source, 4)}
	addr, out, env, _ := proofServer(t, ServerConfig{}, b, testRegistry(t))
	c := dialHeld(t, addr, clientConfig(t, env, cellID("otel")))
	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, proof.MaxFrame+1)
	if _, err := c.Write(head); err != nil {
		t.Fatal(err)
	}
	if got := refusalError(t, out, ProofInvalid); !strings.Contains(got, "too_large") {
		t.Fatalf("error %q, want too_large", got)
	}
	if !closedWithin(c, time.Second) {
		t.Fatal("the server kept a connection with an oversize proof frame")
	}
	noSource(t, b.sources)
}

// firstBytesBackend reports the first n bytes that the peer sends after the proof.
type firstBytesBackend struct {
	n     int
	bytes chan string
}

func (b *firstBytesBackend) Name() string { return "first-bytes" }

func (b *firstBytesBackend) Serve(_ context.Context, conn *tls.Conn, _ Source) error {
	buf := make([]byte, b.n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	b.bytes <- string(buf)
	return nil
}

func TestClientProofWritesBeforeBytes(t *testing.T) {
	b := &firstBytesBackend{n: 5, bytes: make(chan string, 1)}
	addr, out, env, mgmt := proofServer(t, ServerConfig{}, b, testRegistry(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cli := &Client{TLS: ClientTLS(source(env.svid(t, cellID("otel"))), mgmt.bundle(), spiffeIDOf(principalID)), Upstream: addr, Log: jsonLog(&syncBuffer{}), Proof: proofFor(t, cellID("otel"))}
	done := make(chan struct{})
	go func() { _ = cli.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	c := dialTCP(t, ln.Addr().String())
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-b.bytes:
		if got != "hello" {
			t.Fatalf("the backend read %q first, want the payload only", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the backend got no payload:\n%s", out.String())
	}
}

func TestClientProofFailureSendsNoBytes(t *testing.T) {
	b := &firstBytesBackend{n: 1, bytes: make(chan string, 1)}
	addr, _, env, mgmt := proofServer(t, ServerConfig{}, b, testRegistry(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	log := &syncBuffer{}
	fail := func(context.Context, *tls.Conn) error { return errors.New("no token") }
	cli := &Client{TLS: ClientTLS(source(env.svid(t, cellID("otel"))), mgmt.bundle(), spiffeIDOf(principalID)), Upstream: addr, Log: jsonLog(log), Proof: fail}
	done := make(chan struct{})
	go func() { _ = cli.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	c := dialTCP(t, ln.Addr().String())
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("x"))
	if !closedWithin(c, 3*time.Second) {
		t.Fatal("the client kept the downstream connection after a failed proof")
	}
	if !hasMsg(t, log, "proof failed") {
		t.Fatalf("no proof failed line:\n%s", log.String())
	}
	select {
	case got := <-b.bytes:
		t.Fatalf("the backend got %q after a failed proof", got)
	default:
	}
}

func TestTunnelDialerSendsProof(t *testing.T) {
	h := newTunnelHarnessWith(t, tunnelHarnessConfig{wait: 5 * time.Second, proof: true})
	dial := TunnelDialer(h.server, ClientTLS(source(h.env.svid(t, meshViewID1)), h.mgmt.bundle(), spiffeIDOf(kialiID)), jsonLog(h.cellLog), WithProof(proofFor(t, meshViewID1)))
	startCell(t, dial, h.cellHandler(t))
	h.waitTunnels(t, 1, 5*time.Second)
	if code, body := h.get(t, "/api/v1/pods"); code != http.StatusOK {
		t.Fatalf("status %d, body %s", code, body)
	}
}

// rewriteRegistry replaces the records and signers.pub of dir with those that writeRegistry makes.
func rewriteRegistry(t *testing.T, dir string, pubs []ed25519.PublicKey, priv ed25519.PrivateKey, cells ...record.Cell) {
	t.Helper()
	src := writeRegistry(t, pubs, priv, cells...)
	old, err := filepath.Glob(filepath.Join(dir, "*"+recordSuffix))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		tmp := filepath.Join(dir, "."+e.Name()+".tmp")
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

// TestReloadChangesHandshakeAdmission checks that a reload reaches the TLS authorizer: a cell that a
// reload adds connects, and a cell that a reload revokes is refused at the handshake, with no restart.
func TestReloadChangesHandshakeAdmission(t *testing.T) {
	f := newWatchFixture(t, cell("dev-cell-1", false))
	b := &holdBackend{sources: make(chan Source, 16)}
	addr, out, env, _ := proofServer(t, ServerConfig{}, b, f.w)
	connects := func(id, cellName string) bool {
		c, err := tls.Dial("tcp", addr, clientConfig(t, env, id))
		if err != nil {
			return false
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write(frameOf(t, testSigner, testSubject, cellName, "otel")(c)); err != nil {
			return false
		}
		select {
		case <-b.sources:
			return true
		case <-time.After(300 * time.Millisecond):
			return false
		}
	}
	newID := "spiffe://dev.env.poc.internal/cell/dev-cell-2/otel"
	if connects(newID, "dev-cell-2") {
		t.Fatal("a cell with no record connected")
	}
	waitForLog(t, out, "peer refused", PeerNotAllowed, newID)
	if !connects(cellID("otel"), "dev-cell-1") {
		t.Fatal("the cell of the registry did not connect")
	}

	rewriteRegistry(t, f.dir, []ed25519.PublicKey{f.pub}, f.priv, cell("dev-cell-1", false), cell("dev-cell-2", false))
	waitFor(t, "the added cell to connect", func() bool { return connects(newID, "dev-cell-2") })

	rewriteRegistry(t, f.dir, []ed25519.PublicKey{f.pub}, f.priv, atRevision("dev-cell-1", 1, 2), revokedCell("dev-cell-2"))
	waitFor(t, "the revoked cell to be refused", func() bool { return !connects(newID, "dev-cell-2") })
	if !connects(cellID("otel"), "dev-cell-1") {
		t.Fatal("the cell that stayed in the registry stopped connecting")
	}
}

func revokedCell(name string) record.Cell {
	c := atRevision(name, 1, 2)
	c.Revoked = true
	return c
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestProofUsesRecordOfOwnEnvironment checks that a record of the same name in another environment
// does not give the keys of the proof.
func TestProofUsesRecordOfOwnEnvironment(t *testing.T) {
	pub, priv := signerKey(t)
	prod := atRevision("dev-cell-1", 9, 9)
	prod.Env = "prod"
	prod.JWKS = kubetoken.NewSigner(t, "ec-9", jose.ES256).JWKS()
	reg, err := LoadRegistry(writeRegistry(t, []ed25519.PublicKey{pub}, priv, cell("dev-cell-1", false), prod))
	if err != nil {
		t.Fatal(err)
	}
	if rec, ok := reg.Record("dev-cell-1"); !ok || rec.Env != "prod" {
		t.Fatalf("Record without an environment gave %+v", rec)
	}
	b := &holdBackend{sources: make(chan Source, 4)}
	addr, out, env, _ := proofServer(t, ServerConfig{}, b, reg)
	dialWithProof(t, addr, env, cellID("otel"), frameOf(t, testSigner, testSubject, "dev-cell-1", "otel"))
	waitSource(t, b.sources, out)
}

// TestProofRefusesCellWithoutSubjects checks that a server with a proof check and no subjects
// refuses every cell stream, also one that carries a frame.
func TestProofRefusesCellWithoutSubjects(t *testing.T) {
	reg := testRegistry(t)
	b := &holdBackend{sources: make(chan Source, 4)}
	addr, out, env, _ := proofServer(t, ServerConfig{Proof: &ProofCheck{Registry: reg}}, b, reg)
	dialWithProof(t, addr, env, cellID("otel"), frameOf(t, testSigner, testSubject, "dev-cell-1", "otel"))
	if got := refusalError(t, out, ProofInvalid); !strings.Contains(got, "no_subject") {
		t.Fatalf("error %q, want no_subject", got)
	}
	noSource(t, b.sources)
}

func TestClientProofFailureLogsReason(t *testing.T) {
	b := &firstBytesBackend{n: 1, bytes: make(chan string, 1)}
	addr, _, env, mgmt := proofServer(t, ServerConfig{}, b, testRegistry(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	log := &syncBuffer{}
	fail := func(context.Context, *tls.Conn) error { return errors.New("no token") }
	cli := &Client{TLS: ClientTLS(source(env.svid(t, cellID("otel"))), mgmt.bundle(), spiffeIDOf(principalID)), Upstream: addr, Log: jsonLog(log), Proof: fail}
	done := make(chan struct{})
	go func() { _ = cli.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	c := dialTCP(t, ln.Addr().String())
	defer func() { _ = c.Close() }()
	waitForLog(t, log, "proof failed", ProofFailed, "")
}
