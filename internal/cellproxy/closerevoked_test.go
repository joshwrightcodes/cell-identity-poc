package cellproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const (
	cellProxyID = "spiffe://dev.env.poc.internal/cp/otel"
	agentID3    = "spiffe://dev.env.poc.internal/cell/dev-cell-3/argocd-agent"
)

// blockBackend keeps each connection open until it ends, and reports the sources it serves.
type blockBackend struct{ served chan Source }

func (b *blockBackend) Name() string { return "hold" }

func (b *blockBackend) Serve(_ context.Context, conn *tls.Conn, src Source) error {
	b.served <- src
	_, _ = io.Copy(io.Discard, conn)
	return nil
}

type closeFixture struct {
	srv  *Server
	out  *syncBuffer
	ln   net.Listener
	ca   *testCA
	back *blockBackend
}

// newCloseFixture starts a server that allows the cells dev-cell-1 to dev-cell-3 and every environment source.
func newCloseFixture(t *testing.T) *closeFixture {
	t.Helper()
	mgmt, env := newCA(t, mgmtTD), newCA(t, envTD)
	pub, priv := signerKey(t)
	reg, err := LoadRegistry(writeRegistry(t, []ed25519.PublicKey{pub}, priv, cell("dev-cell-1", false), cell("dev-cell-2", false), cell("dev-cell-3", false)))
	if err != nil {
		t.Fatal(err)
	}
	f := &closeFixture{out: &syncBuffer{}, ca: env, back: &blockBackend{served: make(chan Source, 16)}}
	f.srv = NewServer(ServerConfig{
		TLS: ServerTLS(source(mgmt.svid(t, principalID)), env.bundle(), regexp.MustCompile(`^spiffe://dev\.env\.poc\.internal/.*$`), reg, jsonLog(f.out)),
	}, f.back, jsonLog(f.out))
	f.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { _ = f.srv.Serve(ctx, f.ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return f
}

// open connects as id and waits until the backend serves the connection.
func (f *closeFixture) open(t *testing.T, id string) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", f.ln.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{tlsCert(f.ca.svid(t, id))}, InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	select {
	case <-f.back.served:
	case <-time.After(5 * time.Second):
		t.Fatalf("the backend did not serve %s:\n%s", id, f.out.String())
	}
	return c
}

func isClosed(c *tls.Conn, within time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(within))
	_, err := c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

func registryOf(t *testing.T, cells ...record.Cell) *Registry {
	t.Helper()
	pub, priv := signerKey(t)
	reg, err := LoadRegistry(writeRegistry(t, []ed25519.PublicKey{pub}, priv, cells...))
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestCloseRevokedCell(t *testing.T) {
	f := newCloseFixture(t)
	c := f.open(t, agentID2)
	if n := f.srv.CloseRevoked(registryOf(t, cell("dev-cell-1", false), cell("dev-cell-2", true), cell("dev-cell-3", false))); n != 1 {
		t.Fatalf("CloseRevoked closed %d connections, want 1", n)
	}
	if !isClosed(c, 5*time.Second) {
		t.Fatal("the connection of the revoked cell is still open")
	}
	line := findLog(t, f.out, "connection closed", map[string]any{"reason": "cell_revoked", "cell": "dev-cell-2"}, 5*time.Second)
	if line["spiffe_id"] != agentID2 {
		t.Fatalf("the line names %v, want %s", line["spiffe_id"], agentID2)
	}
}

func TestCloseRetiredCell(t *testing.T) {
	f := newCloseFixture(t)
	c := f.open(t, agentID3)
	if n := f.srv.CloseRevoked(registryOf(t, cell("dev-cell-1", false), cell("dev-cell-2", false))); n != 1 {
		t.Fatalf("CloseRevoked closed %d connections, want 1", n)
	}
	if !isClosed(c, 5*time.Second) {
		t.Fatal("the connection of the retired cell is still open")
	}
	findLog(t, f.out, "connection closed", map[string]any{"reason": "cell_revoked", "cell": "dev-cell-3"}, 5*time.Second)
}

func TestCloseKeepsOtherCells(t *testing.T) {
	f := newCloseFixture(t)
	keep, drop := f.open(t, agentID1), f.open(t, agentID2)
	f.srv.CloseRevoked(registryOf(t, cell("dev-cell-1", false), cell("dev-cell-2", true), cell("dev-cell-3", false)))
	if !isClosed(drop, 5*time.Second) {
		t.Fatal("the revoked connection is still open")
	}
	if isClosed(keep, 300*time.Millisecond) {
		t.Fatal("the connection of an allowed cell closed")
	}
	if got := countLog(t, f.out, "connection closed"); got != 1 {
		t.Fatalf("%d connection closed lines, want 1", got)
	}
}

func TestCloseKeepsEnvironmentSources(t *testing.T) {
	f := newCloseFixture(t)
	env := f.open(t, cellProxyID)
	if n := f.srv.CloseRevoked(registryOf(t, cell("dev-cell-1", true))); n != 0 {
		t.Fatalf("CloseRevoked closed %d connections, want 0", n)
	}
	if isClosed(env, 300*time.Millisecond) {
		t.Fatal("the connection of an environment source closed")
	}
}

func TestCloseRefusesLateConnection(t *testing.T) {
	f := newCloseFixture(t)
	f.srv.CloseRevoked(registryOf(t, cell("dev-cell-1", false), cell("dev-cell-2", true), cell("dev-cell-3", false)))
	// The handshake still sees the old registry, as a connection that passed it before the swap does.
	c := f.open(t, agentID2)
	if !isClosed(c, 5*time.Second) {
		t.Fatal("a connection that registered after the adoption stayed open")
	}
}

func TestCloseOnlyOnAdoptedRegistry(t *testing.T) {
	f := newWatchFixture(t, atRevision("dev-cell-1", 1, 1), atRevision("dev-cell-2", 1, 1))
	// A broken file makes every reload fail. The callback registers after the first failure, so
	// the reloads that succeeded before it do not count.
	if err := os.WriteFile(filepath.Join(f.dir, "dev-cell-2.dsse.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.waitLog(t, "registry_reload_failed", "")
	calls := make(chan *Registry, 8)
	f.w.OnAdopt(func(r *Registry) { calls <- r })
	noCall := func(why string) {
		t.Helper()
		select {
		case <-calls:
			t.Fatalf("OnAdopt ran after %s", why)
		case <-time.After(300 * time.Millisecond):
		}
	}
	noCall("a failed reload")

	// A revocation below the revision mark is a refused registry, so it closes nothing either.
	putRecord(t, f.dir, f.priv, revokedAt("dev-cell-2", 1, 0))
	f.waitLog(t, "registry_reload_failed", "lower revision refused")
	noCall("a refused lower revision")

	putRecord(t, f.dir, f.priv, revokedAt("dev-cell-2", 1, 2))
	select {
	case r := <-calls:
		if r.Allows(Source{Env: "dev", Plane: PlaneCell, Cell: "dev-cell-2"}) {
			t.Fatal("the callback got a registry that still allows the revoked cell")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnAdopt did not run after an adopted registry")
	}
}

// putRecord replaces the file of one cell at once, so a reload never sees a directory with a record missing.
func putRecord(t *testing.T, dir string, priv ed25519.PrivateKey, c record.Cell) {
	t.Helper()
	env, err := record.Sign(c, priv)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "."+c.Name+".tmp")
	if err := os.WriteFile(tmp, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, c.Name+".dsse.json")); err != nil {
		t.Fatal(err)
	}
}

func revokedAt(name string, epoch, counter uint64) record.Cell {
	c := atRevision(name, epoch, counter)
	c.Revoked = true
	return c
}

// A tick of the watcher is one reload, and the callback runs inside it, so the close needs no
// second tick: it happens within the 5 seconds of the reload period.
func TestCloseWithinFiveSeconds(t *testing.T) {
	f := newCloseFixture(t)
	c := f.open(t, agentID2)

	pub, priv := signerKey(t)
	dir := writeRegistry(t, []ed25519.PublicKey{pub}, priv, atRevision("dev-cell-1", 1, 1), atRevision("dev-cell-2", 1, 1))
	signerFile := filepath.Join(t.TempDir(), "signers.pub")
	copyFile(t, filepath.Join(dir, "signers.pub"), signerFile)
	reg, fp, err := LoadPinnedRegistry(dir, signerFile)
	if err != nil {
		t.Fatal(err)
	}
	w := WatchLoaded(t.Context(), reg, fp, dir, signerFile, 0, jsonLog(&syncBuffer{}))
	w.OnAdopt(func(r *Registry) { f.srv.CloseRevoked(r) })
	putRecord(t, dir, priv, revokedAt("dev-cell-2", 1, 2))

	w.reload() // the body of one tick
	if !isClosed(c, time.Second) {
		t.Fatal("the connection was still open after the reload that adopted the revocation")
	}
}
