package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/proof"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

const (
	testTD    = "dev.env.poc.internal"
	gwSPIFFE  = "spiffe://" + testTD + "/cp/gateway"
	envdID    = "spiffe://" + testTD + "/envd"
	testNS    = "ns"
	testSA    = "sa"
	celld1    = "spiffe://" + testTD + "/cell/dev-cell-1/celld"
	celld2    = "spiffe://" + testTD + "/cell/dev-cell-2/celld"
	cell1Iss  = "https://dev-cell-1.example"
	frameWait = 3 * time.Second
)

// lockedBuf is a log sink that tests read while servers write.
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type staticSource struct{ svid *x509svid.SVID }

func (s staticSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

// gwEnv is a store with two cell records, a CA and a signer for the cell tokens.
type gwEnv struct {
	t    *testing.T
	ca   *spiffetest.CA
	kt   *kubetoken.Signer
	g    *signer
	st   *Store
	n    *gwapi.Notifier
	logs *lockedBuf
	gwID spiffeid.ID
}

func newGwEnv(t *testing.T) *gwEnv {
	t.Helper()
	kt := kubetoken.NewSigner(t, "k1", jose.ES256)
	g := newSigner(t)
	g.jwks = kt.JWKS()
	logs := &lockedBuf{}
	n := gwapi.NewNotifier()
	st, err := Open(context.Background(), filepath.Join(t.TempDir(), "queue.db"), n, nil, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &gwEnv{t: t, ca: spiffetest.NewCA(t, testTD), kt: kt, g: g, st: st, n: n, logs: logs}
	e.gwID, _ = spiffeid.FromString(gwSPIFFE)
	b := e.bundle()
	if err := st.ApplySync(context.Background(), b.spec, b.records, g.keys()); err != nil {
		t.Fatal(err)
	}
	return e
}

// bundle signs a spec at revision 1,1 with a record for each of the two cells.
func (e *gwEnv) bundle() bundle {
	e.t.Helper()
	b := bundle{records: map[string]json.RawMessage{}}
	sp := spec.Spec{Env: e.g.env, Revision: rev(1, 1), Retired: []spec.Retired{}}
	for _, name := range []string{cell1, cell2} {
		c := record.Cell{Name: name, Env: e.g.env, Issuer: "https://" + name + ".example", JWKS: e.g.jwks,
			Subjects: []record.Subject{{Namespace: testNS, ServiceAccount: testSA}}, Epoch: 1, Counter: 1}
		env, err := record.Sign(c, e.g.priv)
		if err != nil {
			e.t.Fatal(err)
		}
		_, payload, err := record.VerifyWithPayload(env, e.g.keys())
		if err != nil {
			e.t.Fatal(err)
		}
		b.records[name] = env
		sp.Cells = append(sp.Cells, spec.Entry{Name: name, Revision: rev(1, 1), RecordSHA256: spec.RecordDigest(payload)})
	}
	env, err := spec.Sign(sp, e.g.priv)
	if err != nil {
		e.t.Fatal(err)
	}
	b.spec = env
	return b
}

func (e *gwEnv) subject() record.Subject {
	return record.Subject{Namespace: testNS, ServiceAccount: testSA}
}

func (e *gwEnv) tlsConfig() *tls.Config {
	return StreamServerTLS(e.ca.Source(e.t, gwSPIFFE), e.ca.Bundle(), e.gwID.TrustDomain())
}

func listenDual(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
	}
	return ln
}

// serveStream starts the stream server and returns the handler and the address.
func (e *gwEnv) serveStream(cfg StreamConfig) (*StreamHandler, string) {
	e.t.Helper()
	cfg.Subject, cfg.Notifier, cfg.Log = e.subject(), e.n, slog.New(slog.NewJSONHandler(e.logs, nil))
	h := NewStreamHandler(e.st, cfg)
	tlsCfg := e.tlsConfig()
	srv := NewStreamServer(h, tlsCfg, nil)
	ln := ListenStream(listenDual(e.t), tlsCfg)
	go func() { _ = srv.Serve(ln) }()
	e.t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return h, "127.0.0.1:" + port
}

func (e *gwEnv) clientTLS(src x509svid.Source) *tls.Config {
	cfg := tlsconfig.MTLSClientConfig(src, e.ca.Bundle(), tlsconfig.AuthorizeID(e.gwID))
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.NextProtos = []string{"h2"}
	return cfg
}

// stallConn drops every write after stall is set, so that a peer's PING never gets an answer.
type stallConn struct {
	net.Conn
	stall *atomic.Bool
}

func (c stallConn) Write(p []byte) (int, error) {
	if c.stall.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// cstream is a client of one stream.
type cstream struct {
	t      *testing.T
	e      *gwEnv
	cell   string
	pod    string
	tc     *tls.Conn
	pw     *io.PipeWriter
	resp   *http.Response
	frames chan frameResult
	stall  atomic.Bool
	status int
	cancel context.CancelFunc
}

// close ends the stream and its connection, so the connection frees its slot of the listener.
func (c *cstream) close() {
	c.cancel()
	_ = c.pw.Close()
	if c.tc != nil {
		_ = c.tc.Close()
	}
}

type openOpts struct {
	svid *x509svid.SVID
	pod  string
}

func (e *gwEnv) open(addr, cell string, o openOpts) *cstream {
	e.t.Helper()
	if o.svid == nil {
		o.svid = e.ca.SVID(e.t, "spiffe://"+testTD+"/cell/"+cell+"/celld")
	}
	if o.pod == "" {
		o.pod = "pod-a"
	}
	c := &cstream{t: e.t, e: e, cell: cell, pod: o.pod, frames: make(chan frameResult, 16)}
	cfg := e.clientTLS(staticSource{o.svid})
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, a)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(stallConn{Conn: raw, stall: &c.stall}, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			c.tc = tc
			return tc, nil
		},
	}
	pr, pw := io.Pipe()
	c.pw = pw
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+gwapi.StreamPath(cell), pr)
	e.t.Cleanup(func() {
		c.close()
		tr.CloseIdleConnections()
	})
	type res struct {
		r   *http.Response
		err error
	}
	done := make(chan res, 1)
	go func() {
		r, err := (&http.Client{Transport: tr}).Do(req)
		done <- res{r, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			e.t.Fatalf("open stream: %v", r.err)
		}
		c.resp, c.status = r.r, r.r.StatusCode
	case <-time.After(5 * time.Second):
		e.t.Fatal("open stream: no response")
	}
	if c.status == http.StatusOK {
		go func() {
			dec := gwapi.NewDecoder(c.resp.Body)
			for {
				f, err := dec.Decode()
				c.frames <- frameResult{f, err}
				if err != nil {
					return
				}
			}
		}()
	}
	return c
}

func (c *cstream) send(f gwapi.Frame) {
	c.t.Helper()
	if err := gwapi.Encode(c.pw, f); err != nil {
		c.t.Fatalf("send %s: %v", f.Type, err)
	}
}

func (c *cstream) recv(d time.Duration) (gwapi.Frame, error) {
	select {
	case fr := <-c.frames:
		return fr.f, fr.err
	case <-time.After(d):
		return gwapi.Frame{}, errors.New("timeout")
	}
}

// expect reads the next frame and requires its type.
func (c *cstream) expect(typ string) gwapi.Frame {
	c.t.Helper()
	f, err := c.recv(frameWait)
	if err != nil || f.Type != typ {
		c.t.Fatalf("want a %s frame, got %+v, %v", typ, f, err)
	}
	return f
}

// token makes a token for audience with the claims of the pod of the stream.
func (c *cstream) token(aud string) string {
	return c.e.kt.Token(c.t, kubetoken.Claims{Issuer: "https://" + c.cell + ".example", Namespace: testNS, ServiceAccount: testSA,
		PodName: "name-" + c.pod, PodUID: c.pod, NodeName: "node", Audience: []string{aud}})
}

func (c *cstream) binding() string {
	c.t.Helper()
	b, err := proof.Binding(c.tc.ConnectionState())
	if err != nil {
		c.t.Fatal(err)
	}
	return b
}

func (c *cstream) hello(last op.Fence) {
	c.t.Helper()
	c.send(gwapi.Frame{Type: gwapi.TypeHello, Token: c.token(proof.HelloAudience(c.cell, c.binding())), LastFence: last})
}

// join opens a stream and completes the hello.
func (e *gwEnv) join(addr, cell, pod string) *cstream {
	e.t.Helper()
	c := e.open(addr, cell, openOpts{pod: pod})
	c.hello(op.Fence{})
	c.expect(gwapi.TypeWelcome)
	return c
}

// ended reports whether the stream is closed by the server within d.
func (c *cstream) ended(d time.Duration) bool {
	deadline := time.After(d)
	for {
		select {
		case fr := <-c.frames:
			if fr.err != nil {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func (e *gwEnv) opEnvelope(n int, cell string) []byte {
	e.t.Helper()
	o := op.Operation{ID: opID(n), Env: "dev", Cell: cell, Kind: op.KindDemoAppend, Version: 1, KeyEpoch: 1,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute), Args: json.RawMessage(fmt.Sprintf(`{"line":"n%d"}`, n))}
	env, err := op.Sign(o, e.g.priv)
	if err != nil {
		e.t.Fatal(err)
	}
	return env
}

func (e *gwEnv) enqueue(n int, cell string) []byte {
	e.t.Helper()
	env := e.opEnvelope(n, cell)
	if _, _, err := e.st.Enqueue(context.Background(), cell, env); err != nil {
		e.t.Fatal(err)
	}
	return env
}

// ---- hello

func TestStreamHelloRequired(t *testing.T) {
	e := newGwEnv(t)
	h, addr := e.serveStream(StreamConfig{HelloTimeout: 300 * time.Millisecond})
	if got := NewStreamHandler(e.st, StreamConfig{}).cfg.HelloTimeout; got != 5*time.Second {
		t.Fatalf("default hello timeout %v, want 5s", got)
	}
	t.Run("timeout", func(t *testing.T) {
		start := time.Now()
		c := e.open(addr, cell1, openOpts{})
		defer c.close()
		f := c.expect(gwapi.TypeRefused)
		if f.Reason != gwapi.ReasonHelloTimeout || time.Since(start) > 2*time.Second {
			t.Fatalf("refused %+v after %v", f, time.Since(start))
		}
	})
	t.Run("other_frame_first", func(t *testing.T) {
		c := e.open(addr, cell1, openOpts{})
		defer c.close()
		c.send(gwapi.Frame{Type: gwapi.TypePing})
		if f := c.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonProofMissing {
			t.Fatalf("refused %+v", f)
		}
	})
	t.Run("empty_token", func(t *testing.T) {
		c := e.open(addr, cell1, openOpts{})
		defer c.close()
		c.send(gwapi.Frame{Type: gwapi.TypeHello})
		if f := c.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonProofMissing {
			t.Fatalf("refused %+v", f)
		}
	})
	if n := len(h.Streams()); n != 0 {
		t.Fatalf("%d cells hold streams after refused hellos", n)
	}
}

func TestStreamHelloProof(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	rogue := kubetoken.NewSigner(t, "k1", jose.ES256)
	cases := map[string]func(c *cstream) string{
		"other_binding": func(c *cstream) string { return c.token(proof.HelloAudience(c.cell, "BBBBBBBBBBBBBBBBBBBBBB")) },
		"other_cell":    func(c *cstream) string { return c.token(proof.HelloAudience(cell2, c.binding())) },
		"other_subject": func(c *cstream) string {
			return e.kt.Token(t, kubetoken.Claims{Issuer: cell1Iss, Namespace: testNS, ServiceAccount: "other", PodName: "p", PodUID: "u",
				NodeName: "n", Audience: []string{proof.HelloAudience(c.cell, c.binding())}})
		},
		"rogue_key": func(c *cstream) string {
			return rogue.Token(t, kubetoken.Claims{Issuer: cell1Iss, Namespace: testNS, ServiceAccount: testSA, PodName: "p", PodUID: "u",
				NodeName: "n", Audience: []string{proof.HelloAudience(c.cell, c.binding())}})
		},
		"stream_audience": func(c *cstream) string { return c.token(proof.StreamAudience(c.cell, "otel", c.binding())) },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			c := e.open(addr, cell1, openOpts{})
			defer c.close()
			c.send(gwapi.Frame{Type: gwapi.TypeHello, Token: mk(c)})
			if f := c.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonProofInvalid {
				t.Fatalf("refused %+v", f)
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		c := e.open(addr, cell1, openOpts{pod: "uid-valid"})
		defer c.close()
		c.hello(op.Fence{})
		w := c.expect(gwapi.TypeWelcome)
		if w.Pod != "uid-valid" || w.Cap != 2 || w.Fence.Epoch != e.st.Epoch() {
			t.Fatalf("welcome %+v", w)
		}
	})
}

func TestStreamPeerMustMatchPath(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	for name, id := range map[string]string{
		"other_cell":  celld2,
		"other_role":  "spiffe://" + testTD + "/cell/dev-cell-1/argocd-agent",
		"control_pln": "spiffe://" + testTD + "/cp/celld",
	} {
		t.Run(name, func(t *testing.T) {
			c := e.open(addr, cell1, openOpts{svid: e.ca.SVID(t, id)})
			if c.status != http.StatusForbidden {
				t.Fatalf("status %d, want 403", c.status)
			}
		})
	}
	if c := e.open(addr, cell1, openOpts{svid: e.ca.SVID(t, celld1)}); c.status != http.StatusOK {
		t.Fatalf("the right peer got status %d", c.status)
	}
}

func TestStreamRevokedCell(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	t.Run("unknown", func(t *testing.T) {
		c := e.open(addr, "dev-cell-3", openOpts{})
		if f := c.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonCellUnknown {
			t.Fatalf("refused %+v", f)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		sp := spec.Spec{Env: e.g.env, Revision: rev(1, 2), Retired: []spec.Retired{}}
		recs := map[string]json.RawMessage{}
		for _, name := range []string{cell1, cell2} {
			c := record.Cell{Name: name, Env: e.g.env, Issuer: "https://" + name + ".example", JWKS: e.g.jwks,
				Subjects: []record.Subject{{Namespace: testNS, ServiceAccount: testSA}}, Revoked: name == cell1, Epoch: 1, Counter: 2}
			env, _ := record.Sign(c, e.g.priv)
			_, payload, _ := record.VerifyWithPayload(env, e.g.keys())
			recs[name] = env
			sp.Cells = append(sp.Cells, spec.Entry{Name: name, Revision: rev(1, 2), RecordSHA256: spec.RecordDigest(payload)})
		}
		senv, err := spec.Sign(sp, e.g.priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.st.ApplySync(context.Background(), senv, recs, e.g.keys()); err != nil {
			t.Fatal(err)
		}
		c := e.open(addr, cell1, openOpts{})
		if f := c.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonCellRevoked {
			t.Fatalf("refused %+v", f)
		}
		if c2 := e.open(addr, cell2, openOpts{}); c2.status != http.StatusOK {
			t.Fatalf("an unrevoked cell got status %d", c2.status)
		}
	})
}

// ---- replica cap

func TestStreamReplicaCap(t *testing.T) {
	e := newGwEnv(t)
	h, addr := e.serveStream(StreamConfig{ReplicaCap: 2})
	e.join(addr, cell1, "uid-a")
	e.join(addr, cell1, "uid-b")
	c := e.open(addr, cell1, openOpts{pod: "uid-c"})
	c.hello(op.Fence{})
	if f := c.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonReplicaCap {
		t.Fatalf("third pod: %+v", f)
	}
	if got := h.Streams()[cell1]; got != 2 {
		t.Fatalf("streams of %s: %d, want 2", cell1, got)
	}
	// The cap counts for each cell on its own.
	e.join(addr, cell2, "uid-a")
}

func TestStreamReplicaCapConcurrent(t *testing.T) {
	e := newGwEnv(t)
	h, addr := e.serveStream(StreamConfig{ReplicaCap: 2})
	streams := make([]*cstream, 3)
	for i := range streams {
		streams[i] = e.open(addr, cell1, openOpts{pod: fmt.Sprintf("uid-%d", i)})
	}
	var wg sync.WaitGroup
	var welcomed, capped atomic.Int32
	start := make(chan struct{})
	for _, c := range streams {
		wg.Go(func() {
			<-start
			c.hello(op.Fence{})
			f, err := c.recv(frameWait)
			switch {
			case err == nil && f.Type == gwapi.TypeWelcome:
				welcomed.Add(1)
			case err == nil && f.Type == gwapi.TypeRefused && f.Reason == gwapi.ReasonReplicaCap:
				capped.Add(1)
			default:
				t.Errorf("answer %+v, %v", f, err)
			}
		})
	}
	close(start)
	wg.Wait()
	if welcomed.Load() != 2 || capped.Load() != 1 || h.Streams()[cell1] != 2 {
		t.Fatalf("welcomed %d, capped %d, streams %d; want 2, 1, 2", welcomed.Load(), capped.Load(), h.Streams()[cell1])
	}
}

func TestStreamSamePodSupersedes(t *testing.T) {
	e := newGwEnv(t)
	h, addr := e.serveStream(StreamConfig{ReplicaCap: 2})
	old := e.join(addr, cell1, "uid-a")
	e.join(addr, cell1, "uid-b")
	fresh := e.join(addr, cell1, "uid-a")
	if f := old.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonSuperseded {
		t.Fatalf("old stream: %+v", f)
	}
	if !old.ended(frameWait) {
		t.Fatal("the superseded stream stays open")
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.Streams()[cell1] != 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.Streams()[cell1]; got != 2 {
		t.Fatalf("streams %d after a supersede, want 2", got)
	}
	fresh.send(gwapi.Frame{Type: gwapi.TypePing})
	fresh.expect(gwapi.TypePong)
}

// ---- frames

func TestStreamClaimLeaseResult(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	env := e.enqueue(1, cell1)
	c := e.join(addr, cell1, "uid-a")
	c.send(gwapi.Frame{Type: gwapi.TypeClaim})
	var lease gwapi.Frame
	for { // a work frame may come first
		f, err := c.recv(frameWait)
		if err != nil {
			t.Fatal(err)
		}
		if f.Type == gwapi.TypeLease {
			lease = f
			break
		}
	}
	if lease.OpID != opID(1) || lease.LeaseID == "" || lease.Fence.Epoch != e.st.Epoch() || lease.Until.IsZero() {
		t.Fatalf("lease %+v", lease)
	}
	if !bytes.Equal(compact(t, lease.Envelope), compact(t, env)) {
		t.Fatal("the lease carries another envelope")
	}
	it := resultItem(cell1, opID(1))
	c.send(gwapi.Frame{Type: gwapi.TypeResult, LeaseID: lease.LeaseID, OpID: opID(1), Fence: lease.Fence, Item: &it})
	if f := c.expect(gwapi.TypeAck); f.OpID != opID(1) {
		t.Fatalf("ack %+v", f)
	}
	c.send(gwapi.Frame{Type: gwapi.TypeClaim})
	c.expect(gwapi.TypeNone)
	items, err := e.st.Peek(context.Background(), 10, 1<<20)
	if err != nil || len(items) != 1 || items[0].OpID != opID(1) || items[0].Kind != gwapi.KindResult {
		t.Fatalf("outbox %+v, %v", items, err)
	}
}

func compact(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestStreamWorkOnEnqueue(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	c := e.join(addr, cell1, "uid-a")
	e.enqueue(1, cell1)
	start := time.Now()
	f := c.expect(gwapi.TypeWork)
	if f.Queued != 1 || time.Since(start) > time.Second {
		t.Fatalf("work %+v after %v", f, time.Since(start))
	}
	// An operation of another cell does not wake this stream.
	e.enqueue(2, cell2)
	if f, err := c.recv(500 * time.Millisecond); err == nil {
		t.Fatalf("a frame %+v for work of another cell", f)
	}
}

func TestStreamWorkRepeatsWhileQueued(t *testing.T) {
	setVar(t, &workEvery, time.Second)
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	e.enqueue(1, cell1)
	c := e.join(addr, cell1, "uid-a")
	start := time.Now()
	c.expect(gwapi.TypeWork)
	c.send(gwapi.Frame{Type: gwapi.TypePing}) // keep the stream open past the idle limit
	deadline := time.After(10 * time.Second)
	for {
		select {
		case fr := <-c.frames:
			if fr.err == nil && fr.f.Type == gwapi.TypeWork {
				if d := time.Since(start); d < 500*time.Millisecond || d > 4500*time.Millisecond {
					t.Fatalf("second work frame after %v, want 1 to 2 s", d)
				}
				return
			}
		case <-deadline:
			t.Fatal("no repeated work frame while an item is queued")
		}
	}
}

func TestStreamForgedItemNotLeasedAgain(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	e.enqueue(1, cell1)
	c := e.join(addr, cell1, "uid-a")
	c.send(gwapi.Frame{Type: gwapi.TypeClaim})
	var lease gwapi.Frame
	for lease.Type != gwapi.TypeLease {
		f, err := c.recv(frameWait)
		if err != nil {
			t.Fatal(err)
		}
		lease = f
	}
	it := resultItem(cell1, "")
	c.send(gwapi.Frame{Type: gwapi.TypeResult, LeaseID: lease.LeaseID, Fence: lease.Fence, Item: &it})
	c.expect(gwapi.TypeAck)
	// The row is on hold, not done, so the next claim gives nothing for now.
	c.send(gwapi.Frame{Type: gwapi.TypeClaim})
	c.expect(gwapi.TypeNone)
}

func TestStreamResendAfterDoneIsAcked(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	e.enqueue(1, cell1)
	c := e.join(addr, cell1, "uid-a")
	c.send(gwapi.Frame{Type: gwapi.TypeClaim})
	var lease gwapi.Frame
	for lease.Type != gwapi.TypeLease {
		f, err := c.recv(frameWait)
		if err != nil {
			t.Fatal(err)
		}
		lease = f
	}
	it := resultItem(cell1, opID(1))
	for i := 0; i < 2; i++ {
		c.send(gwapi.Frame{Type: gwapi.TypeResult, LeaseID: lease.LeaseID, OpID: opID(1), Fence: lease.Fence, Item: &it})
		if f := c.expect(gwapi.TypeAck); f.OpID != opID(1) {
			t.Fatalf("ack %d: %+v", i, f)
		}
	}
	// A result whose lease the gateway lost still gets an ack.
	c.send(gwapi.Frame{Type: gwapi.TypeResult, LeaseID: "nonsense", OpID: opID(1), Item: &it})
	c.expect(gwapi.TypeAck)
	c.send(gwapi.Frame{Type: gwapi.TypeClaim})
	c.expect(gwapi.TypeNone)
}

func TestStreamResultOnlyForTheCellOfTheHello(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	e.enqueue(1, cell2)
	c := e.join(addr, cell1, "uid-a")
	it := resultItem(cell2, opID(1))
	c.send(gwapi.Frame{Type: gwapi.TypeResult, OpID: opID(1), Item: &it})
	if f := c.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonProofInvalid {
		t.Fatalf("refused %+v", f)
	}
	if !c.ended(frameWait) {
		t.Fatal("the stream stays open after a result for another cell")
	}
	if items, _ := e.st.Peek(context.Background(), 10, 1<<20); len(items) != 0 {
		t.Fatalf("outbox holds %d items from a forged result", len(items))
	}
	// Neither is a status item for another cell taken.
	c = e.join(addr, cell1, "uid-a")
	st := gwapi.Item{Kind: gwapi.KindStatus, Cell: cell2, Body: json.RawMessage(`{}`), Token: "t"}
	c.send(gwapi.Frame{Type: gwapi.TypeStatus, Item: &st})
	c.expect(gwapi.TypeRefused)
}

func TestStreamStatusAppends(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	c := e.join(addr, cell1, "uid-a")
	st := gwapi.Item{Kind: gwapi.KindStatus, Cell: cell1, Body: json.RawMessage(`{}`), Token: "t"}
	c.send(gwapi.Frame{Type: gwapi.TypeStatus, Item: &st})
	c.expect(gwapi.TypeAck)
	if items, _ := e.st.Peek(context.Background(), 10, 1<<20); len(items) != 1 || items[0].Kind != gwapi.KindStatus {
		t.Fatalf("outbox %+v", items)
	}
}

// With the outbox full of results, a status item gets overloaded and the stream stays open.
func TestStreamStatusRefusedWhenFull(t *testing.T) {
	e := newGwEnv(t)
	e.st.perCell = 1
	if _, err := e.st.Append(context.Background(), resultItem(cell1, opID(7))); err != nil {
		t.Fatal(err)
	}
	_, addr := e.serveStream(StreamConfig{})
	c := e.join(addr, cell1, "uid-a")
	st := gwapi.Item{Kind: gwapi.KindStatus, Cell: cell1, Body: json.RawMessage(`{}`), Token: "t"}
	c.send(gwapi.Frame{Type: gwapi.TypeStatus, Item: &st})
	c.send(gwapi.Frame{Type: gwapi.TypePing})
	for {
		f, err := c.recv(frameWait)
		if err != nil {
			t.Fatal(err)
		}
		if f.Type == gwapi.TypeRefused {
			if f.Reason != gwapi.ReasonOverloaded {
				t.Fatalf("refused %+v", f)
			}
			break
		}
	}
	c.expect(gwapi.TypePong)
}

func TestStreamForwardsFinalAndRetry(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	ctx := context.Background()
	c := e.join(addr, cell1, "uid-a")
	var ids []gwapi.ItemID
	for _, n := range []int{1, 2} {
		id, err := e.st.Append(ctx, resultItem(cell1, opID(n)))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := e.st.Ack(ctx, []mgmtapi.ItemOutcome{
		{ID: string(ids[0]), Outcome: mgmtapi.OutcomeAccepted},
		{ID: string(ids[1]), Outcome: mgmtapi.OutcomeRetry, Reason: mgmtapi.ReasonProofInvalid, Detail: "token_expired"},
	}); err != nil {
		t.Fatal(err)
	}
	got := map[string]gwapi.Frame{}
	deadline := time.After(4 * time.Second)
	for len(got) < 2 {
		select {
		case fr := <-c.frames:
			if fr.err != nil {
				t.Fatal(fr.err)
			}
			if fr.f.Type == gwapi.TypeFinal || fr.f.Type == gwapi.TypeRetry {
				got[fr.f.Type] = fr.f
			}
		case <-deadline:
			t.Fatalf("frames so far: %+v", got)
		}
	}
	if f := got[gwapi.TypeFinal]; f.OpID != opID(1) || f.Outcome != mgmtapi.OutcomeAccepted {
		t.Fatalf("final %+v", f)
	}
	if f := got[gwapi.TypeRetry]; f.OpID != opID(2) {
		t.Fatalf("retry %+v", f)
	}
	// The same stream does not repeat either frame, and a new stream gets the final only.
	if f, err := c.recv(1500 * time.Millisecond); err == nil {
		t.Fatalf("repeated frame %+v", f)
	}
	again := e.join(addr, cell1, "uid-b")
	f := again.expect(gwapi.TypeFinal)
	if f.OpID != opID(1) {
		t.Fatalf("final on a new stream: %+v", f)
	}
	if f, err := again.recv(1500 * time.Millisecond); err == nil {
		t.Fatalf("a new stream got %+v after the retry was forwarded", f)
	}
}

// A retry outcome from the management plane goes down by its kind. Its reason can be any string.
func TestStreamRetryPassesAnyReason(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	ctx := context.Background()
	c := e.join(addr, cell1, "uid-a")
	reasons := []string{"issuer_unavailable", "store", "internal", "proof_invalid", "reason_nobody_knew_before", ""}
	var outs []mgmtapi.ItemOutcome
	for i, reason := range reasons {
		id, err := e.st.Append(ctx, resultItem(cell1, opID(20+i)))
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, mgmtapi.ItemOutcome{ID: string(id), Outcome: mgmtapi.OutcomeRetry, Reason: reason})
	}
	if err := e.st.Ack(ctx, outs); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for len(got) < len(reasons) {
		select {
		case fr := <-c.frames:
			if fr.err != nil {
				t.Fatal(fr.err)
			}
			if fr.f.Type != gwapi.TypeRetry {
				t.Fatalf("frame %+v, want only retry frames", fr.f)
			}
			got[fr.f.OpID] = true
		case <-deadline:
			t.Fatalf("retry frames for %d of %d outcomes", len(got), len(reasons))
		}
	}
}

// A failed write after FinalOutcomes loses no retry outcome.
func TestStreamFailedWriteKeepsRetries(t *testing.T) {
	e := newGwEnv(t)
	h := NewStreamHandler(e.st, StreamConfig{})
	ctx := context.Background()
	id, err := e.st.Append(ctx, resultItem(cell1, opID(2)))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Ack(ctx, []mgmtapi.ItemOutcome{{ID: string(id), Outcome: mgmtapi.OutcomeRetry}}); err != nil {
		t.Fatal(err)
	}
	cursor, err := h.forward(ctx, cell1, 0, func(gwapi.Frame) error { return errors.New("write failed") })
	if err == nil || cursor != 0 {
		t.Fatalf("forward after a failed write: cursor %d, %v", cursor, err)
	}
	var sent []gwapi.Frame
	cursor, err = h.forward(ctx, cell1, 0, func(f gwapi.Frame) error { sent = append(sent, f); return nil })
	if err != nil || len(sent) != 1 || sent[0].Type != gwapi.TypeRetry || cursor == 0 {
		t.Fatalf("second forward: %+v, cursor %d, %v", sent, cursor, err)
	}
	sent = nil
	if _, err := h.forward(ctx, cell1, 0, func(f gwapi.Frame) error { sent = append(sent, f); return nil }); err != nil || len(sent) != 0 {
		t.Fatalf("a forwarded retry came again: %+v, %v", sent, err)
	}
}

func TestStreamPingPong(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	c := e.join(addr, cell1, "uid-a")
	for i := 0; i < 3; i++ {
		c.send(gwapi.Frame{Type: gwapi.TypePing})
		c.expect(gwapi.TypePong)
	}
}

func TestStreamFrameLimit(t *testing.T) {
	e := newGwEnv(t)
	h, addr := e.serveStream(StreamConfig{})
	c := e.join(addr, cell1, "uid-a")
	big := `{"type":"status","item":{"kind":"status","cell":"` + cell1 + `","body":"` + strings.Repeat("x", gwapi.MaxFrame) + `","token":"t"}}` + "\n"
	go func() { _, _ = c.pw.Write([]byte(big)) }()
	if !c.ended(frameWait) {
		t.Fatal("a frame above 64 KiB leaves the stream open")
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.Streams()[cell1] != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.Streams()[cell1] != 0 {
		t.Fatal("the stream keeps its cap slot")
	}
	if items, _ := e.st.Peek(context.Background(), 10, 1<<20); len(items) != 0 {
		t.Fatal("an oversized frame reached the outbox")
	}
}

// A write deadline must not outlive its write: a quiet stream stays open and answers later.
func TestStreamSurvivesQuietWrites(t *testing.T) {
	setVar(t, &writeTimeout, time.Second)
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	c := e.join(addr, cell1, "uid-a")
	time.Sleep(writeTimeout + time.Second)
	c.send(gwapi.Frame{Type: gwapi.TypePing})
	c.expect(gwapi.TypePong)
}

func TestStreamNoFrameEndsStream(t *testing.T) {
	e := newGwEnv(t)
	h, addr := e.serveStream(StreamConfig{FrameIdle: 600 * time.Millisecond, ReplicaCap: 1})
	c := e.join(addr, cell1, "uid-a")
	if !c.ended(3 * time.Second) {
		t.Fatal("a stream with no frame stays open")
	}
	e.join(addr, cell1, "uid-b") // the slot is free again
	_ = h
	if got := NewStreamHandler(e.st, StreamConfig{}).cfg.FrameIdle; got != 30*time.Second {
		t.Fatalf("default frame idle %v, want 30s", got)
	}
}

func TestStreamClosesAtMaxLife(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{MaxLife: time.Second})
	c := e.join(addr, cell1, "uid-a")
	start := time.Now()
	f := c.expect(gwapi.TypeRefused)
	if f.Reason != gwapi.ReasonReauth || time.Since(start) > 2*time.Second {
		t.Fatalf("refused %+v after %v", f, time.Since(start))
	}
	if got := NewStreamHandler(e.st, StreamConfig{}).cfg.MaxLife; got != time.Hour {
		t.Fatalf("default max life %v, want 1h", got)
	}
}

func TestStreamClosesAtLeafExpiry(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	start := time.Now()
	c := e.open(addr, cell1, openOpts{svid: e.ca.SVIDWithTTL(t, celld1, 3*time.Second), pod: "uid-a"})
	c.hello(op.Fence{})
	c.expect(gwapi.TypeWelcome)
	f, err := c.recv(4 * time.Second)
	if err != nil || f.Type != gwapi.TypeRefused || f.Reason != gwapi.ReasonReauth {
		t.Fatalf("frame %+v, %v", f, err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("reauth after %v", d)
	}
}

func TestStreamDeadPodFreesCap(t *testing.T) {
	// The HTTP/2 ping alone frees the slot: the frame idle limit is out of reach.
	setVar(t, &sendPingTimeout, 500*time.Millisecond)
	setVar(t, &pingTimeout, 500*time.Millisecond)
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{ReplicaCap: 1, FrameIdle: time.Hour})
	dead := e.join(addr, cell1, "uid-dead")
	dead.stall.Store(true) // the client stops answering from now on
	start := time.Now()
	for {
		c := e.open(addr, cell1, openOpts{pod: "uid-new"})
		c.hello(op.Fence{})
		f, err := c.recv(frameWait)
		c.close()
		if err == nil && f.Type == gwapi.TypeWelcome {
			break
		}
		if time.Since(start) > 8*time.Second {
			t.Fatalf("the slot of a silent pod is still taken after %v (last %+v, %v)", time.Since(start), f, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// setVar sets a package variable for one test.
func setVar[T any](t *testing.T, v *T, val T) {
	t.Helper()
	old := *v
	*v = val
	t.Cleanup(func() { *v = old })
}

func TestStreamRealTimeLimits(t *testing.T) {
	if writeTimeout != 10*time.Second || workEvery != 5*time.Second || sendPingTimeout != 30*time.Second ||
		pingTimeout != 10*time.Second || noRequestTimeout != 5*time.Second {
		t.Fatal("a limit differs from the shared table")
	}
}

// ---- listener limits

func rawTLS(t *testing.T, e *gwEnv, addr string) (*tls.Conn, error) {
	t.Helper()
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: e.clientTLS(e.ca.Source(t, celld1))}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*tls.Conn), nil
}

func TestStreamListenerPerSourceCap(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	_, port, _ := net.SplitHostPort(addr)
	var held []*tls.Conn
	for i := 0; i < 4; i++ {
		c, err := rawTLS(t, e, addr)
		if err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
		held = append(held, c)
	}
	start := time.Now()
	if c, err := rawTLS(t, e, addr); err == nil {
		_ = c.Close()
		t.Fatal("the fifth connection from one source is served")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("the fifth connection took %v to close", time.Since(start))
	}
	// A client from another source is served while the first four stay open.
	probe, err := net.Dial("tcp", "[::1]:"+port)
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = probe.Close()
	start = time.Now()
	c := e.open("[::1]:"+port, cell1, openOpts{pod: "uid-v6"})
	c.hello(op.Fence{})
	c.expect(gwapi.TypeWelcome)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the client from ::1 waited %v", time.Since(start))
	}
	_ = held
}

func TestStreamIdleConnectionReleased(t *testing.T) {
	e := newGwEnv(t)
	_, addr := e.serveStream(StreamConfig{})
	start := time.Now()
	closed := make(chan time.Duration, 4)
	for i := 0; i < 4; i++ {
		c, err := rawTLS(t, e, addr)
		if err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
		go func() {
			_, _ = io.Copy(io.Discard, c)
			closed <- time.Since(start)
		}()
	}
	if c, err := rawTLS(t, e, addr); err == nil {
		_ = c.Close()
		t.Fatal("a fifth silent connection is served")
	}
	for i := 0; i < 4; i++ {
		select {
		case d := <-closed:
			if d < 4*time.Second {
				t.Fatalf("a silent connection closed after %v, before the 5 s limit", d)
			}
		case <-time.After(6*time.Second - time.Since(start)):
			t.Fatalf("%d of 4 silent connections are still open after 6 s", 4-i)
		}
	}
	c := e.open(addr, cell1, openOpts{pod: "uid-good"})
	c.hello(op.Fence{})
	c.expect(gwapi.TypeWelcome)
}

// ---- key hints and trace

func TestHelloUnknownKidHints(t *testing.T) {
	e := newGwEnv(t)
	h, addr := e.serveStream(StreamConfig{})
	other := kubetoken.NewSigner(t, "unknown-kid", jose.ES256)
	hello := func(sg *kubetoken.Signer) {
		c := e.open(addr, cell1, openOpts{})
		tok := sg.Token(t, kubetoken.Claims{Issuer: cell1Iss, Namespace: testNS, ServiceAccount: testSA, PodName: "p", PodUID: "u",
			NodeName: "n", Audience: []string{proof.HelloAudience(cell1, c.binding())}})
		c.send(gwapi.Frame{Type: gwapi.TypeHello, Token: tok})
		if f := c.expect(gwapi.TypeRefused); f.Reason != gwapi.ReasonProofInvalid {
			t.Fatalf("refused %+v", f)
		}
	}
	bad := kubetoken.NewSigner(t, "k1", jose.ES256) // the known kid under another key: a bad signature
	hello(bad)
	if got := h.TakeHints(); len(got) != 0 {
		t.Fatalf("a bad signature made hints %+v", got)
	}
	hello(other)
	hello(other)
	got := h.TakeHints()
	if len(got) != 1 || got[0].Cell != cell1 || got[0].At.IsZero() {
		t.Fatalf("two unknown-kid hellos made hints %+v, want one", got)
	}
	if again := h.TakeHints(); len(again) != 0 {
		t.Fatalf("hints come again: %+v", again)
	}
	// The hint rides the next sync status.
	hello(other) // within 60 s of the first: no new hint
	if got := h.TakeHints(); len(got) != 0 {
		t.Fatalf("a hint inside the 60 s gap: %+v", got)
	}
}

func TestHintBookGap(t *testing.T) {
	b := hintBook{last: map[string]time.Time{}, pending: map[string]time.Time{}}
	t0 := time.Now()
	b.note("c", t0)
	b.take()
	b.note("c", t0.Add(59*time.Second))
	if got := b.take(); len(got) != 0 {
		t.Fatalf("hint at 59 s: %+v", got)
	}
	b.note("c", t0.Add(61*time.Second))
	if got := b.take(); len(got) != 1 {
		t.Fatalf("no hint at 61 s: %+v", got)
	}
}

func TestStreamServerLogLineCarriesTraceID(t *testing.T) {
	e := newGwEnv(t)
	var out lockedBuf
	log := telemetry.NewLogger(&out, slog.DiscardHandler)
	h := NewStreamHandler(e.st, StreamConfig{Subject: e.subject(), Log: log, HelloTimeout: 200 * time.Millisecond})
	tlsCfg := e.tlsConfig()
	srv := NewStreamServer(h, tlsCfg, sdktrace.NewTracerProvider().Tracer("test"))
	ln := ListenStream(listenDual(t), tlsCfg)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	c := e.open("127.0.0.1:"+port, cell1, openOpts{})
	c.expect(gwapi.TypeRefused)
	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "stream_refused" {
			line = m
		}
	}
	if id, _ := line["trace_id"].(string); len(id) != 32 {
		t.Fatalf("log output %q has no stream_refused line with a trace_id", out.String())
	}
}
