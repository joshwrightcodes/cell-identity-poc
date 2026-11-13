package mgmt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

var (
	celld = record.Subject{Namespace: "cell-identity-system", ServiceAccount: "celld"}
	agent = record.Subject{Namespace: "cell-identity-system", ServiceAccount: "spire-agent"}
)

const (
	cell1 = "dev-cell-1"
	cell2 = "dev-cell-2"
	cell3 = "dev-cell-3"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) count(msg string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Count(b.buf.String(), `"msg":"`+msg+`"`)
}

type cluster struct {
	issuer  string
	signers []*kubetoken.Signer
}

type fakeKeys struct {
	mu       sync.Mutex
	clusters map[string]*cluster
	errs     map[string]error
	calls    map[string]int
	gate     chan struct{}
	gateCell string
}

func newFakeKeys() *fakeKeys {
	return &fakeKeys{clusters: map[string]*cluster{}, errs: map[string]error{}, calls: map[string]int{}}
}

func (f *fakeKeys) set(name, issuer string, signers ...*kubetoken.Signer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clusters[name] = &cluster{issuer: issuer, signers: signers}
}

func (f *fakeKeys) fail(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.errs, name)
		return
	}
	f.errs[name] = err
}

func (f *fakeKeys) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func (f *fakeKeys) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
}

func (f *fakeKeys) issuer(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clusters[name].issuer
}

func (f *fakeKeys) Keys(ctx context.Context, name string) (mgmtapi.ClusterKeys, error) {
	f.mu.Lock()
	f.calls[name]++
	gate := f.gate
	if f.gateCell != "" && f.gateCell != name {
		gate = nil
	}
	c, ok := f.clusters[name]
	err := f.errs[name]
	f.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return mgmtapi.ClusterKeys{}, ctx.Err()
		}
	}
	if err != nil {
		return mgmtapi.ClusterKeys{}, err
	}
	if !ok {
		return mgmtapi.ClusterKeys{}, &mgmtapi.KeyError{Reason: mgmtapi.ReasonIssuerUnavailable, Err: errors.New("no such cluster")}
	}
	return mgmtapi.ClusterKeys{Name: name, Issuer: c.issuer, JWKS: mergeJWKS(c.signers...)}, nil
}

func mergeJWKS(signers ...*kubetoken.Signer) json.RawMessage {
	keys := []json.RawMessage{}
	for _, s := range signers {
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(s.JWKS(), &set); err != nil {
			panic(err)
		}
		keys = append(keys, set.Keys...)
	}
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		panic(err)
	}
	return b
}

func testIntent(cells ...string) Intent {
	in := Intent{Env: "dev", BindSubject: celld}
	for _, c := range cells {
		in.Cells = append(in.Cells, IntentCell{Name: c, Subjects: []record.Subject{celld, agent}})
	}
	return in
}

type rig struct {
	t       *testing.T
	clk     *fakeClock
	keys    *fakeKeys
	dir     string
	store   Store
	intent  Intent
	plane   *Plane
	logs    *lockedBuf
	ticks   chan time.Time
	signers map[string]*kubetoken.Signer
	mod     func(*Config)
}

func newSigner(t testing.TB, kid string) *kubetoken.Signer {
	t.Helper()
	return kubetoken.NewSigner(t, kid, jose.ES256)
}

func newRig(t *testing.T, cells ...string) *rig {
	t.Helper()
	if len(cells) == 0 {
		cells = []string{cell1, cell2}
	}
	r := &rig{
		t:       t,
		clk:     &fakeClock{now: time.Now().Truncate(time.Second)},
		keys:    newFakeKeys(),
		dir:     t.TempDir(),
		intent:  testIntent(cells...),
		logs:    &lockedBuf{},
		ticks:   make(chan time.Time),
		signers: map[string]*kubetoken.Signer{},
	}
	log := slog.New(slog.NewJSONHandler(r.logs, nil))
	r.store = &FileStore{Path: filepath.Join(r.dir, "state.json"), Log: log, Now: r.clk.Now}
	for _, c := range []string{cell1, cell2, cell3} {
		r.signers[c] = newSigner(t, "kid-1")
		r.keys.set(c, "https://"+c+".test", r.signers[c])
	}
	r.start()
	return r
}

func (r *rig) config() Config {
	cfg := Config{
		Intent:  cloneIntent(r.intent),
		KeyPath: filepath.Join(r.dir, "ed25519.key"),
		Store:   r.store,
		Keys:    r.keys,
		Now:     r.clk.Now,
		Ticks:   func(time.Duration) <-chan time.Time { return r.ticks },
		Log:     slog.New(slog.NewJSONHandler(r.logs, nil)),
	}
	if r.mod != nil {
		r.mod(&cfg)
	}
	return cfg
}

func cloneIntent(in Intent) Intent {
	out := in
	out.Cells = make([]IntentCell, len(in.Cells))
	for i, c := range in.Cells {
		out.Cells[i] = IntentCell{Name: c.Name, Subjects: append([]record.Subject(nil), c.Subjects...)}
	}
	return out
}

func (r *rig) start() {
	r.t.Helper()
	p, err := NewPlane(r.config())
	if err != nil {
		r.t.Fatalf("NewPlane: %v", err)
	}
	r.plane = p
}

func (r *rig) token(cell, nonce string, sig *kubetoken.Signer, mod func(*kubetoken.Claims)) string {
	r.t.Helper()
	c := kubetoken.Claims{
		Issuer: r.keys.issuer(cell), Namespace: celld.Namespace, ServiceAccount: celld.ServiceAccount,
		PodName: "celld-0", PodUID: "pod-uid", NodeName: "node-1",
		Audience: []string{mgmtapi.BindAudience(cell, nonce)}, IssuedAt: r.clk.Now(),
	}
	if mod != nil {
		mod(&c)
	}
	return sig.Token(r.t, c)
}

func (r *rig) nonce(cell string) string {
	r.t.Helper()
	n, err := r.plane.Nonce(cell)
	if err != nil {
		r.t.Fatalf("Nonce(%s): %v", cell, err)
	}
	return n.Nonce
}

func (r *rig) bind(cell string, sig *kubetoken.Signer) (mgmtapi.BindResponse, error) {
	r.t.Helper()
	n := r.nonce(cell)
	return r.plane.Bind(r.t.Context(), cell, mgmtapi.BindRequest{Nonce: n, Token: r.token(cell, n, sig, nil)})
}

func (r *rig) mustBind(cell string, sig *kubetoken.Signer, want string) mgmtapi.BindResponse {
	r.t.Helper()
	resp, err := r.bind(cell, sig)
	if err != nil || resp.Status != want {
		r.t.Fatalf("bind %s: %+v, %v; want %s", cell, resp, err, want)
	}
	return resp
}

func (r *rig) stateBytes() []byte {
	b, err := os.ReadFile(filepath.Join(r.dir, "state.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

func (r *rig) restart(mod func(*Intent)) {
	r.t.Helper()
	if mod != nil {
		mod(&r.intent)
	}
	r.start()
}

func marshal(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func reasonDetail(err error) (string, string) {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason, e.Detail
	}
	return "", ""
}

func (r *rig) verifySpec() spec.Spec {
	r.t.Helper()
	s, _, err := spec.Verify(r.plane.Spec().Spec, []ed25519.PublicKey{r.plane.PublicKey()})
	if err != nil {
		r.t.Fatalf("spec does not verify: %v", err)
	}
	return s
}

func (r *rig) verifyRecord(cell string) record.Cell {
	r.t.Helper()
	raw, ok := r.plane.Records()[cell]
	if !ok {
		r.t.Fatalf("no record for %s", cell)
	}
	c, payload, err := record.VerifyWithPayload(raw, []ed25519.PublicKey{r.plane.PublicKey()})
	if err != nil {
		r.t.Fatalf("record %s: %v", cell, err)
	}
	if err := r.verifySpec().CheckRecord(cell, c, payload); err != nil {
		r.t.Fatalf("record %s against spec: %v", cell, err)
	}
	return c
}

func (r *rig) status() Status { return r.plane.Status() }

func cellStatus(st Status, name string) CellStatus {
	for _, c := range st.Cells {
		if c.Name == name {
			return c
		}
	}
	return CellStatus{}
}

func rev(e, c uint64) spec.Revision { return spec.Revision{Epoch: e, Counter: c} }

func TestNewPlaneSignsInitialSpec(t *testing.T) {
	r := newRig(t)
	s := r.verifySpec()
	if s.Revision != rev(1, 1) || s.Env != "dev" || len(s.Cells) != 0 || len(s.Retired) != 0 {
		t.Fatalf("initial spec %+v", s)
	}
	if len(r.plane.Records()) != 0 {
		t.Fatal("initial bundle holds records")
	}
	st := r.status()
	if st.Signed != rev(1, 1) || st.Served != rev(1, 1) || st.Env != "dev" || len(st.Cells) != 2 {
		t.Fatalf("status %+v", st)
	}
	if c := cellStatus(st, cell1); c.Bound {
		t.Fatal("a fresh cell is bound")
	}
	if len(r.stateBytes()) == 0 {
		t.Fatal("no state file")
	}
	info, _ := os.Stat(filepath.Join(r.dir, "state.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %o", info.Mode().Perm())
	}
	if !r.plane.PublicKey().Equal(r.plane.PublicKey()) || len(r.plane.PublicKey()) != ed25519.PublicKeySize {
		t.Fatal("public key")
	}
}

func TestNewPlaneRefusesBadConfig(t *testing.T) {
	r := newRig(t)
	cfg := r.config()
	cfg.Store = nil
	if _, err := NewPlane(cfg); err == nil {
		t.Fatal("no store accepted")
	}
	cfg = r.config()
	cfg.Keys = nil
	if _, err := NewPlane(cfg); err == nil {
		t.Fatal("no key source accepted")
	}
	cfg = r.config()
	cfg.Intent.Cells[0].Name = "rogue"
	if _, err := NewPlane(cfg); err == nil {
		t.Fatal("reserved cell name accepted")
	}
	cfg = r.config()
	cfg.Intent.Env = "other"
	if _, err := NewPlane(cfg); err == nil {
		t.Fatal("an intent for another env is accepted over the stored state")
	}
}

func TestBindHappyPath(t *testing.T) {
	r := newRig(t)
	n, err := r.plane.Nonce(cell1)
	if err != nil || n.Bound || n.Audience != mgmtapi.BindAudience(cell1, n.Nonce) || !n.ExpiresAt.After(r.clk.Now()) {
		t.Fatalf("nonce %+v, %v", n, err)
	}
	resp, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n.Nonce, Token: r.token(cell1, n.Nonce, r.signers[cell1], nil)})
	if err != nil || resp.Status != mgmtapi.StatusBound || resp.Record != rev(1, 2) {
		t.Fatalf("bind %+v, %v", resp, err)
	}
	s := r.verifySpec()
	if s.Revision != rev(1, 2) || len(s.Cells) != 1 || s.Cells[0].Name != cell1 || s.Cells[0].Revision != rev(1, 2) {
		t.Fatalf("spec %+v", s)
	}
	c := r.verifyRecord(cell1)
	if c.Issuer != "https://dev-cell-1.test" || c.Env != "dev" || c.Revoked || c.Epoch != 1 || c.Counter != 2 {
		t.Fatalf("record %+v", c)
	}
	if !slices.Equal(c.Subjects, []record.Subject{celld, agent}) {
		t.Fatalf("subjects %v", c.Subjects)
	}
	if !strings.Contains(string(c.JWKS), `"kid":"kid-1"`) {
		t.Fatalf("jwks %s", c.JWKS)
	}
	if again, _ := r.plane.Nonce(cell1); !again.Bound {
		t.Fatal("nonce for a bound cell says unbound")
	}
	st := r.status()
	cs := cellStatus(st, cell1)
	if !cs.Bound || cs.Issuer != "https://dev-cell-1.test" || !slices.Equal(cs.Kids, []string{"kid-1"}) || cs.Record != rev(1, 2) {
		t.Fatalf("cell status %+v", cs)
	}
	if _, err := r.plane.Nonce("dev-cell-9"); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("nonce for an unknown cell: %v", err)
	}
	if st.Signed != rev(1, 2) {
		t.Fatalf("signed %v", st.Signed)
	}
}

func TestBindUpdatesKeys(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	b := newSigner(t, "kid-2")
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], b)
	r.clk.Advance(61 * time.Second)
	resp := r.mustBind(cell1, b, mgmtapi.StatusKeysUpdated)
	if resp.Record != rev(1, 3) {
		t.Fatalf("record %v", resp.Record)
	}
	c := r.verifyRecord(cell1)
	if !strings.Contains(string(c.JWKS), "kid-2") || !strings.Contains(string(c.JWKS), "kid-1") {
		t.Fatalf("jwks %s", c.JWKS)
	}

	// The old key leaves, and the token proves the new one.
	r.keys.set(cell1, "https://dev-cell-1.test", b)
	r.clk.Advance(61 * time.Second)
	r.mustBind(cell1, b, mgmtapi.StatusAlreadyBound)
	c3 := newSigner(t, "kid-3")
	r.keys.set(cell1, "https://dev-cell-1.test", c3)
	r.clk.Advance(61 * time.Second)
	r.mustBind(cell1, c3, mgmtapi.StatusKeysUpdated)
	c = r.verifyRecord(cell1)
	if strings.Contains(string(c.JWKS), "kid-1") || strings.Contains(string(c.JWKS), "kid-2") || !strings.Contains(string(c.JWKS), "kid-3") {
		t.Fatalf("jwks after replace %s", c.JWKS)
	}
}

func TestBindAlreadyBound(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	before, spBefore := r.stateBytes(), marshal(t, r.plane.Spec())
	calls := r.keys.count(cell1)
	resp := r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusAlreadyBound)
	if resp.Record != rev(1, 2) {
		t.Fatalf("record %v", resp.Record)
	}
	if r.keys.count(cell1) != calls {
		t.Fatal("an already bound bind fetched keys")
	}
	if !bytes.Equal(before, r.stateBytes()) || spBefore != marshal(t, r.plane.Spec()) {
		t.Fatal("an already bound bind changed state")
	}
}

func TestBindRefusals(t *testing.T) {
	type attempt struct {
		cell, nonce, token string
	}
	type tc struct {
		name           string
		prep           func(r *rig) attempt
		reason, detail string
	}
	valid := func(r *rig, cell string, mod func(*kubetoken.Claims), sig *kubetoken.Signer) attempt {
		n := r.nonce(cell)
		if sig == nil {
			sig = r.signers[cell]
		}
		return attempt{cell, n, r.token(cell, n, sig, mod)}
	}
	boundWith := func(r *rig, cell string) { r.mustBind(cell, r.signers[cell], mgmtapi.StatusBound) }
	cases := []tc{
		{"unknown_cell", func(r *rig) attempt {
			n, _ := r.plane.nonces.Issue("dev-cell-9")
			return attempt{"dev-cell-9", n, "x.y.z"}
		}, mgmtapi.ReasonCellUnknown, ""},
		{"unknown_nonce", func(r *rig) attempt {
			raw := make([]byte, 56)
			for i := range raw {
				raw[i] = byte(i*7 + 1)
			}
			a := valid(r, cell1, nil, nil)
			a.nonce = base64.RawURLEncoding.EncodeToString(raw)
			return a
		}, mgmtapi.ReasonNonceInvalid, "bad_mac"},
		{"expired_nonce", func(r *rig) attempt {
			a := valid(r, cell1, nil, nil)
			r.clk.Advance(121 * time.Second)
			return a
		}, mgmtapi.ReasonNonceInvalid, "expired"},
		{"other_cells_nonce", func(r *rig) attempt {
			n := r.nonce(cell2)
			return attempt{cell1, n, r.token(cell1, n, r.signers[cell1], nil)}
		}, mgmtapi.ReasonNonceInvalid, "bad_mac"},
		{"reused_nonce", func(r *rig) attempt {
			a := valid(r, cell1, nil, nil)
			if _, err := r.plane.Bind(t.Context(), a.cell, mgmtapi.BindRequest{Nonce: a.nonce, Token: a.token}); err != nil {
				t.Fatal(err)
			}
			return a
		}, mgmtapi.ReasonNonceInvalid, "consumed"},
		{"other_nonce_audience", func(r *rig) attempt {
			n1, n2 := r.nonce(cell1), r.nonce(cell1)
			return attempt{cell1, n1, r.token(cell1, n2, r.signers[cell1], nil)}
		}, mgmtapi.ReasonTokenInvalid, "wrong_audience"},
		{"attest_audience", func(r *rig) attempt {
			return valid(r, cell1, func(c *kubetoken.Claims) { c.Audience = []string{"dev/" + r.nonce(cell1)} }, nil)
		}, mgmtapi.ReasonTokenInvalid, "wrong_audience"},
		{"foreign_key", func(r *rig) attempt {
			return valid(r, cell1, nil, newSigner(t, "kid-1"))
		}, mgmtapi.ReasonTokenInvalid, "bad_signature"},
		{"foreign_key_bound", func(r *rig) attempt {
			boundWith(r, cell1)
			return valid(r, cell1, nil, newSigner(t, "kid-1"))
		}, mgmtapi.ReasonTokenInvalid, "bad_signature"},
		{"other_issuer", func(r *rig) attempt {
			return valid(r, cell1, func(c *kubetoken.Claims) { c.Issuer = "https://evil.test" }, nil)
		}, mgmtapi.ReasonTokenInvalid, "issuer_mismatch"},
		{"other_issuer_bound", func(r *rig) attempt {
			boundWith(r, cell1)
			return valid(r, cell1, func(c *kubetoken.Claims) { c.Issuer = "https://evil.test" }, nil)
		}, mgmtapi.ReasonTokenInvalid, "issuer_mismatch"},
		{"agent_subject", func(r *rig) attempt {
			return valid(r, cell1, func(c *kubetoken.Claims) { c.ServiceAccount = agent.ServiceAccount }, nil)
		}, mgmtapi.ReasonTokenInvalid, "subject_not_allowed"},
		{"unbound_token", func(r *rig) attempt {
			return valid(r, cell1, func(c *kubetoken.Claims) { c.Unbound = true }, nil)
		}, mgmtapi.ReasonTokenInvalid, "not_pod_bound"},
		{"pin_mismatch", func(r *rig) attempt {
			r.keys.fail(cell1, &mgmtapi.KeyError{Reason: mgmtapi.ReasonIssuerUntrusted, Err: errors.New("pin")})
			return valid(r, cell1, nil, nil)
		}, mgmtapi.ReasonIssuerUntrusted, ""},
		{"source_down", func(r *rig) attempt {
			r.keys.fail(cell1, errors.New("connection refused"))
			return valid(r, cell1, nil, nil)
		}, mgmtapi.ReasonIssuerUnavailable, ""},
		{"issuer_changed", func(r *rig) attempt {
			boundWith(r, cell1)
			b := newSigner(t, "kid-2")
			r.keys.set(cell1, "https://other.test", b)
			r.clk.Advance(61 * time.Second)
			// The token names the stored issuer, and the source now publishes another one.
			n := r.nonce(cell1)
			return attempt{cell1, n, r.token(cell1, n, b, func(c *kubetoken.Claims) { c.Issuer = "https://dev-cell-1.test" })}
		}, mgmtapi.ReasonIssuerUntrusted, "issuer_changed"},
		{"three_new_keys", func(r *rig) attempt {
			boundWith(r, cell1)
			b, c, d := newSigner(t, "kid-b"), newSigner(t, "kid-c"), newSigner(t, "kid-d")
			r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], b, c, d)
			r.clk.Advance(61 * time.Second)
			return valid(r, cell1, nil, b)
		}, mgmtapi.ReasonKeysUntrusted, "too_many_new_keys"},
		{"second_update_within_60s", func(r *rig) attempt {
			boundWith(r, cell1)
			r.mod = func(c *Config) { c.KeyCacheTTL = time.Second }
			r.restart(nil)
			b := newSigner(t, "kid-b")
			r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], b)
			r.clk.Advance(30 * time.Second)
			return valid(r, cell1, nil, b)
		}, mgmtapi.ReasonRateLimited, "key_update_gap"},
		{"empty_set_first_bind", func(r *rig) attempt {
			r.keys.set(cell1, "https://dev-cell-1.test")
			return valid(r, cell1, nil, nil)
		}, mgmtapi.ReasonTokenInvalid, "unknown_kid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			a := c.prep(r)
			stateBefore, specBefore := r.stateBytes(), marshal(t, r.plane.Spec())
			_, err := r.plane.Bind(t.Context(), a.cell, mgmtapi.BindRequest{Nonce: a.nonce, Token: a.token})
			if err == nil {
				t.Fatal("bind accepted")
			}
			reason, detail := reasonDetail(err)
			if reason != c.reason || detail != c.detail && c.detail != "" {
				t.Fatalf("got %s/%s (%v), want %s/%s", reason, detail, err, c.reason, c.detail)
			}
			if !bytes.Equal(stateBefore, r.stateBytes()) {
				t.Fatal("the state file changed")
			}
			if specBefore != marshal(t, r.plane.Spec()) {
				t.Fatal("the served spec changed")
			}
		})
	}
}

func TestFailedBindKeepsNonce(t *testing.T) {
	r := newRig(t)
	n := r.nonce(cell1)
	bad := r.token(cell1, n, newSigner(t, "kid-1"), nil)
	if _, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: bad}); ReasonOf(err) != mgmtapi.ReasonTokenInvalid {
		t.Fatalf("bad bind: %v", err)
	}
	good := r.token(cell1, n, r.signers[cell1], nil)
	resp, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: good})
	if err != nil || resp.Status != mgmtapi.StatusBound {
		t.Fatalf("good bind after a bad one with the same nonce: %+v, %v", resp, err)
	}
}

func TestNonceFloodDoesNotBlockCell(t *testing.T) {
	r := newRig(t)
	for range 200 {
		if _, err := r.plane.Nonce(cell2); err != nil {
			t.Fatal(err)
		}
	}
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	if r.keys.count(cell2) != 1 {
		t.Fatalf("%d fetches", r.keys.count(cell2))
	}
}

func TestBindGarbageTokenNoFetch(t *testing.T) {
	for _, bound := range []bool{false, true} {
		name := "unbound"
		if bound {
			name = "bound"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			if bound {
				r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
			}
			calls := r.keys.total()
			tokens := map[string]func(n string) string{
				"malformed": func(string) string { return "not.a.jwt" },
				"empty":     func(string) string { return "" },
				"wrong_audience": func(n string) string {
					return r.token(cell1, n, r.signers[cell1], func(c *kubetoken.Claims) { c.Audience = []string{"dev/" + n} })
				},
				"wrong_subject": func(n string) string {
					return r.token(cell1, n, r.signers[cell1], func(c *kubetoken.Claims) { c.ServiceAccount = "other" })
				},
				"no_kid_claims_only": func(n string) string {
					return r.token(cell1, n, r.signers[cell1], func(c *kubetoken.Claims) { c.Unbound = true })
				},
			}
			for name, mk := range tokens {
				n := r.nonce(cell1)
				_, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: mk(n)})
				if ReasonOf(err) != mgmtapi.ReasonTokenInvalid {
					t.Fatalf("%s: %v", name, err)
				}
			}
			if r.keys.total() != calls {
				t.Fatalf("garbage tokens caused %d fetches", r.keys.total()-calls)
			}
		})
	}
}

func forged(t testing.TB, r *rig, cell, nonce string) string {
	t.Helper()
	tok := r.token(cell, nonce, newSigner(t, "random-kid-"+nonce[:6]), nil)
	parts := strings.Split(tok, ".")
	parts[2] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	return strings.Join(parts, ".")
}

func TestForgedTokenDoesNotBlockBind(t *testing.T) {
	for _, bound := range []bool{false, true} {
		name := "unbound"
		if bound {
			name = "bound"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			signer := r.signers[cell1]
			if bound {
				r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
				b := newSigner(t, "kid-b")
				r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], b)
				signer = b
				r.clk.Advance(61 * time.Second)
			}
			for range 3 {
				n := r.nonce(cell1)
				_, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: forged(t, r, cell1, n)})
				if ReasonOf(err) != mgmtapi.ReasonTokenInvalid {
					t.Fatalf("forged token: %v", err)
				}
			}
			r.clk.Advance(time.Second)
			want := mgmtapi.StatusBound
			if bound {
				want = mgmtapi.StatusKeysUpdated
			}
			r.mustBind(cell1, signer, want)
		})
	}
}

func TestKeyCacheServesWithinTTL(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	b := newSigner(t, "kid-b")
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], b)
	r.clk.Advance(61 * time.Second)
	base := r.keys.count(cell1)
	for range 2 {
		n := r.nonce(cell1)
		if _, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: forged(t, r, cell1, n)}); ReasonOf(err) != mgmtapi.ReasonTokenInvalid {
			t.Fatal(err)
		}
		r.clk.Advance(5 * time.Second)
	}
	if got := r.keys.count(cell1) - base; got != 1 {
		t.Fatalf("two unknown_kid binds caused %d fetches, want 1", got)
	}
	r.clk.Advance(61 * time.Second)
	n := r.nonce(cell1)
	_, _ = r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: forged(t, r, cell1, n)})
	if got := r.keys.count(cell1) - base; got != 2 {
		t.Fatalf("after the TTL: %d fetches, want 2", got)
	}
}

func TestKeyCheck(t *testing.T) {
	type tc struct {
		name   string
		cell   string
		mutate func(r *rig)
		want   CheckResult
		kids   []string
	}
	same := func(r *rig) *kubetoken.Signer { return r.signers[cell1] }
	cases := []tc{
		{"unchanged", cell1, func(r *rig) {}, CheckUnchanged, []string{"kid-1"}},
		{"added", cell1, func(r *rig) {
			r.keys.set(cell1, "https://dev-cell-1.test", same(r), newSigner(t, "kid-2"))
		}, CheckKeysUpdated, []string{"kid-1", "kid-2"}},
		{"removed", cell1, func(r *rig) {
			r.keys.set(cell1, "https://dev-cell-1.test", same(r))
		}, CheckKeysUpdated, []string{"kid-1"}},
		{"all_removed", cell1, func(r *rig) { r.keys.set(cell1, "https://dev-cell-1.test") }, CheckKeysUntrusted, []string{"kid-1", "kid-2"}},
		{"three_added", cell1, func(r *rig) {
			r.keys.set(cell1, "https://dev-cell-1.test", same(r), newSigner(t, "a"), newSigner(t, "b"), newSigner(t, "c"))
		}, CheckKeysUntrusted, []string{"kid-1", "kid-2"}},
		{"issuer_changed", cell1, func(r *rig) {
			r.keys.set(cell1, "https://other.test", same(r))
		}, CheckIssuerUntrusted, []string{"kid-1", "kid-2"}},
		{"source_down", cell1, func(r *rig) { r.keys.fail(cell1, errors.New("down")) }, CheckIssuerUnavailable, []string{"kid-1", "kid-2"}},
		{"pin_mismatch", cell1, func(r *rig) {
			r.keys.fail(cell1, &mgmtapi.KeyError{Reason: mgmtapi.ReasonIssuerUntrusted})
		}, CheckIssuerUntrusted, []string{"kid-1", "kid-2"}},
		{"unbound", cell2, func(r *rig) {}, CheckNotBound, nil},
		{"replaced", cell1, func(r *rig) {
			r.keys.set(cell1, "https://dev-cell-1.test", newSigner(t, "kid-new"))
		}, CheckKeysUntrusted, []string{"kid-1", "kid-2"}},
		{"same_kid_other_key", cell1, func(r *rig) {
			r.keys.set(cell1, "https://dev-cell-1.test", same(r), newSigner(t, "kid-1"))
		}, CheckKeysUpdated, []string{"kid-1", "kid-1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
			if c.name != "unchanged" && c.name != "same_kid_other_key" && c.name != "added" {
				// Start from two keys so that a removal leaves one.
				r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], newSigner(t, "kid-2"))
				r.clk.Advance(61 * time.Second)
				if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUpdated {
					t.Fatalf("setup check: %v, %v", res, err)
				}
			}
			r.clk.Advance(61 * time.Second)
			c.mutate(r)
			before := r.verifySpec().Revision
			res, err := r.plane.KeyCheck(t.Context(), c.cell)
			if err != nil || res != c.want {
				t.Fatalf("got %q, %v; want %q", res, err, c.want)
			}
			after := r.verifySpec().Revision
			if (c.want == CheckKeysUpdated) != (after != before) {
				t.Fatalf("spec revision %v to %v for %q", before, after, c.want)
			}
			if c.cell == cell1 {
				if got := cellStatus(r.status(), cell1).Kids; !slices.Equal(got, c.kids) {
					t.Fatalf("kids %v, want %v", got, c.kids)
				}
			}
		})
	}
}

func TestKeyCheckRateLimited(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckUnchanged {
		t.Fatalf("first: %v, %v", res, err)
	}
	calls := r.keys.count(cell1)
	r.clk.Advance(30 * time.Second)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckRateLimited {
		t.Fatalf("second within 60 s: %v, %v", res, err)
	}
	if r.keys.count(cell1) != calls {
		t.Fatal("a rate limited check fetched keys")
	}
	r.clk.Advance(31 * time.Second)
	if res, _ := r.plane.KeyCheck(t.Context(), cell1); res != CheckUnchanged {
		t.Fatalf("after the gap: %v", res)
	}
	if _, err := r.plane.KeyCheck(t.Context(), "dev-cell-9"); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatalf("unknown cell: %v", err)
	}
}

func TestRunChecksEvery15m(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	b := newSigner(t, "kid-b")
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], b)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.plane.RunChecks(ctx) }()
	tick := func() {
		r.ticks <- r.clk.Now()
		r.ticks <- r.clk.Now() // the second send returns once the first tick is handled
	}
	calls := r.keys.count(cell1)
	r.clk.Advance(14 * time.Minute)
	tick()
	if r.keys.count(cell1) != calls {
		t.Fatal("a check ran before 15 minutes")
	}
	r.clk.Advance(2 * time.Minute)
	tick()
	if got := cellStatus(r.status(), cell1); got.LastCheck != string(CheckKeysUpdated) || len(got.Kids) != 2 {
		t.Fatalf("after 16 minutes: %+v", got)
	}
	if cellStatus(r.status(), cell2).LastCheck != "" {
		t.Fatal("an unbound cell was checked")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("RunChecks returned %v", err)
	}
}

func TestStateRoundTripAndAtomic(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	path := filepath.Join(r.dir, "state.json")
	st, err := r.store.Load()
	if err != nil || st == nil {
		t.Fatalf("load: %v, %v", st, err)
	}
	if st.Version != 1 || st.Last != rev(1, 2) || st.Cells[cell1] == nil || len(st.History) != 2 || st.KeySHA256 == "" {
		t.Fatalf("state %+v", st)
	}
	st.Seq += 5
	if err := r.store.Save(st); err != nil {
		t.Fatal(err)
	}
	again, _ := r.store.Load()
	if marshal(t, st) != marshal(t, again) {
		t.Fatal("state does not round trip")
	}
	// Leftovers of an interrupted write never replace the state.
	if err := os.WriteFile(path+".tmp-123", []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := r.store.Load()
	if err != nil || marshal(t, third) != marshal(t, st) {
		t.Fatalf("load beside a temporary file: %v", err)
	}
	// A failed rename leaves the old file whole: the target is a directory.
	bad := &FileStore{Path: filepath.Join(r.dir, "dir")}
	if err := os.Mkdir(bad.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := bad.Save(st); err == nil {
		t.Fatal("save over a directory succeeded")
	}
	left, _ := filepath.Glob(filepath.Join(r.dir, "dir.tmp*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
	if absent, err := (&FileStore{Path: filepath.Join(r.dir, "nothing.json")}).Load(); absent != nil || err != nil {
		t.Fatalf("absent file: %v, %v", absent, err)
	}
}

func TestStateCorruptMovedAside(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	oldPub := r.plane.PublicKey()
	if err := os.WriteFile(filepath.Join(r.dir, "state.json"), []byte(`{"Version":1,"Seq":`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.restart(nil)
	if newPub := r.plane.PublicKey(); bytes.Equal(newPub, oldPub) {
		t.Fatal("a fresh state kept the old signing key")
	}
	if n := r.logs.count("signing_key_replaced"); n != 1 {
		t.Fatalf("%d signing_key_replaced lines", n)
	}
	if got := r.status().Signed; got != rev(1, 1) {
		t.Fatalf("fresh state at %v", got)
	}
	moved, _ := filepath.Glob(filepath.Join(r.dir, "state.json.corrupt-*"))
	if len(moved) != 1 {
		t.Fatalf("moved files: %v", moved)
	}
	if n := r.logs.count("state_corrupt"); n != 1 {
		t.Fatalf("%d state_corrupt lines", n)
	}
	if b, _ := os.ReadFile(moved[0]); string(b) != `{"Version":1,"Seq":` {
		t.Fatalf("moved file holds %q", b)
	}
	if cellStatus(r.status(), cell1).Bound {
		t.Fatal("a cell is bound after the state loss")
	}
}

func TestRestartKeepsRevisions(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	specBefore, statusBefore := marshal(t, r.plane.Spec()), marshal(t, r.plane.Status())
	r.restart(nil)
	if marshal(t, r.plane.Spec()) != specBefore || marshal(t, r.plane.Status()) != statusBefore {
		t.Fatal("restart changed the served state")
	}
	if !cellStatus(r.status(), cell1).Bound || !cellStatus(r.status(), cell2).Bound {
		t.Fatal("restart lost a binding")
	}
	c := newSigner(t, "kid-c")
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], c)
	r.clk.Advance(61 * time.Second)
	if resp := r.mustBind(cell1, c, mgmtapi.StatusKeysUpdated); resp.Record != rev(1, 4) {
		t.Fatalf("next revision %v, want (1,4)", resp.Record)
	}
}

func TestRestoreServesOlderAndBlocksChanges(t *testing.T) {
	r := newRig(t, cell1, cell2, cell3)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	if err := r.plane.Restore(2); err != nil {
		t.Fatal(err)
	}
	if got := r.verifySpec().Revision; got != rev(1, 2) {
		t.Fatalf("served %v", got)
	}
	if _, ok := r.plane.Records()[cell2]; ok {
		t.Fatal("the restored bundle holds a later record")
	}
	st := r.status()
	if !st.RestoreActive || st.Served != rev(1, 2) || st.Signed != rev(1, 3) {
		t.Fatalf("status %+v", st)
	}
	stateBefore := r.stateBytes()
	if _, err := r.bind(cell3, r.signers[cell3]); ReasonOf(err) != mgmtapi.ReasonRestoreActive {
		t.Fatalf("bind during a restore: %v", err)
	}
	if n, err := r.plane.Nonce(cell1); err != nil || !n.Bound {
		t.Fatalf("nonce during a restore: %+v, %v", n, err)
	}
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusAlreadyBound)
	if !bytes.Equal(stateBefore, r.stateBytes()) {
		t.Fatal("a refused change wrote the state file")
	}
	if err := r.plane.Restore(77); err == nil {
		t.Fatal("restore to an unknown revision")
	}
	r.restart(nil)
	if !r.status().RestoreActive || r.verifySpec().Revision != rev(1, 2) {
		t.Fatal("restart ended the restore")
	}
	if err := r.plane.Restore(0); err != nil {
		t.Fatal(err)
	}
	if r.verifySpec().Revision != rev(1, 3) || r.status().RestoreActive {
		t.Fatal("Restore(0) does not serve the latest")
	}
	r.mustBind(cell3, r.signers[cell3], mgmtapi.StatusBound)
}

func TestHistoryCapped(t *testing.T) {
	r := newRig(t, cell1, cell2, cell3)
	r.mod = func(c *Config) { c.HistoryLen = 3 }
	r.restart(nil)
	for _, c := range []string{cell1, cell2, cell3} {
		r.mustBind(c, r.signers[c], mgmtapi.StatusBound)
	}
	st, _ := r.store.Load()
	if len(st.History) != 3 || st.History[0].Revision != rev(1, 2) || st.History[2].Revision != rev(1, 4) {
		t.Fatalf("history %v", []spec.Revision{st.History[0].Revision})
	}
	if err := r.plane.Restore(1); err == nil {
		t.Fatal("restore to a trimmed revision")
	}
	if err := r.plane.Restore(2); err != nil {
		t.Fatal(err)
	}
}

func TestIntentChangeResigns(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	r.restart(nil)
	if got := r.status().Signed; got != rev(1, 3) {
		t.Fatalf("an unchanged intent signed %v", got)
	}
	r.restart(func(in *Intent) { in.Cells[0].Subjects = []record.Subject{celld} })
	if got := r.status().Signed; got != rev(1, 4) {
		t.Fatalf("signed %v, want (1,4)", got)
	}
	c1 := r.verifyRecord(cell1)
	if !slices.Equal(c1.Subjects, []record.Subject{celld}) || c1.Counter != 4 {
		t.Fatalf("cell 1 record %+v", c1)
	}
	if c2 := r.verifyRecord(cell2); c2.Counter != 3 || len(c2.Subjects) != 2 {
		t.Fatalf("cell 2 record %+v", c2)
	}
	if got := cellStatus(r.status(), cell1).Record; got != rev(1, 4) {
		t.Fatalf("cell status record %v", got)
	}
}

func TestReportStoresLag(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	r.clk.Advance(time.Minute)
	refusal := &mgmtapi.Refusal{Reason: "revision_old", Revision: rev(1, 2), At: r.clk.Now()}
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 2), LastRefusal: refusal, StoreError: "disk"})
	st := r.status()
	if st.Applied != rev(1, 2) || st.LagSince.IsZero() || st.LastReportAt.IsZero() || st.LastRefusal == nil || st.StoreError != "disk" || st.AppliedAt.IsZero() {
		t.Fatalf("status %+v", st)
	}
	r.clk.Advance(time.Minute)
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 3)})
	st = r.status()
	if !st.LagSince.IsZero() || st.Applied != rev(1, 3) || st.LastRefusal != nil || st.StateBehindApplied {
		t.Fatalf("after catching up: %+v", st)
	}
	b := marshal(t, st)
	for _, key := range []string{`"env"`, `"signed"`, `"served"`, `"restoreActive"`, `"applied"`, `"appliedAt"`, `"lastReportAt"`, `"pendingDrops"`, `"stateBehindApplied"`, `"cells"`, `"name"`, `"bound"`, `"issuer"`, `"kids"`, `"record"`, `"checkedAt"`, `"lastCheck"`} {
		if !strings.Contains(b, key) {
			t.Fatalf("status JSON lacks %s: %s", key, b)
		}
	}
}

func TestStateBehindApplied(t *testing.T) {
	r := newRig(t)
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 9)})
	if !r.status().StateBehindApplied {
		t.Fatal("stateBehindApplied is not set")
	}
	if r.logs.count("state_behind_applied") != 1 {
		t.Fatalf("%d state_behind_applied lines", r.logs.count("state_behind_applied"))
	}
}

type flakyStore struct {
	Store
	fail atomic.Bool
}

func (s *flakyStore) Save(st *State) error {
	if s.fail.Load() {
		return errors.New("disk full")
	}
	return s.Store.Save(st)
}

func TestStateSavedBeforeServe(t *testing.T) {
	r := newRig(t)
	fs := &flakyStore{Store: r.store}
	r.store = fs
	r.restart(nil)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	specBefore, statusBefore := marshal(t, r.plane.Spec()), marshal(t, r.plane.Status())
	stateBefore := r.stateBytes()

	fs.fail.Store(true)
	n := r.nonce(cell2)
	req := mgmtapi.BindRequest{Nonce: n, Token: r.token(cell2, n, r.signers[cell2], nil)}
	if _, err := r.plane.Bind(t.Context(), cell2, req); err == nil {
		t.Fatal("bind succeeded with a failing store")
	}
	if marshal(t, r.plane.Spec()) != specBefore || marshal(t, r.plane.Status()) != statusBefore {
		t.Fatal("a failed save changed what is served")
	}
	if !bytes.Equal(stateBefore, r.stateBytes()) {
		t.Fatal("the state file changed")
	}
	keyBefore, _ := os.ReadFile(filepath.Join(r.dir, "ed25519.key"))
	if _, err := r.plane.RotateKey(t.Context()); err == nil {
		t.Fatal("rotation succeeded with a failing store")
	}
	if marshal(t, r.plane.Spec()) != specBefore {
		t.Fatal("a failed rotation changed what is served")
	}
	if keyAfter, _ := os.ReadFile(filepath.Join(r.dir, "ed25519.key")); !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("a failed rotation left the new key in the key file")
	}

	fs.fail.Store(false)
	resp, err := r.plane.Bind(t.Context(), cell2, req)
	if err != nil || resp.Status != mgmtapi.StatusBound {
		t.Fatalf("retry with the same nonce after the store recovers: %+v, %v", resp, err)
	}
}

func TestConcurrentChangesSignDistinctRevisions(t *testing.T) {
	for i := range 50 {
		r := newRig(t, cell1, cell2, cell3)
		r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
		b := newSigner(t, "kid-b")
		r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], b)
		r.clk.Advance(61 * time.Second)
		start := r.status().Signed

		type job struct {
			name string
			run  func() error
		}
		mkBind := func(c string) func() error {
			n := r.nonce(c)
			req := mgmtapi.BindRequest{Nonce: n, Token: r.token(c, n, r.signers[c], nil)}
			return func() error {
				_, err := r.plane.Bind(t.Context(), c, req)
				return err
			}
		}
		jobs := []job{
			{"bind2", mkBind(cell2)},
			{"bind3", mkBind(cell3)},
			{"check1", func() error {
				res, err := r.plane.KeyCheck(t.Context(), cell1)
				if err == nil && res != CheckKeysUpdated {
					err = errors.New("check result " + string(res))
				}
				return err
			}},
		}
		var wg sync.WaitGroup
		errs := make([]error, len(jobs))
		gate := make(chan struct{})
		for j := range jobs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				errs[j] = jobs[j].run()
			}()
		}
		close(gate)
		wg.Wait()
		for j, err := range errs {
			if err != nil {
				t.Fatalf("iteration %d, %s: %v", i, jobs[j].name, err)
			}
		}
		st, err := r.store.Load()
		if err != nil || st == nil {
			t.Fatal(err)
		}
		if st.Last != rev(1, start.Counter+3) || r.status().Signed != st.Last {
			t.Fatalf("iteration %d: file at %v, plane at %v, started at %v", i, st.Last, r.status().Signed, start)
		}
		var seen []uint64
		for _, h := range st.History {
			if h.Revision.Counter > start.Counter {
				seen = append(seen, h.Revision.Counter)
			}
		}
		if !slices.Equal(seen, []uint64{start.Counter + 1, start.Counter + 2, start.Counter + 3}) {
			t.Fatalf("iteration %d: revisions %v after %v", i, seen, start)
		}
		for _, c := range []string{cell1, cell2, cell3} {
			r.verifyRecord(c)
		}
		if got := len(r.verifySpec().Cells); got != 3 {
			t.Fatalf("spec holds %d cells", got)
		}
	}
}

func TestKeyFetchDoesNotBlockSpec(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.keys.mu.Lock()
	r.keys.gate, r.keys.gateCell = make(chan struct{}), cell2
	gate := r.keys.gate
	r.keys.mu.Unlock()
	n := r.nonce(cell2)
	req := mgmtapi.BindRequest{Nonce: n, Token: r.token(cell2, n, r.signers[cell2], nil)}
	done := make(chan error, 1)
	go func() {
		_, err := r.plane.Bind(t.Context(), cell2, req)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for r.keys.count(cell2) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the bind never reached the key source")
		}
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	_ = r.plane.Spec()
	_ = r.plane.Status()
	if _, err := r.plane.Nonce(cell1); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Millisecond {
		t.Fatalf("reads took %v during a key fetch", d)
	}

	// Every kind of change commits while the fetch blocks.
	changed := make(chan error, 1)
	go func() {
		_, err := r.bind(cell1, r.signers[cell1])
		if err == nil {
			err = r.plane.Restore(0)
		}
		if err == nil {
			_, err = r.plane.RotateKey(t.Context())
		}
		changed <- err
	}()
	select {
	case err := <-changed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a change waited for a key fetch of another cell")
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestKeyCheckFetchDoesNotBlockChanges(t *testing.T) {
	r := newRig(t, cell1, cell2, cell3)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second)
	r.keys.mu.Lock()
	r.keys.gate, r.keys.gateCell = make(chan struct{}), cell1
	gate := r.keys.gate
	r.keys.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := r.plane.KeyCheck(t.Context(), cell1)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for r.keys.count(cell1) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the check never reached the key source")
		}
		time.Sleep(time.Millisecond)
	}
	changed := make(chan error, 1)
	go func() {
		_, err := r.bind(cell3, r.signers[cell3])
		changed <- err
	}()
	select {
	case err := <-changed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a bind waited for the key fetch of a check")
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCheckSeqConflict(t *testing.T) {
	r := newRig(t)
	seq := r.plane.snapshotSeq()
	if err := r.plane.CheckSeq(seq); err != nil {
		t.Fatal(err)
	}
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	err := r.plane.CheckSeq(seq)
	if ReasonOf(err) != mgmtapi.ReasonConflict {
		t.Fatalf("stale seq: %v", err)
	}
	if err := r.plane.CheckSeq(r.plane.snapshotSeq()); err != nil {
		t.Fatal(err)
	}
}

// release gives envd's report of the signed revision to the plane.
func (r *rig) release() spec.Revision {
	r.t.Helper()
	last := r.status().Signed
	r.plane.Report(mgmtapi.StatusReport{Applied: last})
	return last
}

func TestIntentDropsOneCellPerRevision(t *testing.T) {
	r := newRig(t, cell1, cell2, cell3)
	for _, c := range []string{cell1, cell2, cell3} {
		r.mustBind(c, r.signers[c], mgmtapi.StatusBound)
	}
	r.restart(func(in *Intent) { in.Cells = in.Cells[:1] })
	if s := r.verifySpec(); s.Revision != rev(1, 4) || len(s.Cells) != 3 || len(s.Retired) != 0 {
		t.Fatalf("a restart signed a drop: %+v", s)
	}
	if got := r.status().PendingDrops; !slices.Equal(got, []string{cell2, cell3}) {
		t.Fatalf("pending drops %v", got)
	}

	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 3)})
	if r.verifySpec().Revision != rev(1, 4) {
		t.Fatal("a drop ran before envd applied the signed revision")
	}
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 9)})
	if r.verifySpec().Revision != rev(1, 4) {
		t.Fatal("a drop ran on a report above the signed revision")
	}
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 4)})
	s := r.verifySpec()
	if s.Revision != rev(1, 5) || len(s.Cells) != 2 || len(s.Retired) != 1 || s.Retired[0].Name != cell2 || s.Retired[0].Revision != rev(1, 3) {
		t.Fatalf("first drop %+v", s)
	}
	if _, ok := r.plane.Records()[cell2]; ok {
		t.Fatal("the dropped cell still has a record")
	}
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 4)})
	if r.verifySpec().Revision != rev(1, 5) {
		t.Fatal("the second drop ran before envd applied the first")
	}
	r.release()
	s = r.verifySpec()
	if s.Revision != rev(1, 6) || len(s.Cells) != 1 || len(s.Retired) != 2 || s.Retired[1].Name != cell3 || s.Retired[1].Revision != rev(1, 4) {
		t.Fatalf("second drop %+v", s)
	}
	if got := r.status().PendingDrops; len(got) != 0 {
		t.Fatalf("pending drops %v", got)
	}
}

// Every restart signs no drop. The queue survives restarts and waits for a report.
func TestRestartsNeverDropEarly(t *testing.T) {
	r := newRig(t, cell1, cell2, cell3)
	for _, c := range []string{cell1, cell2, cell3} {
		r.mustBind(c, r.signers[c], mgmtapi.StatusBound)
	}
	r.release()
	r.restart(func(in *Intent) { in.Cells = in.Cells[:2] })
	r.release() // envd applies the signed revision, and the first drop goes out
	dropped := r.status().Signed
	if got := r.verifySpec(); len(got.Retired) != 1 || got.Retired[0].Name != cell3 {
		t.Fatalf("first drop %+v", got)
	}
	// envd has not applied the drop. The operator removes another cell and restarts twice.
	r.restart(func(in *Intent) { in.Cells = in.Cells[:1] })
	r.restart(nil)
	if got := r.status(); got.Signed != dropped || !slices.Equal(got.PendingDrops, []string{cell2}) {
		t.Fatalf("a restart signed a second drop before envd applied the first: %+v", got)
	}
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 4)})
	if r.status().Signed != dropped {
		t.Fatal("a report of an older revision released a drop")
	}
	r.release()
	if got := r.verifySpec(); len(got.Retired) != 2 || len(got.Cells) != 1 {
		t.Fatalf("second drop %+v", got)
	}
	if got := r.status().PendingDrops; len(got) != 0 {
		t.Fatalf("pending drops %v", got)
	}
}

type slowStore struct {
	Store
	delay time.Duration
}

func (s *slowStore) Save(st *State) error {
	time.Sleep(s.delay)
	return s.Store.Save(st)
}

// Two Reports of one applied revision release one drop.
func TestConcurrentReportsReleaseOneDrop(t *testing.T) {
	const cell4 = "dev-cell-4"
	r := newRig(t, cell1, cell2, cell3, cell4)
	r.signers[cell4] = newSigner(t, "kid-1")
	r.keys.set(cell4, "https://"+cell4+".test", r.signers[cell4])
	for _, c := range []string{cell1, cell2, cell3, cell4} {
		r.mustBind(c, r.signers[c], mgmtapi.StatusBound)
	}
	r.restart(func(in *Intent) { in.Cells = in.Cells[:1] })
	r.release()
	if got := r.status(); len(got.PendingDrops) != 2 {
		t.Fatalf("setup: %+v", got)
	}
	r.plane.cfg.Store = &slowStore{Store: r.store, delay: 50 * time.Millisecond}
	applied := r.status().Signed
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.plane.Report(mgmtapi.StatusReport{Applied: applied})
		}()
	}
	wg.Wait()
	if got := r.status(); got.Signed != rev(1, applied.Counter+1) || len(got.PendingDrops) != 1 {
		t.Fatalf("three reports of %v: signed %v, pending %v", applied, got.Signed, got.PendingDrops)
	}
}

func TestIntentReAddAfterDrop(t *testing.T) {
	r := newRig(t, cell1, cell2)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	r.restart(func(in *Intent) { in.Cells = in.Cells[:1] })
	r.release()
	s := r.verifySpec()
	if len(s.Retired) != 1 || s.Retired[0].Name != cell2 {
		t.Fatalf("spec %+v", s)
	}
	oldMark := s.Retired[0].Revision

	r.restart(func(in *Intent) { *in = testIntent(cell1, cell2) })
	if s := r.verifySpec(); len(s.Retired) != 1 {
		t.Fatalf("re-adding the cell to the intent changed the retired list: %+v", s)
	}
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	check := func() {
		s := r.verifySpec()
		if len(s.Retired) != 0 || len(s.Cells) != 2 {
			t.Fatalf("spec %+v", s)
		}
		for _, e := range s.Cells {
			if e.Name == cell2 && e.Revision.Compare(oldMark) <= 0 {
				t.Fatalf("record revision %v is not above the mark %v", e.Revision, oldMark)
			}
		}
		for _, c := range []string{cell1, cell2} {
			r.verifyRecord(c)
		}
	}
	check()
	if _, err := r.plane.RotateKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	check()
	if got := r.verifySpec().Revision; got != rev(2, 1) {
		t.Fatalf("after rotation %v", got)
	}
}

func TestOversizedKeySetsRefused(t *testing.T) {
	r := newRig(t, cell1, cell2)
	many := make([]*kubetoken.Signer, 400)
	for i := range many {
		many[i] = newSigner(t, "k"+string(rune('a'+i%26))+strings.Repeat("x", i/26))
	}
	r.keys.set(cell1, "https://dev-cell-1.test", many...)
	stateBefore := r.stateBytes()
	_, err := r.bind(cell1, many[0])
	if ReasonOf(err) != mgmtapi.ReasonKeysUntrusted {
		t.Fatalf("first bind with 400 keys: %v", err)
	}
	if !bytes.Equal(stateBefore, r.stateBytes()) {
		t.Fatal("a refused bind changed the state")
	}
	// Another cell is not affected.
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	for _, raw := range r.plane.Records() {
		if len(raw) > 48<<10 {
			t.Fatalf("a signed record has %d bytes", len(raw))
		}
	}
}

func TestKeySetGrowthStopsAtTheCap(t *testing.T) {
	r := newRig(t, cell1, cell2)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	set := []*kubetoken.Signer{r.signers[cell1]}
	for i := range 3 {
		set = append(set, newSigner(t, "g"+string(rune('a'+i))+"1"), newSigner(t, "g"+string(rune('a'+i))+"2"))
		r.keys.set(cell1, "https://dev-cell-1.test", set...)
		r.clk.Advance(61 * time.Second)
		if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUpdated {
			t.Fatalf("growth step %d: %v, %v", i, res, err)
		}
	}
	before := r.status().Signed
	set = append(set, newSigner(t, "gz1"), newSigner(t, "gz2"))
	r.keys.set(cell1, "https://dev-cell-1.test", set...)
	r.clk.Advance(61 * time.Second)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUntrusted {
		t.Fatalf("past the cap: %v, %v", res, err)
	}
	if r.status().Signed != before || len(cellStatus(r.status(), cell1).Kids) != 7 {
		t.Fatal("a refused check changed the record")
	}
	// A bind with a key of the oversized set is refused, too, and other cells still change.
	r.clk.Advance(61 * time.Second)
	if _, err := r.bind(cell1, set[len(set)-1]); ReasonOf(err) != mgmtapi.ReasonKeysUntrusted {
		t.Fatalf("bind past the cap: %v", err)
	}
	r.keys.set(cell2, "https://dev-cell-2.test", r.signers[cell2], newSigner(t, "kid-b"))
	r.clk.Advance(61 * time.Second)
	if res, err := r.plane.KeyCheck(t.Context(), cell2); err != nil || res != CheckKeysUpdated {
		t.Fatalf("another cell: %v, %v", res, err)
	}
	r.verifyRecord(cell1)
}

func TestRotateKeyNewEpoch(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	oldPub := r.plane.PublicKey()
	pub, err := r.plane.RotateKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if pub.Equal(oldPub) || !pub.Equal(r.plane.PublicKey()) {
		t.Fatal("public key")
	}
	s := r.verifySpec()
	if s.Revision != rev(2, 1) || len(s.Cells) != 2 {
		t.Fatalf("spec %+v", s)
	}
	if _, _, err := spec.Verify(r.plane.Spec().Spec, []ed25519.PublicKey{oldPub}); err == nil {
		t.Fatal("the spec still verifies under the old key")
	}
	for _, c := range []string{cell1, cell2} {
		rc := r.verifyRecord(c)
		if rc.Epoch != 2 || rc.Counter != 1 {
			t.Fatalf("record %s at %d/%d", c, rc.Epoch, rc.Counter)
		}
	}
	st, _ := r.store.Load()
	if len(st.History) != 1 || st.History[0].Revision != rev(2, 1) {
		t.Fatalf("history %d entries", len(st.History))
	}
	onDisk, created, err := LoadOrCreateKey(filepath.Join(r.dir, "ed25519.key"))
	if err != nil || created || !onDisk.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatalf("key on disk: %v %v", created, err)
	}
	r.restart(nil)
	if r.verifySpec().Revision != rev(2, 1) {
		t.Fatal("restart after rotation")
	}
	// A later change continues in the new epoch.
	n := newSigner(t, "kid-n")
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], n)
	r.clk.Advance(61 * time.Second)
	if resp := r.mustBind(cell1, n, mgmtapi.StatusKeysUpdated); resp.Record != rev(2, 2) {
		t.Fatalf("record %v", resp.Record)
	}
}

func TestKeyChangeOnDiskResigns(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	oldPub := r.plane.PublicKey()
	_, fresh, _ := ed25519.GenerateKey(nil)
	if err := WriteKey(filepath.Join(r.dir, "ed25519.key"), fresh); err != nil {
		t.Fatal(err)
	}
	r.restart(nil)
	if r.plane.PublicKey().Equal(oldPub) {
		t.Fatal("the plane kept the old key")
	}
	if got := r.verifySpec().Revision; got != rev(2, 1) {
		t.Fatalf("revision %v, want (2,1)", got)
	}
	if rc := r.verifyRecord(cell1); rc.Epoch != 2 || rc.Counter != 1 {
		t.Fatalf("record %+v", rc)
	}
	st, _ := r.store.Load()
	if len(st.History) != 1 {
		t.Fatalf("history %d", len(st.History))
	}
	if !cellStatus(r.status(), cell1).Bound {
		t.Fatal("the binding was lost")
	}
}

func TestPreviewKeysChangesNothing(t *testing.T) {
	r := newRig(t)
	before := r.stateBytes()
	k, err := r.plane.PreviewKeys(t.Context(), cell1)
	if err != nil || k.Issuer != "https://dev-cell-1.test" {
		t.Fatalf("%+v, %v", k, err)
	}
	if _, err := r.plane.PreviewKeys(t.Context(), "dev-cell-9"); ReasonOf(err) != mgmtapi.ReasonCellUnknown {
		t.Fatal(err)
	}
	if !bytes.Equal(before, r.stateBytes()) {
		t.Fatal("preview wrote state")
	}
}
