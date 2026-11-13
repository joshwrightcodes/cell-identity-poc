package mgmt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

func TestUnknownKidRefetchesOncePer10s(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second)
	n := r.nonce(cell1)
	if _, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: forged(t, r, cell1, n)}); ReasonOf(err) != mgmtapi.ReasonTokenInvalid {
		t.Fatal(err)
	}
	b := newSigner(t, "kid-b")
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], b)
	r.clk.Advance(5 * time.Second)
	if _, err := r.bind(cell1, b); ReasonOf(err) != mgmtapi.ReasonTokenInvalid {
		t.Fatalf("5 s after a fetch the cache answers: %v", err)
	}
	calls := r.keys.count(cell1)
	r.clk.Advance(6 * time.Second)
	r.mustBind(cell1, b, mgmtapi.StatusKeysUpdated)
	if r.keys.count(cell1) != calls+1 {
		t.Fatalf("the bind fetched %d times", r.keys.count(cell1)-calls)
	}
}

func TestKeyCheckNeverJudgesAStaleSet(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second)
	n := r.nonce(cell1)
	_, _ = r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: forged(t, r, cell1, n)})
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], newSigner(t, "kid-b"))
	r.clk.Advance(30 * time.Second)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUpdated {
		t.Fatalf("check 30 s after a failed bind: %v, %v", res, err)
	}
}

func TestRateLimitedWithDefaultConfig(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second)
	n := newSigner(t, "kid-new")
	r.keys.set(cell1, "https://dev-cell-1.test", n)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUntrusted {
		t.Fatalf("check %v, %v", res, err)
	}
	r.clk.Advance(30 * time.Second)
	if _, err := r.bind(cell1, n); ReasonOf(err) != mgmtapi.ReasonRateLimited {
		t.Fatalf("bind 30 s after a check: %v", err)
	}
	r.clk.Advance(31 * time.Second)
	r.mustBind(cell1, n, mgmtapi.StatusKeysUpdated)
}

func TestPendingDropsGetNoKeyCheck(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	r.restart(func(in *Intent) { in.Cells = in.Cells[:1] })
	ctx := t.Context()
	done := make(chan error, 1)
	go func() { done <- r.plane.RunChecks(ctx) }()
	calls := r.keys.count(cell2)
	r.clk.Advance(16 * time.Minute)
	r.ticks <- r.clk.Now()
	r.ticks <- r.clk.Now()
	if r.keys.count(cell2) != calls || r.logs.count("key_check_failed") != 0 {
		t.Fatalf("a pending drop was checked: %d fetches, %d warnings", r.keys.count(cell2)-calls, r.logs.count("key_check_failed"))
	}
	if r.keys.count(cell1) == 0 {
		t.Fatal("no check ran")
	}
}

func TestBoundBadSignatureNoFetch(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second) // a warm cache would hide a fetch
	calls := r.keys.total()
	n := r.nonce(cell1)
	tok := r.token(cell1, n, newSigner(t, "kid-1"), nil)
	if _, err := r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: tok}); ReasonOf(err) != mgmtapi.ReasonTokenInvalid {
		t.Fatal(err)
	}
	if r.keys.total() != calls {
		t.Fatal("a token with a known kid and a bad signature caused a fetch")
	}
}

func TestFailedCheckIsVisibleAndStartsNoGap(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second)
	checked := cellStatus(r.status(), cell1).CheckedAt
	r.keys.fail(cell1, errors.New("down"))
	if res, _ := r.plane.KeyCheck(t.Context(), cell1); res != CheckIssuerUnavailable {
		t.Fatal(res)
	}
	got := cellStatus(r.status(), cell1)
	if got.LastCheck != string(CheckIssuerUnavailable) || !got.CheckedAt.Equal(checked) {
		t.Fatalf("status after a failed check: %+v", got)
	}
	r.restart(nil)
	if got := cellStatus(r.status(), cell1).LastCheck; got != string(CheckIssuerUnavailable) {
		t.Fatalf("the failed check is not saved: %q", got)
	}
	// The source recovers at once. A failed fetch is not cached, and no gap started.
	r.keys.fail(cell1, nil)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckUnchanged {
		t.Fatalf("check after recovery: %v, %v", res, err)
	}
}

func TestParseKeysRefusesWeakKeys(t *testing.T) {
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	strong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &weak.PublicKey, KeyID: "weak-rsa"},
		{Key: &strong.PublicKey},
		{Key: &p384.PublicKey, KeyID: "p384"},
		{Key: &strong.PublicKey, KeyID: "ok"},
	}}
	raw, _ := json.Marshal(set)
	got := parseKeys(raw)
	if len(got) != 1 || got[0].kid != "ok" {
		t.Fatalf("usable keys %v", got)
	}
}

func TestEncodeKeysDropsCertificates(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: strings.Repeat("a", 60)}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	raw, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "c", Certificates: []*x509.Certificate{cert}}}})
	if !strings.Contains(string(raw), "x5c") {
		t.Skip("the key set did not carry a certificate chain")
	}
	out, err := encodeKeys(parseKeys(raw))
	if err != nil || strings.Contains(string(out), "x5c") || !strings.Contains(string(out), `"kid":"c"`) {
		t.Fatalf("%s, %v", out, err)
	}
}

func TestRecordSizeCap(t *testing.T) {
	old := maxRecordBytes
	maxRecordBytes = 300
	t.Cleanup(func() { maxRecordBytes = old })
	r := newRig(t)
	before := r.stateBytes()
	if _, err := r.bind(cell1, r.signers[cell1]); ReasonOf(err) != mgmtapi.ReasonKeysUntrusted {
		t.Fatalf("bind of a record above the cap: %v", err)
	}
	if !bytes.Equal(before, r.stateBytes()) {
		t.Fatal("state changed")
	}
	maxRecordBytes = old
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second)
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], newSigner(t, "kid-b"))
	maxRecordBytes = 300
	signed := r.status().Signed
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckKeysUntrusted {
		t.Fatalf("check above the cap: %v, %v", res, err)
	}
	if got := r.status().Signed; got != signed || r.verifySpec().Revision != signed {
		t.Fatalf("a refused check signed a new revision: %v to %v", signed, got)
	}
	if got := cellStatus(r.status(), cell1).Kids; len(got) != 1 {
		t.Fatalf("kids %v", got)
	}
}

func TestBundleSizeCap(t *testing.T) {
	old := maxBundleBytes
	maxBundleBytes = 1100
	t.Cleanup(func() { maxBundleBytes = old })
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	before := r.stateBytes()
	if _, err := r.bind(cell2, r.signers[cell2]); ReasonOf(err) != mgmtapi.ReasonKeysUntrusted {
		t.Fatalf("bind past the bundle cap: %v", err)
	}
	if !bytes.Equal(before, r.stateBytes()) {
		t.Fatal("state changed")
	}
}

func TestBindReplayAnswersOnce(t *testing.T) {
	for _, bound := range []bool{false, true} {
		r := newRig(t)
		if bound {
			r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
		}
		n := r.nonce(cell1)
		req := mgmtapi.BindRequest{Nonce: n, Token: r.token(cell1, n, r.signers[cell1], nil)}
		var wg sync.WaitGroup
		errs := make([]error, 8)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = r.plane.Bind(t.Context(), cell1, req)
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if ReasonOf(err) != mgmtapi.ReasonNonceInvalid {
				t.Fatalf("bound %v: %v", bound, err)
			}
		}
		if ok != 1 {
			t.Fatalf("bound %v: %d answers for one nonce", bound, ok)
		}
	}
}

func TestSameCellBindRaceBindsOnce(t *testing.T) {
	r := newRig(t)
	r.keys.mu.Lock()
	r.keys.gate, r.keys.gateCell = make(chan struct{}), cell1
	gate := r.keys.gate
	r.keys.mu.Unlock()
	type out struct {
		req  mgmtapi.BindRequest
		resp mgmtapi.BindResponse
		err  error
	}
	res := make(chan out, 2)
	for range 2 {
		n := r.nonce(cell1)
		req := mgmtapi.BindRequest{Nonce: n, Token: r.token(cell1, n, r.signers[cell1], nil)}
		go func() {
			resp, err := r.plane.Bind(t.Context(), cell1, req)
			res <- out{req, resp, err}
		}()
	}
	for r.keys.count(cell1) == 0 {
		time.Sleep(time.Millisecond)
	}
	close(gate)
	got := []string{}
	var answeredBound mgmtapi.BindRequest
	for range 2 {
		o := <-res
		if o.err != nil {
			t.Fatal(o.err)
		}
		got = append(got, o.resp.Status)
		if o.resp.Status == mgmtapi.StatusAlreadyBound {
			answeredBound = o.req
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{mgmtapi.StatusAlreadyBound, mgmtapi.StatusBound}) || r.status().Signed != rev(1, 2) {
		t.Fatalf("results %v, signed %v", got, r.status().Signed)
	}
	// The request that was answered already_bound consumed its nonce.
	if _, err := r.plane.Bind(t.Context(), cell1, answeredBound); ReasonOf(err) != mgmtapi.ReasonNonceInvalid {
		t.Fatalf("replay of an already_bound request: %v", err)
	}
}

func TestConcurrentChecksStartOneGap(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.clk.Advance(61 * time.Second)
	r.keys.mu.Lock()
	r.keys.gate, r.keys.gateCell = make(chan struct{}), cell1
	gate := r.keys.gate
	r.keys.mu.Unlock()
	res := make(chan CheckResult, 2)
	for range 2 {
		go func() {
			c, _ := r.plane.KeyCheck(t.Context(), cell1)
			res <- c
		}()
	}
	for r.keys.count(cell1) < 2 {
		time.Sleep(time.Millisecond)
	}
	close(gate)
	got := []string{string(<-res), string(<-res)}
	slices.Sort(got)
	if !slices.Equal(got, []string{string(CheckRateLimited), string(CheckUnchanged)}) {
		t.Fatalf("results %v", got)
	}
}

func TestCacheIgnoresClockStepBack(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	calls := r.keys.count(cell1)
	r.clk.Advance(-10 * time.Second)
	n := r.nonce(cell1)
	_, _ = r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: forged(t, r, cell1, n)})
	if r.keys.count(cell1) == calls {
		t.Fatal("a cache entry from the future was served")
	}
}

func TestRestartDuringRestore(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	if err := r.plane.Restore(2); err != nil {
		t.Fatal(err)
	}
	r.restart(func(in *Intent) { in.Cells[0].Subjects = in.Cells[0].Subjects[:1] })
	if !r.status().RestoreActive || r.status().Signed != rev(1, 3) {
		t.Fatalf("status %+v", r.status())
	}
	_, fresh, _ := newKey()
	if err := WriteKey(filepath.Join(r.dir, "ed25519.key"), fresh); err != nil {
		t.Fatal(err)
	}
	r.restart(nil)
	if r.status().RestoreActive || r.status().Signed != rev(2, 1) {
		t.Fatalf("a key change leaves the restore active: %+v", r.status())
	}
}

func TestRepeatedLogsAreRateLimited(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	for range 30 {
		n := r.nonce(cell1)
		_, _ = r.plane.Bind(t.Context(), cell1, mgmtapi.BindRequest{Nonce: n, Token: "x.y.z"})
	}
	if got := r.logs.count("bind_refused"); got != 1 {
		t.Fatalf("%d bind_refused lines for one cell and reason", got)
	}
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	if err := r.plane.Restore(2); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(61 * time.Second)
	r.keys.set(cell1, "https://dev-cell-1.test", r.signers[cell1], newSigner(t, "kid-b"))
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() { defer close(stopped); _ = r.plane.RunChecks(ctx) }()
	// The pass in progress finishes before the temporary directory goes away.
	defer func() { cancel(); <-stopped }()
	r.clk.Advance(16 * time.Minute)
	for range 10 {
		r.clk.Advance(20 * time.Second)
		r.ticks <- r.clk.Now()
		r.ticks <- r.clk.Now()
	}
	// The ticks channel has no buffer. This send returns only after RunChecks finished the pass
	// for the last tick above, so the count below cannot read a pass in progress.
	r.ticks <- r.clk.Now()
	if got := r.logs.count("key_check_failed"); got != 1 {
		t.Fatalf("%d key_check_failed lines in a restore", got)
	}
}

func TestGaugeReportsTheLag(t *testing.T) {
	r := newRig(t)
	reader, meter := testMeter()
	r.mod = func(c *Config) { c.Meter = meter }
	r.restart(nil)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 1)})
	if got := collect(t, reader)["mgmtd.spec.revision.lag/"]; got != 2 {
		t.Fatalf("lag %d, want 2", got)
	}
	r.plane.Report(mgmtapi.StatusReport{Applied: rev(1, 3)})
	if got := collect(t, reader)["mgmtd.spec.revision.lag/"]; got != 0 {
		t.Fatalf("lag %d, want 0", got)
	}
}

func newKey() (ed25519.PublicKey, ed25519.PrivateKey, error) { return ed25519.GenerateKey(rand.Reader) }

func TestFailedFetchIsNotCached(t *testing.T) {
	r := newRig(t)
	r.keys.fail(cell1, errors.New("down"))
	if _, err := r.bind(cell1, r.signers[cell1]); ReasonOf(err) != mgmtapi.ReasonIssuerUnavailable {
		t.Fatalf("bind with the source down: %v", err)
	}
	r.keys.fail(cell1, nil)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
}

func TestUnknownCellsDoNotStarveLogs(t *testing.T) {
	r := newRig(t, cell1, cell2)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.mustBind(cell2, r.signers[cell2], mgmtapi.StatusBound)
	r.restart(func(in *Intent) { in.Cells = in.Cells[:1] })
	fs := &flakyStore{Store: r.store}
	r.plane.cfg.Store = fs
	for i := range 300 {
		_, _ = r.plane.Bind(t.Context(), "invented-"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26)), mgmtapi.BindRequest{Nonce: "n", Token: "t"})
	}
	if got := r.logs.count("bind_refused"); got > 1 {
		t.Fatalf("%d bind_refused lines for invented cell names", got)
	}
	fs.fail.Store(true)
	r.release()
	if got := r.logs.count("drop_failed"); got != 1 {
		t.Fatalf("%d drop_failed lines after 300 unknown names", got)
	}
}

// A key check that cannot reach the host service logs once for each change of outcome of the cell, and not once for each check.
func TestUnavailableKeyCheckLogsOncePerChange(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	r.keys.fail(cell1, errors.New("down"))
	for range 3 {
		r.clk.Advance(61 * time.Second)
		if res, _ := r.plane.KeyCheck(t.Context(), cell1); res != CheckIssuerUnavailable {
			t.Fatal(res)
		}
	}
	if n := r.logs.count("key_check_issuer_unavailable"); n != 1 {
		t.Fatalf("%d lines for three failed checks, want 1", n)
	}
	r.keys.fail(cell1, nil)
	r.clk.Advance(61 * time.Second)
	if res, err := r.plane.KeyCheck(t.Context(), cell1); err != nil || res != CheckUnchanged {
		t.Fatalf("%v, %v", res, err)
	}
	r.keys.fail(cell1, errors.New("down again"))
	r.clk.Advance(61 * time.Second)
	_, _ = r.plane.KeyCheck(t.Context(), cell1)
	if n := r.logs.count("key_check_issuer_unavailable"); n != 2 {
		t.Fatalf("%d lines after a second outage, want 2", n)
	}
}
