package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/kubetoken"
)

var (
	v4Node = netip.MustParseAddr("127.0.0.1")
	v6Node = netip.MustParseAddr("::1")
)

type bindFx struct {
	t    *testing.T
	e    *gwEnv
	h    *BindHandler
	port string
	v4   *http.Client
	v6   *http.Client
}

func (b *bindFx) setNonces(nonces ...string) {
	b.t.Helper()
	for _, n := range nonces {
		cells := []mgmtapi.CellInfo{{Name: cell1, Nonce: n, NonceExpiresAt: time.Now().Add(time.Hour)},
			{Name: cell2, Nonce: n + "-2", NonceExpiresAt: time.Now().Add(time.Hour)}}
		if err := b.e.st.SetCells(context.Background(), cells); err != nil {
			b.t.Fatal(err)
		}
	}
}

func (b *bindFx) client() *http.Client {
	cfg := tlsconfig.TLSClientConfig(b.e.ca.Bundle(), tlsconfig.AuthorizeID(b.e.gwID))
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.NextProtos = []string{"h2"}
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
	b.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func newBindFx(t *testing.T, cfg BindConfig, tracer *sdktrace.TracerProvider, log *slog.Logger) *bindFx {
	t.Helper()
	e := newGwEnv(t)
	cfg.CellNodes = map[string]netip.Addr{cell1: v4Node, cell2: v6Node}
	cfg.Subject = e.subject()
	cfg.Log = log
	b := &bindFx{t: t, e: e, h: NewBindHandler(e.st, cfg)}
	tlsCfg := BindServerTLS(e.ca.Source(t, gwSPIFFE))
	var tr = NewBindServer(b.h, tlsCfg, nil)
	if tracer != nil {
		tr = NewBindServer(b.h, tlsCfg, tracer.Tracer("test"))
	}
	ln := ListenBind(listenDual(t), tlsCfg)
	go func() { _ = tr.Serve(ln) }()
	t.Cleanup(func() { _ = tr.Close() })
	_, b.port, _ = net.SplitHostPort(ln.Addr().String())
	b.v4, b.v6 = b.client(), b.client()
	if _, err := net.Dial("tcp", "[::1]:"+b.port); err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	b.setNonces("n1")
	return b
}

func (b *bindFx) do(c *http.Client, host, method, path string, body []byte) (int, []byte) {
	b.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://"+host+":"+b.port+path, rd)
	if err != nil {
		b.t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// call sends the request from the node of cell-1 (127.0.0.1) or cell-2 (::1).
func (b *bindFx) fromCell1(method, path string, body []byte) (int, []byte) {
	return b.do(b.v4, "127.0.0.1", method, path, body)
}

func (b *bindFx) fromCell2(method, path string, body []byte) (int, []byte) {
	return b.do(b.v6, "[::1]", method, path, body)
}

func (b *bindFx) bindBody(cell, nonce string, mutate func(*kubetoken.Claims)) []byte {
	b.t.Helper()
	c := kubetoken.Claims{Issuer: "https://" + cell + ".example", Namespace: testNS, ServiceAccount: testSA, PodName: "p", PodUID: "u",
		NodeName: "n", Audience: []string{mgmtapi.BindAudience(cell, nonce)}}
	if mutate != nil {
		mutate(&c)
	}
	raw, _ := json.Marshal(mgmtapi.BindRequest{Nonce: nonce, Token: b.e.kt.Token(b.t, c)})
	return raw
}

func requireDenied(t *testing.T, code int, body []byte) mgmtapi.Denied {
	t.Helper()
	var d mgmtapi.Denied
	if code != http.StatusForbidden || json.Unmarshal(body, &d) != nil || d.Error != "denied" || len(d.RequestID) != 16 {
		t.Fatalf("answer %d %s, want 403 denied with a 16 hex request ID", code, body)
	}
	return d
}

func (b *bindFx) lastReason(cell string) string { return b.h.LastRefusals()[cell].Reason }

func TestBindListenerSourceMustMatchCell(t *testing.T) {
	b := newBindFx(t, BindConfig{}, nil, nil)
	bind := b.bindBody(cell1, "n1", nil)
	// The node of cell-2 may not use the routes of cell-1.
	code, body := b.fromCell2(http.MethodGet, gwapi.NoncePath(cell1), nil)
	requireDenied(t, code, body)
	if r, ok := b.h.LastRefusals()[cell1]; ok {
		t.Fatalf("a source mismatch is the last refusal of the claimed cell: %+v", r)
	}
	code, body = b.fromCell2(http.MethodPost, gwapi.BindPath(cell1), bind)
	requireDenied(t, code, body)
	code, body = b.fromCell2(http.MethodGet, gwapi.BindResultPath(cell1, string(gwapi.NewItemID())), nil)
	requireDenied(t, code, body)
	if n, _ := b.e.st.Peek(context.Background(), 10, 1<<20); len(n) != 0 {
		t.Fatal("a bind from the wrong source reached the outbox")
	}
	// A cell that the gateway does not know is a mismatch too, and leaves no state.
	code, body = b.fromCell1(http.MethodGet, gwapi.NoncePath("dev-cell-9"), nil)
	requireDenied(t, code, body)
	if _, ok := b.h.LastRefusals()["dev-cell-9"]; ok {
		t.Fatal("the handler keeps a refusal for a cell it does not know")
	}
	// The right node is served.
	if code, body = b.fromCell1(http.MethodGet, gwapi.NoncePath(cell1), nil); code != http.StatusOK {
		t.Fatalf("right source: %d %s", code, body)
	}
	if code, body = b.fromCell2(http.MethodGet, gwapi.NoncePath(cell2), nil); code != http.StatusOK {
		t.Fatalf("right source for cell-2: %d %s", code, body)
	}
}

func TestBindListenerFourInSix(t *testing.T) {
	e := newGwEnv(t)
	if err := e.st.SetCells(context.Background(), []mgmtapi.CellInfo{{Name: cell1, Nonce: "n1", NonceExpiresAt: time.Now().Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	for name, node := range map[string]netip.Addr{"plain": v4Node, "mapped": netip.MustParseAddr("::ffff:127.0.0.1")} {
		t.Run(name, func(t *testing.T) {
			h := NewBindHandler(e.st, BindConfig{CellNodes: map[string]netip.Addr{cell1: node}, Subject: e.subject()})
			req := httptest.NewRequest(http.MethodGet, gwapi.NoncePath(cell1), nil)
			req.RemoteAddr = "[::ffff:127.0.0.1]:4444"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("a 4-in-6 source: %d %s", rec.Code, rec.Body)
			}
			req.RemoteAddr = "[::ffff:127.0.0.2]:4444"
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			requireDenied(t, rec.Code, rec.Body.Bytes())
		})
	}
}

func TestBindListenerPrecheck(t *testing.T) {
	b := newBindFx(t, BindConfig{PerSourcePerMinute: 100}, nil, nil)
	b.setNonces("n0", "n1") // n0 is now the previous nonce
	post := func(body []byte) (int, []byte) { return b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), body) }
	noKid := kubetoken.NewSigner(t, "", jose.ES256)
	cases := []struct {
		name   string
		body   []byte
		reason string
	}{
		{"latest_nonce", b.bindBody(cell1, "n1", nil), ""},
		{"previous_nonce", b.bindBody(cell1, "n0", nil), ""},
		{"unknown_nonce", b.bindBody(cell1, "n9", nil), gwapi.ReasonNonceInvalid},
		{"nonce_of_other_cell", b.bindBody(cell1, "n1-2", nil), gwapi.ReasonNonceInvalid},
		{"audience_of_other_nonce", b.bindBody(cell1, "n1", func(c *kubetoken.Claims) { c.Audience = []string{mgmtapi.BindAudience(cell1, "n0")} }), gwapi.ReasonTokenInvalid},
		{"audience_of_other_cell", b.bindBody(cell1, "n1", func(c *kubetoken.Claims) { c.Audience = []string{mgmtapi.BindAudience(cell2, "n1")} }), gwapi.ReasonTokenInvalid},
		{"other_subject", b.bindBody(cell1, "n1", func(c *kubetoken.Claims) { c.ServiceAccount = "other" }), gwapi.ReasonTokenInvalid},
		{"not_pod_bound", b.bindBody(cell1, "n1", func(c *kubetoken.Claims) { c.Unbound = true }), gwapi.ReasonTokenInvalid},
		{"expired", b.bindBody(cell1, "n1", func(c *kubetoken.Claims) { c.IssuedAt = time.Now().Add(-3 * time.Hour) }), gwapi.ReasonTokenInvalid},
		{"empty_token", mustJSON(mgmtapi.BindRequest{Nonce: "n1"}), gwapi.ReasonTokenInvalid},
		{"no_kid", func() []byte {
			raw, _ := json.Marshal(mgmtapi.BindRequest{Nonce: "n1", Token: noKid.Token(t, kubetoken.Claims{Issuer: cell1Iss, Namespace: testNS,
				ServiceAccount: testSA, PodName: "p", PodUID: "u", NodeName: "n", Audience: []string{mgmtapi.BindAudience(cell1, "n1")}})})
			return raw
		}(), gwapi.ReasonTokenInvalid},
		{"unknown_member", []byte(`{"nonce":"n1","token":"x","extra":1}`), reasonBadRequest},
		{"not_json", []byte(`nonce=n1`), reasonBadRequest},
		{"body_above_16_kib", mustJSON(mgmtapi.BindRequest{Nonce: "n1", Token: strings.Repeat("a", 16<<10)}), reasonBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b.h.mu.Lock()
			delete(b.h.refusals, cell1)
			b.h.mu.Unlock()
			code, body := post(c.body)
			if c.reason == "" {
				if code != http.StatusAccepted {
					t.Fatalf("answer %d %s", code, body)
				}
				var acc gwapi.BindAccepted
				if json.Unmarshal(body, &acc) != nil || !acc.ID.Valid() {
					t.Fatalf("accepted body %s", body)
				}
				// Free the pending slot for the next case.
				_ = b.e.st.Ack(context.Background(), []mgmtapi.ItemOutcome{{ID: string(acc.ID), Outcome: mgmtapi.OutcomeAccepted}})
				return
			}
			requireDenied(t, code, body)
			if got := b.lastReason(cell1); got != c.reason {
				t.Fatalf("reason %q, want %q", got, c.reason)
			}
		})
	}
	t.Run("expired_nonce", func(t *testing.T) {
		if err := b.e.st.SetCells(context.Background(), []mgmtapi.CellInfo{{Name: cell1, Nonce: "n5", NonceExpiresAt: time.Now().Add(-time.Second)}}); err != nil {
			t.Fatal(err)
		}
		code, body := post(b.bindBody(cell1, "n5", nil))
		requireDenied(t, code, body)
		if got := b.lastReason(cell1); got != gwapi.ReasonNonceInvalid {
			t.Fatalf("an expired nonce: reason %q", got)
		}
	})
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestBindListenerRateAndCap(t *testing.T) {
	t.Run("rate", func(t *testing.T) {
		b := newBindFx(t, BindConfig{PerSourcePerMinute: 3}, nil, nil)
		bad := b.bindBody(cell1, "n9", nil) // nonce_invalid: the post counts but never binds
		for i := 0; i < 5; i++ {
			// A post from the wrong source is a mismatch and does not count toward the rate.
			code, body := b.fromCell2(http.MethodPost, gwapi.BindPath(cell1), bad)
			requireDenied(t, code, body)
			if r := b.lastReason(cell1); r != "" {
				t.Fatalf("mismatch post %d: reason %q", i, r)
			}
		}
		for i := 0; i < 3; i++ {
			code, body := b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), bad)
			requireDenied(t, code, body)
			if r := b.lastReason(cell1); r != gwapi.ReasonNonceInvalid {
				t.Fatalf("post %d: reason %q, want nonce_invalid", i+1, r)
			}
		}
		code, body := b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), bad)
		requireDenied(t, code, body)
		if r := b.lastReason(cell1); r != gwapi.ReasonOverloaded {
			t.Fatalf("fourth post: reason %q, want overloaded", r)
		}
		// GET routes are not binds, so they do not count and still answer.
		if code, _ = b.fromCell1(http.MethodGet, gwapi.NoncePath(cell1), nil); code != http.StatusOK {
			t.Fatalf("nonce after the rate: %d", code)
		}
		if got := NewBindHandler(b.e.st, BindConfig{}).cfg.PerSourcePerMinute; got != 10 {
			t.Fatalf("default rate %d, want 10", got)
		}
	})
	t.Run("rate_window", func(t *testing.T) {
		e := newGwEnv(t)
		now := time.Now()
		h := NewBindHandler(e.st, BindConfig{PerSourcePerMinute: 2, Now: func() time.Time { return now }})
		src := netip.MustParseAddr("192.0.2.9")
		if !h.allow(src) || !h.allow(src) || h.allow(src) {
			t.Fatal("two posts a minute are allowed, a third is not")
		}
		now = now.Add(61 * time.Second)
		if !h.allow(src) {
			t.Fatal("the window does not slide")
		}
	})
	t.Run("pending_cap", func(t *testing.T) {
		b := newBindFx(t, BindConfig{PerSourcePerMinute: 100}, nil, nil)
		for i := 0; i < 4; i++ {
			if code, body := b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), b.bindBody(cell1, "n1", nil)); code != http.StatusAccepted {
				t.Fatalf("bind %d: %d %s", i+1, code, body)
			}
		}
		code, body := b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), b.bindBody(cell1, "n1", nil))
		requireDenied(t, code, body)
		if r := b.lastReason(cell1); r != gwapi.ReasonOverloaded {
			t.Fatalf("fifth pending bind: reason %q", r)
		}
	})
}

func TestBindListenerFlow(t *testing.T) {
	b := newBindFx(t, BindConfig{}, nil, nil)
	ctx := context.Background()
	code, body := b.fromCell1(http.MethodGet, gwapi.NoncePath(cell1), nil)
	var nr mgmtapi.NonceResponse
	if code != http.StatusOK || json.Unmarshal(body, &nr) != nil || nr.Nonce != "n1" || nr.Audience != mgmtapi.BindAudience(cell1, "n1") || nr.ExpiresAt.IsZero() {
		t.Fatalf("nonce %d %s", code, body)
	}
	code, body = b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), b.bindBody(cell1, nr.Nonce, nil))
	var acc gwapi.BindAccepted
	if code != http.StatusAccepted || json.Unmarshal(body, &acc) != nil || !acc.ID.Valid() {
		t.Fatalf("bind %d %s", code, body)
	}
	poll := func() gwapi.BindResult {
		code, body := b.fromCell1(http.MethodGet, gwapi.BindResultPath(cell1, string(acc.ID)), nil)
		var r gwapi.BindResult
		if code != http.StatusOK || json.Unmarshal(body, &r) != nil {
			t.Fatalf("result %d %s", code, body)
		}
		return r
	}
	if r := poll(); r.Status != gwapi.BindPending {
		t.Fatalf("result before the ack: %+v", r)
	}
	items, _ := b.e.st.Peek(ctx, 10, 1<<20)
	if len(items) != 1 || items[0].ID != acc.ID || items[0].Kind != gwapi.KindBind || items[0].Cell != cell1 {
		t.Fatalf("outbox %+v", items)
	}
	var req mgmtapi.BindRequest
	if json.Unmarshal(items[0].Body, &req) != nil || req.Nonce != "n1" || req.Token == "" || req.Token != items[0].Token {
		t.Fatalf("bind item body %s", items[0].Body)
	}
	if err := b.e.st.Ack(ctx, []mgmtapi.ItemOutcome{{ID: string(acc.ID), Outcome: mgmtapi.OutcomeAccepted, Bind: &mgmtapi.BindResponse{Status: mgmtapi.StatusBound}}}); err != nil {
		t.Fatal(err)
	}
	if r := poll(); r.Status != mgmtapi.StatusBound {
		t.Fatalf("result after the ack: %+v", r)
	}
	// A refused bind shows as denied with its request ID.
	_, body = b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), b.bindBody(cell1, "n1", nil))
	_ = json.Unmarshal(body, &acc)
	if err := b.e.st.Ack(ctx, []mgmtapi.ItemOutcome{{ID: string(acc.ID), Outcome: mgmtapi.OutcomeRefused, Reason: gwapi.ReasonTokenInvalid, RequestID: "0123456789abcdef"}}); err != nil {
		t.Fatal(err)
	}
	if r := poll(); r.Status != gwapi.BindDenied || r.RequestID != "0123456789abcdef" {
		t.Fatalf("refused bind: %+v", r)
	}
	// An ID of the wrong form is a denial.
	code, body = b.fromCell1(http.MethodGet, gwapi.BindResultPath(cell1, "not-an-id"), nil)
	requireDenied(t, code, body)
}

func TestBindResultOnlyForOwnCell(t *testing.T) {
	b := newBindFx(t, BindConfig{}, nil, nil)
	code, body := b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), b.bindBody(cell1, "n1", nil))
	var acc gwapi.BindAccepted
	if code != http.StatusAccepted || json.Unmarshal(body, &acc) != nil {
		t.Fatalf("bind %d %s", code, body)
	}
	if err := b.e.st.Ack(context.Background(), []mgmtapi.ItemOutcome{{ID: string(acc.ID), Outcome: mgmtapi.OutcomeAccepted, Bind: &mgmtapi.BindResponse{Status: mgmtapi.StatusBound}}}); err != nil {
		t.Fatal(err)
	}
	// Cell-2 cannot read the result through the path of cell-1.
	code, body = b.fromCell2(http.MethodGet, gwapi.BindResultPath(cell1, string(acc.ID)), nil)
	requireDenied(t, code, body)
	// Through its own path it learns nothing about an ID of cell-1.
	code, body = b.fromCell2(http.MethodGet, gwapi.BindResultPath(cell2, string(acc.ID)), nil)
	var r gwapi.BindResult
	if code != http.StatusOK || json.Unmarshal(body, &r) != nil || r.Status != gwapi.BindPending {
		t.Fatalf("cell-2 read the bind of cell-1: %d %s", code, body)
	}
}

func TestBindRefusalShownInStatus(t *testing.T) {
	b := newBindFx(t, BindConfig{}, nil, nil)
	before := time.Now().Add(-time.Second)
	code, body := b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), b.bindBody(cell1, "n9", nil))
	d := requireDenied(t, code, body)
	r := b.h.LastRefusals()[cell1]
	if r.Reason != gwapi.ReasonNonceInvalid || r.RequestID != d.RequestID || r.At.Before(before) || r.At.After(time.Now().Add(time.Second)) {
		t.Fatalf("last refusal %+v, want nonce_invalid %s", r, d.RequestID)
	}
	// The next refusal replaces it, and another cell keeps its own.
	code, body = b.fromCell1(http.MethodPost, gwapi.BindPath(cell1), []byte(`x`))
	d2 := requireDenied(t, code, body)
	all := b.h.LastRefusals()
	if all[cell1].Reason != reasonBadRequest || all[cell1].RequestID != d2.RequestID || len(all) != 1 {
		t.Fatalf("refusals %+v", all)
	}
	// The copy that LastRefusals returns does not alias the handler state.
	all[cell2] = mgmtapi.BindRefusal{}
	if len(b.h.LastRefusals()) != 1 {
		t.Fatal("LastRefusals returns the live map")
	}
}

func TestBindListenerSlowBodyReleased(t *testing.T) {
	old := bindReadTimeout
	bindReadTimeout = time.Second
	t.Cleanup(func() { bindReadTimeout = old })
	b := newBindFx(t, BindConfig{}, nil, nil)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, _ := http.NewRequest(http.MethodPost, "https://127.0.0.1:"+b.port+gwapi.BindPath(cell1), pr)
	req.ContentLength = 200
	go func() { _, _ = pw.Write([]byte(`{"nonce":`)) }() // the rest never comes
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		resp, err := b.v4.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case <-done:
		if d := time.Since(start); d < 800*time.Millisecond {
			t.Fatalf("the request ended after %v, before the read timeout", d)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("a request with a stalled body holds its connection past the read timeout")
	}
	if got := bindReadTimeout; got != time.Second {
		t.Fatal("test setup")
	}
}

func TestBindListenerConnCaps(t *testing.T) {
	t.Run("per_source", func(t *testing.T) {
		b := newBindFx(t, BindConfig{}, nil, nil)
		dial := func() (*tls.Conn, error) {
			cfg := tlsconfig.TLSClientConfig(b.e.ca.Bundle(), tlsconfig.AuthorizeID(b.e.gwID))
			cfg.NextProtos = []string{"h2"}
			c, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: cfg}).Dial("tcp", "127.0.0.1:"+b.port)
			if err != nil {
				return nil, err
			}
			return c.(*tls.Conn), nil
		}
		for i := 0; i < 4; i++ {
			c, err := dial()
			if err != nil {
				t.Fatalf("connection %d: %v", i+1, err)
			}
			t.Cleanup(func() { _ = c.Close() })
		}
		start := time.Now()
		if c, err := dial(); err == nil {
			_ = c.Close()
			t.Fatal("a fifth connection from one source is served")
		}
		if time.Since(start) > time.Second {
			t.Fatalf("the fifth connection took %v to close", time.Since(start))
		}
		// Another source is not affected.
		if code, body := b.fromCell2(http.MethodGet, gwapi.NoncePath(cell2), nil); code != http.StatusOK {
			t.Fatalf("other source: %d %s", code, body)
		}
	})
	t.Run("max_age", func(t *testing.T) {
		oldAge, oldGrace := bindMaxAge, bindGrace
		bindMaxAge, bindGrace = time.Second, 500*time.Millisecond
		t.Cleanup(func() { bindMaxAge, bindGrace = oldAge, oldGrace })
		b := newBindFx(t, BindConfig{}, nil, nil)
		cfg := tlsconfig.TLSClientConfig(b.e.ca.Bundle(), tlsconfig.AuthorizeID(b.e.gwID))
		cfg.NextProtos = []string{"h2"}
		c, err := (&tls.Dialer{Config: cfg}).Dial("tcp", "127.0.0.1:"+b.port)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, c); close(done) }()
		select {
		case <-done:
			if d := time.Since(start); d < 800*time.Millisecond {
				t.Fatalf("closed after %v, before the maximum age", d)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("a connection outlives the maximum age and the grace")
		}
	})
	t.Run("defaults", func(t *testing.T) {
		if bindMaxAge != 15*time.Second || bindGrace != 5*time.Second || bindReadTimeout != 10*time.Second ||
			bindWriteTimeout != 15*time.Second || bindIdleTimeout != 30*time.Second || bindBodyLimit != 16<<10 ||
			bindConnCap != 32 || bindPerSource != 4 || bindStreamsPerCon != 2 {
			t.Fatal("a limit differs from the shared table")
		}
	})
}

// A log line of the bind handler carries a trace ID, and the public listener ignores a trace context
// from the caller.
func TestBindServerTraces(t *testing.T) {
	const callerTrace = "0af7651916cd43dd8448eb211c80319c"
	var out lockedBuf
	log := telemetry.NewLogger(&out, slog.DiscardHandler)
	b := newBindFx(t, BindConfig{}, sdktrace.NewTracerProvider(), log)
	req, _ := http.NewRequest(http.MethodGet, "https://[::1]:"+b.port+gwapi.NoncePath(cell1), nil) // wrong source: a denial
	req.Header.Set("traceparent", "00-"+callerTrace+"-b7ad6b7169203331-01")
	resp, err := b.v6.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "bind_denied" {
			line = m
		}
	}
	id, _ := line["trace_id"].(string)
	if len(id) != 32 || id == callerTrace {
		t.Fatalf("bind_denied line %v: trace_id %q, want a new 32 character ID unlike %s", line, id, callerTrace)
	}
}
