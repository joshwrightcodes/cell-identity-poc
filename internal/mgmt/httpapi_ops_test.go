package mgmt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

// envdRequest returns a request that carries the verified certificate of id from ca.
func envdRequest(t *testing.T, ca *spiffetest.CA, id, method, target string, body io.Reader) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, body)
	if id != "" {
		r.TLS = &tls.ConnectionState{PeerCertificates: ca.SVID(t, id).Certificates}
	}
	return r
}

type apiFixture struct {
	t    *testing.T
	fake *fakeAPI
	h    http.Handler
	ca   *spiffetest.CA
	logs *lockedBuf
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	f := &apiFixture{t: t, fake: &fakeAPI{bundle: testBundle()}, ca: spiffetest.NewCA(t, devTD), logs: &lockedBuf{}}
	f.h = NewAPIHandler(f.fake, "dev", mustID(t, envdSPIFFE), jsonLog(f.logs))
	return f
}

func (f *apiFixture) do(method, target string, body io.Reader) *httptest.ResponseRecorder {
	f.t.Helper()
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, envdRequest(f.t, f.ca, envdSPIFFE, method, target, body))
	return rec
}

func (f *apiFixture) doAs(id, method, target string, body io.Reader) *httptest.ResponseRecorder {
	f.t.Helper()
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, envdRequest(f.t, f.ca, id, method, target, body))
	return rec
}

func reportBody(t *testing.T, items int, pad int) string {
	t.Helper()
	b := mgmtapi.ReportBatch{}
	for i := 0; i < items; i++ {
		b.Items = append(b.Items, mgmtapi.ReportItem{
			ID: "i" + itoa(uint64(i)), Cell: "dev-cell-1", Kind: "status", Body: json.RawMessage(`{"seq":1}`), Token: strings.Repeat("t", pad),
		})
	}
	return marshal(t, b)
}

func TestAPIServesOpsToEnvdOnly(t *testing.T) {
	fs := &fakeAPI{bundle: testBundle(), ops: mgmtapi.OpsBundle{
		Ops:   []json.RawMessage{json.RawMessage(`{"payloadType":"o","payload":"cA==","signatures":[]}`)},
		Cells: []mgmtapi.CellInfo{{Name: "dev-cell-1", Nonce: "n1", NonceExpiresAt: time.Unix(1700000000, 0).UTC(), Bound: true}},
	}}
	rig := startAPI(t, NewAPIHandler(fs, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard)), nil, nil)
	other := spiffetest.NewCA(t, devTD)
	url := "https://" + rig.addr + mgmtapi.OpsPath("dev")

	t.Run("envd", func(t *testing.T) {
		resp, err := rig.client(t, rig.devCA.Source(t, envdSPIFFE)).Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || resp.ProtoMajor != 2 {
			t.Fatalf("status %d proto %d: %s", resp.StatusCode, resp.ProtoMajor, body)
		}
		var got mgmtapi.OpsBundle
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if marshal(t, got) != marshal(t, fs.OpenOps()) {
			t.Fatalf("body %s is not OpenOps()", body)
		}
	})
	for _, tc := range []struct {
		name string
		svid x509svid.Source
	}{
		{"cp_otel", rig.devCA.Source(t, "spiffe://dev.env.poc.internal/cp/otel")},
		{"cp_gateway", rig.devCA.Source(t, "spiffe://dev.env.poc.internal/cp/gateway")},
		{"no_client_cert", nil},
		{"other_ca_envd", other.Source(t, envdSPIFFE)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, opsBefore := fs.calls()
			resp, err := rig.client(t, tc.svid).Get(url)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("request succeeded with status %d", resp.StatusCode)
			}
			if _, opsAfter := fs.calls(); opsAfter != opsBefore {
				t.Fatal("the plane served a peer that is not envd")
			}
		})
	}
}

// The handler checks the peer on its own, whatever the listener did.
func TestAPIOpsAndReportsCheckThePeer(t *testing.T) {
	f := newAPIFixture(t)
	for name, id := range map[string]string{"cp_otel": "spiffe://dev.env.poc.internal/cp/otel", "no_cert": "", "other_td": "spiffe://other.example/envd"} {
		if rec := f.doAs(id, "GET", mgmtapi.OpsPath("dev"), nil); rec.Code != 403 {
			t.Errorf("ops %s: status %d, want 403", name, rec.Code)
		}
		if rec := f.doAs(id, "POST", mgmtapi.ReportsPath("dev"), strings.NewReader(reportBody(t, 1, 4))); rec.Code != 403 {
			t.Errorf("reports %s: status %d, want 403", name, rec.Code)
		}
	}
	if nr, no := f.fake.calls(); nr != 0 || no != 0 {
		t.Fatalf("%d report and %d ops calls from a peer that is not envd", nr, no)
	}
	if rec := f.do("GET", mgmtapi.OpsPath("dev"), nil); rec.Code != 200 {
		t.Fatalf("envd ops: %d", rec.Code)
	}
	if rec := f.do("POST", mgmtapi.ReportsPath("dev"), strings.NewReader(reportBody(t, 1, 4))); rec.Code != 200 {
		t.Fatalf("envd reports: %d %s", rec.Code, rec.Body)
	}
}

func TestAPIRoutesCheckEnvAndMethod(t *testing.T) {
	f := newAPIFixture(t)
	body := reportBody(t, 1, 4)
	for _, tc := range []struct{ method, path string }{
		{"GET", mgmtapi.OpsPath("prod")},
		{"POST", mgmtapi.OpsPath("dev")},
		{"POST", mgmtapi.ReportsPath("prod")},
		{"GET", mgmtapi.ReportsPath("dev")},
		{"PUT", mgmtapi.ReportsPath("dev")},
		{"DELETE", mgmtapi.OpsPath("dev")},
	} {
		if rec := f.do(tc.method, tc.path, strings.NewReader(body)); rec.Code != 404 {
			t.Errorf("%s %s: status %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
	if nr, no := f.fake.calls(); nr != 0 || no != 0 {
		t.Fatalf("%d report and %d ops calls on a wrong route", nr, no)
	}
}

func TestAPIReportsLimits(t *testing.T) {
	denied := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != 403 {
			t.Fatalf("status %d, want 403: %s", rec.Code, rec.Body)
		}
		var d mgmtapi.Denied
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || d.Error != mgmtapi.DeniedError || !reqIDRE.MatchString(d.RequestID) {
			t.Fatalf("denied body %s: %v", rec.Body, err)
		}
	}
	t.Run("100_items_pass", func(t *testing.T) {
		f := newAPIFixture(t)
		rec := f.do("POST", mgmtapi.ReportsPath("dev"), strings.NewReader(reportBody(t, 100, 4)))
		var res mgmtapi.ReportResult
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &res) != nil || len(res.Outcomes) != 100 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		if nr, _ := f.fake.calls(); nr != 1 || len(f.fake.batches[0].Items) != 100 {
			t.Fatalf("%d calls", nr)
		}
	})
	t.Run("101_items", func(t *testing.T) {
		f := newAPIFixture(t)
		denied(t, f.do("POST", mgmtapi.ReportsPath("dev"), strings.NewReader(reportBody(t, 101, 4))))
		if nr, _ := f.fake.calls(); nr != 0 {
			t.Fatalf("%d Reports calls for 101 items", nr)
		}
	})
	t.Run("one_mib_passes", func(t *testing.T) {
		f := newAPIFixture(t)
		small := len(reportBody(t, 1, 0))
		body := reportBody(t, 1, (1<<20)-small)
		if len(body) != 1<<20 {
			t.Fatalf("body of %d bytes", len(body))
		}
		if rec := f.do("POST", mgmtapi.ReportsPath("dev"), strings.NewReader(body)); rec.Code != 200 {
			t.Fatalf("a body of exactly 1 MiB: status %d: %s", rec.Code, rec.Body)
		}
	})
	t.Run("over_one_mib", func(t *testing.T) {
		f := newAPIFixture(t)
		small := len(reportBody(t, 1, 0))
		body := reportBody(t, 1, (1<<20)-small+1)
		denied(t, f.do("POST", mgmtapi.ReportsPath("dev"), strings.NewReader(body)))
		// A body without Content-Length is limited as well.
		req := envdRequest(t, f.ca, envdSPIFFE, "POST", mgmtapi.ReportsPath("dev"), io.MultiReader(strings.NewReader(body)))
		req.ContentLength = -1
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		denied(t, rec)
		if nr, _ := f.fake.calls(); nr != 0 {
			t.Fatalf("%d Reports calls for an oversized body", nr)
		}
	})
	t.Run("status_keeps_64_kib", func(t *testing.T) {
		f := newAPIFixture(t)
		big := `{"storeError":"` + strings.Repeat("a", 65<<10) + `"}`
		if rec := f.do("POST", mgmtapi.StatusPath("dev"), strings.NewReader(big)); rec.Code < 400 {
			t.Fatalf("a 65 KiB status: %d", rec.Code)
		}
		ok := `{"storeError":"` + strings.Repeat("a", 63<<10) + `"}`
		if rec := f.do("POST", mgmtapi.StatusPath("dev"), strings.NewReader(ok)); rec.Code != 204 {
			t.Fatalf("a 63 KiB status: %d", rec.Code)
		}
	})
}

func TestAPIReportsStrict(t *testing.T) {
	f := newAPIFixture(t)
	good := reportBody(t, 2, 4)
	for name, body := range map[string]string{
		"unknown_field":      `{"items":[],"extra":1}`,
		"unknown_item_field": `{"items":[{"id":"a","cell":"c","kind":"status","body":{},"token":"t","x":1}]}`,
		"duplicate_key":      `{"items":[],"items":[]}`,
		"trailing":           good + `{}`,
		"not_json":           `reports`,
		"array":              `[]`,
		"empty":              ``,
		"items_not_array":    `{"items":{}}`,
	} {
		rec := f.do("POST", mgmtapi.ReportsPath("dev"), strings.NewReader(body))
		if rec.Code != 403 {
			t.Errorf("%s: status %d, want 403", name, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "extra") || strings.Contains(rec.Body.String(), "duplicate") {
			t.Errorf("%s: the body leaks the reason: %s", name, rec.Body)
		}
	}
	if nr, _ := f.fake.calls(); nr != 0 {
		t.Fatalf("%d Reports calls for bodies that are not strict JSON", nr)
	}
	f.logs.mu.Lock()
	logged := f.logs.buf.String()
	f.logs.mu.Unlock()
	if !strings.Contains(logged, "reports_denied") || strings.Contains(logged, `"t":`) {
		t.Fatalf("log %s", logged)
	}
	rec := f.do("POST", mgmtapi.ReportsPath("dev"), strings.NewReader(good))
	if rec.Code != 200 {
		t.Fatalf("a strict body: %d %s", rec.Code, rec.Body)
	}
	var sent mgmtapi.ReportBatch
	if err := json.Unmarshal([]byte(good), &sent); err != nil {
		t.Fatal(err)
	}
	if got := f.fake.batches[0]; marshal(t, got) != marshal(t, sent) {
		t.Fatalf("the plane got %s, want %s", marshal(t, got), marshal(t, sent))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", rec.Header())
	}
}

// A batch that runs past its deadline still gets an answer under the 15 s write timeout.
func TestReportsHandlerDeadline(t *testing.T) {
	old := reportsHandlerTimeout
	reportsHandlerTimeout = 200 * time.Millisecond
	t.Cleanup(func() { reportsHandlerTimeout = old })
	f := newAPIFixture(t)
	f.fake.reportFn = func(ctx context.Context, b mgmtapi.ReportBatch) mgmtapi.ReportResult {
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
		res := mgmtapi.ReportResult{Outcomes: []mgmtapi.ItemOutcome{}}
		for _, it := range b.Items {
			res.Outcomes = append(res.Outcomes, mgmtapi.ItemOutcome{ID: it.ID, Outcome: mgmtapi.OutcomeRetry, Reason: mgmtapi.ReasonIssuerUnavailable})
		}
		return res
	}
	start := time.Now()
	rec := f.do("POST", mgmtapi.ReportsPath("dev"), strings.NewReader(reportBody(t, 3, 4)))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the request ran %s", d)
	}
	var res mgmtapi.ReportResult
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &res) != nil || len(res.Outcomes) != 3 || res.Outcomes[0].Outcome != mgmtapi.OutcomeRetry {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	dl, ok := f.fake.ctxs[0].Deadline()
	if !ok || dl.Sub(start) > 2*time.Second {
		t.Fatalf("the context of Reports has deadline %v (set %v)", dl, ok)
	}
}

// The real plane, with a key source that never answers, still answers a batch at the handler
// deadline, and the other items of the batch get their outcomes.
func TestReportsHandlerAnswersSlowKeySource(t *testing.T) {
	old := reportsHandlerTimeout
	reportsHandlerTimeout = 400 * time.Millisecond
	t.Cleanup(func() { reportsHandlerTimeout = old })
	r, _ := boundRig(t)
	r.keys.mu.Lock()
	r.keys.gate, r.keys.gateCell = make(chan struct{}), cell2
	r.keys.mu.Unlock()
	t.Cleanup(func() {
		r.keys.mu.Lock()
		defer r.keys.mu.Unlock()
		if r.keys.gate != nil {
			close(r.keys.gate)
			r.keys.gate = nil
		}
	})
	n := r.nonce(cell2)
	req := mgmtapi.BindRequest{Nonce: n, Token: r.token(cell2, n, r.signers[cell2], nil)}
	slow := mgmtapi.ReportItem{ID: "slow", Cell: cell2, Kind: "bind", Body: json.RawMessage(marshal(t, req))}
	batch := mgmtapi.ReportBatch{Items: []mgmtapi.ReportItem{slow}}
	h := NewAPIHandler(r.plane, "dev", mustID(t, envdSPIFFE), jsonLog(io.Discard))
	ca := spiffetest.NewCA(t, devTD)
	start := time.Now()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, envdRequest(t, ca, envdSPIFFE, "POST", mgmtapi.ReportsPath("dev"), strings.NewReader(marshal(t, batch))))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the request ran %s", d)
	}
	var res mgmtapi.ReportResult
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &res) != nil || len(res.Outcomes) != 1 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	want(t, res.Outcomes[0], mgmtapi.OutcomeRetry, mgmtapi.ReasonIssuerUnavailable, "key_source")
}

// The API serves no bind route.
func TestAPIHasNoBindRoutes(t *testing.T) {
	f := newAPIFixture(t)
	for _, tc := range []struct{ method, path string }{
		{"POST", "/v1/cells/dev-cell-1/nonce"}, {"POST", "/v1/cells/dev-cell-1/bind"}, {"GET", "/v1/cells/dev-cell-1/bind"},
	} {
		if rec := f.do(tc.method, tc.path, strings.NewReader("{}")); rec.Code != 404 {
			t.Errorf("%s %s: status %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
}

// ---- Admin: operations

func adminDo(h http.Handler, method, target string, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	return do(h, method, target, rd)
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(rec.Body.Bytes()), &m); err != nil || bytes.Count(rec.Body.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return m
}

func TestAdminOpCommands(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	h := NewAdminHandler(r.plane, nil)
	create := `{"cell":"` + cell1 + `","kind":"demo.append","args":{"line":"hello"},"ttl":"5m"}`

	rec := adminDo(h, "POST", "/ops", create)
	if rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	m := decodeMap(t, rec)
	id, _ := m["id"].(string)
	if len(id) != 32 || m["cell"] != cell1 || m["served"] != true || m["envelope"] == nil {
		t.Fatalf("create body %v", m)
	}
	if got := r.plane.OpenOps().Ops; len(got) != 1 {
		t.Fatalf("%d served ops", len(got))
	}

	rec = adminDo(h, "POST", "/ops?serve=0", create)
	if rec.Code != 200 {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	sm := decodeMap(t, rec)
	if sm["served"] != false || sm["id"] == id {
		t.Fatalf("sign body %v", sm)
	}
	if got := r.plane.OpenOps().Ops; len(got) != 1 {
		t.Fatalf("a signed op was served: %d ops", len(got))
	}
	if env, _ := json.Marshal(sm["envelope"]); len(env) < 10 {
		t.Fatalf("sign body has no envelope: %v", sm)
	}

	rec = adminDo(h, "GET", "/ops/"+id, "")
	gm := decodeMap(t, rec)
	if rec.Code != 200 || gm["id"] != id || gm["state"] != "open" || gm["cell"] != cell1 || gm["served"] != true {
		t.Fatalf("get: %d %v", rec.Code, gm)
	}
	var envelope map[string]any
	if b, _ := json.Marshal(gm["envelope"]); json.Unmarshal(b, &envelope) != nil || envelope["payload"] == nil {
		t.Fatalf("get has no envelope: %v", gm)
	}
	if rec = adminDo(h, "GET", "/ops/"+strings.Repeat("0", 32), ""); rec.Code != 404 || !strings.Contains(rec.Body.String(), `"reason":"operation_unknown"`) {
		t.Fatalf("unknown op: %d %s", rec.Code, rec.Body)
	}

	rec = adminDo(h, "GET", "/ops?cell="+cell1, "")
	var list struct {
		Ops []map[string]any `json:"ops"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Ops) != 2 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec = adminDo(h, "GET", "/ops?cell="+cell2, ""); !strings.Contains(rec.Body.String(), `"ops":[]`) {
		t.Fatalf("list of another cell: %s", rec.Body)
	}
	if rec = adminDo(h, "GET", "/ops?cell=nope", ""); rec.Code != 404 {
		t.Fatalf("list of an unknown cell: %d", rec.Code)
	}

	for name, body := range map[string]string{
		"unknown_field": `{"cell":"` + cell1 + `","kind":"demo.append","args":{"line":"x"},"x":1}`,
		"not_json":      `nope`,
		"bad_ttl":       `{"cell":"` + cell1 + `","kind":"demo.append","args":{"line":"x"},"ttl":"soon"}`,
	} {
		if rec = adminDo(h, "POST", "/ops", body); rec.Code != 400 {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	for name, tc := range map[string]struct {
		body string
		want int
		why  string
	}{
		"unknown_cell":  {`{"cell":"dev-cell-9","kind":"demo.append","args":{"line":"x"}}`, 404, mgmtapi.ReasonCellUnknown},
		"unbound_cell":  {`{"cell":"` + cell2 + `","kind":"demo.append","args":{"line":"x"}}`, 422, mgmtapi.ReasonNotBound},
		"unknown_kind":  {`{"cell":"` + cell1 + `","kind":"x","args":{"line":"x"}}`, 422, mgmtapi.ReasonPayloadInvalid},
		"ttl_too_long":  {`{"cell":"` + cell1 + `","kind":"demo.append","args":{"line":"x"},"ttl":"2h"}`, 422, mgmtapi.ReasonPayloadInvalid},
		"args_no_line":  {`{"cell":"` + cell1 + `","kind":"demo.append","args":{}}`, 422, mgmtapi.ReasonPayloadInvalid},
		"serve_invalid": {`{"cell":"` + cell1 + `","kind":"demo.append","args":{"line":"x"}}`, 400, ""},
	} {
		target := "/ops"
		if name == "serve_invalid" {
			target = "/ops?serve=maybe"
		}
		rec = adminDo(h, "POST", target, tc.body)
		if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.why) {
			t.Errorf("%s: %d %s, want %d %q", name, rec.Code, rec.Body, tc.want, tc.why)
		}
	}
	if rec = adminDo(h, "GET", "/ops", ""); rec.Code != 200 {
		t.Fatalf("list of every op: %d", rec.Code)
	}
	if rec = adminDo(h, "DELETE", "/ops/"+id, ""); rec.Code != 405 && rec.Code != 404 {
		t.Fatalf("DELETE: %d", rec.Code)
	}
}

// Each sentinel of CloseOp has its own status and reason.
func TestAdminCloseOpStatuses(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	h := NewAdminHandler(r.plane, nil)

	t.Run("unknown", func(t *testing.T) {
		rec := adminDo(h, "POST", "/ops/"+strings.Repeat("0", 32)+"/close", "")
		if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"reason":"operation_unknown"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("not_expired", func(t *testing.T) {
		o, _ := r.newOp(cell1)
		rec := adminDo(h, "POST", "/ops/"+o.ID+"/close", "")
		if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"reason":"operation_not_expired"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		if !r.isOpen(o.ID) {
			t.Fatal("the op closed")
		}
	})
	t.Run("final", func(t *testing.T) {
		o, e := r.newOp(cell1)
		if out := r.one(r.resultItem(resultFor(o, e, op.OutcomeApplied), r.signers[cell1])); out.Outcome != mgmtapi.OutcomeAccepted {
			t.Fatalf("result %+v", out)
		}
		rec := adminDo(h, "POST", "/ops/"+o.ID+"/close", "")
		if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"reason":"operation_final"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("expired", func(t *testing.T) {
		o, _ := r.newOp(cell1)
		r.clk.Advance(op.MaxTTL + 5*time.Minute)
		rec := adminDo(h, "POST", "/ops/"+o.ID+"/close", "")
		m := decodeMap(t, rec)
		if rec.Code != 200 || m["id"] != o.ID || m["final"] != OpAbandoned {
			t.Fatalf("%d %v", rec.Code, m)
		}
		if got := r.opState(o.ID); got.Final != OpAbandoned {
			t.Fatalf("state %+v", got)
		}
		if rec = adminDo(h, "POST", "/ops/"+o.ID+"/close", ""); rec.Code != 409 {
			t.Fatalf("a second close: %d", rec.Code)
		}
	})
	if rec := adminDo(h, "GET", "/ops/"+strings.Repeat("0", 32)+"/close", ""); rec.Code != 405 && rec.Code != 404 {
		t.Fatalf("GET close: %d", rec.Code)
	}
}

// ---- Admin: rotation

func TestRotateKeyStageThenCommit(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	var mu sync.Mutex
	var published []ed25519.PublicKey
	var failWith error
	h := NewAdminHandler(r.plane, func(_ context.Context, pub ed25519.PublicKey) error {
		mu.Lock()
		defer mu.Unlock()
		published = append(published, append(ed25519.PublicKey(nil), pub...))
		return failWith
	})
	old := r.plane.PublicKey()
	o, _ := r.newOp(cell1)

	// A commit with no staged key refuses, and changes nothing.
	rec := adminDo(h, "POST", "/rotate-key?commit=1", "")
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"reason":"not_staged"`) || !r.plane.PublicKey().Equal(old) || len(published) != 0 {
		t.Fatalf("commit without stage: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"?stage=1&commit=1", "?stage=2", "?commit=yes", "?stage="} {
		if rec = adminDo(h, "POST", "/rotate-key"+bad, ""); rec.Code != 400 {
			t.Errorf("%s: status %d, want 400", bad, rec.Code)
		}
	}
	if _, ok := r.plane.StagedPublicKey(); ok || len(published) != 0 {
		t.Fatal("a refused request staged a key")
	}

	// Stage: the signing key stays, the next key exists, and the publisher is told.
	rec = adminDo(h, "POST", "/rotate-key?stage=1", "")
	if rec.Code != 200 {
		t.Fatalf("stage: %d %s", rec.Code, rec.Body)
	}
	m := decodeMap(t, rec)
	next, ok := r.plane.StagedPublicKey()
	if !ok || m["next.pub"] != base64.StdEncoding.EncodeToString(next) || m["staged"] != true || m["spec.pub"] != nil {
		t.Fatalf("stage body %v, staged %v", m, ok)
	}
	if !r.plane.PublicKey().Equal(old) || next.Equal(old) {
		t.Fatal("staging changed the signing key")
	}
	if r.status().StagedKey == "" || len(published) != 1 {
		t.Fatalf("stagedKey %q, %d publishes", r.status().StagedKey, len(published))
	}
	// A second stage returns the same key.
	rec = adminDo(h, "POST", "/rotate-key?stage=1", "")
	if m2 := decodeMap(t, rec); m2["next.pub"] != m["next.pub"] {
		t.Fatalf("a second stage gave %v", m2)
	}
	// A failed publish of the staged key says so.
	mu.Lock()
	failWith = errors.New("api server down")
	mu.Unlock()
	rec = adminDo(h, "POST", "/rotate-key?stage=1", "")
	fm := decodeMap(t, rec)
	if rec.Code != 500 || fm["staged"] != true || fm["rotated"] != nil || fm["error"] == nil {
		t.Fatalf("failed publish: %d %v", rec.Code, fm)
	}
	mu.Lock()
	failWith = nil
	mu.Unlock()

	// Commit: the staged key signs, the stage is gone, and the open op is signed again.
	rec = adminDo(h, "POST", "/rotate-key?commit=1", "")
	if rec.Code != 200 {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	cm := decodeMap(t, rec)
	if !r.plane.PublicKey().Equal(next) || cm["spec.pub"] != base64.StdEncoding.EncodeToString(next) {
		t.Fatalf("commit body %v", cm)
	}
	if _, ok := r.plane.StagedPublicKey(); ok || r.status().StagedKey != "" {
		t.Fatal("the stage remained after the commit")
	}
	if _, err := os.Stat(filepath.Join(r.dir, nextKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the staged key file remained: %v", err)
	}
	mu.Lock()
	last := published[len(published)-1]
	mu.Unlock()
	if !last.Equal(next) {
		t.Fatal("the commit did not publish the new key")
	}
	if got := r.opState(o.ID); got.KeyEpoch != r.status().Signed.Epoch {
		t.Fatalf("the open op has epoch %d, signed epoch %d", got.KeyEpoch, r.status().Signed.Epoch)
	}
	// A second commit has nothing to commit.
	if rec = adminDo(h, "POST", "/rotate-key?commit=1", ""); rec.Code != 409 {
		t.Fatalf("a second commit: %d", rec.Code)
	}
}

// A plain POST /rotate-key is the emergency rotation: it needs no stage.
func TestRotateKeyEmergencyNeedsNoStage(t *testing.T) {
	r := newRig(t)
	h := NewAdminHandler(r.plane, func(context.Context, ed25519.PublicKey) error { return nil })
	old := r.plane.PublicKey()
	if rec := adminDo(h, "POST", "/rotate-key", ""); rec.Code != 200 || r.plane.PublicKey().Equal(old) {
		t.Fatalf("emergency rotate: %d %s", rec.Code, rec.Body)
	}
}

// With a stale expect-seq, neither stage nor commit changes anything.
func TestRotateKeyStageCommitExpectSeq(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	h := NewAdminHandler(r.plane, func(context.Context, ed25519.PublicKey) error { return nil })
	seq := r.status().Seq
	if rec := adminDo(h, "POST", "/rotate-key?stage=1&expect-seq="+itoa(seq-1), ""); rec.Code != 409 {
		t.Fatalf("stale stage: %d %s", rec.Code, rec.Body)
	}
	if _, ok := r.plane.StagedPublicKey(); ok {
		t.Fatal("a stale stage staged a key")
	}
	if rec := adminDo(h, "POST", "/rotate-key?stage=1&expect-seq="+itoa(seq), ""); rec.Code != 200 {
		t.Fatalf("stage at the current seq: %d %s", rec.Code, rec.Body)
	}
	old := r.plane.PublicKey()
	if rec := adminDo(h, "POST", "/rotate-key?commit=1&expect-seq="+itoa(seq), ""); rec.Code != 409 || !r.plane.PublicKey().Equal(old) {
		t.Fatalf("stale commit: %d %s", rec.Code, rec.Body)
	}
	if rec := adminDo(h, "POST", "/rotate-key?commit=1&expect-seq="+itoa(r.status().Seq), ""); rec.Code != 200 {
		t.Fatalf("commit at the current seq: %d %s", rec.Code, rec.Body)
	}
}

// POST /keycheck/{cell} is a manual check, so it bypasses the key cache, also under expect-seq.
func TestManualKeycheckVia(t *testing.T) {
	r := newRig(t)
	r.mustBind(cell1, r.signers[cell1], mgmtapi.StatusBound)
	h := NewAdminHandler(r.plane, nil)
	for _, guarded := range []bool{false, true} {
		r.clk.Advance(2 * time.Second)
		q := ""
		if guarded {
			q = "?expect-seq=" + itoa(r.status().Seq)
		}
		calls := r.keys.count(cell1)
		rec := adminDo(h, "POST", "/keycheck/"+cell1+q, "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), string(CheckUnchanged)) {
			t.Fatalf("keycheck%s: %d %s", q, rec.Code, rec.Body)
		}
		if got := r.keys.count(cell1) - calls; got != 1 {
			t.Fatalf("keycheck%s made %d fetches, want 1", q, got)
		}
		// The next manual check, a moment later, fetches again.
		if q == "" {
			rec = adminDo(h, "POST", "/keycheck/"+cell1, "")
			if got := r.keys.count(cell1) - calls; got != 2 || rec.Code != 200 {
				t.Fatalf("a second manual check: %d fetches, status %d", got, rec.Code)
			}
		}
	}
}

func TestStagedPublicKeyAccessor(t *testing.T) {
	r := newRig(t)
	if _, ok := r.plane.StagedPublicKey(); ok {
		t.Fatal("a fresh plane has a staged key")
	}
	pub, err := r.plane.StageKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := r.plane.StagedPublicKey(); !ok || !got.Equal(pub) {
		t.Fatalf("staged key %x, %v; want %x", got, ok, pub)
	}
	r.restart(nil)
	if _, ok := r.plane.StagedPublicKey(); !ok {
		t.Fatal("the stage was lost over a restart")
	}
}

// The emergency rotation needs no stage, and it discards a staged key: that key sits on the same
// volume as the signing key, so a reason to rotate at once covers it.
func TestRotateKeyEmergencyDiscardsTheStage(t *testing.T) {
	r := newRig(t)
	var published []ed25519.PublicKey
	h := NewAdminHandler(r.plane, func(_ context.Context, pub ed25519.PublicKey) error {
		published = append(published, pub)
		return nil
	})
	old := r.plane.PublicKey()
	if rec := adminDo(h, "POST", "/rotate-key", ""); rec.Code != 200 || r.plane.PublicKey().Equal(old) {
		t.Fatalf("emergency rotate with no stage: %d %s", rec.Code, rec.Body)
	}
	if rec := adminDo(h, "POST", "/rotate-key?stage=1", ""); rec.Code != 200 {
		t.Fatalf("stage: %d %s", rec.Code, rec.Body)
	}
	staged, ok := r.plane.StagedPublicKey()
	if !ok {
		t.Fatal("no staged key")
	}
	staged1, _ := os.ReadFile(filepath.Join(r.dir, nextKeyFile))
	before := r.plane.PublicKey()
	if rec := adminDo(h, "POST", "/rotate-key", ""); rec.Code != 200 {
		t.Fatalf("emergency rotate: %d %s", rec.Code, rec.Body)
	}
	got := r.plane.PublicKey()
	if got.Equal(before) || got.Equal(staged) {
		t.Fatal("the emergency rotation used the old key or the staged key")
	}
	if _, ok := r.plane.StagedPublicKey(); ok || r.status().StagedKey != "" {
		t.Fatal("the stage remained")
	}
	if _, err := os.Stat(filepath.Join(r.dir, nextKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the staged key file remained in place: %v", err)
	}
	asides, _ := filepath.Glob(filepath.Join(r.dir, nextKeyFile+".stale-*"))
	if len(asides) != 1 {
		t.Fatalf("%d moved staged key files", len(asides))
	}
	if b, err := os.ReadFile(asides[0]); err != nil || !bytes.Equal(b, staged1) {
		t.Fatalf("moved staged key differs: %v", err)
	}
	if !published[len(published)-1].Equal(got) {
		t.Fatal("the emergency rotation did not publish the new key")
	}
	// A guarded emergency rotation behaves the same, and a stale one changes nothing.
	if rec := adminDo(h, "POST", "/rotate-key?expect-seq="+itoa(r.status().Seq-1), ""); rec.Code != 409 || !r.plane.PublicKey().Equal(got) {
		t.Fatalf("stale emergency rotate: %d", rec.Code)
	}
}

// Two commits that race: one rotates to the staged key, the other finds no stage and changes nothing.
func TestRotateKeyRacingCommits(t *testing.T) {
	r := newRig(t)
	var mu sync.Mutex
	var published []ed25519.PublicKey
	h := NewAdminHandler(r.plane, func(_ context.Context, pub ed25519.PublicKey) error {
		mu.Lock()
		defer mu.Unlock()
		published = append(published, pub)
		return nil
	})
	if rec := adminDo(h, "POST", "/rotate-key?stage=1", ""); rec.Code != 200 {
		t.Fatalf("stage: %d", rec.Code)
	}
	staged, _ := r.plane.StagedPublicKey()
	mu.Lock()
	published = nil
	mu.Unlock()
	codes := make(chan int, 2)
	reasons := make(chan string, 2)
	for i := 0; i < 2; i++ {
		go func() {
			rec := adminDo(h, "POST", "/rotate-key?commit=1", "")
			codes <- rec.Code
			var m map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &m)
			r, _ := m["reason"].(string)
			reasons <- r
		}()
	}
	c1, c2 := <-codes, <-codes
	if !((c1 == 200 && c2 == 409) || (c1 == 409 && c2 == 200)) {
		t.Fatalf("status codes %d and %d, want one 200 and one 409", c1, c2)
	}
	if a, b := <-reasons, <-reasons; a != ReasonNotStaged && b != ReasonNotStaged {
		t.Fatalf("reasons %q %q", a, b)
	}
	mu.Lock()
	defer mu.Unlock()
	if !r.plane.PublicKey().Equal(staged) || len(published) != 1 || !published[0].Equal(r.plane.PublicKey()) {
		t.Fatalf("signing key is the staged key: %v; %d publishes", r.plane.PublicKey().Equal(staged), len(published))
	}
}

func TestPlaneGuardedStageKey(t *testing.T) {
	r := newRig(t)
	seq := r.status().Seq
	if _, err := r.plane.IfSeq(seq - 1).StageKey(t.Context()); ReasonOf(err) != mgmtapi.ReasonConflict {
		t.Fatalf("stale guarded stage: %v", err)
	}
	if _, ok := r.plane.StagedPublicKey(); ok {
		t.Fatal("a stale guarded stage staged a key")
	}
	if _, err := r.plane.IfSeq(seq).StageKey(t.Context()); err != nil {
		t.Fatalf("guarded stage at the current seq: %v", err)
	}
	if _, err := r.plane.CommitStagedKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.plane.CommitStagedKey(t.Context()); !errors.Is(err, ErrNotStaged) {
		t.Fatalf("a commit with no stage: %v", err)
	}
}

// failAfterStore passes the first n saves and fails every later one.
type failAfterStore struct {
	Store
	left atomic.Int64
}

func (f *failAfterStore) Save(st *State) error {
	if f.left.Add(-1) < 0 {
		return fmt.Errorf("disk full")
	}
	return f.Store.Save(st)
}

// An emergency rotation clears the stage in a save of its own before it writes the new key. When the
// save of the rotation itself fails, the stage is gone and the old key stays.
func TestRotateKeyEmergencyClearsTheStageBeforeTheKeyWrite(t *testing.T) {
	r := newRig(t)
	fs := &failAfterStore{Store: r.store}
	fs.left.Store(1 << 30)
	r.store = fs
	r.restart(nil)
	if _, err := r.plane.StageKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	staged1, _ := os.ReadFile(filepath.Join(r.dir, nextKeyFile))
	before := r.plane.PublicKey()
	fs.left.Store(1) // the save that clears the stage passes, the save of the rotation fails
	if _, err := r.plane.RotateKeyEmergency(t.Context()); err == nil {
		t.Fatal("the rotation did not fail with a failing save")
	}
	if !r.plane.PublicKey().Equal(before) {
		t.Fatal("a failed rotation changed the signing key")
	}
	if _, ok := r.plane.StagedPublicKey(); ok || r.status().StagedKey != "" {
		t.Fatal("the staged key survived a failed emergency rotation")
	}
	asides, _ := filepath.Glob(filepath.Join(r.dir, nextKeyFile+".stale-*"))
	if len(asides) != 1 {
		t.Fatalf("%d moved staged key files", len(asides))
	}
	if b, err := os.ReadFile(asides[0]); err != nil || !bytes.Equal(b, staged1) {
		t.Fatalf("moved staged key differs: %v", err)
	}
	// A restart finds no stage to promote.
	r.store = fs.Store
	r.restart(nil)
	if _, ok := r.plane.StagedPublicKey(); ok {
		t.Fatal("the stage returned after a restart")
	}
	if _, err := r.plane.CommitStagedKey(t.Context()); !errors.Is(err, ErrNotStaged) {
		t.Fatalf("commit after the failed emergency: %v", err)
	}
}
