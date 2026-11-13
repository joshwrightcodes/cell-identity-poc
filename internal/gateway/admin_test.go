package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/gwapi"
)

func adminDo(t *testing.T, h http.Handler, method, path string, body []byte) (int, []byte) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestAdminQueueShowsState(t *testing.T) {
	e := newGwEnv(t)
	h := NewAdminHandler(e.st, nil)
	ctx := context.Background()
	e.enqueue(1, cell1)
	e.enqueue(2, cell1)
	e.enqueue(3, cell1)
	l, err := e.st.Claim(ctx, cell1, "uid-a")
	if err != nil || l == nil {
		t.Fatal(l, err)
	}
	l2, _ := e.st.Claim(ctx, cell1, "uid-b")
	if _, err := e.st.CompleteWithItem(ctx, cell1, l2.ID, resultItem(cell1, l2.OpID), l2.Fence); err != nil {
		t.Fatal(err)
	}
	code, body := adminDo(t, h, http.MethodGet, "/queue?cell="+cell1, nil)
	var out struct {
		Cell  string       `json:"cell"`
		Items []QueueEntry `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &out) != nil || len(out.Items) != 3 {
		t.Fatalf("queue %d %s", code, body)
	}
	a, b, c := out.Items[0], out.Items[1], out.Items[2]
	if a.State != StateLeased || a.Holder != "uid-a" || a.Claims != 1 || a.Fence != l.Fence || a.LeaseUntil.IsZero() {
		t.Fatalf("leased row %+v", a)
	}
	if b.State != StateDone || b.Holder != "uid-b" || b.Fence != l2.Fence {
		t.Fatalf("done row %+v", b)
	}
	if c.State != StateQueued || c.Claims != 0 || c.Holder != "" || c.OpID != opID(3) || !c.LeaseUntil.IsZero() {
		t.Fatalf("queued row %+v", c)
	}
	if strings.Contains(string(body), "envelope") {
		t.Fatal("the listing carries an envelope")
	}
	for _, q := range []string{"/queue", "/queue?cell=", "/queue?cell=a&cell=b", "/queue?cell=Bad_Name"} {
		if code, _ := adminDo(t, h, http.MethodGet, q, nil); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, code)
		}
	}
}

func TestAdminEnqueueReplay(t *testing.T) {
	e := newGwEnv(t)
	h := NewAdminHandler(e.st, nil)
	ctx := context.Background()
	env := e.opEnvelope(1, cell1)
	code, body := adminDo(t, h, http.MethodPost, "/enqueue?cell="+cell1, env)
	var out struct {
		OpID  string `json:"opId"`
		Added bool   `json:"added"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &out) != nil || out.OpID != opID(1) || !out.Added {
		t.Fatalf("enqueue %d %s", code, body)
	}
	// The same envelope adds nothing.
	if code, body = adminDo(t, h, http.MethodPost, "/enqueue?cell="+cell1, env); code != http.StatusOK || strings.Contains(string(body), `"added":true`) {
		t.Fatalf("second enqueue %d %s", code, body)
	}
	// Finish the operation, then enqueue without and with replay.
	l, _ := e.st.Claim(ctx, cell1, "uid-a")
	if _, err := e.st.CompleteWithItem(ctx, cell1, l.ID, resultItem(cell1, l.OpID), l.Fence); err != nil {
		t.Fatal(err)
	}
	state := func() string {
		rows, err := e.st.QueueEntries(ctx, cell1)
		if err != nil || len(rows) != 1 {
			t.Fatalf("rows %+v, %v", rows, err)
		}
		return rows[0].State
	}
	adminDo(t, h, http.MethodPost, "/enqueue?cell="+cell1, env)
	if s := state(); s != StateDone {
		t.Fatalf("a plain enqueue of a done operation gave state %s", s)
	}
	if code, body = adminDo(t, h, http.MethodPost, "/enqueue?cell="+cell1+"&replay=1", env); code != http.StatusOK || !strings.Contains(string(body), `"replay":true`) {
		t.Fatalf("replay %d %s", code, body)
	}
	if s := state(); s != StateQueued {
		t.Fatalf("a replay gave state %s, want queued", s)
	}
	// A claim finds it again.
	if l, _ = e.st.Claim(ctx, cell1, "uid-a"); l == nil || l.OpID != opID(1) {
		t.Fatalf("claim after replay: %+v", l)
	}
	// Errors: an envelope for another cell, garbage, a bad flag, an unknown replay value.
	if code, _ = adminDo(t, h, http.MethodPost, "/enqueue?cell="+cell2, env); code != http.StatusBadRequest {
		t.Fatalf("envelope for another cell: %d", code)
	}
	if code, _ = adminDo(t, h, http.MethodPost, "/enqueue?cell="+cell1, []byte("garbage")); code != http.StatusBadRequest {
		t.Fatalf("garbage: %d", code)
	}
	if code, _ = adminDo(t, h, http.MethodPost, "/enqueue?cell="+cell1+"&replay=yes", env); code != http.StatusBadRequest {
		t.Fatalf("replay=yes: %d", code)
	}
	if code, _ = adminDo(t, h, http.MethodPost, "/enqueue", env); code != http.StatusBadRequest {
		t.Fatalf("no cell: %d", code)
	}
	if code, _ = adminDo(t, h, http.MethodPost, "/enqueue?cell="+cell1, bytes.Repeat([]byte("a"), maxAdminBody+1)); code != http.StatusBadRequest {
		t.Fatalf("a body above 1 MiB: %d", code)
	}
}

func jwtWith(kid, aud string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]string{"alg": "ES256", "kid": kid}) + "." + enc(map[string]any{"aud": []string{aud}, "sub": "secret-subject"}) + ".c2VjcmV0LXNpZw"
}

func TestOutboxRedactsTokens(t *testing.T) {
	e := newGwEnv(t)
	h := NewAdminHandler(e.st, nil)
	token := jwtWith("kid-7", "mgmt-report/dev-cell-1/result/abc")
	it := gwapi.Item{Kind: gwapi.KindResult, Cell: cell1, OpID: opID(1), Body: json.RawMessage(`{"secret":"BODY-SECRET"}`), Token: token}
	if _, err := e.st.Append(context.Background(), it); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Append(context.Background(), gwapi.Item{Kind: gwapi.KindStatus, Cell: cell1, Body: json.RawMessage(`{}`), Token: "not-a-token"}); err != nil {
		t.Fatal(err)
	}
	code, body := adminDo(t, h, http.MethodGet, "/outbox", nil)
	if code != http.StatusOK {
		t.Fatalf("outbox %d %s", code, body)
	}
	for _, leak := range []string{token, strings.Split(token, ".")[0], strings.Split(token, ".")[1], strings.Split(token, ".")[2], "BODY-SECRET", "secret-subject"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("the outbox listing leaks %q: %s", leak, body)
		}
	}
	var out struct{ Items []OutboxEntry }
	if err := json.Unmarshal(body, &out); err != nil || len(out.Items) != 2 {
		t.Fatalf("items %s, %v", body, err)
	}
	if g := out.Items[0]; g.KID != "kid-7" || g.Audience != "mgmt-report/dev-cell-1/result/abc" || g.Cell != cell1 || g.Kind != gwapi.KindResult || g.OpID != opID(1) || g.ID == "" {
		t.Fatalf("entry %+v", g)
	}
	if g := out.Items[1]; g.KID != "" || g.Audience != "" {
		t.Fatalf("an unparsable token shows %+v", g)
	}
}

func TestAdminInject(t *testing.T) {
	e := newGwEnv(t)
	h := NewAdminHandler(e.st, func() any { return map[string]string{"custom": "status"} })
	if code, body := adminDo(t, h, http.MethodGet, "/status", nil); code != http.StatusOK || !strings.Contains(string(body), `"custom":"status"`) {
		t.Fatalf("status %d %s", code, body)
	}
	item := `{"kind":"result","cell":"dev-cell-1","opId":"` + opID(1) + `","body":{"x":1},"token":"t"}`
	code, body := adminDo(t, h, http.MethodPost, "/inject", []byte(item))
	if code != http.StatusOK || !strings.Contains(string(body), `"id":"`) {
		t.Fatalf("inject %d %s", code, body)
	}
	items, _ := e.st.Peek(context.Background(), 10, 1<<20)
	if len(items) != 1 || items[0].OpID != opID(1) {
		t.Fatalf("outbox %+v", items)
	}
	for name, bad := range map[string]string{
		"unknown_kind":   `{"kind":"x","cell":"dev-cell-1","body":{},"token":"t"}`,
		"no_cell":        `{"kind":"result","body":{},"token":"t"}`,
		"unknown_member": `{"kind":"result","cell":"dev-cell-1","body":{},"token":"t","x":1}`,
		"not_json":       `nope`,
	} {
		if code, _ := adminDo(t, h, http.MethodPost, "/inject", []byte(bad)); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, code)
		}
	}
	// The default status is the store status.
	h = NewAdminHandler(e.st, nil)
	code, body = adminDo(t, h, http.MethodGet, "/status", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"outboxItems":1`) {
		t.Fatalf("store status %d %s", code, body)
	}
}
