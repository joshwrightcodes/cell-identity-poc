package cellproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore"
	"github.com/joshwrightcodes/cell-identity-poc/internal/ocistore/ocitest"
)

const (
	subReader  = "system:serviceaccount:argocd:argocd-repo-server"
	subWriter  = "system:serviceaccount:cell-identity-system:celld"
	subOther   = "system:serviceaccount:envd-system:envd"
	subDefault = "system:serviceaccount:apps-demo:default"

	tokReader   = "reader-secret-token"
	tokWriter   = "writer-secret-token"
	tokOther    = "other-secret-token"
	tokDefault  = "default-secret-token"
	tokAudience = "audience-secret-token"
	tokBad      = "unauthenticated-secret-token"

	storeAudience = "bundle-store"
	digestA       = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// fakeReviewer answers TokenReview from a table and counts the calls.
type fakeReviewer struct {
	mu      sync.Mutex
	reviews map[string]TokenReview
	err     error
	calls   int
}

func (f *fakeReviewer) Review(_ context.Context, token, audience string) (TokenReview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return TokenReview{}, f.err
	}
	if r, ok := f.reviews[token]; ok {
		return r, nil
	}
	return TokenReview{Error: "invalid bearer token"}, nil
}

func (f *fakeReviewer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newFakeReviewer() *fakeReviewer {
	ok := func(user string) TokenReview {
		return TokenReview{Authenticated: true, Username: user, Audiences: []string{storeAudience}}
	}
	return &fakeReviewer{reviews: map[string]TokenReview{
		tokReader:   ok(subReader),
		tokWriter:   ok(subWriter),
		tokOther:    ok(subOther),
		tokDefault:  ok(subDefault),
		tokAudience: {Authenticated: true, Username: subReader, Audiences: []string{"other"}},
	}}
}

type upstreamHit struct {
	Method, URI, Authorization string
}

// recordingUpstream answers 200 to every request and records what it got.
type recordingUpstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []upstreamHit
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits = append(u.hits, upstreamHit{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization")})
		u.mu.Unlock()
		_, _ = io.WriteString(w, "upstream")
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *recordingUpstream) hostPort() string { return strings.TrimPrefix(u.srv.URL, "http://") }

func (u *recordingUpstream) got() []upstreamHit {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamHit(nil), u.hits...)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type tokenFixture struct {
	srv      *httptest.Server
	upstream *recordingUpstream
	reviewer *fakeReviewer
	logs     *syncBuf
	reader   *sdkmetric.ManualReader
}

func newTokenFixture(t *testing.T, mut ...func(*TokenConfig)) *tokenFixture {
	t.Helper()
	f := &tokenFixture{upstream: newRecordingUpstream(t), reviewer: newFakeReviewer(), logs: &syncBuf{}, reader: sdkmetric.NewManualReader()}
	cfg := TokenConfig{
		Upstream: f.upstream.hostPort(),
		Audience: storeAudience,
		Readers:  []string{subReader},
		Writers:  []string{subWriter},
		Reviewer: f.reviewer,
		Log:      slog.New(slog.NewJSONHandler(f.logs, nil)),
		Meter:    sdkmetric.NewMeterProvider(sdkmetric.WithReader(f.reader)).Meter("test"),
	}
	for _, m := range mut {
		m(&cfg)
	}
	h, err := NewTokenHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(h)
	t.Cleanup(f.srv.Close)
	return f
}

type tokenResp struct {
	Status int
	Body   string
	Header http.Header
}

func (f *tokenFixture) do(t *testing.T, method, path, token string, mut ...func(*http.Request)) tokenResp {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range mut {
		m(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return tokenResp{resp.StatusCode, string(b), resp.Header}
}

// deniedBody checks a 403 with the neutral body, and returns the request ID.
func deniedBody(t *testing.T, r tokenResp) string {
	t.Helper()
	if r.Status != http.StatusForbidden {
		t.Fatalf("status %d (%s), want 403", r.Status, r.Body)
	}
	var body struct {
		Error     string `json:"error"`
		RequestID string `json:"requestId"`
	}
	if r.Body == "" {
		// A HEAD answer has no body, so the header carries the request ID.
		id := r.Header.Get("X-Request-Id")
		if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(id) {
			t.Fatalf("X-Request-Id %q, want 16 hex", id)
		}
		return id
	}
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	if body.Error != "denied" || !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(body.RequestID) {
		t.Fatalf("body %q, want error denied and a 16 hex requestId", r.Body)
	}
	return body.RequestID
}

func (f *tokenFixture) denialLine(t *testing.T, id string) map[string]any {
	t.Helper()
	for _, l := range strings.Split(strings.TrimSpace(f.logs.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "request denied" && m["request_id"] == id {
			return m
		}
	}
	t.Fatalf("no request denied line for %s in:\n%s", id, f.logs.String())
	return nil
}

// wantDenied checks the 403, the reason and detail in the log line, and that upstream saw nothing.
func (f *tokenFixture) wantDenied(t *testing.T, r tokenResp, reason Reason, detail string) {
	t.Helper()
	id := deniedBody(t, r)
	l := f.denialLine(t, id)
	if l["reason"] != string(reason) || l["detail"] != detail {
		t.Fatalf("log line %v, want reason %s detail %s", l, reason, detail)
	}
	if n := len(f.upstream.got()); n != 0 {
		t.Fatalf("upstream got %d requests, want 0: %v", n, f.upstream.got())
	}
	if v, ok := metricValue(t, f.reader, "store_proxy.denials", map[string]string{"reason": string(reason), "detail": detail}); !ok || v != 1 {
		t.Fatalf("store_proxy.denials{%s,%s} = %d, %v, want 1", reason, detail, v, ok)
	}
}

const (
	pathManifest = "/v2/bundles/root/manifests/current"
	pathBlob     = "/v2/bundles/argocd/blobs/" + digestA
	pathUploads  = "/v2/bundles/argocd/blobs/uploads/"
)

func TestTokenRepoServerRead(t *testing.T) {
	f := newTokenFixture(t)
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		r := f.do(t, m, pathManifest, tokReader, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tokReader) })
		if r.Status != http.StatusOK {
			t.Fatalf("%s status %d (%s), want 200", m, r.Status, r.Body)
		}
	}
	for _, h := range f.upstream.got() {
		if h.Authorization != "" {
			t.Fatalf("upstream got Authorization %q, want none", h.Authorization)
		}
	}
	if n := len(f.upstream.got()); n != 2 {
		t.Fatalf("upstream got %d requests, want 2", n)
	}
}

func TestTokenRepoServerWriteDenied(t *testing.T) {
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		t.Run(m, func(t *testing.T) {
			f := newTokenFixture(t)
			f.wantDenied(t, f.do(t, m, pathUploads, tokReader), PeerNotAllowed, "subject")
		})
	}
}

func TestTokenWriterReadDenied(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		t.Run(m, func(t *testing.T) {
			f := newTokenFixture(t)
			f.wantDenied(t, f.do(t, m, pathManifest, tokWriter), PeerNotAllowed, "subject")
		})
	}
}

func TestTokenWriterWrite(t *testing.T) {
	f := newTokenFixture(t)
	for _, m := range []string{http.MethodPost, http.MethodPatch, http.MethodPut} {
		if r := f.do(t, m, pathUploads, tokWriter); r.Status != http.StatusOK {
			t.Fatalf("%s status %d (%s), want 200", m, r.Status, r.Body)
		}
	}
	if r := f.do(t, http.MethodPut, "/v2/bundles/root/manifests/current", tokWriter); r.Status != http.StatusOK {
		t.Fatalf("manifest PUT status %d", r.Status)
	}
	for _, h := range f.upstream.got() {
		if h.Authorization != "" {
			t.Fatalf("upstream got Authorization %q, want none", h.Authorization)
		}
	}
}

func TestTokenNoWriter(t *testing.T) {
	f := newTokenFixture(t, func(c *TokenConfig) { c.Writers = nil })
	f.wantDenied(t, f.do(t, http.MethodPost, pathUploads, tokWriter), PeerNotAllowed, "subject")
}

func TestTokenNoToken(t *testing.T) {
	f := newTokenFixture(t)
	f.wantDenied(t, f.do(t, http.MethodGet, pathManifest, ""), PeerNotAllowed, "no_token")
	if n := f.reviewer.count(); n != 0 {
		t.Fatalf("reviewer called %d times for a request with no token", n)
	}
	// A scheme other than Bearer carries no token.
	f2 := newTokenFixture(t)
	f2.wantDenied(t, f2.do(t, http.MethodPost, pathUploads, "", func(r *http.Request) { r.Header.Set("Authorization", "Basic dXNlcjpwdw==") }), PeerNotAllowed, "no_token")
}

func TestTokenWrongAudience(t *testing.T) {
	f := newTokenFixture(t)
	f.wantDenied(t, f.do(t, http.MethodGet, pathManifest, tokAudience), PeerNotAllowed, "audience")
	// The reviewer is asked for the audience of the store, and nothing else.
	f.reviewer.mu.Lock()
	defer f.reviewer.mu.Unlock()
	if f.reviewer.calls != 1 {
		t.Fatalf("reviewer calls %d, want 1", f.reviewer.calls)
	}
}

func TestTokenNotAuthenticated(t *testing.T) {
	f := newTokenFixture(t)
	f.wantDenied(t, f.do(t, http.MethodGet, pathManifest, tokBad), PeerNotAllowed, "token_invalid")
}

func TestTokenOtherSubject(t *testing.T) {
	for name, tok := range map[string]string{"other applier": tokOther, "default account": tokDefault} {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			t.Run(name+" "+m, func(t *testing.T) {
				f := newTokenFixture(t)
				path := pathManifest
				if m == http.MethodPost {
					path = pathUploads
				}
				f.wantDenied(t, f.do(t, m, path, tok), PeerNotAllowed, "subject")
			})
		}
	}
}

func TestTokenDeleteRefused(t *testing.T) {
	for _, m := range []string{http.MethodDelete, http.MethodOptions, http.MethodTrace} {
		t.Run(m, func(t *testing.T) {
			f := newTokenFixture(t)
			f.wantDenied(t, f.do(t, m, pathManifest, tokWriter), RequestNotAllowed, "method")
		})
	}
}

func TestTokenPathOutsidePrefix(t *testing.T) {
	paths := []string{
		"/", "/v2", "/v2/bundles", "/v2/bundles/", "/v2/other/root/manifests/current",
		"/v2/bundles/root/manifests/", "/v2/bundles/Root/manifests/current",
		"/v2/bundles/root/blobs/sha256:abc", "/v2/bundles/root/blobs/" + digestA + "/x",
		"/v2/bundles/root/manifests/a/b", "/v2/bundles/root/tags/list", "/v2/_catalog",
		"/v2/bundles/../other/manifests/x", "/v2/bundles/root/manifests/%2e%2e", "/v2//bundles/root/manifests/x",
		"/v2/bundles/root/blobs/uploads/a/b",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			f := newTokenFixture(t)
			f.wantDenied(t, f.do(t, http.MethodGet, p, tokReader), RequestNotAllowed, "path")
		})
	}
}

func TestTokenTagsListRefused(t *testing.T) {
	f := newTokenFixture(t)
	f.wantDenied(t, f.do(t, http.MethodGet, "/v2/bundles/root/tags/list", tokReader), RequestNotAllowed, "path")
}

func TestTokenPing(t *testing.T) {
	f := newTokenFixture(t)
	for _, tok := range []string{tokReader, tokWriter} {
		if r := f.do(t, http.MethodGet, "/v2/", tok); r.Status != http.StatusOK {
			t.Fatalf("GET /v2/ status %d, want 200", r.Status)
		}
	}
	f.wantDeniedNoUpstreamCheck(t, f.do(t, http.MethodGet, "/v2/", tokOther), PeerNotAllowed, "subject")
	f.wantDeniedNoUpstreamCheck(t, f.do(t, http.MethodGet, "/v2/", ""), PeerNotAllowed, "no_token")
	f.wantDeniedNoUpstreamCheck(t, f.do(t, http.MethodPost, "/v2/", tokWriter), RequestNotAllowed, "method")
	f.wantDeniedNoUpstreamCheck(t, f.do(t, http.MethodHead, "/v2/", tokReader), RequestNotAllowed, "method")
	if n := len(f.upstream.got()); n != 2 {
		t.Fatalf("upstream got %d requests, want 2", n)
	}
}

// wantDeniedNoUpstreamCheck is wantDenied without the check of the upstream request count and counter value.
func (f *tokenFixture) wantDeniedNoUpstreamCheck(t *testing.T, r tokenResp, reason Reason, detail string) {
	t.Helper()
	id := deniedBody(t, r)
	if l := f.denialLine(t, id); l["reason"] != string(reason) || l["detail"] != detail {
		t.Fatalf("log line %v, want reason %s detail %s", l, reason, detail)
	}
}

func TestTokenCache(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	f := newTokenFixture(t, func(c *TokenConfig) {
		c.CacheTTL = 30 * time.Second
		c.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	for i := 0; i < 3; i++ {
		if r := f.do(t, http.MethodGet, pathManifest, tokReader); r.Status != http.StatusOK {
			t.Fatalf("status %d", r.Status)
		}
	}
	if n := f.reviewer.count(); n != 1 {
		t.Fatalf("reviewer calls %d after 3 requests, want 1", n)
	}
	mu.Lock()
	now = now.Add(31 * time.Second)
	mu.Unlock()
	f.do(t, http.MethodGet, pathManifest, tokReader)
	if n := f.reviewer.count(); n != 2 {
		t.Fatalf("reviewer calls %d after the TTL, want 2", n)
	}
	// A refused token is never cached.
	f.do(t, http.MethodGet, pathManifest, tokBad)
	f.do(t, http.MethodGet, pathManifest, tokBad)
	if n := f.reviewer.count(); n != 4 {
		t.Fatalf("reviewer calls %d after two bad tokens, want 4", n)
	}
}

func TestTokenReviewerErrorFailsClosed(t *testing.T) {
	f := newTokenFixture(t)
	f.reviewer.err = io.ErrUnexpectedEOF
	r := f.do(t, http.MethodGet, pathManifest, tokReader)
	if r.Status != http.StatusServiceUnavailable || len(f.upstream.got()) != 0 {
		t.Fatalf("status %d, upstream hits %d, want 503 and none", r.Status, len(f.upstream.got()))
	}
}

func TestTokenLocationRewritten(t *testing.T) {
	reg := ocitest.NewRegistry(t)
	reg.UploadLocation(reg.URL())
	f := newTokenFixture(t, func(c *TokenConfig) { c.Upstream = reg.URL() })
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/v2/bundles/argocd/blobs/uploads/", nil)
	req.Header.Set("Authorization", "Bearer "+tokWriter)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusAccepted || !strings.HasPrefix(loc, "/v2/bundles/argocd/blobs/uploads/") {
		t.Fatalf("status %d, Location %q, want 202 and a path with no host", resp.StatusCode, loc)
	}
}

func TestTokenRequestIDMatchesLog(t *testing.T) {
	f := newTokenFixture(t)
	r := f.do(t, http.MethodGet, pathManifest, tokOther)
	id := deniedBody(t, r)
	if r.Header.Get("X-Request-Id") != id {
		t.Fatalf("X-Request-Id %q, body %q", r.Header.Get("X-Request-Id"), id)
	}
	l := f.denialLine(t, id)
	if l["reason"] != "peer_not_allowed" || l["detail"] != "subject" || l["method"] != "GET" || l["subject"] != subOther {
		t.Fatalf("log line %v", l)
	}
	// Two denials carry two IDs.
	if id2 := deniedBody(t, f.do(t, http.MethodGet, pathManifest, tokOther)); id2 == id {
		t.Fatal("two denials share a request ID")
	}
}

func TestTokenLogsHoldNoToken(t *testing.T) {
	f := newTokenFixture(t)
	for _, tok := range []string{tokReader, tokWriter, tokOther, tokBad, tokAudience} {
		f.do(t, http.MethodGet, pathManifest, tok)
		f.do(t, http.MethodPost, pathUploads, tok)
	}
	f.do(t, http.MethodDelete, pathManifest, tokWriter)
	for _, tok := range []string{tokReader, tokWriter, tokOther, tokBad, tokAudience} {
		if strings.Contains(f.logs.String(), tok) {
			t.Fatalf("a log line holds the token %q:\n%s", tok, f.logs.String())
		}
	}
}

func TestTokenDenialCounter(t *testing.T) {
	f := newTokenFixture(t)
	f.do(t, http.MethodGet, pathManifest, tokOther)
	f.do(t, http.MethodGet, pathManifest, tokOther)
	f.do(t, http.MethodGet, pathManifest, "")
	f.do(t, http.MethodDelete, pathManifest, tokWriter)
	f.do(t, http.MethodGet, pathManifest, tokReader) // admitted: not counted
	for _, c := range []struct {
		reason, detail string
		want           int64
	}{
		{"peer_not_allowed", "subject", 2},
		{"peer_not_allowed", "no_token", 1},
		{"request_not_allowed", "method", 1},
	} {
		v, ok := metricValue(t, f.reader, "store_proxy.denials", map[string]string{"reason": c.reason, "detail": c.detail})
		if !ok || v != c.want {
			t.Errorf("store_proxy.denials{%s,%s} = %d, %v, want %d", c.reason, c.detail, v, ok, c.want)
		}
	}
}

func TestTokenConfigErrors(t *testing.T) {
	good := func() TokenConfig {
		return TokenConfig{Upstream: "127.0.0.1:5001", Audience: storeAudience, Readers: []string{subReader}, Reviewer: newFakeReviewer()}
	}
	cases := map[string]func(*TokenConfig){
		"no upstream": func(c *TokenConfig) { c.Upstream = "" },
		"no audience": func(c *TokenConfig) { c.Audience = "" },
		"no reader":   func(c *TokenConfig) { c.Readers = nil },
		"no reviewer": func(c *TokenConfig) { c.Reviewer = nil },
		"empty entry": func(c *TokenConfig) { c.Writers = []string{""} },
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			c := good()
			m(&c)
			if _, err := NewTokenHandler(c); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	if _, err := NewTokenHandler(good()); err != nil {
		t.Fatal(err)
	}
}

// TestTokenStoreRoundTrip drives the proxy with the real store client: the writer pushes without
// a read, and the repo server reads.
func TestTokenStoreRoundTrip(t *testing.T) {
	ctx := t.Context()
	reg := ocitest.NewRegistry(t)
	reg.UploadLocation(reg.URL())
	f := newTokenFixture(t, func(c *TokenConfig) { c.Upstream = reg.URL() })
	base := strings.TrimPrefix(f.srv.URL, "http://")
	client := func(tok string, writeOnly bool) *ocistore.Store {
		s, err := ocistore.New(ocistore.Client{Base: base, WriteOnly: writeOnly, Token: func() (string, error) { return tok, nil }})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	w, r := client(tokWriter, true), client(tokReader, false)
	blob := []byte("layer")
	if err := w.PushBlob(ctx, "bundles/demo", ocitest.Digest(blob), blob); err != nil {
		t.Fatalf("PushBlob: %v", err)
	}
	man := []byte(`{"schemaVersion":2}`)
	d, err := w.PushManifest(ctx, "bundles/demo", "current", "application/vnd.oci.image.manifest.v1+json", man)
	if err != nil {
		t.Fatalf("PushManifest: %v", err)
	}
	got, err := r.Manifest(ctx, "bundles/demo", d)
	if err != nil || !bytes.Equal(got, man) {
		t.Fatalf("Manifest = %q, %v", got, err)
	}
	if rd, err := r.Resolve(ctx, "bundles/demo", "current"); err != nil || rd != d {
		t.Fatalf("Resolve = %q, %v, want %s", rd, err, d)
	}
	if _, err := r.PushManifest(ctx, "bundles/demo", "other", "application/vnd.oci.image.manifest.v1+json", []byte(`{"schemaVersion":2,"x":1}`)); err == nil {
		t.Fatal("the repo server pushed a manifest")
	}
	for _, h := range reg.Requests() {
		if h.Header.Get("Authorization") != "" {
			t.Fatalf("registry got Authorization on %s %s", h.Method, h.Path)
		}
	}
}
