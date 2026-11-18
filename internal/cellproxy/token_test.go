package cellproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
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
	mu          sync.Mutex
	reviews     map[string]TokenReview
	err         error
	calls       int
	audiences   []string
	inflight    int
	maxInflight int
	gate        chan struct{} // when set, a review waits until it closes
}

func (f *fakeReviewer) Review(_ context.Context, token, audience string) (TokenReview, error) {
	f.mu.Lock()
	f.calls++
	f.audiences = append(f.audiences, audience)
	f.inflight++
	f.maxInflight = max(f.maxInflight, f.inflight)
	gate := f.gate
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inflight--
	if f.err != nil {
		return TokenReview{}, f.err
	}
	// Like the API server, a review for an audience that the token does not name is refused.
	if r, ok := f.reviews[token]; ok && slices.Contains(r.Audiences, audience) {
		return r, nil
	}
	if r, ok := f.reviews[token]; ok && r.Authenticated {
		return TokenReview{Error: "token audiences are invalid for the current audience"}, nil
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
	handler  http.Handler
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
	f.handler = h
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
	// The API server refuses a token for another audience.
	f := newTokenFixture(t)
	f.wantDenied(t, f.do(t, http.MethodGet, pathManifest, tokAudience), PeerNotAllowed, "token_invalid")
	// A reviewer that accepts the token but returns other audiences is refused by the proxy itself.
	f2 := newTokenFixture(t, func(c *TokenConfig) { c.Reviewer = laxReviewer{} })
	f2.wantDenied(t, f2.do(t, http.MethodGet, pathManifest, tokAudience), PeerNotAllowed, "audience")
}

type laxReviewer struct{}

func (laxReviewer) Review(context.Context, string, string) (TokenReview, error) {
	return TokenReview{Authenticated: true, Username: subReader, Audiences: []string{"other"}}, nil
}

func TestTokenReviewerAskedForTheStoreAudience(t *testing.T) {
	f := newTokenFixture(t)
	f.do(t, http.MethodGet, pathManifest, tokReader)
	f.do(t, http.MethodGet, pathManifest, tokBad)
	f.reviewer.mu.Lock()
	defer f.reviewer.mu.Unlock()
	if len(f.reviewer.audiences) != 2 {
		t.Fatalf("reviewer calls %d, want 2", len(f.reviewer.audiences))
	}
	for _, a := range f.reviewer.audiences {
		if a != storeAudience {
			t.Fatalf("reviewer asked for audience %q, want %q", a, storeAudience)
		}
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
	// A refused token is cached for 10 seconds, and then reviewed again.
	f.do(t, http.MethodGet, pathManifest, tokBad)
	f.do(t, http.MethodGet, pathManifest, tokBad)
	if n := f.reviewer.count(); n != 3 {
		t.Fatalf("reviewer calls %d after two identical bad tokens, want 3", n)
	}
	mu.Lock()
	now = now.Add(11 * time.Second)
	mu.Unlock()
	f.do(t, http.MethodGet, pathManifest, tokBad)
	if n := f.reviewer.count(); n != 4 {
		t.Fatalf("reviewer calls %d after the refusal TTL, want 4", n)
	}
	// A reviewer error is never cached.
	f.reviewer.err = io.ErrUnexpectedEOF
	f.do(t, http.MethodGet, pathManifest, "unknown-a")
	f.do(t, http.MethodGet, pathManifest, "unknown-a")
	if n := f.reviewer.count(); n != 6 {
		t.Fatalf("reviewer calls %d after two review errors, want 6", n)
	}
}

// TestTokenCacheKeepsNoToken checks that the cache keys hold a hash and never the token.
func TestTokenCacheKeepsNoToken(t *testing.T) {
	f := newTokenFixture(t)
	f.do(t, http.MethodGet, pathManifest, tokReader)
	f.do(t, http.MethodGet, pathManifest, tokBad)
	p := f.handler.(*tokenProxy)
	p.mu.Lock()
	defer p.mu.Unlock()
	for k := range p.cache {
		if bytes.Contains(k[:], []byte(tokReader)) || bytes.Contains(k[:], []byte(tokBad)) {
			t.Fatal("a cache key holds a token")
		}
	}
	if len(p.cache) != 2 {
		t.Fatalf("cache holds %d entries, want 2", len(p.cache))
	}
}

// TestTokenCacheCap checks that the cache never holds more than maxTokenCache entries.
func TestTokenCacheCap(t *testing.T) {
	f := newTokenFixture(t)
	for i := 0; i < maxTokenCache+50; i++ {
		f.do(t, http.MethodGet, pathManifest, fmt.Sprintf("bad-%d", i))
	}
	p := f.handler.(*tokenProxy)
	p.mu.Lock()
	n := len(p.cache)
	p.mu.Unlock()
	if n == 0 || n > maxTokenCache {
		t.Fatalf("cache holds %d entries, want between 1 and %d", n, maxTokenCache)
	}
}

// TestTokenSingleFlight checks that identical tokens in flight share one review.
func TestTokenSingleFlight(t *testing.T) {
	f := newTokenFixture(t)
	gate := make(chan struct{})
	f.reviewer.gate = gate
	var wg sync.WaitGroup
	codes := make(chan int, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- f.do(t, http.MethodGet, pathManifest, tokReader).Status }()
	}
	waitCond(t, func() bool { return f.reviewer.count() >= 1 })
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != http.StatusOK {
			t.Fatalf("status %d, want 200", c)
		}
	}
	if n := f.reviewer.count(); n != 1 {
		t.Fatalf("reviewer calls %d for 20 identical in-flight tokens, want 1", n)
	}
}

// TestTokenReviewCap checks that at most maxReviews reviews run at once, and that the proxy
// answers 503 overloaded beyond that.
func TestTokenReviewCap(t *testing.T) {
	f := newTokenFixture(t)
	gate := make(chan struct{})
	f.reviewer.gate = gate
	const n = 40
	var wg sync.WaitGroup
	results := make(chan tokenResp, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- f.do(t, http.MethodGet, pathManifest, fmt.Sprintf("distinct-%d", i))
		}()
	}
	waitCond(t, func() bool { return f.reviewer.count() >= maxReviews })
	time.Sleep(200 * time.Millisecond)
	f.reviewer.mu.Lock()
	peak := f.reviewer.maxInflight
	f.reviewer.mu.Unlock()
	close(gate)
	wg.Wait()
	close(results)
	if peak > maxReviews {
		t.Fatalf("%d reviews ran at once, want at most %d", peak, maxReviews)
	}
	over := 0
	for r := range results {
		if r.Status == http.StatusServiceUnavailable && strings.Contains(r.Body, `"overloaded"`) {
			over++
		}
	}
	if over != n-maxReviews {
		t.Fatalf("%d requests got 503 overloaded, want %d", over, n-maxReviews)
	}
	if v, ok := metricValue(t, f.reader, "store_proxy.denials", map[string]string{"reason": "overloaded"}); !ok || v != int64(n-maxReviews) {
		t.Fatalf("denials{overloaded} = %d, %v, want %d", v, ok, n-maxReviews)
	}
}

func waitCond(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

// jwtWithExp makes an unsigned token whose payload carries exp.
func jwtWithExp(exp int64) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(fmt.Sprintf(`{"exp":%d}`, exp))) + ".sig"
}

// TestTokenCacheStopsAtExp checks that an accepted token is cached no longer than its exp claim.
func TestTokenCacheStopsAtExp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	f := newTokenFixture(t, func(c *TokenConfig) {
		c.CacheTTL = 30 * time.Second
		c.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	short := jwtWithExp(now.Add(5 * time.Second).Unix())
	f.reviewer.reviews[short] = TokenReview{Authenticated: true, Username: subReader, Audiences: []string{storeAudience}}
	f.do(t, http.MethodGet, pathManifest, short)
	mu.Lock()
	now = now.Add(3 * time.Second)
	mu.Unlock()
	f.do(t, http.MethodGet, pathManifest, short)
	if n := f.reviewer.count(); n != 1 {
		t.Fatalf("reviewer calls %d before exp, want 1", n)
	}
	mu.Lock()
	now = now.Add(3 * time.Second)
	mu.Unlock()
	f.do(t, http.MethodGet, pathManifest, short)
	if n := f.reviewer.count(); n != 2 {
		t.Fatalf("reviewer calls %d after exp (6 s, TTL 30 s), want 2", n)
	}
	// A token with a late exp is bounded by the TTL, and one with garbage in the payload by the TTL too.
	long := jwtWithExp(now.Add(time.Hour).Unix())
	garbage := "a.!!!.c"
	for _, tk := range []string{long, garbage} {
		f.reviewer.reviews[tk] = TokenReview{Authenticated: true, Username: subReader, Audiences: []string{storeAudience}}
		before := f.reviewer.count()
		f.do(t, http.MethodGet, pathManifest, tk)
		mu.Lock()
		now = now.Add(31 * time.Second)
		mu.Unlock()
		f.do(t, http.MethodGet, pathManifest, tk)
		if n := f.reviewer.count() - before; n != 2 {
			t.Fatalf("token %q: %d reviews over 31 s, want 2 (TTL bound)", tk, n)
		}
	}
}

func TestTokenDuplicateAuthorization(t *testing.T) {
	f := newTokenFixture(t)
	r := f.do(t, http.MethodGet, pathManifest, "", func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+tokReader)
		r.Header.Add("Authorization", "Bearer "+tokReader)
	})
	f.wantDenied(t, r, PeerNotAllowed, "no_token")
	if n := f.reviewer.count(); n != 0 {
		t.Fatalf("reviewer called %d times", n)
	}
}

func TestTokenOversizeToken(t *testing.T) {
	f := newTokenFixture(t)
	f.wantDenied(t, f.do(t, http.MethodGet, pathManifest, strings.Repeat("a", maxBearerBytes+1)), PeerNotAllowed, "no_token")
	if n := f.reviewer.count(); n != 0 {
		t.Fatalf("reviewer called %d times", n)
	}
}

func TestTokenReaderUploadRefused(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		t.Run(m, func(t *testing.T) {
			f := newTokenFixture(t)
			f.wantDenied(t, f.do(t, m, "/v2/bundles/argocd/blobs/uploads/abc", tokReader), RequestNotAllowed, "path")
		})
	}
}

func TestTokenMountRefused(t *testing.T) {
	for _, q := range []string{"?mount=" + digestA + "&from=other", "?from=other", "?mount=" + digestA} {
		t.Run(q, func(t *testing.T) {
			f := newTokenFixture(t)
			f.wantDenied(t, f.do(t, http.MethodPost, pathUploads+q, tokWriter), RequestNotAllowed, "path")
		})
	}
	// A monolithic upload keeps its digest parameter.
	f := newTokenFixture(t)
	if r := f.do(t, http.MethodPost, pathUploads+"?digest="+digestA, tokWriter); r.Status != http.StatusOK {
		t.Fatalf("status %d, want 200", r.Status)
	}
}

func TestTokenReadQueryRefused(t *testing.T) {
	f := newTokenFixture(t)
	f.wantDenied(t, f.do(t, http.MethodGet, pathManifest+"?x=1", tokReader), RequestNotAllowed, "path")
}

func TestTokenDotSegmentsRefused(t *testing.T) {
	for _, p := range []string{"/v2/bundles/root/manifests/..", "/v2/bundles/root/manifests/.", "/v2/bundles/root/blobs/uploads/..", "/v2/bundles/root/blobs/uploads/."} {
		for _, tok := range []struct{ m, t string }{{http.MethodGet, tokReader}, {http.MethodPut, tokWriter}} {
			t.Run(tok.m+p, func(t *testing.T) {
				f := newTokenFixture(t)
				f.wantDenied(t, f.do(t, tok.m, p, tok.t), RequestNotAllowed, "path")
			})
		}
	}
}

// TestTokenUploadOfAnotherRepo checks that the writer cannot finish an upload in a repo that did
// not start it. The registry owns the upload ID, so the registry refuses it.
func TestTokenUploadOfAnotherRepo(t *testing.T) {
	reg := ocitest.NewRegistry(t)
	f := newTokenFixture(t, func(c *TokenConfig) { c.Upstream = reg.URL() })
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/v2/bundles/one/blobs/uploads/", nil)
	req.Header.Set("Authorization", "Bearer "+tokWriter)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	id := resp.Header.Get("Location")[strings.LastIndex(resp.Header.Get("Location"), "/")+1:]
	data := []byte("x")
	for _, m := range []string{http.MethodPut, http.MethodPatch} {
		r := f.do(t, m, "/v2/bundles/two/blobs/uploads/"+id+"?digest="+ocitest.Digest(data), tokWriter)
		if r.Status < 400 {
			t.Fatalf("%s to the upload of another repo: status %d, want a refusal", m, r.Status)
		}
	}
	if _, ok := reg.Blob("bundles/two", ocitest.Digest(data)); ok {
		t.Fatal("the blob reached the other repo")
	}
}

func TestRewriteLocation(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:5001/v2/a/blobs/uploads/1?x=y": "/v2/a/blobs/uploads/1?x=y",
		"//127.0.0.1:5001/v2/a/blobs/uploads/1":          "/v2/a/blobs/uploads/1",
		"/v2/a/blobs/uploads/1":                          "/v2/a/blobs/uploads/1",
		"http://other:5001/v2/a":                         "http://other:5001/v2/a",
		"//other:5001/v2/a":                              "//other:5001/v2/a",
	}
	for in, want := range cases {
		resp := &http.Response{Header: http.Header{"Location": {in}}}
		rewriteLocation(resp, "127.0.0.1:5001")
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("Location %q became %q, want %q", in, got, want)
		}
	}
}

func TestTokenSlowUpstream(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	defer slow.Close()
	f := newTokenFixture(t, func(c *TokenConfig) {
		c.Upstream = strings.TrimPrefix(slow.URL, "http://")
		c.UpstreamTimeout = 150 * time.Millisecond
	})
	start := time.Now()
	r := f.do(t, http.MethodGet, pathManifest, tokReader)
	if r.Status != http.StatusServiceUnavailable || time.Since(start) > time.Second {
		t.Fatalf("status %d after %v, want 503 within the timeout", r.Status, time.Since(start))
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
