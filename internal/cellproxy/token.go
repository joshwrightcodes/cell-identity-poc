package cellproxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// Details of a store refusal, for the detail attribute of the log line and of store_proxy.denials.
const (
	detailNoToken      = "no_token"
	detailTokenInvalid = "token_invalid"
	detailAudience     = "audience"
	detailSubject      = "subject"
	detailMethod       = "method"
	detailPath         = "path"
	detailReview       = "review"
	detailUpstream     = "upstream"
)

const (
	defaultTokenCacheTTL = 30 * time.Second
	// refusalCacheTTL is how long the proxy keeps a refused token, so a flood of one bad token costs one review.
	refusalCacheTTL = 10 * time.Second
	maxTokenCache   = 1024
	// maxReviews bounds the TokenReview calls that run at once. A request that would start another one gets 503 overloaded.
	maxReviews     = 8
	reviewTimeout  = 10 * time.Second
	maxBearerBytes = 16 << 10
	// defaultUpstreamTimeout bounds the wait for the response header of the upstream.
	defaultUpstreamTimeout = 60 * time.Second
)

// storePath is the part of the OCI distribution API that bundle stores use: the manifests and
// blobs of one repo under bundles/, and the upload start and continuation of its blobs.
var storePath = regexp.MustCompile(`^/v2/bundles/[a-z0-9-]+/(?:manifests/[^/]+|blobs/sha256:[0-9a-f]{64}|blobs/uploads/[^/]*)$`)

// TokenConfig configures a store proxy.
//
// Upstream is the host:port of the registry. Audience is the audience that each token must name.
// A token is accepted for a read (GET and HEAD) only from a subject in Readers, and for a write
// (POST, PUT and PATCH) only from a subject in Writers. An empty Writers refuses every write.
// Reviewer checks the tokens, and CacheTTL is how long the proxy keeps an accepted token (30
// seconds when zero), and never longer than the exp claim of the token. A revoked token or a
// deleted account therefore still works for at most CacheTTL. The proxy keeps a refused token for
// 10 seconds. UpstreamTimeout bounds the wait for the response header of the registry (60
// seconds when zero). Now defaults to time.Now, Log to a discarding logger and Meter to a meter
// that records nothing.
type TokenConfig struct {
	Upstream, Audience string
	Readers, Writers   []string
	Reviewer           TokenReviewer
	CacheTTL           time.Duration
	UpstreamTimeout    time.Duration
	Now                func() time.Time
	Log                *slog.Logger
	Meter              metric.Meter
}

type tokenProxy struct {
	audience         string
	readers, writers []string
	reviewer         TokenReviewer
	ttl              time.Duration
	now              func() time.Time
	log              *slog.Logger
	denials          metric.Int64Counter
	proxy            *httputil.ReverseProxy

	mu     sync.Mutex
	cache  map[[sha256.Size]byte]cachedReview
	flight map[[sha256.Size]byte]*reviewCall
	slots  chan struct{}
}

// cachedReview is the outcome of one review, accepted (detail "") or refused.
type cachedReview struct {
	username string
	detail   string
	until    time.Time
}

// reviewCall is a review in flight. Requests with the same token wait for done and share the result.
type reviewCall struct {
	done     chan struct{}
	username string
	detail   string
	err      error
	reason   Reason
}

// NewTokenHandler returns the store proxy. It sends a request to Upstream only after it has
// checked the method, the path and the bearer token. It never sends the Authorization header of
// the caller upstream. Every refusal adds one to the counter store_proxy.denials.
func NewTokenHandler(cfg TokenConfig) (http.Handler, error) {
	switch {
	case cfg.Upstream == "":
		return nil, errors.New("store proxy needs an upstream")
	case cfg.Audience == "":
		return nil, errors.New("store proxy needs an audience")
	case cfg.Reviewer == nil:
		return nil, errors.New("store proxy needs a token reviewer")
	case len(cfg.Readers) == 0:
		return nil, errors.New("store proxy needs at least one reader")
	}
	for _, s := range slices.Concat(cfg.Readers, cfg.Writers) {
		if s == "" {
			return nil, errors.New("store proxy subjects must not be empty")
		}
	}
	p := &tokenProxy{
		audience: cfg.Audience,
		readers:  slices.Clone(cfg.Readers),
		writers:  slices.Clone(cfg.Writers),
		reviewer: cfg.Reviewer,
		ttl:      cfg.CacheTTL,
		now:      cfg.Now,
		log:      cfg.Log,
		cache:    map[[sha256.Size]byte]cachedReview{},
		flight:   map[[sha256.Size]byte]*reviewCall{},
		slots:    make(chan struct{}, maxReviews),
	}
	if p.ttl <= 0 {
		p.ttl = defaultTokenCacheTTL
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.log == nil {
		p.log = slog.New(slog.DiscardHandler)
	}
	meter := cfg.Meter
	if meter == nil {
		meter = noop.NewMeterProvider().Meter("cell-proxy")
	}
	var err error
	p.denials, err = meter.Int64Counter("store_proxy.denials", metric.WithUnit("{request}"),
		metric.WithDescription("Requests that the store proxy refused, by reason and detail"))
	if err != nil {
		return nil, fmt.Errorf("store proxy metrics: %w", err)
	}
	target := &url.URL{Scheme: "http", Host: cfg.Upstream}
	p.proxy = &httputil.ReverseProxy{
		Transport: upstreamTransport(cfg.UpstreamTimeout),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header.Del("Authorization")
		},
		ModifyResponse: func(resp *http.Response) error {
			rewriteLocation(resp, target.Host)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.deny(w, r, UpstreamUnavailable, detailUpstream, "", err.Error())
		},
		ErrorLog: slog.NewLogLogger(p.log.Handler(), slog.LevelWarn),
	}
	return p, nil
}

// upstreamTransport clones the default transport and bounds the wait for a response header.
func upstreamTransport(timeout time.Duration) *http.Transport {
	if timeout <= 0 {
		timeout = defaultUpstreamTimeout
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = timeout
	t.MaxIdleConns = 16
	t.MaxIdleConnsPerHost = 16
	return t
}

// rewriteLocation turns an absolute or scheme-relative Location that names the upstream into a path, so the caller
// sends the next request of an upload through the proxy and not to the registry.
func rewriteLocation(resp *http.Response, upstreamHost string) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" || !strings.EqualFold(u.Host, upstreamHost) {
		return
	}
	resp.Header.Set("Location", (&url.URL{Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}).String())
}

// checkStorePath returns why the request path or query is outside the store API, or "".
func checkStorePath(r *http.Request, need access) string {
	u := r.URL
	if u.RawPath != "" || u.Opaque != "" || !storePath.MatchString(u.Path) {
		return "path outside the store API"
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return "dot segment in the path"
		}
	}
	isUpload := strings.Contains(u.Path, "/blobs/uploads/")
	switch {
	case need == accessRead && isUpload:
		return "read of an upload"
	case need == accessRead && u.RawQuery != "":
		return "query on a read"
	case need == accessWrite && r.Method == http.MethodPost:
		// mount and from would tell the writer whether a blob exists in another repo.
		q := u.Query()
		if q.Has("mount") || q.Has("from") {
			return "blob mount"
		}
	}
	return ""
}

type access int

const (
	accessRead access = iota
	accessWrite
	accessPing
)

func (p *tokenProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var need access
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		need = accessRead
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		need = accessWrite
	default:
		p.deny(w, r, RequestNotAllowed, detailMethod, "", "method "+r.Method)
		return
	}
	if r.URL.Path == "/v2/" && r.URL.RawPath == "" && r.URL.Opaque == "" {
		if r.Method != http.MethodGet {
			p.deny(w, r, RequestNotAllowed, detailMethod, "", "method "+r.Method+" on /v2/")
			return
		}
		need = accessPing
	} else if why := checkStorePath(r, need); why != "" {
		p.deny(w, r, RequestNotAllowed, detailPath, "", why)
		return
	}
	token, ok := bearerToken(r)
	if !ok {
		p.deny(w, r, PeerNotAllowed, detailNoToken, "", "no bearer token")
		return
	}
	user, detail, reason, err := p.authenticate(r.Context(), token)
	switch {
	case err != nil:
		p.deny(w, r, reason, detailReview, "", err.Error())
		return
	case detail != "":
		p.deny(w, r, PeerNotAllowed, detail, user, "token refused")
		return
	}
	allowed := false
	switch need {
	case accessRead:
		allowed = slices.Contains(p.readers, user)
	case accessWrite:
		allowed = slices.Contains(p.writers, user)
	case accessPing:
		allowed = slices.Contains(p.readers, user) || slices.Contains(p.writers, user)
	}
	if !allowed {
		p.deny(w, r, PeerNotAllowed, detailSubject, user, "subject not allowed for "+r.Method)
		return
	}
	p.proxy.ServeHTTP(w, r)
}

// bearerToken returns the token of the one Authorization header, if it has the Bearer scheme.
func bearerToken(r *http.Request) (string, bool) {
	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(vals[0], " ")
	token = strings.TrimSpace(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > maxBearerBytes {
		return "", false
	}
	return token, true
}

// authenticate returns the subject of token. detail is "" for an accepted token, else the detail
// of the refusal. A refused token is kept for refusalCacheTTL and an accepted one for the TTL of
// the proxy or until its exp claim, whichever is earlier. Reviews of one token run once at a time,
// and at most maxReviews reviews run at once. reason is the reason of err: Overloaded or
// UpstreamUnavailable. The proxy never keeps a review error.
func (p *tokenProxy) authenticate(ctx context.Context, token string) (user, detail string, reason Reason, err error) {
	key := sha256.Sum256([]byte(token))
	now := p.now()
	p.mu.Lock()
	if c, hit := p.cache[key]; hit && now.Before(c.until) {
		p.mu.Unlock()
		return c.username, c.detail, "", nil
	}
	if call, ok := p.flight[key]; ok {
		p.mu.Unlock()
		select {
		case <-call.done:
			return call.username, call.detail, call.reason, call.err
		case <-ctx.Done():
			return "", "", UpstreamUnavailable, errors.New("request ended during the token review")
		}
	}
	select {
	case p.slots <- struct{}{}:
	default:
		p.mu.Unlock()
		return "", "", Overloaded, errors.New("too many token reviews in flight")
	}
	call := &reviewCall{done: make(chan struct{})}
	p.flight[key] = call
	p.mu.Unlock()

	// The review does not end when the request that started it ends, because other requests may wait for it.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reviewTimeout)
	call.username, call.detail, call.err = p.review(rctx, token)
	cancel()
	if call.err != nil {
		call.reason = UpstreamUnavailable
	}
	p.mu.Lock()
	delete(p.flight, key)
	if call.err == nil {
		if len(p.cache) >= maxTokenCache {
			clear(p.cache)
		}
		p.cache[key] = cachedReview{username: call.username, detail: call.detail, until: p.cacheUntil(token, call.detail, now)}
	}
	p.mu.Unlock()
	<-p.slots
	close(call.done)
	return call.username, call.detail, call.reason, call.err
}

// cacheUntil is the end of the cache life of a review made at now.
func (p *tokenProxy) cacheUntil(token, detail string, now time.Time) time.Time {
	if detail != "" {
		return now.Add(refusalCacheTTL)
	}
	until := now.Add(p.ttl)
	if exp, ok := tokenExp(token); ok && exp.Before(until) {
		until = exp
	}
	return until
}

// tokenExp reads the exp claim of a compact JWT without checking the signature. The proxy uses it
// only to end the cache life of an accepted token early, never to accept anything.
func tokenExp(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp *float64 `json:"exp"`
	}
	if json.Unmarshal(b, &claims) != nil || claims.Exp == nil {
		return time.Time{}, false
	}
	return time.Unix(int64(*claims.Exp), 0), true
}

// review asks the reviewer and maps the answer to a subject and a refusal detail.
func (p *tokenProxy) review(ctx context.Context, token string) (user, detail string, err error) {
	rev, err := p.reviewer.Review(ctx, token, p.audience)
	if err != nil {
		return "", "", errors.New("token review failed")
	}
	switch {
	case !rev.Authenticated:
		return "", detailTokenInvalid, nil
	case !slices.Contains(rev.Audiences, p.audience):
		return rev.Username, detailAudience, nil
	case rev.Username == "":
		return "", detailTokenInvalid, nil
	}
	return rev.Username, "", nil
}

// deny counts and logs one refusal and answers it. The body names no reason. The log line holds
// the subject only when a review gave one, and never a token.
func (p *tokenProxy) deny(w http.ResponseWriter, r *http.Request, reason Reason, detail, subject, why string) {
	id := requestID()
	p.denials.Add(r.Context(), 1, metric.WithAttributes(
		attribute.String("reason", string(reason)), attribute.String("detail", detail)))
	p.log.Warn("request denied", "reason", string(reason), "detail", detail, "method", r.Method,
		"path", r.URL.Path, "subject", subject, "request_id", id, "error", why)
	word := "denied"
	if reason.HTTPStatus() != http.StatusForbidden {
		word = string(reason)
	}
	body, _ := json.Marshal(struct {
		Error     string `json:"error"`
		RequestID string `json:"requestId"`
	}{word, id})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", id)
	w.WriteHeader(reason.HTTPStatus())
	_, _ = w.Write(append(body, '\n'))
}
