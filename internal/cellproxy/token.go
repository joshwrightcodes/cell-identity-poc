package cellproxy

import (
	"context"
	"crypto/sha256"
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
	maxTokenCache        = 1024
	reviewTimeout        = 10 * time.Second
	maxBearerBytes       = 16 << 10
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
// seconds when zero). Now defaults to time.Now, Log to a discarding logger and Meter to a meter
// that records nothing.
type TokenConfig struct {
	Upstream, Audience string
	Readers, Writers   []string
	Reviewer           TokenReviewer
	CacheTTL           time.Duration
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

	mu    sync.Mutex
	cache map[[sha256.Size]byte]cachedReview
}

type cachedReview struct {
	username string
	until    time.Time
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

// rewriteLocation turns an absolute Location that names the upstream into a path, so the caller
// sends the next request of an upload through the proxy and not to the registry.
func rewriteLocation(resp *http.Response, upstreamHost string) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil || !u.IsAbs() || !strings.EqualFold(u.Host, upstreamHost) {
		return
	}
	resp.Header.Set("Location", (&url.URL{Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}).String())
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
	} else if r.URL.RawPath != "" || r.URL.Opaque != "" || !storePath.MatchString(r.URL.Path) {
		p.deny(w, r, RequestNotAllowed, detailPath, "", "path outside the store API")
		return
	}
	token, ok := bearerToken(r)
	if !ok {
		p.deny(w, r, PeerNotAllowed, detailNoToken, "", "no bearer token")
		return
	}
	user, detail, err := p.authenticate(r.Context(), token)
	switch {
	case err != nil:
		p.deny(w, r, UpstreamUnavailable, detailReview, "", err.Error())
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
// of the refusal. err is set when no review could be made. The proxy keeps only accepted reviews.
func (p *tokenProxy) authenticate(ctx context.Context, token string) (user, detail string, err error) {
	key := sha256.Sum256([]byte(token))
	now := p.now()
	p.mu.Lock()
	c, hit := p.cache[key]
	p.mu.Unlock()
	if hit && now.Before(c.until) {
		return c.username, "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, reviewTimeout)
	defer cancel()
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
	p.mu.Lock()
	if len(p.cache) >= maxTokenCache {
		clear(p.cache)
	}
	p.cache[key] = cachedReview{username: rev.Username, until: now.Add(p.ttl)}
	p.mu.Unlock()
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
