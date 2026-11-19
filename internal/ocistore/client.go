// Package ocistore reads and writes bundles in an OCI registry over plain HTTP. It wraps the
// registry resolver of containerd and adds what a signed bundle needs: a bearer token for one
// host, a refusal of every other host, size limits, a digest check of all content and typed errors.
//
// The resolver sends requests only through the HTTP client of this package. The transport of that
// client sends one host, sets Accept-Encoding to identity and refuses any Content-Encoding.
// Descriptors that the store builds never carry urls, and the store refuses any manifest or index
// that sets urls, because the resolver would fetch such a url with the default HTTP client.
package ocistore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	remoteerrors "github.com/containerd/containerd/v2/core/remotes/errors"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	lslog "github.com/sirupsen/logrus/hooks/slog"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
)

// Errors that the store returns, wrapped with the cause. Test them with errors.Is.
var (
	ErrDigestMismatch  = errors.New("content does not match its digest")
	ErrNotFound        = errors.New("not found")
	ErrTooLarge        = errors.New("content is too large")
	ErrDenied          = errors.New("access denied")
	ErrLayout          = errors.New("unexpected artifact layout")
	ErrOffHost         = errors.New("request to another host refused")
	ErrContentEncoding = errors.New("content encoding refused")
	ErrWriteOnly       = errors.New("store is write-only")
)

const (
	mediaTypeBlob = "application/octet-stream"
	maxRedirects  = 10
	// maxIndex bounds the referrers index, which grows with each attestation.
	maxIndex       = 256 << 10
	defaultMaxMan  = bundle.MaxManifestBytes
	defaultMaxBlob = bundle.MaxLayerBytes
)

var (
	repoRe   = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	baseRe   = regexp.MustCompile(`^(?:http://)?([A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?$`)
)

// Client holds the settings of a Store.
type Client struct {
	// Base is the registry as host:port, or http://host:port. Only plain HTTP is supported.
	Base string
	// Token returns the bearer token for each request to Base. Nil sends no token.
	Token func() (string, error)
	// MaxManifest and MaxBlob bound the bytes that the store reads or writes for a manifest and
	// for a blob. A value of zero or less selects the bundle limits.
	MaxManifest, MaxBlob int64
	// WriteOnly answers every HEAD and GET locally with 404 and sends it nowhere, so that the
	// resolver goes straight to POST and PUT. Use it for a writer that the registry proxy refuses
	// to let read. Every read method of the store then returns ErrWriteOnly.
	WriteOnly bool
	// Transport carries the requests. It is a seam for tests. Nil selects a clone of http.DefaultTransport.
	Transport http.RoundTripper
}

// Store is a client of one registry. It is safe for concurrent use.
type Store struct {
	c    Client
	host string
	hc   *http.Client
	logr *logrus.Logger
}

// New returns a Store for the registry in c.Base.
func New(c Client) (*Store, error) {
	m := baseRe.FindStringSubmatch(c.Base)
	if m == nil {
		return nil, fmt.Errorf("registry base %q is not host:port or http://host:port", c.Base)
	}
	host := strings.TrimPrefix(c.Base, "http://")
	if c.MaxManifest <= 0 {
		c.MaxManifest = defaultMaxMan
	}
	if c.MaxBlob <= 0 {
		c.MaxBlob = defaultMaxBlob
	}
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
	}
	hc := &http.Client{
		Transport: &guard{host: host, token: c.Token, base: base, writeOnly: c.WriteOnly, bodyCap: max(c.MaxManifest, maxIndex) + 1},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if !strings.EqualFold(req.URL.Host, host) {
				return fmt.Errorf("%w: redirect to %s", ErrOffHost, req.URL.Host)
			}
			return nil
		},
	}
	routeGlobalLogger()
	return &Store{c: c, host: host, hc: hc, logr: newLogger()}, nil
}

// guard is the transport of the store. It is the only path to the network.
type guard struct {
	host      string
	token     func() (string, error)
	base      http.RoundTripper
	writeOnly bool
	bodyCap   int64
}

// acceptManifests is what a read of a manifest or index sends. A registry that follows Distribution
// 3.1.2 answers 404 for a stored index when the OCI index type is not listed.
const acceptManifests = ocispec.MediaTypeImageIndex + ", " + ocispec.MediaTypeImageManifest

type limitedBody struct {
	io.Reader
	io.Closer
}

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	closeBody := func() {
		if req.Body != nil {
			_ = req.Body.Close()
		}
	}
	if req.URL.Scheme != "http" || !strings.EqualFold(req.URL.Host, g.host) {
		closeBody()
		return nil, fmt.Errorf("%w: %s://%s", ErrOffHost, req.URL.Scheme, req.URL.Host)
	}
	read := req.Method == http.MethodGet || req.Method == http.MethodHead
	if g.writeOnly && read {
		closeBody()
		return &http.Response{
			Status: "404 Not Found", StatusCode: http.StatusNotFound, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{}, Body: http.NoBody, Request: req,
		}, nil
	}
	manifestRead := read && strings.Contains(req.URL.Path, "/manifests/")
	out := req.Clone(req.Context())
	if manifestRead {
		out.Header.Set("Accept", acceptManifests)
	}
	out.Header.Del("Authorization")
	out.Header.Set("Accept-Encoding", "identity")
	if g.token != nil {
		tok, err := g.token()
		if err != nil {
			closeBody()
			return nil, fmt.Errorf("get registry token: %w", err)
		}
		if tok != "" {
			out.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := g.base.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: %q from %s", ErrContentEncoding, enc, req.URL.Host)
	}
	if manifestRead && req.Method == http.MethodGet {
		// The resolver hashes a body that has no digest header without a bound of its own.
		resp.Body = limitedBody{io.LimitReader(resp.Body, g.bodyCap), resp.Body}
	}
	return resp, nil
}

// slogHandler sends records to the default slog logger that is current when the record is made.
type slogHandler struct{}

func (slogHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return slog.Default().Handler().Enabled(ctx, l)
}
func (slogHandler) Handle(ctx context.Context, r slog.Record) error {
	return slog.Default().Handler().Handle(ctx, r)
}
func (slogHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return slog.Default().Handler().WithAttrs(a)
}
func (slogHandler) WithGroup(n string) slog.Handler { return slog.Default().Handler().WithGroup(n) }

// hook bridges logrus entries to slog. An info entry of the resolver, for example a missing tag,
// is a normal result that the store returns as a typed error, so it goes out at debug level.
func newHook() logrus.Hook {
	return lslog.NewHook(slog.New(slogHandler{}), &lslog.HookOptions{LevelMapper: func(l logrus.Level) slog.Level {
		if l == logrus.InfoLevel {
			return slog.LevelDebug
		}
		return lslog.Level(l).Level()
	}})
}

// newLogger returns the logger that the resolver uses. It writes nothing itself and passes records
// of level info and above to slog, so request headers at debug level never leave the process.
func newLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	l.SetLevel(logrus.InfoLevel)
	l.AddHook(newHook())
	return l
}

var routeOnce sync.Once

// routeGlobalLogger points the global logger of containerd at slog, once. A few paths of the
// resolver, for example a close error of a response body, log through it and not through the
// context logger. This changes a process global: no other code of the process may rely on text
// output of the containerd logger.
func routeGlobalLogger() {
	routeOnce.Do(func() {
		g := log.L.Logger
		g.SetOutput(io.Discard)
		g.AddHook(newHook())
	})
}

func (s *Store) logCtx(ctx context.Context) context.Context {
	return log.WithLogger(ctx, logrus.NewEntry(s.logr))
}

// resolver returns a resolver with its own upload tracker, so no state outlives one call.
func (s *Store) resolver() remotes.Resolver {
	host := docker.RegistryHost{
		Client:       s.hc,
		Host:         s.host,
		Scheme:       "http",
		Path:         "/v2",
		Capabilities: docker.HostCapabilityPull | docker.HostCapabilityResolve | docker.HostCapabilityPush,
	}
	return docker.NewResolver(docker.ResolverOptions{
		Hosts: func(h string) ([]docker.RegistryHost, error) {
			if !strings.EqualFold(h, s.host) {
				return nil, fmt.Errorf("%w: %s", ErrOffHost, h)
			}
			return []docker.RegistryHost{host}, nil
		},
	})
}

func checkRepo(repo string) error {
	if len(repo) > 255 || !repoRe.MatchString(repo) {
		return fmt.Errorf("repository %q is not valid", repo)
	}
	return nil
}

func checkDigest(d string) (digest.Digest, error) {
	if !digestRe.MatchString(d) {
		return "", fmt.Errorf("digest %q is not sha256:<64 lowercase hex>", d)
	}
	return digest.Digest(d), nil
}

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// mapErr turns an error of the resolver or the transport into one of the sentinels.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	for _, sentinel := range []error{ErrDigestMismatch, ErrNotFound, ErrTooLarge, ErrDenied, ErrLayout, ErrOffHost, ErrContentEncoding} {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	var status remoteerrors.ErrUnexpectedStatus
	switch {
	case errdefs.IsNotFound(err):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case errors.Is(err, docker.ErrInvalidAuthorization):
		return fmt.Errorf("%w: %w", ErrDenied, err)
	case errors.As(err, &status) && (status.StatusCode == http.StatusUnauthorized || status.StatusCode == http.StatusForbidden):
		return fmt.Errorf("%w: %w", ErrDenied, err)
	}
	return err
}

func (s *Store) readable() error {
	if s.c.WriteOnly {
		return ErrWriteOnly
	}
	return nil
}

// Ping checks that the registry answers the version endpoint.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.readable(); err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodGet, "/v2/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return statusErr(resp, "ping")
}

// HasBlob reports whether the repository holds the blob.
func (s *Store) HasBlob(ctx context.Context, repo, dgst string) (bool, error) {
	if err := s.readable(); err != nil {
		return false, err
	}
	if err := checkRepo(repo); err != nil {
		return false, err
	}
	if _, err := checkDigest(dgst); err != nil {
		return false, err
	}
	resp, err := s.do(ctx, http.MethodHead, "/v2/"+repo+"/blobs/"+dgst)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, statusErr(resp, "check blob")
}

func (s *Store) do(ctx context.Context, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://"+s.host+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, mapErr(err)
	}
	return resp, nil
}

func statusErr(resp *http.Response, what string) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %s answered %s", ErrDenied, what, resp.Status)
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: %s answered %s", ErrNotFound, what, resp.Status)
	}
	return fmt.Errorf("%s answered %s", what, resp.Status)
}

// Manifest returns the manifest or index at the digest. The bytes match the digest, fit MaxManifest
// and carry no urls.
func (s *Store) Manifest(ctx context.Context, repo, dgst string) ([]byte, error) {
	return s.manifest(ctx, repo, dgst, s.c.MaxManifest)
}

func (s *Store) manifest(ctx context.Context, repo, dgst string, limit int64) ([]byte, error) {
	data, err := s.fetch(ctx, repo, dgst, ocispec.MediaTypeImageManifest, limit)
	if err != nil {
		return nil, err
	}
	if err := refuseURLs(data); err != nil {
		return nil, err
	}
	return data, nil
}

// Blob returns the blob at the digest. The bytes match the digest and fit MaxBlob.
func (s *Store) Blob(ctx context.Context, repo, dgst string) ([]byte, error) {
	return s.fetch(ctx, repo, dgst, mediaTypeBlob, s.c.MaxBlob)
}

// fetch reads one object by digest. The descriptor has no urls, and its size is the limit, which
// bounds the bytes that the resolver reads to limit plus one.
func (s *Store) fetch(ctx context.Context, repo, dgst, mediaType string, limit int64) ([]byte, error) {
	if err := s.readable(); err != nil {
		return nil, err
	}
	if err := checkRepo(repo); err != nil {
		return nil, err
	}
	d, err := checkDigest(dgst)
	if err != nil {
		return nil, err
	}
	ctx = s.logCtx(ctx)
	f, err := s.resolver().Fetcher(ctx, s.host+"/"+repo+"@"+dgst)
	if err != nil {
		return nil, mapErr(err)
	}
	rc, err := f.Fetch(ctx, ocispec.Descriptor{MediaType: mediaType, Digest: d, Size: limit})
	if err != nil {
		return nil, mapErr(err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		if errdefs.IsFailedPrecondition(err) {
			return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrTooLarge, dgst, limit)
		}
		return nil, mapErr(err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrTooLarge, dgst, limit)
	}
	if got := sha(data); got != dgst {
		return nil, fmt.Errorf("%w: asked for %s, got %s", ErrDigestMismatch, dgst, got)
	}
	return data, nil
}

// Resolve returns the digest that the tag names. The registry is trusted for this answer only
// as a pointer: Manifest checks the content against the digest.
func (s *Store) Resolve(ctx context.Context, repo, tag string) (string, error) {
	return s.resolve(ctx, repo, tag, s.c.MaxManifest)
}

func (s *Store) resolve(ctx context.Context, repo, tag string, limit int64) (string, error) {
	if err := s.readable(); err != nil {
		return "", err
	}
	if err := checkRepo(repo); err != nil {
		return "", err
	}
	if !tagRe.MatchString(tag) {
		return "", fmt.Errorf("tag %q is not valid", tag)
	}
	_, desc, err := s.resolver().Resolve(s.logCtx(ctx), s.host+"/"+repo+":"+tag)
	if err != nil {
		return "", mapErr(err)
	}
	if _, err := checkDigest(desc.Digest.String()); err != nil {
		return "", fmt.Errorf("registry answered: %w", err)
	}
	if desc.Size > limit {
		return "", fmt.Errorf("%w: %s names %d bytes", ErrTooLarge, tag, desc.Size)
	}
	return desc.Digest.String(), nil
}

// PushBlob uploads a blob. A blob that the registry already holds is a success.
func (s *Store) PushBlob(ctx context.Context, repo, dgst string, data []byte) error {
	if int64(len(data)) > s.c.MaxBlob {
		return fmt.Errorf("%w: blob of %d bytes, limit %d", ErrTooLarge, len(data), s.c.MaxBlob)
	}
	if err := checkRepo(repo); err != nil {
		return err
	}
	if _, err := checkDigest(dgst); err != nil {
		return err
	}
	if got := sha(data); got != dgst {
		return fmt.Errorf("%w: blob is %s, not %s", ErrDigestMismatch, got, dgst)
	}
	return s.push(ctx, s.host+"/"+repo+"@"+dgst, mediaTypeBlob, dgst, data)
}

// PushManifest uploads a manifest or index under a tag or its digest and returns its digest. An
// empty ref means the digest. Content that the registry already holds under the ref is a success.
func (s *Store) PushManifest(ctx context.Context, repo, ref, mediaType string, data []byte) (string, error) {
	if mediaType != ocispec.MediaTypeImageManifest && mediaType != ocispec.MediaTypeImageIndex {
		return "", fmt.Errorf("media type %q is not an OCI manifest or index", mediaType)
	}
	limit := s.c.MaxManifest
	if mediaType == ocispec.MediaTypeImageIndex {
		limit = max(limit, maxIndex)
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("%w: manifest of %d bytes, limit %d", ErrTooLarge, len(data), limit)
	}
	if err := checkRepo(repo); err != nil {
		return "", err
	}
	dgst := sha(data)
	var target string
	switch {
	case ref == "" || ref == dgst:
		target = s.host + "/" + repo + "@" + dgst
	case digestRe.MatchString(ref):
		return "", fmt.Errorf("%w: manifest is %s, not %s", ErrDigestMismatch, dgst, ref)
	case tagRe.MatchString(ref):
		target = s.host + "/" + repo + ":" + ref
	default:
		return "", fmt.Errorf("reference %q is not a tag or a sha256 digest", ref)
	}
	if err := s.push(ctx, target, mediaType, dgst, data); err != nil {
		return "", err
	}
	return dgst, nil
}

func (s *Store) push(ctx context.Context, ref, mediaType, dgst string, data []byte) error {
	ctx = s.logCtx(ctx)
	p, err := s.resolver().Pusher(ctx, ref)
	if err != nil {
		return mapErr(err)
	}
	d := ocispec.Descriptor{MediaType: mediaType, Digest: digest.Digest(dgst), Size: int64(len(data))}
	w, err := p.Push(ctx, d)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return mapErr(err)
	}
	defer w.Close()
	if _, err := w.Write(data); err != nil {
		return mapErr(err)
	}
	if err := w.Commit(ctx, d.Size, d.Digest); err != nil && !errdefs.IsAlreadyExists(err) {
		return mapErr(err)
	}
	return nil
}
