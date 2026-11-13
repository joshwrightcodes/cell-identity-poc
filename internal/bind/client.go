// Package bind binds the cluster issuer of a cell to the management plane. The client asks for a
// nonce, mints a token for the audience of that nonce, and sends the token with the nonce. The
// connection has server-only TLS: the client sends no certificate, and the server is the one
// SPIFFE ID that the caller expects.
package bind

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"go.opentelemetry.io/otel/trace"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/satoken"
	"github.com/joshwrightcodes/cell-identity-poc/internal/telemetry"
)

// Defaults of Config.
const (
	DefaultMinBackoff     = time.Second
	DefaultMaxBackoff     = 30 * time.Second
	DefaultRefusedBackoff = 60 * time.Second
	DefaultAttemptTimeout = 30 * time.Second
	DefaultRecheckEvery   = 5 * time.Minute

	tokenTTL       = 600 * time.Second
	maxResponse    = 64 << 10
	maxHeaderBytes = 16 << 10
	maxIDLength    = 32
	pingIdle       = 15 * time.Second
	pingTimeout    = 10 * time.Second
	recheckSpread  = 0.2
)

// TokenFunc returns a token whose only audience is audience.
type TokenFunc func(ctx context.Context, audience string) (string, error)

// PodTokenFunc returns a TokenFunc that requests a token of 600 s for the service account, bound
// to the pod.
func PodTokenFunc(c corev1client.ServiceAccountsGetter, namespace, serviceAccount, podName, podUID string) TokenFunc {
	return func(ctx context.Context, audience string) (string, error) {
		return satoken.Create(ctx, c, satoken.Request{
			Namespace: namespace, ServiceAccount: serviceAccount, PodName: podName, PodUID: podUID,
			Audience: audience, TTL: tokenTTL,
		})
	}
}

// ClientTLS returns the TLS settings for the bind listener: the server must present the SPIFFE ID
// expect and a certificate that chains to peer. The client sends no certificate. Only TLS 1.3 and
// HTTP/2 are allowed.
func ClientTLS(peer x509bundle.Source, expect spiffeid.ID) *tls.Config {
	cfg := tlsconfig.TLSClientConfig(peer, tlsconfig.AuthorizeID(expect))
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.NextProtos = []string{"h2"}
	return cfg
}

// Config holds the settings of Once and Run. A zero duration takes the default.
type Config struct {
	Cell     string
	Upstream string // host:port of the bind listener
	TLS      *tls.Config
	Tokens   TokenFunc
	Log      *slog.Logger

	// MinBackoff and MaxBackoff bound the wait after a transient failure. RefusedBackoff is the wait
	// after the management plane refuses a request.
	MinBackoff, MaxBackoff, RefusedBackoff time.Duration
	// AttemptTimeout bounds one Once, or one recheck.
	AttemptTimeout time.Duration
	// RecheckEvery is the interval at which Run asks whether the cell is still bound.
	RecheckEvery time.Duration
	// Sleep waits for d or until ctx ends. The default uses a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Observe, when set, receives the result of each Once that Run makes: a bind status,
	// "refused" or "error".
	Observe func(ctx context.Context, result string)
	// Tracer, when set, starts a span for each bind attempt, so the log lines of the attempt carry trace_id and
	// the requests carry the traceparent header.
	Tracer trace.Tracer

	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (c Config) withDefaults() (Config, error) {
	switch {
	case c.Cell == "":
		return c, errors.New("bind: Cell is required")
	case c.Upstream == "":
		return c, errors.New("bind: Upstream is required")
	case c.TLS == nil:
		return c, errors.New("bind: TLS is required")
	case c.Tokens == nil:
		return c, errors.New("bind: Tokens is required")
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	for _, d := range []struct {
		v   *time.Duration
		def time.Duration
	}{
		{&c.MinBackoff, DefaultMinBackoff}, {&c.MaxBackoff, DefaultMaxBackoff}, {&c.RefusedBackoff, DefaultRefusedBackoff},
		{&c.AttemptTimeout, DefaultAttemptTimeout}, {&c.RecheckEvery, DefaultRecheckEvery},
	} {
		if *d.v <= 0 {
			*d.v = d.def
		}
	}
	if c.MaxBackoff < c.MinBackoff {
		c.MaxBackoff = c.MinBackoff
	}
	if c.Sleep == nil {
		c.Sleep = sleep
	}
	return c, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Refused is the error of a definite refusal: the management plane answered HTTP 403.
type Refused struct{ RequestID string }

func (e *Refused) Error() string { return "the management plane refused the request: " + e.RequestID }

// LogAttrs adds the request ID to the error line of a command.
func (e *Refused) LogAttrs() []any { return []any{"request_id", e.RequestID} }

// StatusError is the error of any other answer that is not HTTP 200.
type StatusError struct{ Code int }

func (e *StatusError) Error() string {
	return fmt.Sprintf("the management plane answered HTTP %d", e.Code)
}

// Client sends the nonce and bind requests of one cell. Each request uses its own connection, so
// a connection that the server or the network closed between two requests cannot fail an attempt.
type Client struct {
	cell string
	base string
	http *http.Client
	tr   *http.Transport
}

// NewClient returns a client for the bind listener at upstream. It reads Upstream, TLS and Cell
// from cfg. Close the client after use.
func NewClient(cfg Config) *Client {
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	tr := &http.Transport{
		TLSClientConfig:   cfg.TLS,
		Protocols:         protos,
		DisableKeepAlives: true,
		// The limit is far below the default of 10 MiB, for a pod with a small memory limit.
		MaxResponseHeaderBytes: maxHeaderBytes,
		HTTP2:                  &http.HTTP2Config{SendPingTimeout: pingIdle, PingTimeout: pingTimeout},
		DialContext:            cfg.dial,
	}
	return &Client{cell: cfg.Cell, base: "https://" + cfg.Upstream, tr: tr, http: &http.Client{
		Transport: telemetry.Transport(tr),
		// A redirect would send the token to a host that the SPIFFE ID check never covered.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Close drops idle connections.
func (c *Client) Close() { c.tr.CloseIdleConnections() }

// Nonce requests a nonce. The request body is empty.
func (c *Client) Nonce(ctx context.Context) (mgmtapi.NonceResponse, error) {
	var out mgmtapi.NonceResponse
	err := c.post(ctx, mgmtapi.NoncePath(c.cell), nil, &out)
	return out, err
}

// Bind sends a bind request.
func (c *Client) Bind(ctx context.Context, req mgmtapi.BindRequest) (mgmtapi.BindResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return mgmtapi.BindResponse{}, err
	}
	var out mgmtapi.BindResponse
	if err = c.post(ctx, mgmtapi.BindPath(c.cell), body, &out); err != nil {
		return mgmtapi.BindResponse{}, err
	}
	if !knownStatus(out.Status) {
		return mgmtapi.BindResponse{}, errors.New("the bind response holds no known status")
	}
	return out, nil
}

func (c *Client) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponse {
		return fmt.Errorf("the response is too large: more than %d bytes", maxResponse)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode the response: %w", err)
		}
		return nil
	case http.StatusForbidden:
		var d mgmtapi.Denied
		_ = json.Unmarshal(raw, &d)
		return &Refused{RequestID: cleanID(d.RequestID)}
	default:
		return &StatusError{Code: resp.StatusCode}
	}
}

// cleanID keeps the leading characters of a request ID that a log line or a command output can
// carry safely.
func cleanID(id string) string {
	var b strings.Builder
	for _, r := range id {
		if b.Len() >= maxIDLength {
			break
		}
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// CheckNonce reports an error unless n is a usable nonce for cell: a nonce of base64url
// characters, at most 128 bytes long, and the bind audience of that nonce. The error text never
// repeats a value from the answer.
func CheckNonce(cell string, n mgmtapi.NonceResponse) error {
	if !clusterjwt.ValidNonce(n.Nonce) {
		return errors.New("the nonce response holds no valid nonce")
	}
	if n.Audience != mgmtapi.BindAudience(cell, n.Nonce) {
		return errors.New("the audience of the nonce response is not the bind audience of this cell and nonce")
	}
	return nil
}

// knownStatus reports whether status is a result that a bind can have.
func knownStatus(status string) bool {
	switch status {
	case mgmtapi.StatusBound, mgmtapi.StatusAlreadyBound, mgmtapi.StatusKeysUpdated:
		return true
	}
	return false
}

// Once binds the cell: it requests a nonce, mints a token for the audience of the nonce, and sends
// the bind request. The whole attempt takes at most AttemptTimeout. A *Refused error is a definite
// refusal. Every other error is transient.
func Once(ctx context.Context, cfg Config) (mgmtapi.BindResponse, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return mgmtapi.BindResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.AttemptTimeout)
	defer cancel()
	c := NewClient(cfg)
	defer c.Close()

	n, err := c.Nonce(ctx)
	if err != nil {
		return mgmtapi.BindResponse{}, fmt.Errorf("request a nonce: %w", err)
	}
	if err := CheckNonce(cfg.Cell, n); err != nil {
		return mgmtapi.BindResponse{}, err
	}
	token, err := cfg.Tokens(ctx, n.Audience)
	if err != nil {
		return mgmtapi.BindResponse{}, fmt.Errorf("mint a token: %w", err)
	}
	resp, err := c.Bind(ctx, mgmtapi.BindRequest{Nonce: n.Nonce, Token: token})
	if err != nil {
		return mgmtapi.BindResponse{}, fmt.Errorf("send the bind request: %w", err)
	}
	return resp, nil
}

// Run repeats Once until a bind succeeds, with no limit. After a success it asks for a nonce every
// RecheckEvery, with jitter, and binds again when the answer has Bound false. Run returns when ctx
// ends, or at once when cfg is invalid.
func Run(ctx context.Context, cfg Config) error {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return err
	}
	for {
		if err := bindUntilDone(ctx, cfg); err != nil {
			return err
		}
		if err := recheck(ctx, cfg); err != nil {
			return err
		}
	}
}

// attempt starts the span of one bind attempt. The returned function ends it.
func (c Config) attempt(ctx context.Context) (context.Context, func()) {
	if c.Tracer == nil {
		return ctx, func() {}
	}
	ctx, span := c.Tracer.Start(ctx, "celld.bind")
	return ctx, func() { span.End() }
}

func (c Config) observe(ctx context.Context, result string) {
	if c.Observe != nil {
		c.Observe(ctx, result)
	}
}

func bindUntilDone(ctx context.Context, cfg Config) error {
	for failures := 0; ; failures++ {
		actx, end := cfg.attempt(ctx)
		resp, err := Once(actx, cfg)
		end()
		if err == nil {
			cfg.observe(ctx, resp.Status)
			cfg.Log.InfoContext(actx, "bound", "cell", cfg.Cell, "status", resp.Status,
				"record_epoch", resp.Record.Epoch, "record_counter", resp.Record.Counter)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var wait time.Duration
		var refused *Refused
		result := "error"
		if errors.As(err, &refused) {
			result, wait = "refused", jitter(cfg.RefusedBackoff, 0.1, 0)
			failures = 0
		} else {
			wait = backoff(cfg, failures)
		}
		cfg.observe(ctx, result)
		cfg.Log.WarnContext(actx, "bind failed", "cell", cfg.Cell, "result", result, "error", err.Error(), "retry_in", wait.String())
		if err := cfg.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func recheck(ctx context.Context, cfg Config) error {
	var refused *Refused
	wait := jitter(cfg.RecheckEvery, recheckSpread, -recheckSpread/2)
	for failures := 0; ; {
		if err := cfg.Sleep(ctx, wait); err != nil {
			return err
		}
		bound, err := checkBound(ctx, cfg)
		switch {
		case err != nil && ctx.Err() != nil:
			return ctx.Err()
		case errors.As(err, &refused):
			wait, failures = jitter(cfg.RefusedBackoff, 0.1, 0), 0
			cfg.Log.WarnContext(ctx, "bind recheck refused", "cell", cfg.Cell, "request_id", refused.RequestID, "retry_in", wait.String())
		case err != nil:
			wait = backoff(cfg, failures)
			failures++
			cfg.Log.WarnContext(ctx, "bind recheck failed", "cell", cfg.Cell, "error", err.Error(), "retry_in", wait.String())
		case !bound:
			cfg.Log.WarnContext(ctx, "the management plane holds no record", "cell", cfg.Cell)
			return nil
		default:
			failures, wait = 0, jitter(cfg.RecheckEvery, recheckSpread, -recheckSpread/2)
		}
	}
}

func checkBound(ctx context.Context, cfg Config) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.AttemptTimeout)
	defer cancel()
	c := NewClient(cfg)
	defer c.Close()
	n, err := c.Nonce(ctx)
	if err != nil {
		return false, err
	}
	return n.Bound, nil
}

// backoff returns the wait after the failures-th transient failure in a row: MinBackoff doubled
// each time up to MaxBackoff, plus up to half again, and never more than MaxBackoff.
func backoff(cfg Config, failures int) time.Duration {
	d := cfg.MinBackoff
	for i := 0; i < failures && d < cfg.MaxBackoff; i++ {
		d *= 2
	}
	d = min(d, cfg.MaxBackoff)
	return min(jitter(d, 0.5, 0), cfg.MaxBackoff)
}

// jitter returns d scaled by a random factor between 1+offset and 1+offset+spread.
func jitter(d time.Duration, spread, offset float64) time.Duration {
	return time.Duration(float64(d) * (1 + offset + rand.Float64()*spread))
}
