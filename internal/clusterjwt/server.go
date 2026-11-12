package clusterjwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	envspec "github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// PluginName is the name of the NodeAttestor plugin and the path segment of the agent ID.
const PluginName = "cluster_jwt"

// Reasons that the server adds to the reasons of Validate.
const (
	UnknownCell      Reason = "unknown_cell"
	RateLimited      Reason = "rate_limited"
	TooManyPending   Reason = "too_many_pending"
	ChallengeTimeout Reason = "challenge_timeout"
	Abandoned        Reason = "challenge_abandoned"
	NotConfigured    Reason = "not_configured"
)

const (
	defaultRate      = 2.0
	defaultBurst     = 10
	defaultInflight  = 8
	defaultTimeout   = "30s"
	defaultReload    = "10s"
	minReload        = time.Second
	recordSuffix     = ".dsse.json"
	maxKIDLogLength  = 64
	maxRecordFileLen = 1 << 20
)

var (
	cellNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	podUIDRE   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// pluginConfig is the HCL configuration of the plugin.
type pluginConfig struct {
	Env              string   `hcl:"env"`
	TrustDomain      string   `hcl:"trust_domain"`
	RecordsDir       string   `hcl:"records_dir"`
	RecordPublicKeys []string `hcl:"record_public_keys"`
	PerCellRate      float64  `hcl:"per_cell_rate"`
	PerCellBurst     int      `hcl:"per_cell_burst"`
	PerCellInflight  int      `hcl:"per_cell_inflight"`
	ChallengeTimeout string   `hcl:"challenge_timeout"`
	ReloadInterval   string   `hcl:"reload_interval"`
}

var configKeys = map[string]bool{
	"env": true, "trust_domain": true, "records_dir": true, "record_public_keys": true,
	"per_cell_rate": true, "per_cell_burst": true, "per_cell_inflight": true, "challenge_timeout": true,
	"reload_interval": true,
}

// state is the immutable result of one Configure call.
type state struct {
	env         string
	trustDomain string
	timeout     time.Duration
	records     map[string]record.Cell
	// digests holds the digest of the signed payload of each record.
	digests     map[string]string
	dir         string
	keys        []ed25519.PublicKey
	reloadEvery time.Duration
	rate        float64
	burst       int
	maxInflight int
	limit       *limiter
	gate        *gate
}

// Plugin is the SPIRE server NodeAttestor of type cluster_jwt.
type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	now    func() time.Time
	log    hclog.Logger
	st     atomic.Pointer[state]
	active atomic.Int64

	// tick and stop drive the reload goroutine. A nil tick means a real ticker that runs for the
	// process life.
	tick    <-chan time.Time
	stop    <-chan struct{}
	started atomic.Bool

	// markMu guards the fields below. They only grow for the process life.
	markMu sync.Mutex
	// marks holds the highest revision that any accepted spec gave each cell.
	marks map[string]envspec.Revision
	// retired holds the cells whose mark came from the retired list of a spec.
	retired  map[string]bool
	specMark envspec.Revision
	// noted holds the refusals that the last load logged, so a repeated refusal is logged once.
	noted map[string]bool

	// Test seams. They stay nil in production.
	afterResolve func()
	afterLoad    func()
	afterReload  func()
}

// New returns a plugin that is not configured yet. It reloads the records on a real ticker.
func New() *Plugin {
	return &Plugin{now: time.Now, log: hclog.NewNullLogger()}
}

// newWithTicker returns a plugin that reloads the records on each value of tick until stop closes.
func newWithTicker(tick <-chan time.Time, stop <-chan struct{}) *Plugin {
	p := New()
	p.tick, p.stop = tick, stop
	return p
}

// SetLogger receives the logger that SPIRE writes.
func (p *Plugin) SetLogger(l hclog.Logger) { p.log = l }

// Validate checks a configuration without applying it.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	if _, err := p.build(req.GetHclConfiguration(), req.GetCoreConfiguration().GetTrustDomain(), false); err != nil {
		return &configv1.ValidateResponse{Valid: false, Notes: []string{err.Error()}}, nil
	}
	return &configv1.ValidateResponse{Valid: true}, nil
}

// Configure loads the signed cell records and applies the configuration.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	st, err := p.build(req.GetHclConfiguration(), req.GetCoreConfiguration().GetTrustDomain(), true)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "cluster_jwt: %v", err)
	}
	if old := p.st.Load(); old != nil && old.rate == st.rate && old.burst == st.burst && old.maxInflight == st.maxInflight {
		st.limit, st.gate = old.limit, old.gate
	}
	p.st.Store(st)
	p.log.Info("configured", "env", st.env, "records", len(st.records), "reload_interval", st.reloadEvery.String())
	p.startReload(st.reloadEvery)
	return &configv1.ConfigureResponse{}, nil
}

// build parses the configuration and loads the records. Only a build with commit set raises the marks.
func (p *Plugin) build(text, coreTrustDomain string, commit bool) (*state, error) {
	st, err := p.parse(text, coreTrustDomain)
	if err != nil {
		return nil, err
	}
	snap, err := p.load(st, nil, commit)
	if err != nil {
		return nil, err
	}
	st.records, st.digests = snap.records, snap.digests
	return st, nil
}

func (p *Plugin) parse(text, coreTrustDomain string) (*state, error) {
	cfg := pluginConfig{PerCellRate: defaultRate, PerCellBurst: defaultBurst, PerCellInflight: defaultInflight, ChallengeTimeout: defaultTimeout, ReloadInterval: defaultReload}
	if err := hcl.Decode(&cfg, text); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	var raw map[string]any
	if err := hcl.Decode(&raw, text); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	for k := range raw {
		if !configKeys[k] {
			return nil, fmt.Errorf("unknown setting %q", k)
		}
	}
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = coreTrustDomain
	}
	switch {
	case cfg.Env == "":
		return nil, errors.New("env is required")
	case cfg.TrustDomain == "":
		return nil, errors.New("trust_domain is required")
	case coreTrustDomain != "" && cfg.TrustDomain != coreTrustDomain:
		return nil, errors.New("trust_domain differs from the server trust domain")
	case cfg.RecordsDir == "":
		return nil, errors.New("records_dir is required")
	case cfg.PerCellRate <= 0:
		return nil, errors.New("per_cell_rate must be above zero")
	case cfg.PerCellBurst < 1:
		return nil, errors.New("per_cell_burst must be at least 1")
	case cfg.PerCellInflight < 1:
		return nil, errors.New("per_cell_inflight must be at least 1")
	}
	timeout, err := time.ParseDuration(cfg.ChallengeTimeout)
	if err != nil || timeout <= 0 {
		return nil, errors.New("challenge_timeout must be a positive duration such as 30s")
	}
	every, err := time.ParseDuration(cfg.ReloadInterval)
	if err != nil || (every != 0 && every < minReload) {
		return nil, errors.New("reload_interval must be 0s or a duration of at least 1s")
	}
	keys, err := parseKeys(cfg.RecordPublicKeys)
	if err != nil {
		return nil, err
	}
	return &state{
		env: cfg.Env, trustDomain: cfg.TrustDomain, timeout: timeout,
		dir: cfg.RecordsDir, keys: keys, reloadEvery: every,
		rate: cfg.PerCellRate, burst: cfg.PerCellBurst, maxInflight: cfg.PerCellInflight,
		limit: newLimiter(cfg.PerCellRate, cfg.PerCellBurst, p.now),
		gate:  newGate(cfg.PerCellInflight),
	}, nil
}

func parseKeys(in []string) ([]ed25519.PublicKey, error) {
	if len(in) == 0 {
		return nil, errors.New("record_public_keys needs at least one key")
	}
	keys := make([]ed25519.PublicKey, 0, len(in))
	for i, s := range in {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("record_public_keys[%d] is not a base64 Ed25519 public key", i)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

// Attest challenges the agent with a fresh nonce and checks the token that answers it.
func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	p.active.Add(1)
	defer p.active.Add(-1)

	st := p.st.Load()
	if st == nil {
		return p.deny("", "", NotConfigured)
	}
	first, err := stream.Recv()
	if err != nil {
		return p.deny("", "", Malformed)
	}
	var payload Payload
	if err := decodeStrict(first.GetPayload(), &payload); err != nil {
		return p.deny("", "", Malformed)
	}
	rec, ok := st.records[payload.Cell]
	if !ok {
		return p.deny(logCell(payload.Cell), "", UnknownCell)
	}
	if rec.Revoked {
		return p.deny(rec.Name, "", Revoked)
	}
	if !st.gate.acquire(rec.Name) {
		return p.deny(rec.Name, "", TooManyPending)
	}
	defer st.gate.release(rec.Name)

	nonce, err := newNonce()
	if err != nil {
		p.log.Error("nonce generation failed", "error", err.Error())
		return status.Error(codes.Internal, "cluster_jwt: internal")
	}
	if err := stream.Send(&nodeattestorv1.AttestResponse{Response: &nodeattestorv1.AttestResponse_Challenge{Challenge: []byte(nonce)}}); err != nil {
		return p.deny(rec.Name, "", Abandoned)
	}
	sent := time.Now()
	reply, reason := recvWithin(stream, st.timeout)
	if reason != "" {
		return p.deny(rec.Name, "", reason)
	}
	// replyMS is the time from the challenge to the reply, which challenge_timeout bounds.
	replyMS := time.Since(sent).Milliseconds()
	var resp Response
	if err := decodeStrict(reply.GetChallengeResponse(), &resp); err != nil {
		return p.deny(rec.Name, "", Malformed, "challenge_reply_ms", replyMS)
	}
	kid := tokenKID(resp.Token)
	claims, err := Validate(rec, resp.Token, st.env, nonce, p.now())
	if err != nil {
		return p.deny(rec.Name, kid, ReasonOf(err), "challenge_reply_ms", replyMS)
	}
	if !podUIDRE.MatchString(claims.PodUID) {
		return p.deny(rec.Name, kid, Malformed, "challenge_reply_ms", replyMS)
	}
	if !st.limit.allow(rec.Name) {
		return p.deny(rec.Name, kid, RateLimited, "challenge_reply_ms", replyMS)
	}

	id := fmt.Sprintf("spiffe://%s/spire/agent/%s/%s/%s/%s", st.trustDomain, PluginName, rec.Name, claims.PodUID, nonceHash(nonce))
	p.log.Info("attested", "cell", rec.Name, "kid", kid, "namespace", claims.Namespace, "service_account", claims.ServiceAccount,
		"agent_id", id, "challenge_reply_ms", replyMS)
	return stream.Send(&nodeattestorv1.AttestResponse{Response: &nodeattestorv1.AttestResponse_AgentAttributes{
		AgentAttributes: &nodeattestorv1.AgentAttributes{
			SpiffeId: id,
			SelectorValues: []string{
				"cell:" + rec.Name,
				"ns:" + claims.Namespace,
				"sa:" + claims.Namespace + ":" + claims.ServiceAccount,
			},
			CanReattest: false,
		},
	}})
}

// recvWithin reads the next request, or returns the reason it could not. The reading goroutine ends
// when gRPC cancels the stream after Attest returns.
func recvWithin(stream nodeattestorv1.NodeAttestor_AttestServer, d time.Duration) (*nodeattestorv1.AttestRequest, Reason) {
	type result struct {
		req *nodeattestorv1.AttestRequest
		err error
	}
	ch := make(chan result, 1)
	go func() {
		req, err := stream.Recv()
		ch <- result{req, err}
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, Abandoned
		}
		return r.req, ""
	case <-timer.C:
		return nil, ChallengeTimeout
	case <-stream.Context().Done():
		return nil, Abandoned
	}
}

func newNonce() (string, error) {
	b := make([]byte, NonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// deny logs the refusal with any extra key and value pairs, and returns the gRPC error. It never
// receives the token.
func (p *Plugin) deny(cell, kid string, reason Reason, extra ...any) error {
	p.log.Warn("attestation refused", append([]any{"reason", string(reason), "cell", cell, "kid", kid}, extra...)...)
	return status.Error(codes.PermissionDenied, "cluster_jwt: "+string(reason))
}

func logCell(s string) string {
	if len(s) > maxKIDLogLength {
		return s[:maxKIDLogLength]
	}
	return s
}

// tokenKID returns the key ID from the unverified token header, for logs only.
func tokenKID(token string) string {
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return ""
	}
	var h struct {
		KID string `json:"kid"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return logCell(h.KID)
}
