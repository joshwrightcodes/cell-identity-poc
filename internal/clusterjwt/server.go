package clusterjwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
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
}

var configKeys = map[string]bool{
	"env": true, "trust_domain": true, "records_dir": true, "record_public_keys": true,
	"per_cell_rate": true, "per_cell_burst": true, "per_cell_inflight": true, "challenge_timeout": true,
}

// state is the immutable result of one Configure call.
type state struct {
	env         string
	trustDomain string
	timeout     time.Duration
	records     map[string]record.Cell
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
}

// New returns a plugin that is not configured yet.
func New() *Plugin {
	return &Plugin{now: time.Now, log: hclog.NewNullLogger()}
}

// SetLogger receives the logger that SPIRE writes.
func (p *Plugin) SetLogger(l hclog.Logger) { p.log = l }

// Validate checks a configuration without applying it.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	if _, err := p.build(req.GetHclConfiguration(), req.GetCoreConfiguration().GetTrustDomain()); err != nil {
		return &configv1.ValidateResponse{Valid: false, Notes: []string{err.Error()}}, nil
	}
	return &configv1.ValidateResponse{Valid: true}, nil
}

// Configure loads the signed cell records and applies the configuration.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	st, err := p.build(req.GetHclConfiguration(), req.GetCoreConfiguration().GetTrustDomain())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "cluster_jwt: %v", err)
	}
	if old := p.st.Load(); old != nil && old.rate == st.rate && old.burst == st.burst && old.maxInflight == st.maxInflight {
		st.limit, st.gate = old.limit, old.gate
	}
	p.st.Store(st)
	p.log.Info("configured", "env", st.env, "records", len(st.records))
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) build(text, coreTrustDomain string) (*state, error) {
	cfg := pluginConfig{PerCellRate: defaultRate, PerCellBurst: defaultBurst, PerCellInflight: defaultInflight, ChallengeTimeout: defaultTimeout}
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
	keys, err := parseKeys(cfg.RecordPublicKeys)
	if err != nil {
		return nil, err
	}
	records, err := p.loadRecords(cfg.RecordsDir, cfg.Env, keys)
	if err != nil {
		return nil, err
	}
	return &state{
		env: cfg.Env, trustDomain: cfg.TrustDomain, timeout: timeout, records: records,
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

// loadRecords reads every *.dsse.json file in dir. A file that fails verification, names another
// environment or holds an unusable cell name is logged and skipped, so that its cell stays unknown.
// For one cell name, supersedes picks the record.
func (p *Plugin) loadRecords(dir, env string, keys []ed25519.PublicKey) (map[string]record.Cell, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read records_dir: %w", err)
	}
	out := map[string]record.Cell{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, recordSuffix) {
			continue
		}
		path := filepath.Join(dir, name)
		if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() || fi.Size() > maxRecordFileLen {
			p.log.Warn("skipped record file", "file", name, "reason", "not a regular file of acceptable size")
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			p.log.Warn("skipped record file", "file", name, "reason", "unreadable")
			continue
		}
		rec, err := record.Verify(data, keys)
		switch {
		case err != nil:
			p.log.Error("record file failed verification", "file", name, "file_cell", strings.TrimSuffix(name, recordSuffix), "reason", err.Error())
			continue
		case rec.Env != env:
			p.log.Warn("skipped record file", "file", name, "reason", "other environment", "record_env", rec.Env)
			continue
		case !cellNameRE.MatchString(rec.Name):
			p.log.Warn("skipped record file", "file", name, "reason", "cell name is not a DNS label")
			continue
		}
		if old, ok := out[rec.Name]; ok && !supersedes(rec, old) {
			continue
		}
		out[rec.Name] = rec
	}
	return out, nil
}

// supersedes reports whether a replaces b for one cell. A higher epoch and counter wins. At the same
// epoch and counter, the revoked record wins, whatever the order of the files.
func supersedes(a, b record.Cell) bool {
	if a.Epoch != b.Epoch {
		return a.Epoch > b.Epoch
	}
	if a.Counter != b.Counter {
		return a.Counter > b.Counter
	}
	return a.Revoked && !b.Revoked
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
