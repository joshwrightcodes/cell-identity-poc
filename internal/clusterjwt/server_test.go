package clusterjwt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const testTrustDomain = "dev.env.poc.internal"

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fixture struct {
	t      *testing.T
	plugin *Plugin
	client *nodeattestorv1.NodeAttestorPluginClient
	logs   *syncBuffer
	keys   keys
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	cfg    *configv1.ConfigServiceClient
	base   string
}

type fixtureOptions struct {
	cells          []string
	extraHCL       string
	signRecordWith ed25519.PrivateKey
	revoked        map[string]bool
	// mutate changes the record of a cell before it is signed.
	mutate func(rec *record.Cell)
}

func newFixture(t *testing.T, o fixtureOptions) *fixture {
	t.Helper()
	if o.cells == nil {
		o.cells = []string{"dev-cell-1", "dev-cell-2"}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := newKeys(t)
	dir := t.TempDir()
	signer := priv
	if o.signRecordWith != nil {
		signer = o.signRecordWith
	}
	for _, name := range o.cells {
		rec := k.record(t)
		rec.Name = name
		rec.Revoked = o.revoked[name]
		if o.mutate != nil {
			o.mutate(&rec)
		}
		env, err := record.Sign(rec, signer)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".dsse.json"), env, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	logs := &syncBuffer{}
	logger := hclog.New(&hclog.LoggerOptions{Level: hclog.Debug, Output: logs, JSONFormat: true})
	p := New()
	p.now = func() time.Time { return testNow }
	f := &fixture{t: t, plugin: p, client: new(nodeattestorv1.NodeAttestorPluginClient), logs: logs, keys: k, pub: pub, priv: priv}
	cfg := new(configv1.ConfigServiceClient)
	f.cfg = cfg
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   nodeattestorv1.NodeAttestorPluginServer(p),
		PluginClient:   f.client,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(p)},
		ServiceClients: []pluginsdk.ServiceClient{cfg},
		Logger:         logger,
	})
	hcl := fmt.Sprintf(`
env = "dev"
trust_domain = %q
records_dir = %q
record_public_keys = [%q]
`, testTrustDomain, dir, base64.StdEncoding.EncodeToString(pub))
	f.base = hcl
	hcl += o.extraHCL + "\n"
	_, err = cfg.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: testTrustDomain},
		HclConfiguration:  hcl,
	})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	return f
}

// attest runs one attestation. tokenFor receives the challenge nonce and returns the token to send.
func (f *fixture) attest(cell string, tokenFor func(nonce string) string) (*nodeattestorv1.AgentAttributes, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.Attest(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	payload, _ := json.Marshal(Payload{Cell: cell})
	if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}}); err != nil {
		f.t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	nonce := string(resp.GetChallenge())
	if nonce == "" {
		f.t.Fatalf("expected a challenge, got %v", resp)
	}
	body, _ := json.Marshal(Response{Token: tokenFor(nonce)})
	if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_ChallengeResponse{ChallengeResponse: body}}); err != nil {
		f.t.Fatal(err)
	}
	resp, err = stream.Recv()
	if err != nil {
		return nil, err
	}
	return resp.GetAgentAttributes(), nil
}

func (f *fixture) goodToken(nonce string) string {
	s := f.keys.good()
	s.Audience = []string{"spire-" + testEnv + "/" + nonce}
	return s.token(f.t)
}

func wantDenied(t *testing.T, err error, reason Reason) {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v (err %v), want PermissionDenied", status.Code(err), err)
	}
	if got, want := status.Convert(err).Message(), "cluster_jwt: "+string(reason); got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}

func TestAttestIssuesAgentID(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	attrs, err := f.attest("dev-cell-1", f.goodToken)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^spiffe://dev\.env\.poc\.internal/spire/agent/cluster_jwt/dev-cell-1/pod-uid/[0-9a-f]{32}$`)
	if !re.MatchString(attrs.GetSpiffeId()) {
		t.Fatalf("agent id = %q", attrs.GetSpiffeId())
	}
	want := []string{"cell:dev-cell-1", "ns:celld", "sa:celld:celld"}
	if got := attrs.GetSelectorValues(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("selectors = %v, want %v", got, want)
	}
	if attrs.GetCanReattest() {
		t.Fatal("CanReattest must be false")
	}
}

func TestAgentIDDiffersPerAttestation(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	a, err := f.attest("dev-cell-1", f.goodToken)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.attest("dev-cell-1", f.goodToken)
	if err != nil {
		t.Fatal(err)
	}
	if a.GetSpiffeId() == b.GetSpiffeId() {
		t.Fatalf("two attestations share agent id %q", a.GetSpiffeId())
	}
}

func TestNonceHashIsFirst16BytesOfSHA256(t *testing.T) {
	if got := nonceHash("abc"); got != "ba7816bf8f01cfea414140de5dae2223" {
		t.Fatalf("nonceHash = %q", got)
	}
}

func TestChallengeIsBase64URLOf32Bytes(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	var seen string
	_, err := f.attest("dev-cell-1", func(nonce string) string { seen = nonce; return f.goodToken(nonce) })
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(seen)
	if err != nil || len(raw) != 32 {
		t.Fatalf("nonce %q: %d bytes, err %v", seen, len(raw), err)
	}
}

func TestTokenForOtherNonceFails(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	_, err := f.attest("dev-cell-1", func(string) string { return f.goodToken("an-earlier-challenge") })
	wantDenied(t, err, WrongAudience)
}

func TestUnknownCellFails(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := f.client.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(Payload{Cell: "nope"})
	if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}}); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	wantDenied(t, err, UnknownCell)
}

func TestUnsignedRecordFails(t *testing.T) {
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, fixtureOptions{signRecordWith: other})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := f.client.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(Payload{Cell: "dev-cell-1"})
	if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}}); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	wantDenied(t, err, UnknownCell)
}

func TestRevokedCellFails(t *testing.T) {
	f := newFixture(t, fixtureOptions{revoked: map[string]bool{"dev-cell-1": true}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := f.client.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(Payload{Cell: "dev-cell-1"})
	if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}}); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	wantDenied(t, err, Revoked)
}

func TestMalformedPayloadFails(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	for _, p := range []string{``, `not json`, `{"cell":"dev-cell-1","extra":1}`, `{"cell":"dev-cell-1"} x`} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := f.client.Attest(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: []byte(p)}}); err != nil {
			t.Fatal(err)
		}
		_, err = stream.Recv()
		wantDenied(t, err, Malformed)
		cancel()
	}
}

func TestMalformedResponseFails(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := f.client.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(Payload{Cell: "dev-cell-1"})
	_ = stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}})
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_ChallengeResponse{ChallengeResponse: []byte(`{"token":1}`)}})
	_, err = stream.Recv()
	wantDenied(t, err, Malformed)
}

func TestRateLimitPerCell(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	for i := 0; i < 10; i++ {
		if _, err := f.attest("dev-cell-1", f.goodToken); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	_, err := f.attest("dev-cell-1", f.goodToken)
	wantDenied(t, err, RateLimited)
	if _, err := f.attest("dev-cell-2", f.goodToken); err != nil {
		t.Fatalf("other cell: %v", err)
	}
}

func (f *fixture) reconfigure(t *testing.T, extra string) *state {
	t.Helper()
	_, err := f.cfg.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: testTrustDomain},
		HclConfiguration:  f.base + extra + "\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f.plugin.st.Load()
}

func (f *fixture) openChallenge(cell string) (nodeattestorv1.NodeAttestor_AttestClient, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := f.client.Attest(ctx)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	payload, _ := json.Marshal(Payload{Cell: cell})
	if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}}); err != nil {
		cancel()
		return nil, nil, err
	}
	if _, err := stream.Recv(); err != nil {
		cancel()
		return stream, func() {}, err
	}
	return stream, cancel, nil
}

func TestJunkAttemptsDoNotConsumeSuccessBudget(t *testing.T) {
	f := newFixture(t, fixtureOptions{extraHCL: "per_cell_burst = 2\nper_cell_rate = 0.001"})
	for i := 0; i < 6; i++ {
		_, err := f.attest("dev-cell-1", func(string) string { return "garbage" })
		wantDenied(t, err, Malformed)
	}
	_, err := f.attest("dev-cell-1", func(string) string { return f.goodToken("an-earlier-challenge") })
	wantDenied(t, err, WrongAudience)
	for i := 0; i < 2; i++ {
		if _, err := f.attest("dev-cell-1", f.goodToken); err != nil {
			t.Fatalf("success %d: %v", i+1, err)
		}
	}
	_, err = f.attest("dev-cell-1", f.goodToken)
	wantDenied(t, err, RateLimited)
}

func TestInflightCapRefusesNinthChallenge(t *testing.T) {
	f := newFixture(t, fixtureOptions{extraHCL: `challenge_timeout = "30s"`})
	var cancels []context.CancelFunc
	for i := 0; i < 8; i++ {
		_, cancel, err := f.openChallenge("dev-cell-1")
		if err != nil {
			t.Fatalf("challenge %d: %v", i+1, err)
		}
		cancels = append(cancels, cancel)
	}
	_, cancel, err := f.openChallenge("dev-cell-1")
	if cancel != nil {
		defer cancel()
	}
	wantDenied(t, err, TooManyPending)
	if _, err := f.attest("dev-cell-2", f.goodToken); err != nil {
		t.Fatalf("other cell: %v", err)
	}
	for _, c := range cancels {
		c()
	}
	waitIdle(t, f.plugin)
	if n := f.plugin.st.Load().gate.count("dev-cell-1"); n != 0 {
		t.Fatalf("%d in-flight slots left", n)
	}
	if _, err := f.attest("dev-cell-1", f.goodToken); err != nil {
		t.Fatalf("after abandon: %v", err)
	}
}

func TestAbandonedStreamsFreeInflightSlot(t *testing.T) {
	f := newFixture(t, fixtureOptions{extraHCL: "per_cell_inflight = 1\nchallenge_timeout = \"200ms\""})
	for i := 0; i < 3; i++ {
		_, cancel, err := f.openChallenge("dev-cell-1")
		if err != nil {
			t.Fatalf("round %d: %v", i+1, err)
		}
		cancel()
		waitIdle(t, f.plugin)
	}
	// A silent client frees the slot through the challenge timeout.
	stream, cancel, err := f.openChallenge("dev-cell-1")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	_, err = stream.Recv()
	wantDenied(t, err, ChallengeTimeout)
	if n := f.plugin.st.Load().gate.count("dev-cell-1"); n != 0 {
		t.Fatalf("%d slots left", n)
	}
}

func TestRealCellAttestsDuringAbandonedFlood(t *testing.T) {
	f := newFixture(t, fixtureOptions{extraHCL: "per_cell_inflight = 4\nchallenge_timeout = \"150ms\""})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, cancel, err := f.openChallenge("dev-cell-1"); err == nil {
					time.Sleep(10 * time.Millisecond)
					cancel()
				}
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := f.attest("dev-cell-1", f.goodToken)
		if err == nil {
			return
		}
		if status.Convert(err).Message() != "cluster_jwt: "+string(TooManyPending) || time.Now().After(deadline) {
			t.Fatalf("real attestation failed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestParallelAttestations(t *testing.T) {
	f := newFixture(t, fixtureOptions{extraHCL: "per_cell_burst = 100\nper_cell_inflight = 16"})
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cell := "dev-cell-1"
			if i%2 == 1 {
				cell = "dev-cell-2"
			}
			_, err := f.attest(cell, f.goodToken)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	waitIdle(t, f.plugin)
}

func TestReconfigureKeepsLimiterState(t *testing.T) {
	f := newFixture(t, fixtureOptions{extraHCL: "per_cell_burst = 2\nper_cell_rate = 0.001"})
	for i := 0; i < 2; i++ {
		if _, err := f.attest("dev-cell-1", f.goodToken); err != nil {
			t.Fatal(err)
		}
	}
	old := f.plugin.st.Load()
	same := f.reconfigure(t, "per_cell_burst = 2\nper_cell_rate = 0.001")
	if same == old || same.limit != old.limit || same.gate != old.gate {
		t.Fatal("limiter state must carry over when the settings are unchanged")
	}
	_, err := f.attest("dev-cell-1", f.goodToken)
	wantDenied(t, err, RateLimited)
	changed := f.reconfigure(t, "per_cell_burst = 3\nper_cell_rate = 0.001")
	if changed.limit == old.limit {
		t.Fatal("changed settings must start new buckets")
	}
	if _, err := f.attest("dev-cell-1", f.goodToken); err != nil {
		t.Fatal(err)
	}
}

func TestRevokedRecordWinsATie(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	k := newKeys(t)
	for _, order := range [][2]string{{"a", "b"}, {"b", "a"}} {
		dir := t.TempDir()
		for i, rev := range []bool{false, true} {
			rec := k.record(t)
			rec.Revoked, rec.Epoch, rec.Counter = rev, 1, 1
			env, _ := record.Sign(rec, priv)
			name := order[i] + ".dsse.json"
			if err := os.WriteFile(filepath.Join(dir, name), env, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		recs, err := New().loadRecords(dir, "dev", []ed25519.PublicKey{pub})
		if err != nil {
			t.Fatal(err)
		}
		if !recs["dev-cell-1"].Revoked {
			t.Fatalf("order %v: revoked record lost the tie", order)
		}
	}
}

func TestBadRecordFileLogsAtError(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f := newFixture(t, fixtureOptions{signRecordWith: other})
	logs := f.logs.String()
	if !strings.Contains(logs, `"@level":"error"`) || !strings.Contains(logs, "dev-cell-1.dsse.json") {
		t.Fatalf("log lacks the error line:\n%s", logs)
	}
}

func waitIdle(t *testing.T, p *Plugin) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for p.active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d attestations still active", p.active.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAbandonedChallenge(t *testing.T) {
	f := newFixture(t, fixtureOptions{extraHCL: `challenge_timeout = "300ms"`})
	payload, _ := json.Marshal(Payload{Cell: "dev-cell-1"})

	// The client closes its side after the challenge. The plugin returns at once.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := f.client.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}})
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = stream.Recv()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("closed stream: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("returned after %v", time.Since(start))
	}
	waitIdle(t, f.plugin)

	// The client stays silent. The plugin returns when the challenge times out.
	stream, err = f.client.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}})
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	_, err = stream.Recv()
	wantDenied(t, err, ChallengeTimeout)
	if d := time.Since(start); d < 250*time.Millisecond || d > 2*time.Second {
		t.Fatalf("timeout after %v", d)
	}
	waitIdle(t, f.plugin)
}

func TestTokenNeverLogged(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	var tokens []string
	capture := func(nonce string) string {
		tok := f.goodToken(nonce)
		tokens = append(tokens, tok)
		return tok
	}
	if _, err := f.attest("dev-cell-1", capture); err != nil {
		t.Fatal(err)
	}
	_, err := f.attest("dev-cell-1", func(string) string {
		tok := f.goodToken("an-earlier-challenge")
		tokens = append(tokens, tok)
		return tok
	})
	wantDenied(t, err, WrongAudience)
	logs := f.logs.String()
	for _, tok := range tokens {
		for _, part := range strings.Split(tok, ".") {
			if strings.Contains(logs, part) {
				t.Fatalf("log holds token bytes %q", part)
			}
		}
	}
	for _, want := range []string{"wrong_audience", "dev-cell-1", rsaKID} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log lacks %q:\n%s", want, logs)
		}
	}
}

func TestConfigureRejectsBadConfig(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := map[string]string{
		"env": `"dev"`, "trust_domain": `"` + testTrustDomain + `"`, "records_dir": `"` + t.TempDir() + `"`,
		"record_public_keys": `["` + base64.StdEncoding.EncodeToString(pub) + `"]`,
	}
	with := func(k, v string) string {
		var b strings.Builder
		for name, val := range good {
			if name == k {
				if v == "" {
					continue
				}
				val = v
			}
			fmt.Fprintf(&b, "%s = %s\n", name, val)
		}
		if _, ok := good[k]; !ok {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
		return b.String()
	}
	cases := map[string]string{
		"no env":            with("env", ""),
		"no keys":           with("record_public_keys", "[]"),
		"bad key":           with("record_public_keys", `["AAAA"]`),
		"other trust":       with("trust_domain", `"other.example"`),
		"missing dir":       with("records_dir", `"/nonexistent/dir"`),
		"bad timeout":       with("challenge_timeout", `"soon"`),
		"zero rate":         with("per_cell_rate", "0"),
		"zero burst":        with("per_cell_burst", "0"),
		"zero inflight":     with("per_cell_inflight", "0"),
		"unknown attribute": with("surprise", "1"),
	}
	for name, hcl := range cases {
		t.Run(name, func(t *testing.T) {
			p := New()
			_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
				CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: testTrustDomain},
				HclConfiguration:  hcl,
			})
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestLimiterRefills(t *testing.T) {
	now := testNow
	l := newLimiter(2, 3, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if !l.allow("a") {
			t.Fatalf("attempt %d denied", i+1)
		}
	}
	if l.allow("a") {
		t.Fatal("burst not enforced")
	}
	now = now.Add(500 * time.Millisecond)
	if !l.allow("a") || l.allow("a") {
		t.Fatal("expected exactly one token after 500ms at 2 per second")
	}
	now = now.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if !l.allow("a") {
			t.Fatal("bucket must refill to the burst")
		}
	}
	if l.allow("a") {
		t.Fatal("refill must cap at the burst")
	}
}
