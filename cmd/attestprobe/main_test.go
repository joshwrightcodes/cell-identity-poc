package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	k8stesting "k8s.io/client-go/testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

const testNonce = "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9u"

func testPod() podIdentity {
	return podIdentity{name: "celld-abc", uid: "3e7fbe4e-3ba7-4be3-a9e1-75b680971ac0", namespace: "cell-identity-system", serviceAccount: "celld"}
}

// tokenServer returns a fake clientset that answers each TokenRequest with "token-<n>" and records
// the requests.
func tokenServer(t *testing.T) (*fake.Clientset, *[]*authenticationv1.TokenRequest) {
	t.Helper()
	cs := fake.NewClientset()
	var seen []*authenticationv1.TokenRequest
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca, ok := a.(k8stesting.CreateAction)
		if !ok || a.GetSubresource() != "token" {
			return false, nil, nil
		}
		req, ok := ca.GetObject().(*authenticationv1.TokenRequest)
		if !ok {
			return true, nil, errors.New("not a TokenRequest")
		}
		seen = append(seen, req.DeepCopy())
		out := req.DeepCopy()
		out.Status.Token = "token-" + string(rune('0'+len(seen)))
		return true, out, nil
	})
	return cs, &seen
}

func TestTokenRequestForEachVariant(t *testing.T) {
	pod := testPod()
	nonceAudience := "spire-dev/" + testNonce
	for _, tc := range []struct {
		variant  string
		bound    bool
		lifetime int64
		audience func(t *testing.T, got string)
	}{
		{"good", true, 600, equalTo(nonceAudience)},
		{"not-pod-bound", false, 600, equalTo(nonceAudience)},
		{"long-lifetime", true, 3600, equalTo(nonceAudience)},
		{"wrong-audience", true, 600, otherNonceAudience(nonceAudience)},
		{"other-subject", true, 600, equalTo(nonceAudience)},
	} {
		t.Run(tc.variant, func(t *testing.T) {
			cs, seen := tokenServer(t)
			m := minter{client: cs.CoreV1(), pod: pod, env: "dev", variant: variants[tc.variant]}
			tok, err := m.mint(context.Background(), testNonce)
			if err != nil {
				t.Fatal(err)
			}
			if tok != "token-1" || len(*seen) != 1 {
				t.Fatalf("want one TokenRequest and its token, got %q after %d requests", tok, len(*seen))
			}
			req := (*seen)[0]
			if got := req.Spec.ExpirationSeconds; got == nil || *got != tc.lifetime {
				t.Fatalf("ExpirationSeconds: want %d, got %v", tc.lifetime, got)
			}
			if len(req.Spec.Audiences) != 1 {
				t.Fatalf("want one audience, got %v", req.Spec.Audiences)
			}
			tc.audience(t, req.Spec.Audiences[0])
			ref := req.Spec.BoundObjectRef
			switch {
			case tc.bound && (ref == nil || ref.Kind != "Pod" || ref.APIVersion != "v1" || ref.Name != pod.name || string(ref.UID) != pod.uid):
				t.Fatalf("want a binding to pod %s/%s, got %+v", pod.name, pod.uid, ref)
			case !tc.bound && ref != nil:
				t.Fatalf("want no bound object, got %+v", ref)
			}
		})
	}
}

func equalTo(want string) func(*testing.T, string) {
	return func(t *testing.T, got string) {
		t.Helper()
		if got != want {
			t.Fatalf("audience: want %q, got %q", want, got)
		}
	}
}

// otherNonceAudience accepts the audience of the same environment with a nonce that differs from
// the challenge.
func otherNonceAudience(challenge string) func(*testing.T, string) {
	return func(t *testing.T, got string) {
		t.Helper()
		rest, ok := strings.CutPrefix(got, "spire-dev/")
		if !ok || got == challenge || len(rest) < 32 {
			t.Fatalf("audience: want spire-dev/<another nonce>, got %q", got)
		}
	}
}

func TestEveryVariantIsTested(t *testing.T) {
	want := []string{"good", "long-lifetime", "not-pod-bound", "other-subject", "wrong-audience"}
	if got := variantNames(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("variants: want %v, got %v", want, got)
	}
}

// fakeStream plays the server side of AttestAgent from a script of responses.
type fakeStream struct {
	sent      []*agentv1.AttestAgentRequest
	responses []func(sent []*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error)
}

func (f *fakeStream) Send(r *agentv1.AttestAgentRequest) error {
	f.sent = append(f.sent, r)
	return nil
}

func (f *fakeStream) Recv() (*agentv1.AttestAgentResponse, error) {
	if len(f.responses) == 0 {
		return nil, io.EOF
	}
	next := f.responses[0]
	f.responses = f.responses[1:]
	return next(f.sent)
}

func challenge(nonce string) func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error) {
	return func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error) {
		return &agentv1.AttestAgentResponse{Step: &agentv1.AttestAgentResponse_Challenge{Challenge: []byte(nonce)}}, nil
	}
}

func result(path string) func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error) {
	return func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error) {
		return &agentv1.AttestAgentResponse{Step: &agentv1.AttestAgentResponse_Result_{Result: &agentv1.AttestAgentResponse_Result{
			Svid: &types.X509SVID{Id: &types.SPIFFEID{TrustDomain: "dev.env.poc.internal", Path: path}},
		}}}, nil
	}
}

func fail(err error) func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error) {
	return func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error) { return nil, err }
}

func nonceMint(_ context.Context, nonce string) (string, error) { return "token-for-" + nonce, nil }

func TestAttestIssued(t *testing.T) {
	agentPath := "/spire/agent/cluster_jwt/dev-cell-1/3e7fbe4e/0123456789abcdef0123456789abcdef"
	s := &fakeStream{responses: []func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error){
		challenge(testNonce), result(agentPath),
	}}
	out, err := attest(context.Background(), s, "dev-cell-1", nonceMint)
	if err != nil {
		t.Fatal(err)
	}
	if want := "issued:spiffe://dev.env.poc.internal" + agentPath; out != want {
		t.Fatalf("want %q, got %q", want, out)
	}
	if len(s.sent) != 2 {
		t.Fatalf("want the params and one challenge response, got %d requests", len(s.sent))
	}
	params := s.sent[0].GetParams()
	if params.GetData().GetType() != "cluster_jwt" || string(params.GetData().GetPayload()) != `{"cell":"dev-cell-1"}` {
		t.Fatalf("attestation data: got type %q, payload %q", params.GetData().GetType(), params.GetData().GetPayload())
	}
	csr, err := x509.ParseCertificateRequest(params.GetParams().GetCsr())
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(s.sent[1].GetChallengeResponse(), &resp); err != nil || resp.Token != "token-for-"+testNonce {
		t.Fatalf("challenge response: want the token for the nonce, got %q (%v)", s.sent[1].GetChallengeResponse(), err)
	}
}

func TestAttestDenied(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "nodeattestor(cluster_jwt): cluster_jwt: not_pod_bound")
	for name, script := range map[string][]func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error){
		"after the challenge":  {challenge(testNonce), fail(denied)},
		"before any challenge": {fail(denied)},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := attest(context.Background(), &fakeStream{responses: script}, "dev-cell-1", nonceMint)
			if err != nil {
				t.Fatal(err)
			}
			if want := "denied:nodeattestor(cluster_jwt): cluster_jwt: not_pod_bound"; out != want {
				t.Fatalf("want %q, got %q", want, out)
			}
		})
	}
}

func TestAttestFails(t *testing.T) {
	for name, script := range map[string][]func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error){
		"server unavailable": {fail(status.Error(codes.Unavailable, "connection refused"))},
		"invalid argument":   {challenge(testNonce), fail(status.Error(codes.InvalidArgument, "malformed param"))},
		"second challenge":   {challenge(testNonce), challenge(testNonce)},
		"stream ends":        {challenge(testNonce)},
		"empty response": {func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error) {
			return &agentv1.AttestAgentResponse{}, nil
		}},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := attest(context.Background(), &fakeStream{responses: script}, "dev-cell-1", nonceMint)
			if err == nil {
				t.Fatalf("want an error, got outcome %q", out)
			}
		})
	}
}

func TestAttestFailsWhenTheTokenRequestFails(t *testing.T) {
	s := &fakeStream{responses: []func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error){challenge(testNonce)}}
	mint := func(context.Context, string) (string, error) { return "", errors.New("forbidden") }
	if out, err := attest(context.Background(), s, "dev-cell-1", mint); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("want the TokenRequest error, got %q, %v", out, err)
	}
	if len(s.sent) != 1 {
		t.Fatalf("want no challenge response after a failed TokenRequest, got %d requests", len(s.sent))
	}
}

func TestAttestRefusesAMalformedNonce(t *testing.T) {
	s := &fakeStream{responses: []func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error){challenge("not a nonce!")}}
	if out, err := attest(context.Background(), s, "dev-cell-1", nonceMint); err == nil {
		t.Fatalf("want an error, got %q", out)
	}
}

func podEnv(extra map[string]string) func(string) (string, bool) {
	env := map[string]string{
		"POD_NAME": "celld-abc", "POD_UID": "3e7fbe4e-3ba7-4be3-a9e1-75b680971ac0",
		"POD_NAMESPACE": "cell-identity-system", "SERVICE_ACCOUNT": "celld",
	}
	for k, v := range extra {
		env[k] = v
	}
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

type testDeps struct {
	deps
	stream *fakeStream
	tokens *[]*authenticationv1.TokenRequest
	dialed *config
}

func newTestDeps(t *testing.T, script ...func([]*agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse, error)) *testDeps {
	t.Helper()
	cs, seen := tokenServer(t)
	td := &testDeps{stream: &fakeStream{responses: script}, tokens: seen}
	td.deps = deps{
		lookupEnv: podEnv(nil),
		readFile: func(path string) ([]byte, error) {
			if path == "/run/attestprobe/token" {
				return []byte("file-token\n"), nil
			}
			return nil, errors.New("no file " + path)
		},
		tokenClient: func() (corev1client.ServiceAccountsGetter, error) { return cs.CoreV1(), nil },
		dial: func(_ context.Context, cfg config) (attestStream, func(), error) {
			td.dialed = &cfg
			return td.stream, func() {}, nil
		},
	}
	return td
}

var baseArgs = []string{"--server", "172.18.0.3:30081", "--cell", "dev-cell-1", "--env", "dev"}

func TestExecutePrintsOnlyTheOutcome(t *testing.T) {
	td := newTestDeps(t, challenge(testNonce), result("/spire/agent/cluster_jwt/dev-cell-1/x/y"))
	var out bytes.Buffer
	if code := execute(context.Background(), append([]string{"--variant", "good"}, baseArgs...), &out, td.deps); code != 0 {
		t.Fatalf("exit code %d, output %q", code, out.String())
	}
	if want := "issued:spiffe://dev.env.poc.internal/spire/agent/cluster_jwt/dev-cell-1/x/y\n"; out.String() != want {
		t.Fatalf("stdout: want %q, got %q", want, out.String())
	}
	if len(*td.tokens) != 1 {
		t.Fatalf("want one TokenRequest, got %d", len(*td.tokens))
	}
	cfg := td.dialed
	if cfg == nil || cfg.server != "172.18.0.3:30081" || cfg.trustDomain != "dev.env.poc.internal" || cfg.bundlePath != "/run/spire/bundle/bundle.crt" {
		t.Fatalf("dial config: got %+v", cfg)
	}
}

func TestExecuteUsesTheTokenFile(t *testing.T) {
	td := newTestDeps(t, challenge(testNonce), fail(status.Error(codes.PermissionDenied, "nodeattestor(cluster_jwt): cluster_jwt: unknown_kid")))
	var out bytes.Buffer
	args := append([]string{"--variant", "good", "--token-file", "/run/attestprobe/token"}, baseArgs...)
	if code := execute(context.Background(), args, &out, td.deps); code != 0 {
		t.Fatalf("exit code %d, output %q", code, out.String())
	}
	if want := "denied:nodeattestor(cluster_jwt): cluster_jwt: unknown_kid\n"; out.String() != want {
		t.Fatalf("stdout: want %q, got %q", want, out.String())
	}
	if len(*td.tokens) != 0 {
		t.Fatalf("want no TokenRequest with a token file, got %d", len(*td.tokens))
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(td.stream.sent[1].GetChallengeResponse(), &resp); err != nil || resp.Token != "file-token" {
		t.Fatalf("challenge response: want the token from the file, got %q (%v)", td.stream.sent[1].GetChallengeResponse(), err)
	}
}

func TestExecuteFailsWithOneJSONLine(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"no variant":              {args: baseArgs},
		"unknown variant":         {args: append([]string{"--variant", "bad"}, baseArgs...)},
		"no server":               {args: []string{"--variant", "good", "--cell", "dev-cell-1", "--env", "dev"}},
		"no cell":                 {args: []string{"--variant", "good", "--server", "172.18.0.3:30081", "--env", "dev"}},
		"no env":                  {args: []string{"--variant", "good", "--server", "172.18.0.3:30081", "--cell", "dev-cell-1"}},
		"token file with variant": {args: append([]string{"--variant", "long-lifetime", "--token-file", "/run/attestprobe/token"}, baseArgs...)},
		"missing pod identity":    {args: append([]string{"--variant", "good"}, baseArgs...), env: map[string]string{"POD_UID": ""}},
		"unknown flag":            {args: append([]string{"--variant", "good", "--nope"}, baseArgs...)},
		"server unavailable":      {args: append([]string{"--variant", "good"}, baseArgs...)},
	} {
		t.Run(name, func(t *testing.T) {
			td := newTestDeps(t, fail(status.Error(codes.Unavailable, "connection refused")))
			td.lookupEnv = podEnv(tc.env)
			var out bytes.Buffer
			if code := execute(context.Background(), tc.args, &out, td.deps); code != 1 {
				t.Fatalf("exit code: want 1, got %d", code)
			}
			lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
			var rec map[string]any
			if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &rec) != nil || rec["level"] != "ERROR" || rec["error"] == "" {
				t.Fatalf("want one JSON error line, got %q", out.String())
			}
		})
	}
}

func TestExecuteHonoursTheTimeout(t *testing.T) {
	td := newTestDeps(t)
	td.dial = func(ctx context.Context, _ config) (attestStream, func(), error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	start := time.Now()
	var out bytes.Buffer
	args := append([]string{"--variant", "good", "--timeout", "50ms"}, baseArgs...)
	if code := execute(context.Background(), args, &out, td.deps); code != 1 {
		t.Fatalf("exit code: want 1, got %d", code)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the probe ignored --timeout")
	}
}

// apiServer stands in for the Kubernetes API server: it answers each TokenRequest with a JWT that
// it signs the way the API server does, from the fields of the request.
type apiServer struct {
	key    *ecdsa.PrivateKey
	issuer string
	now    time.Time
}

func (a apiServer) sign(t *testing.T, pod podIdentity, req *authenticationv1.TokenRequest) string {
	t.Helper()
	kube := map[string]any{
		"namespace":      pod.namespace,
		"serviceaccount": map[string]string{"name": pod.serviceAccount, "uid": "sa-uid"},
	}
	if ref := req.Spec.BoundObjectRef; ref != nil {
		kube["pod"] = map[string]string{"name": ref.Name, "uid": string(ref.UID)}
		kube["node"] = map[string]string{"name": "dev-cell-1-control-plane", "uid": "node-uid"}
	}
	claims := map[string]any{
		"iss": a.issuer, "aud": req.Spec.Audiences, "iat": a.now.Unix(), "nbf": a.now.Unix(),
		"exp":           a.now.Unix() + *req.Spec.ExpirationSeconds,
		"sub":           "system:serviceaccount:" + pod.namespace + ":" + pod.serviceAccount,
		"kubernetes.io": kube,
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: a.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "ec-1"))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestProbeTokensAgainstValidate makes the token of each variant through the probe, signs it like
// the API server, and checks it with clusterjwt.Validate. The good token must pass, and every other
// variant must fail with the reason that its rejection test expects in the server log. The probe
// and the server plugin share the wire contract, so a change to one side fails here.
func TestProbeTokensAgainstValidate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	api := apiServer{key: key, issuer: "https://dev-cell-1.issuer.poc.internal", now: time.Unix(1_800_000_000, 0)}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "ec-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	pod := testPod()
	rec := record.Cell{
		Name: "dev-cell-1", Env: "dev", Issuer: api.issuer, JWKS: jwks,
		Subjects: []record.Subject{{Namespace: pod.namespace, ServiceAccount: pod.serviceAccount}},
	}
	for _, tc := range []struct {
		variant string
		want    clusterjwt.Reason
	}{
		{"good", ""},
		{"not-pod-bound", clusterjwt.NotPodBound},
		{"long-lifetime", clusterjwt.LifetimeTooLong},
		{"wrong-audience", clusterjwt.WrongAudience},
	} {
		t.Run(tc.variant, func(t *testing.T) {
			cs := fake.NewClientset()
			cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
				req := a.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenRequest).DeepCopy()
				req.Status.Token = api.sign(t, pod, req)
				return true, req, nil
			})
			m := minter{client: cs.CoreV1(), pod: pod, env: "dev", variant: variants[tc.variant]}
			token, err := m.mint(context.Background(), testNonce)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := clusterjwt.Validate(rec, token, "dev", testNonce, api.now)
			if got := clusterjwt.ReasonOf(err); got != tc.want {
				t.Fatalf("Validate: reason %q (err %v), want %q", got, err, tc.want)
			}
			if tc.want == "" && (claims.PodUID != pod.uid || claims.PodName != pod.name || claims.ServiceAccount != pod.serviceAccount) {
				t.Fatalf("Validate returned claims %+v for pod %+v", claims, pod)
			}
		})
	}
}

// The environment comes from the caller, so cells/common.env stays its one source.
func TestParseNeedsEnv(t *testing.T) {
	_, err := parse([]string{"--variant", "good", "--server", "172.18.0.3:30081", "--cell", "dev-cell-1"}, podEnv(nil))
	if err == nil || !strings.Contains(err.Error(), "--env") {
		t.Fatalf("err = %v, want an error that names --env", err)
	}
}

func TestAttestprobeSourceParse(t *testing.T) {
	base := []string{"--variant", "good", "--server", "172.18.0.3:30081", "--cell", "dev-cell-1", "--env", "dev"}
	cfg, err := parse(append(slices.Clone(base), "--source", "172.18.0.9"), podEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.source.Equal(net.ParseIP("172.18.0.9")) {
		t.Fatalf("source = %v", cfg.source)
	}
	if _, err := parse(append(slices.Clone(base), "--source", "not-an-ip"), podEnv(nil)); err == nil || !strings.Contains(err.Error(), "--source") {
		t.Fatalf("err = %v, want an error that names --source", err)
	}
}
