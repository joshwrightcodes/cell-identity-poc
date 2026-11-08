package clusterjwt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const testAgentNonce = "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9u"

func podEnv() map[string]string {
	return map[string]string{
		"POD_NAME": "celld-0", "POD_UID": "pod-uid", "POD_NAMESPACE": "celld", "SERVICE_ACCOUNT": "celld",
	}
}

type agentFixture struct {
	t      *testing.T
	client *agentv1.NodeAttestorPluginClient
	cfg    *configv1.ConfigServiceClient
	kube   *fake.Clientset
	logs   *syncBuffer

	mu       sync.Mutex
	requests []*authenticationv1.TokenRequest
	calls    []string
}

// newAgentFixture serves the agent plugin. mint returns the token for a TokenRequest.
func newAgentFixture(t *testing.T, env map[string]string, mint func(*authenticationv1.TokenRequest) string) *agentFixture {
	t.Helper()
	f := &agentFixture{t: t, client: new(agentv1.NodeAttestorPluginClient), cfg: new(configv1.ConfigServiceClient), kube: fake.NewSimpleClientset(), logs: &syncBuffer{}}
	f.kube.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca, ok := a.(k8stesting.CreateAction)
		if !ok || a.GetSubresource() != "token" {
			return false, nil, nil
		}
		tr := ca.GetObject().(*authenticationv1.TokenRequest).DeepCopy()
		f.mu.Lock()
		f.requests = append(f.requests, tr)
		f.calls = append(f.calls, a.GetNamespace()+"/"+ca.(k8stesting.CreateActionImpl).Name)
		f.mu.Unlock()
		out := tr.DeepCopy()
		out.Status.Token = mint(tr)
		return true, out, nil
	})
	a := NewAgent()
	a.lookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok && v != "" }
	a.newClient = func() (tokenClient, error) { return f.kube.CoreV1(), nil }
	logger := hclog.New(&hclog.LoggerOptions{Level: hclog.Debug, Output: f.logs, JSONFormat: true})
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   agentv1.NodeAttestorPluginServer(a),
		PluginClient:   f.client,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(a)},
		ServiceClients: []pluginsdk.ServiceClient{f.cfg},
		Logger:         logger,
	})
	return f
}

func (f *agentFixture) configure(hcl string) error {
	_, err := f.cfg.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: testTrustDomain},
		HclConfiguration:  hcl,
	})
	return err
}

const goodAgentHCL = `
cell = "dev-cell-1"
env = "dev"
`

func challenge(nonce string) *agentv1.Challenge { return &agentv1.Challenge{Challenge: []byte(nonce)} }

func TestAgentRequestsNonceAudience(t *testing.T) {
	f := newAgentFixture(t, podEnv(), func(*authenticationv1.TokenRequest) string { return "the-token" })
	if err := f.configure(goodAgentHCL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.AidAttestation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	var p Payload
	if err := json.Unmarshal(first.GetPayload(), &p); err != nil || p.Cell != "dev-cell-1" {
		t.Fatalf("payload = %q, err %v", first.GetPayload(), err)
	}
	if err := stream.Send(challenge(testAgentNonce)); err != nil {
		t.Fatal(err)
	}
	reply, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := decodeStrict(reply.GetChallengeResponse(), &resp); err != nil || resp.Token != "the-token" {
		t.Fatalf("response = %q, err %v", reply.GetChallengeResponse(), err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("after response: %v, want EOF", err)
	}

	if len(f.requests) != 1 || f.calls[0] != "celld/celld" {
		t.Fatalf("requests %d, calls %v", len(f.requests), f.calls)
	}
	tr := f.requests[0]
	if got, want := strings.Join(tr.Spec.Audiences, ","), "spire-dev/"+testAgentNonce; got != want {
		t.Fatalf("audiences = %q, want %q", got, want)
	}
	if tr.Spec.ExpirationSeconds == nil || *tr.Spec.ExpirationSeconds != 600 {
		t.Fatalf("expirationSeconds = %v, want 600", tr.Spec.ExpirationSeconds)
	}
	ref := tr.Spec.BoundObjectRef
	if ref == nil || ref.Kind != "Pod" || ref.APIVersion != "v1" || ref.Name != "celld-0" || ref.UID != "pod-uid" {
		t.Fatalf("boundObjectRef = %+v", ref)
	}
	if strings.Contains(f.logs.String(), "the-token") {
		t.Fatal("the token appears in the log")
	}
}

func TestAgentRefusesSecondChallenge(t *testing.T) {
	f := newAgentFixture(t, podEnv(), func(*authenticationv1.TokenRequest) string { return "the-token" })
	if err := f.configure(goodAgentHCL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.AidAttestation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(challenge(testAgentNonce)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(challenge(testAgentNonce)); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("second challenge: %v, want an error", err)
	}
	if len(f.requests) != 1 {
		t.Fatalf("TokenRequests = %d, want 1", len(f.requests))
	}
}

func TestAgentFailsWithoutPodUID(t *testing.T) {
	for _, name := range []string{"POD_UID", "POD_NAME", "POD_NAMESPACE", "SERVICE_ACCOUNT"} {
		t.Run(name, func(t *testing.T) {
			env := podEnv()
			delete(env, name)
			f := newAgentFixture(t, env, func(*authenticationv1.TokenRequest) string { return "x" })
			err := f.configure(goodAgentHCL)
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), name) {
				t.Fatalf("Configure: %v, want InvalidArgument naming %s", err, name)
			}
		})
	}
}

func TestAgentRejectsBadChallenge(t *testing.T) {
	for name, nonce := range map[string]string{
		"empty": "", "slash": "a/b", "space": "a b", "long": strings.Repeat("a", 129),
	} {
		t.Run(name, func(t *testing.T) {
			f := newAgentFixture(t, podEnv(), func(*authenticationv1.TokenRequest) string { return "x" })
			if err := f.configure(goodAgentHCL); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stream, err := f.client.AidAttestation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Recv(); err != nil {
				t.Fatal(err)
			}
			if err := stream.Send(challenge(nonce)); err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Recv(); err == nil {
				t.Fatal("expected an error")
			}
			if len(f.requests) != 0 {
				t.Fatalf("TokenRequests = %d, want 0", len(f.requests))
			}
		})
	}
}

func TestAgentTokenRequestFailure(t *testing.T) {
	f := newAgentFixture(t, podEnv(), func(*authenticationv1.TokenRequest) string { return "x" })
	f.kube.PrependReactor("create", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden: secret-detail")
	})
	if err := f.configure(goodAgentHCL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := f.client.AidAttestation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(challenge(testAgentNonce)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err == nil || strings.Contains(err.Error(), "secret-detail") {
		t.Fatalf("error = %v, want a generic error", err)
	}
}

func TestAgentConfigure(t *testing.T) {
	cases := map[string]struct {
		hcl  string
		want string
	}{
		"no cell":        {`env = "dev"`, "cell is required"},
		"bad cell":       {"cell = \"Dev_1\"\nenv = \"dev\"", "cell"},
		"no env":         {`cell = "dev-cell-1"`, "env is required"},
		"env with slash": {"cell = \"dev-cell-1\"\nenv = \"a/b\"", "env"},
		"ttl too small":  {goodAgentHCL + `token_ttl = "9m59s"`, "token_ttl"},
		"ttl bad":        {goodAgentHCL + `token_ttl = "soon"`, "token_ttl"},
		"unknown":        {goodAgentHCL + `extra = 1`, "unknown setting"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newAgentFixture(t, podEnv(), func(*authenticationv1.TokenRequest) string { return "x" })
			err := f.configure(c.hcl)
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Configure: %v, want InvalidArgument containing %q", err, c.want)
			}
		})
	}
}

func TestAgentTokenTTL(t *testing.T) {
	f := newAgentFixture(t, podEnv(), func(*authenticationv1.TokenRequest) string { return "x" })
	if err := f.configure(goodAgentHCL + `token_ttl = "15m"`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, _ := f.client.AidAttestation(ctx)
	_, _ = stream.Recv()
	_ = stream.Send(challenge(testAgentNonce))
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if got := *f.requests[0].Spec.ExpirationSeconds; got != 900 {
		t.Fatalf("expirationSeconds = %d, want 900", got)
	}
}

// TestAgentAgainstServer drives the agent through the real server plugin. The server and the agent
// each run behind their own plugin harness. This test plays the part of SPIRE between them.
func TestAgentAgainstServer(t *testing.T) {
	s := newFixture(t, fixtureOptions{})
	a := newAgentFixture(t, podEnv(), func(tr *authenticationv1.TokenRequest) string {
		sp := s.keys.good()
		sp.Audience = tr.Spec.Audiences
		return sp.token(t)
	})
	if err := a.configure(goodAgentHCL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	as, err := a.client.AidAttestation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := s.client.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := as.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload.GetPayload()}}); err != nil {
		t.Fatal(err)
	}
	ch, err := ss.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if err := as.Send(&agentv1.Challenge{Challenge: ch.GetChallenge()}); err != nil {
		t.Fatal(err)
	}
	reply, err := as.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_ChallengeResponse{ChallengeResponse: reply.GetChallengeResponse()}}); err != nil {
		t.Fatal(err)
	}
	done, err := ss.Recv()
	if err != nil {
		t.Fatalf("server refused the agent: %v", err)
	}
	id := done.GetAgentAttributes().GetSpiffeId()
	wantPrefix := "spiffe://" + testTrustDomain + "/spire/agent/cluster_jwt/dev-cell-1/pod-uid/" + nonceHash(string(ch.GetChallenge()))
	if id != wantPrefix {
		t.Fatalf("agent id = %q, want %q", id, wantPrefix)
	}
}
