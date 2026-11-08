// Command attestprobe attests once to the SPIRE server through the agent API (AttestAgent), with a
// throwaway CSR and a token of one variant. The rejection tests of the cluster_jwt attestor run it
// as a Job in a cell.
//
//	attestprobe --variant <name> --server <ip>:<port> --cell <cell> [--token-file <path>]
//
// The probe sends the cell name, waits for the nonce, and answers with a token. It makes the token
// through TokenRequest for the service account of its own pod. With --token-file it sends the token
// from the file instead. A denial is a result, not a failure: on success the probe prints one line,
// issued:<agent SPIFFE ID> or denied:<message>, and exits 0. Any other failure prints one JSON error
// line on stdout and exits 1.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const (
	attestorType   = "cluster_jwt"
	defaultTimeout = 60 * time.Second
	maxNonceLength = 128
	nonceBytes     = 32
)

var nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// variant describes the token that the probe makes. Each variant breaks one rule of the server
// plugin, apart from good and other-subject.
type variant struct {
	bound      bool
	lifetime   time.Duration
	otherNonce bool
}

var variants = map[string]variant{
	"good":          {bound: true, lifetime: 10 * time.Minute},
	"not-pod-bound": {bound: false, lifetime: 10 * time.Minute},
	"long-lifetime": {bound: true, lifetime: time.Hour},
	// The audience names the environment and a nonce that the server did not send, as a token made
	// for another attestation does.
	"wrong-audience": {bound: true, lifetime: 10 * time.Minute, otherNonce: true},
	// The token is the same as for good. The test runs the pod as a service account that the cell
	// record does not name.
	"other-subject": {bound: true, lifetime: 10 * time.Minute},
}

func variantNames() []string { return slices.Sorted(maps.Keys(variants)) }

// podIdentity names the pod of the probe, from the downward API.
type podIdentity struct{ name, uid, namespace, serviceAccount string }

// minter makes a token of one variant for the service account of the pod.
type minter struct {
	client  corev1client.ServiceAccountsGetter
	pod     podIdentity
	env     string
	variant variant
}

func (m minter) mint(ctx context.Context, nonce string) (string, error) {
	audienceNonce := nonce
	if m.variant.otherNonce {
		var err error
		if audienceNonce, err = randomNonce(); err != nil {
			return "", err
		}
	}
	seconds := int64(m.variant.lifetime / time.Second)
	req := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
		Audiences:         []string{"spire-" + m.env + "/" + audienceNonce},
		ExpirationSeconds: &seconds,
	}}
	if m.variant.bound {
		req.Spec.BoundObjectRef = &authenticationv1.BoundObjectReference{
			APIVersion: "v1", Kind: "Pod", Name: m.pod.name, UID: apitypes.UID(m.pod.uid),
		}
	}
	out, err := m.client.ServiceAccounts(m.pod.namespace).CreateToken(ctx, m.pod.serviceAccount, req, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	if out == nil || strings.TrimSpace(out.Status.Token) == "" {
		return "", errors.New("token request: the API returned no token")
	}
	return out.Status.Token, nil
}

func randomNonce() (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// attestStream is the client side of the AttestAgent stream.
type attestStream interface {
	Send(*agentv1.AttestAgentRequest) error
	Recv() (*agentv1.AttestAgentResponse, error)
}

// attest runs one attestation and returns the outcome line. A PermissionDenied status is the
// outcome denied:<message>. Every other error fails the attestation.
func attest(ctx context.Context, stream attestStream, cell string, mint func(context.Context, string) (string, error)) (string, error) {
	csr, err := throwawayCSR()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(struct {
		Cell string `json:"cell"`
	}{cell})
	if err != nil {
		return "", err
	}
	params := &agentv1.AttestAgentRequest{Step: &agentv1.AttestAgentRequest_Params_{Params: &agentv1.AttestAgentRequest_Params{
		Data:   &types.AttestationData{Type: attestorType, Payload: payload},
		Params: &agentv1.AgentX509SVIDParams{Csr: csr},
	}}}
	if err := send(stream, params); err != nil {
		return outcome(err)
	}
	challenged := false
	for {
		resp, err := stream.Recv()
		if err != nil {
			return outcome(err)
		}
		switch step := resp.GetStep().(type) {
		case *agentv1.AttestAgentResponse_Result_:
			id := step.Result.GetSvid().GetId()
			if id.GetTrustDomain() == "" {
				return "", errors.New("the result holds no SPIFFE ID")
			}
			return "issued:spiffe://" + id.GetTrustDomain() + id.GetPath(), nil
		case *agentv1.AttestAgentResponse_Challenge:
			if challenged {
				return "", errors.New("the server sent a second challenge")
			}
			challenged = true
			nonce := string(step.Challenge)
			if len(nonce) > maxNonceLength || !nonceRE.MatchString(nonce) {
				return "", errors.New("the server sent a malformed nonce")
			}
			token, err := mint(ctx, nonce)
			if err != nil {
				return "", err
			}
			body, err := json.Marshal(struct {
				Token string `json:"token"`
			}{token})
			if err != nil {
				return "", err
			}
			if err := send(stream, &agentv1.AttestAgentRequest{Step: &agentv1.AttestAgentRequest_ChallengeResponse{ChallengeResponse: body}}); err != nil {
				return outcome(err)
			}
		default:
			return "", errors.New("the server sent an empty response")
		}
	}
}

// send writes one request. gRPC reports io.EOF when the server has closed the stream, and the
// status then comes from the next Recv.
func send(stream attestStream, req *agentv1.AttestAgentRequest) error {
	if err := stream.Send(req); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func outcome(err error) (string, error) {
	if st, ok := status.FromError(err); ok && st.Code() == codes.PermissionDenied {
		return "denied:" + st.Message(), nil
	}
	if errors.Is(err, io.EOF) {
		return "", errors.New("the server closed the stream with no result")
	}
	return "", fmt.Errorf("attestation failed: %w", err)
}

// throwawayCSR returns a CSR for a new P-256 key. The probe keeps no key: an issued SVID is only
// evidence, and the probe never uses it.
func throwawayCSR() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
}

type config struct {
	variant     string
	server      string
	trustDomain string
	bundlePath  string
	cell        string
	env         string
	tokenFile   string
	timeout     time.Duration
	pod         podIdentity
}

type deps struct {
	lookupEnv   func(string) (string, bool)
	readFile    func(string) ([]byte, error)
	tokenClient func() (corev1client.ServiceAccountsGetter, error)
	dial        func(context.Context, config) (attestStream, func(), error)
}

func main() {
	os.Exit(execute(context.Background(), os.Args[1:], os.Stdout, deps{
		lookupEnv: os.LookupEnv, readFile: os.ReadFile, tokenClient: inClusterClient, dial: dial,
	}))
}

// execute runs the probe. It prints the outcome line, or one compact JSON error line, to w.
func execute(ctx context.Context, args []string, w io.Writer, d deps) int {
	line, err := run(ctx, args, d)
	if err != nil {
		slog.New(slog.NewJSONHandler(w, nil)).Error("attestprobe failed", "error", err.Error())
		return 1
	}
	if _, err := fmt.Fprintln(w, line); err != nil {
		return 1
	}
	return 0
}

func run(ctx context.Context, args []string, d deps) (string, error) {
	cfg, err := parse(args, d.lookupEnv)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	var mint func(context.Context, string) (string, error)
	if cfg.tokenFile != "" {
		raw, err := d.readFile(cfg.tokenFile)
		if err != nil {
			return "", fmt.Errorf("read --token-file: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", errors.New("--token-file is empty")
		}
		mint = func(context.Context, string) (string, error) { return token, nil }
	} else {
		client, err := d.tokenClient()
		if err != nil {
			return "", err
		}
		mint = minter{client: client, pod: cfg.pod, env: cfg.env, variant: variants[cfg.variant]}.mint
	}

	stream, closeConn, err := d.dial(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("open the AttestAgent stream to %s: %w", cfg.server, err)
	}
	defer closeConn()
	return attest(ctx, stream, cfg.cell, mint)
}

func parse(args []string, lookupEnv func(string) (string, bool)) (config, error) {
	fs := flag.NewFlagSet("attestprobe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := config{}
	fs.StringVar(&cfg.variant, "variant", "", "token variant: "+strings.Join(variantNames(), ", "))
	fs.StringVar(&cfg.server, "server", "", "SPIRE server address as <IP address>:<port>")
	fs.StringVar(&cfg.cell, "cell", "", "cell name in the attestation payload")
	fs.StringVar(&cfg.env, "env", "dev", "environment in the token audience")
	fs.StringVar(&cfg.trustDomain, "trust-domain", "dev.env.poc.internal", "trust domain of the SPIRE server")
	fs.StringVar(&cfg.bundlePath, "bundle", "/run/spire/bundle/bundle.crt", "PEM trust bundle of the SPIRE server")
	fs.StringVar(&cfg.tokenFile, "token-file", "", "send the token in this file instead of a new one; needs --variant good")
	fs.DurationVar(&cfg.timeout, "timeout", defaultTimeout, "time limit of the whole attestation")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if _, ok := variants[cfg.variant]; !ok {
		return config{}, fmt.Errorf("--variant must be one of %s, got %q", strings.Join(variantNames(), ", "), cfg.variant)
	}
	switch {
	case cfg.server == "":
		return config{}, errors.New("--server is required")
	case cfg.cell == "":
		return config{}, errors.New("--cell is required")
	case cfg.tokenFile != "" && cfg.variant != "good":
		return config{}, errors.New("--token-file needs --variant good")
	case cfg.timeout <= 0:
		return config{}, errors.New("--timeout must be positive")
	}
	if cfg.tokenFile == "" {
		for _, e := range []struct {
			name string
			dst  *string
		}{
			{"POD_NAME", &cfg.pod.name}, {"POD_UID", &cfg.pod.uid}, {"POD_NAMESPACE", &cfg.pod.namespace}, {"SERVICE_ACCOUNT", &cfg.pod.serviceAccount},
		} {
			v, ok := lookupEnv(e.name)
			if !ok || v == "" {
				return config{}, fmt.Errorf("environment variable %s is required", e.name)
			}
			*e.dst = v
		}
	}
	return cfg, nil
}

func inClusterClient() (corev1client.ServiceAccountsGetter, error) {
	rc, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster configuration: %w", err)
	}
	return corev1client.NewForConfig(rc)
}

// dial opens the AttestAgent stream. The probe trusts only the roots in the bundle file, and it
// talks only to a server that presents the ID spiffe://<trust domain>/spire/server.
func dial(ctx context.Context, cfg config) (attestStream, func(), error) {
	td, err := spiffeid.TrustDomainFromString(cfg.trustDomain)
	if err != nil {
		return nil, nil, err
	}
	bundle, err := x509bundle.Load(td, cfg.bundlePath)
	if err != nil {
		return nil, nil, fmt.Errorf("load the trust bundle: %w", err)
	}
	serverID, err := spiffeid.FromSegments(td, "spire", "server")
	if err != nil {
		return nil, nil, err
	}
	creds := credentials.NewTLS(tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeID(serverID)))
	conn, err := grpc.NewClient(cfg.server, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, err
	}
	// WaitForReady keeps the call open while the connection comes up, up to the deadline of ctx.
	// A new pod can start before its NetworkPolicy applies.
	stream, err := agentv1.NewAgentClient(conn).AttestAgent(ctx, grpc.WaitForReady(true))
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return stream, func() { _ = conn.Close() }, nil
}
