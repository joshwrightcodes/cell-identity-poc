package clusterjwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const (
	// MinTokenTTL is the shortest lifetime that the Kubernetes TokenRequest API accepts.
	MinTokenTTL = 10 * time.Minute

	tokenRequestTimeout = 30 * time.Second
	maxNonceLength      = 128
)

// Names of the downward API variables that identify the pod of the agent.
const (
	envPodName       = "POD_NAME"
	envPodUID        = "POD_UID"
	envPodNamespace  = "POD_NAMESPACE"
	envServiceAcct   = "SERVICE_ACCOUNT"
	audiencePrefix   = "spire-"
	boundObjectKind  = "Pod"
	boundObjectAPIV  = "v1"
	maxIdentityValue = 253
)

var (
	nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	envRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
)

// tokenClient is the part of the Kubernetes core client that the agent uses.
type tokenClient interface {
	ServiceAccounts(namespace string) corev1client.ServiceAccountInterface
}

type agentConfig struct {
	Cell     string `hcl:"cell"`
	Env      string `hcl:"env"`
	TokenTTL string `hcl:"token_ttl"`
}

var agentConfigKeys = map[string]bool{"cell": true, "env": true, "token_ttl": true}

// agentState is the immutable result of one Configure call.
type agentState struct {
	cell, env      string
	ttl            time.Duration
	podName        string
	podUID         string
	namespace      string
	serviceAccount string
	client         tokenClient
}

// Agent is the SPIRE agent NodeAttestor of type cluster_jwt. It requests a pod-bound token for the
// service account of its own pod.
type Agent struct {
	agentv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	lookupEnv func(string) (string, bool)
	newClient func() (tokenClient, error)
	log       hclog.Logger
	st        atomic.Pointer[agentState]
}

// NewAgent returns an agent that reads the pod identity from the environment and reaches the
// Kubernetes API with the in-cluster credentials.
func NewAgent() *Agent {
	return &Agent{lookupEnv: os.LookupEnv, newClient: inClusterClient, log: hclog.NewNullLogger()}
}

func inClusterClient() (tokenClient, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster configuration: %w", err)
	}
	cs, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return cs, nil
}

// SetLogger receives the logger that SPIRE writes.
func (a *Agent) SetLogger(l hclog.Logger) { a.log = l }

// Validate checks a configuration without applying it.
func (a *Agent) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	if _, err := a.build(req.GetHclConfiguration(), false); err != nil {
		return &configv1.ValidateResponse{Valid: false, Notes: []string{err.Error()}}, nil
	}
	return &configv1.ValidateResponse{Valid: true}, nil
}

// Configure reads the configuration and the pod identity, and creates the Kubernetes client.
func (a *Agent) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	st, err := a.build(req.GetHclConfiguration(), true)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "cluster_jwt agent: %v", err)
	}
	a.st.Store(st)
	a.log.Info("configured", "cell", st.cell, "env", st.env, "namespace", st.namespace,
		"service_account", st.serviceAccount, "pod", st.podName, "pod_uid", st.podUID)
	return &configv1.ConfigureResponse{}, nil
}

func (a *Agent) build(text string, withClient bool) (*agentState, error) {
	cfg := agentConfig{TokenTTL: MinTokenTTL.String()}
	if err := hcl.Decode(&cfg, text); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	var raw map[string]any
	if err := hcl.Decode(&raw, text); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	for k := range raw {
		if !agentConfigKeys[k] {
			return nil, fmt.Errorf("unknown setting %q", k)
		}
	}
	switch {
	case cfg.Cell == "":
		return nil, errors.New("cell is required")
	case !cellNameRE.MatchString(cfg.Cell):
		return nil, errors.New("cell is not a DNS label")
	case cfg.Env == "":
		return nil, errors.New("env is required")
	case !envRE.MatchString(cfg.Env):
		return nil, errors.New("env holds characters that an audience cannot carry")
	}
	ttl, err := time.ParseDuration(cfg.TokenTTL)
	if err != nil || ttl < MinTokenTTL || ttl > MaxTokenLifetime {
		return nil, fmt.Errorf("token_ttl must be a duration from %s to %s", MinTokenTTL, MaxTokenLifetime)
	}
	st := &agentState{cell: cfg.Cell, env: cfg.Env, ttl: ttl}
	for _, e := range []struct {
		name string
		dst  *string
	}{
		{envPodName, &st.podName}, {envPodUID, &st.podUID}, {envPodNamespace, &st.namespace}, {envServiceAcct, &st.serviceAccount},
	} {
		name, dst := e.name, e.dst
		v, ok := a.lookupEnv(name)
		if !ok || v == "" {
			return nil, fmt.Errorf("environment variable %s is required", name)
		}
		if len(v) > maxIdentityValue {
			return nil, fmt.Errorf("environment variable %s is too long", name)
		}
		*dst = v
	}
	if withClient {
		if st.client, err = a.newClient(); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// AidAttestation sends the cell name, waits for the nonce, and answers with a token that carries
// the nonce in its audience. It accepts one challenge only.
func (a *Agent) AidAttestation(stream agentv1.NodeAttestor_AidAttestationServer) error {
	st := a.st.Load()
	if st == nil {
		return status.Error(codes.FailedPrecondition, "cluster_jwt agent: not configured")
	}
	payload, err := json.Marshal(Payload{Cell: st.cell})
	if err != nil {
		return status.Error(codes.Internal, "cluster_jwt agent: internal")
	}
	if err := stream.Send(&agentv1.PayloadOrChallengeResponse{Data: &agentv1.PayloadOrChallengeResponse_Payload{Payload: payload}}); err != nil {
		return err
	}
	ch, err := stream.Recv()
	if err != nil {
		return status.Error(codes.Aborted, "cluster_jwt agent: stream ended before the challenge")
	}
	nonce := string(ch.GetChallenge())
	if nonce == "" || len(nonce) > maxNonceLength || !nonceRE.MatchString(nonce) {
		a.log.Warn("challenge refused", "reason", "malformed nonce")
		return status.Error(codes.InvalidArgument, "cluster_jwt agent: malformed challenge")
	}

	token, err := a.requestToken(stream.Context(), st, nonce)
	if err != nil {
		a.log.Error("token request failed", "error", err.Error(), "namespace", st.namespace, "service_account", st.serviceAccount)
		return status.Error(codes.Unavailable, "cluster_jwt agent: token request failed")
	}
	body, err := json.Marshal(Response{Token: token})
	if err != nil {
		return status.Error(codes.Internal, "cluster_jwt agent: internal")
	}
	if err := stream.Send(&agentv1.PayloadOrChallengeResponse{Data: &agentv1.PayloadOrChallengeResponse_ChallengeResponse{ChallengeResponse: body}}); err != nil {
		return err
	}
	a.log.Info("answered challenge", "cell", st.cell, "nonce_hash", nonceHash(nonce))

	switch _, err := stream.Recv(); {
	case err == nil:
		a.log.Warn("second challenge refused")
		return status.Error(codes.FailedPrecondition, "cluster_jwt agent: only one challenge is allowed")
	case errors.Is(err, io.EOF), status.Code(err) == codes.Canceled:
		return nil
	default:
		return err
	}
}

// requestToken asks for a token of the service account of the pod. The token binds to the pod by
// name and UID, and its audience carries the nonce.
func (a *Agent) requestToken(ctx context.Context, st *agentState, nonce string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, tokenRequestTimeout)
	defer cancel()
	seconds := int64(st.ttl / time.Second)
	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audiencePrefix + st.env + "/" + nonce},
			ExpirationSeconds: &seconds,
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				APIVersion: boundObjectAPIV, Kind: boundObjectKind, Name: st.podName, UID: apitypes.UID(st.podUID),
			},
		},
	}
	out, err := st.client.ServiceAccounts(st.namespace).CreateToken(ctx, st.serviceAccount, req, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	if out == nil || strings.TrimSpace(out.Status.Token) == "" {
		return "", errors.New("the API returned no token")
	}
	return out.Status.Token, nil
}
