package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/hostsvc"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
	"github.com/joshwrightcodes/cell-identity-poc/internal/topology"
)

type svidSource struct{ s *x509svid.SVID }

func (s svidSource) GetX509SVID() (*x509svid.SVID, error) { return s.s, nil }

// devCA is a root for dev.env.poc.internal with the URI SAN that the host service demands.
func devCA(t *testing.T) (root []byte, issue func(id string) x509svid.Source) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://" + hostsvc.StepClientTrustDomain)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), func(id string) x509svid.Source {
		lk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		lu, _ := url.Parse(id)
		lt := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{lu}}
		ld, err := x509.CreateCertificate(rand.Reader, lt, ca, &lk.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(ld)
		return svidSource{&x509svid.SVID{ID: spiffeid.RequireFromString(id), Certificates: []*x509.Certificate{leaf}, PrivateKey: lk}}
	}
}

// TestHostClientAgainstTheStepRoute runs the real step client, through the adapter that serve uses,
// against the router, the step route, the verifier and the actor of the host service.
func TestHostClientAgainstTheStepRoute(t *testing.T) {
	const controllerID = "spiffe://dev.env.poc.internal/cp/cell-controller"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := func() []ed25519.PublicKey { return []ed25519.PublicKey{pub} }
	topo := &topology.Topology{
		NodeImage: "kindest/node:test@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
		Clusters: []topology.Cluster{
			{Name: "dev-cp", PodSubnet: "10.11.0.0/16", ServiceSubnet: "10.111.0.0/16", Issuer: "https://dev-cp.issuer.poc.internal", Components: []string{"envd"}},
			{Name: "dev-cell-1", PodSubnet: "10.20.0.0/16", ServiceSubnet: "10.120.0.0/16", Issuer: "https://dev-cell-1.issuer.poc.internal", Components: []string{"cell-identity"}},
		},
	}
	dir := t.TempDir()
	specs, err := hostsvc.OpenSpecStore(filepath.Join(dir, "spec"), keys, "dev")
	if err != nil {
		t.Fatal(err)
	}
	j, err := hostsvc.OpenJournal(filepath.Join(dir, "steps"), nil)
	if err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ver := &hostsvc.StepVerifier{Keys: keys, Env: "dev", Topo: topo, Spec: specs, Now: time.Now,
		Digest: func() (string, error) { return step.TestDigest, nil }}
	stage := hostsvc.Stage{Name: "creating", Timeout: time.Minute,
		Cluster: func(s step.Step) string { return s.Cell },
		Command: func(step.Step, hostsvc.Attempt) []string { return []string{"true"} }}
	actor, err := hostsvc.NewActor(hostsvc.ActorConfig{Journal: j, Verifier: ver, Spec: specs, Stages: []hostsvc.Stage{stage},
		Start: func([]string, []string, io.Writer) (*hostsvc.Group, error) {
			return nil, errors.New("no stage runs in this test")
		},
		Log: quiet})
	if err != nil {
		t.Fatal(err)
	}

	_, rogue, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var signStepKey func(ed25519.PrivateKey, string) (step.Step, []byte)
	signStep := func(cell string) (step.Step, []byte) { return signStepKey(priv, cell) }
	signStepKey = func(key ed25519.PrivateKey, cell string) (step.Step, []byte) {
		cl, _ := topo.Cluster(cell)
		s := step.Step{ID: step.NewID(), Env: "dev", Cell: cell, Kind: step.KindCellCreate, Version: 1, KeyEpoch: 1,
			IssuedAt: time.Now(), ExpiresAt: time.Now().Add(step.DefaultTTL),
			Cluster:         step.ClusterRef{PodSubnet: cl.PodSubnet, ServiceSubnet: cl.ServiceSubnet, Issuer: cl.Issuer},
			BootstrapSHA256: step.TestDigest}
		env, err := step.Sign(s, key)
		if err != nil {
			t.Fatal(err)
		}
		return s, env
	}
	indexed, indexedEnv := signStep("dev-cell-1")
	_, strayEnv := signStep("dev-cell-1")
	_, body, err := step.Verify(indexedEnv, keys())
	if err != nil {
		t.Fatal(err)
	}
	sp, err := spec.Sign(spec.Spec{Env: "dev", Revision: spec.Revision{Epoch: 1, Counter: 1},
		Steps: []spec.StepEntry{{Name: "dev-cell-1", StepID: indexed.ID, StepSHA256: step.PayloadSHA256(body)}}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := specs.Put(sp); err != nil {
		t.Fatal(err)
	}

	root, issue := devCA(t)
	rootFile := filepath.Join(dir, "dev-root.crt")
	if err := os.WriteFile(rootFile, root, 0o600); err != nil {
		t.Fatal(err)
	}
	mgmtID, stepsID := spiffeid.RequireFromString("spiffe://mgmt.poc.internal/api"), spiffeid.RequireFromString(controllerID)
	roots := hostsvc.FileBundleSet(map[spiffeid.TrustDomain]string{spiffeid.RequireTrustDomainFromString(hostsvc.StepClientTrustDomain): rootFile})
	cert, err := hostsvc.SelfSignedCert(hostsvc.KeyServerHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	router := hostsvc.NewRouter(http.NotFoundHandler(), http.NotFoundHandler(), hostsvc.NewStepHandler(ver, actor, quiet, time.Now), mgmtID, stepsID, 4)
	srv := hostsvc.NewKeyServer(router, hostsvc.ServerTLS(cert, roots, mgmtID, stepsID), quiet)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- hostsvc.ServeKeys(ctx, srv, ln, quiet, nil) }()
	t.Cleanup(func() { cancel(); <-done })

	sum := sha256.Sum256(cert.Leaf.Raw)
	client, err := realDeps().host(runConfig{hostAddr: ln.Addr().String(), hostServerName: hostsvc.KeyServerHost, pin: sum[:]}, issue(controllerID))
	if err != nil {
		t.Fatal(err)
	}

	// Put sends the envelope and the step ID of that envelope.
	st, err := client.Put(t.Context(), indexed.ID, indexedEnv)
	if err != nil || st.ID != indexed.ID || st.Cell != "dev-cell-1" || st.State != mgmtapi.StepQueued {
		t.Fatalf("put: %+v, %v", st, err)
	}
	// Get asks for the ID that it is given.
	st, err = client.Get(t.Context(), indexed.ID)
	if err != nil || st.ID != indexed.ID || st.State != mgmtapi.StepQueued {
		t.Fatalf("get: %+v, %v", st, err)
	}
	// A step that the host service does not know is hostsvc_denied with status 404: the poll of a
	// dropped step ends there.
	var he *mgmtapi.HostError
	if _, err := client.Get(t.Context(), step.NewID()); !errors.As(err, &he) || he.Reason != mgmtapi.ReasonHostsvcDenied || he.Status != http.StatusNotFound {
		t.Errorf("get of an unknown step: %v", err)
	}
	// A signed step that the spec does not index is the case spec_behind: busy with Retry-After 30.
	if _, err := client.Put(t.Context(), "", strayEnv); !errors.As(err, &he) || he.Reason != mgmtapi.ReasonHostsvcBusy || he.RetryAfter != 30*time.Second {
		t.Errorf("put of an unindexed step: %v (%+v)", err, he)
	}
	// A step under another key is refused with 403 and a request ID.
	_, rogueEnv := signStepKey(rogue, "dev-cell-1")
	if _, err := client.Put(t.Context(), "", rogueEnv); !errors.As(err, &he) || he.Reason != mgmtapi.ReasonHostsvcDenied || he.Status != http.StatusForbidden || he.RequestID == "" {
		t.Errorf("put of a step under another key: %v (%+v)", err, he)
	}
	// A peer that the router does not allow is refused in the handshake.
	other, err := realDeps().host(runConfig{hostAddr: ln.Addr().String(), hostServerName: hostsvc.KeyServerHost, pin: sum[:]},
		issue("spiffe://dev.env.poc.internal/cp/other"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Get(t.Context(), indexed.ID); !errors.As(err, &he) || he.Reason != mgmtapi.ReasonHostsvcUnavailable {
		t.Errorf("get by another peer: %v", err)
	}
}
