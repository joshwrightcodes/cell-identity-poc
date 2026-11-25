package spireclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
)

// outage is longer than the default gRPC connection back-off needs to reach
// its large delays, so a client on default options misses a restart.
const (
	outage      = 75 * time.Second
	recoverWait = 15 * time.Second
)

// clientOptions is the option set under test.
var clientOptions = ClientOptions

type fakeAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	resp *workload.X509SVIDResponse
}

func (f *fakeAPI) FetchX509SVID(_ *workload.X509SVIDRequest, s workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := s.Send(f.resp); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func newResponse(t *testing.T) *workload.X509SVIDResponse {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://example.org/w")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "w"}, URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &workload.X509SVIDResponse{Svids: []*workload.X509SVID{{
		SpiffeId: "spiffe://example.org/w", X509Svid: der, X509SvidKey: pk, Bundle: der,
	}}}
}

func serve(t *testing.T, path string, resp *workload.X509SVIDResponse) *grpc.Server {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(s, &fakeAPI{resp: resp})
	go func() { _ = s.Serve(l) }()
	return s
}

type counter struct{ n atomic.Int64 }

func (c *counter) OnX509ContextUpdate(*workloadapi.X509Context) { c.n.Add(1) }
func (c *counter) OnX509ContextWatchError(error)                {}

func TestClientRecoversAfterLongOutage(t *testing.T) {
	if testing.Short() {
		t.Skip("runs for about 80 s")
	}
	// A unix socket path must stay short.
	dir, err := os.MkdirTemp("/tmp", "wl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "agent.sock")
	resp := newResponse(t)
	srv := serve(t, path, resp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &counter{}
	go func() {
		_ = workloadapi.WatchX509Context(ctx, c, append(clientOptions(), workloadapi.WithAddr("unix://"+path))...)
	}()
	waitFor(t, c, 1, 5*time.Second, "first update")

	srv.Stop()
	time.Sleep(outage)
	srv = serve(t, path, resp)
	defer srv.Stop()
	restarted := time.Now()

	waitFor(t, c, 2, recoverWait, "update after restart")
	t.Logf("update arrived %v after the restart", time.Since(restarted).Round(time.Millisecond))
}

func waitFor(t *testing.T, c *counter, n int64, d time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c.n.Load() >= n {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no %s within %v", what, d)
}
