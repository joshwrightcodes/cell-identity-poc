package hostsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
)

// stuckRuntime blocks one runtime call until release closes, and counts the calls that run.
type stuckRuntime struct {
	*fakeRuntime
	stuck   string
	release chan struct{}
	running atomic.Int32
	started atomic.Int32
}

func (s *stuckRuntime) hang(name string) {
	if name != s.stuck {
		return
	}
	s.started.Add(1)
	s.running.Add(1)
	defer s.running.Add(-1)
	<-s.release
}

func (s *stuckRuntime) List() ([]string, error)          { s.hang("List"); return s.fakeRuntime.List() }
func (s *stuckRuntime) Create(c *v1alpha4.Cluster) error { return s.fakeRuntime.Create(c) }
func (s *stuckRuntime) Kubeconfig(n string) (string, error) {
	s.hang("Kubeconfig")
	return s.fakeRuntime.Kubeconfig(n)
}
func (s *stuckRuntime) NodeIP(n string) (string, error) {
	s.hang("NodeIP")
	return s.fakeRuntime.NodeIP(n)
}

func stuckService(call string) (*Service, *stuckRuntime) {
	rt := &stuckRuntime{fakeRuntime: &fakeRuntime{clusters: map[string]bool{"rogue": true}}, stuck: call, release: make(chan struct{})}
	s := newTestService(rt.fakeRuntime, matchingObs())
	s.rt = rt
	return s, rt
}

// While docker hangs, no more than MaxFactsInFlight runtime calls run, whatever the callers do.
func TestFactsBoundsHungRuntimeCalls(t *testing.T) {
	for _, call := range []string{"List", "Kubeconfig", "NodeIP"} {
		t.Run(call, func(t *testing.T) {
			s, rt := stuckService(call)
			defer close(rt.release)
			var busy int
			for range 20 {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				start := time.Now()
				_, err := s.Facts(ctx, "rogue")
				cancel()
				if time.Since(start) > 2*time.Second {
					t.Fatalf("Facts took %v with %s hung", time.Since(start), call)
				}
				switch {
				case errors.Is(err, ErrLookupBusy):
					busy++
				case !errors.Is(err, context.DeadlineExceeded):
					t.Fatalf("Facts error = %v, want deadline exceeded or busy", err)
				}
			}
			const most = 2
			if got := rt.started.Load(); got > most {
				t.Errorf("%d runtime calls started with %s hung, want at most %d", got, call, most)
			}
			if busy < 20-most {
				t.Errorf("%d lookups failed fast, want at least %d", busy, 20-most)
			}
		})
	}
}

func TestFactsRecoversAfterRuntimeCallsReturn(t *testing.T) {
	s, rt := stuckService("List")
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, _ = s.Facts(ctx, "rogue")
		cancel()
	}
	busyCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := s.Facts(busyCtx, "rogue"); !errors.Is(err, ErrLookupBusy) {
		t.Fatalf("Facts error = %v, want busy while two calls hang", err)
	}
	close(rt.release)
	waitFor(t, "the hung calls to return", func() bool { return rt.running.Load() == 0 })
	waitFor(t, "a free lookup token", func() bool { return len(s.lookups) == 0 })
	if f, err := s.Facts(context.Background(), "rogue"); err != nil || f.Name != "rogue" {
		t.Fatalf("Facts = %+v, %v", f, err)
	}
}

// The slot wait of a lookup counts against its deadline.
func TestKeyCacheSlotWaitHasDeadline(t *testing.T) {
	hold := make(chan struct{})
	defer close(hold)
	facts := func(_ context.Context, cluster string) (Facts, error) {
		if cluster == "a" {
			<-hold
		}
		return Facts{Name: cluster, Issuer: "i", JWKS: testJWKS()}, nil
	}
	c := NewKeyCache(facts, KeyTTL, 1, nil)
	c.lookupTimeout = 50 * time.Millisecond
	go func() { _, _ = c.Get(context.Background(), "a") }()
	time.Sleep(20 * time.Millisecond)
	done := make(chan error, 1)
	go func() { _, err := c.Get(context.Background(), "b"); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Get error = %v, want deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a lookup waited for a slot without a deadline")
	}
}

func TestAPICallTimeoutDefault(t *testing.T) {
	if apiCallTimeout != 10*time.Second {
		t.Errorf("apiCallTimeout = %v, want 10s", apiCallTimeout)
	}
}

func shorten(t *testing.T) {
	t.Helper()
	old := apiCallTimeout
	apiCallTimeout = 150 * time.Millisecond
	t.Cleanup(func() { apiCallTimeout = old })
}

func returnsWithin(t *testing.T, d time.Duration, f func() error) error {
	t.Helper()
	ch := make(chan error, 1)
	go func() { ch <- f() }()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		t.Fatalf("call did not return within %v", d)
		return nil
	}
}

// Each API-server call has its own time limit, even when the caller gives no deadline.
func TestProbeCallsHaveTimeout(t *testing.T) {
	shorten(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/namespaces/kube-system/configmaps/kubeadm-config" {
			_, _ = w.Write([]byte(`{"data":{"ClusterConfiguration":"networking:\n  podSubnet: 10.0.0.0/16\n  serviceSubnet: 10.1.0.0/16\n"}}`))
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(4 * time.Second):
		}
	}))
	defer srv.Close()
	err := returnsWithin(t, 3*time.Second, func() error {
		_, err := HTTPProber{}.Probe(context.Background(), kubeconfigFor(t, srv))
		return err
	})
	if err == nil {
		t.Fatal("Probe succeeded against a server that never answers")
	}
}

func kubeconfigFor(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	cert, err := SelfSignedCert("client", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { j, _ := json.Marshal(b); return string(j[1 : len(j)-1]) }
	return `{"clusters":[{"cluster":{"server":"` + srv.URL + `","certificate-authority-data":"` + b64(ca) + `"}}],` +
		`"users":[{"user":{"client-certificate-data":"` + b64(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Leaf.Raw})) +
		`","client-key-data":"` + b64(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})) + `"}}]}`
}

func TestDockerReservedHasTimeout(t *testing.T) {
	shorten(t)
	dir := t.TempDir()
	script := "#!/bin/sh\nexec sleep 5\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	err := returnsWithin(t, 3*time.Second, func() error {
		_, err := DockerReserved(context.Background())
		return err
	})
	if err == nil {
		t.Fatal("DockerReserved succeeded with a docker that never answers")
	}
}
