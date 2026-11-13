//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	resourceProxyService = "svc/argocd-agent-resource-proxy"
	resourceProxyPort    = 9090
	// resourceProxyName is a name in the server certificate of the resource proxy.
	resourceProxyName = "argocd-agent-resource-proxy.central-view-system.svc"
)

// viewREST returns a client config for the resource proxy of the central view, as the central
// argocd-server uses it for the cell of agent. It reads the client certificate and key from Secret
// cluster-<agent> in management into memory, and reaches the proxy through a port-forward that
// stops when the test ends. The requests leave the principal as resource requests to the agent,
// and the agent sends them to the API server of its cell with its own ServiceAccount.
func viewREST(t *testing.T, agent string) *rest.Config {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", viewNamespace, "get", "secret", "cluster-"+agent, "-o", "jsonpath={.data.config}")
	if err != nil {
		t.Fatalf("read the cluster Secret of %s: %v", agent, err)
	}
	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatalf("decode the cluster Secret of %s: %v", agent, err)
	}
	var cfg struct {
		TLSClientConfig struct {
			CAData   []byte `json:"caData"`
			CertData []byte `json:"certData"`
			KeyData  []byte `json:"keyData"`
		} `json:"tlsClientConfig"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse the cluster Secret of %s: %v", agent, err)
	}
	c := cfg.TLSClientConfig
	if len(c.CAData) == 0 || len(c.CertData) == 0 || len(c.KeyData) == 0 {
		t.Fatalf("the cluster Secret of %s holds no client certificate", agent)
	}
	addr := portForward(t, mgmtCluster, viewNamespace, resourceProxyService, resourceProxyPort)
	return &rest.Config{
		Host:    "https://" + addr,
		Timeout: 90 * time.Second,
		TLSClientConfig: rest.TLSClientConfig{
			ServerName: resourceProxyName,
			CAData:     c.CAData,
			CertData:   c.CertData,
			KeyData:    c.KeyData,
		},
		ContentConfig: rest.ContentConfig{ContentType: "application/json", AcceptContentTypes: "application/json"},
		QPS:           50,
		Burst:         50,
	}
}

// viewClient returns a typed client over viewREST.
func viewClient(t *testing.T, agent string) (*kubernetes.Clientset, *rest.Config) {
	t.Helper()
	cfg := viewREST(t, agent)
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cs, cfg
}

func ctxTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 90*time.Second)
}
