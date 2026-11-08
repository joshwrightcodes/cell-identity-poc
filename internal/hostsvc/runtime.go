package hostsvc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/yaml"
)

// kindNetwork is the Docker network that kind attaches its nodes to.
const kindNetwork = "kind"

// limaHostPrefix is the Lima host network inside the Colima VM.
const limaHostPrefix = "192.168.5.0/24"

// KindRuntime runs clusters through the kind library and its Docker provider.
// The Docker provider runs the docker command line, so docker must be on PATH.
type KindRuntime struct {
	provider *cluster.Provider
}

// NewKindRuntime returns a Runtime backed by kind with the Docker provider.
func NewKindRuntime() *KindRuntime {
	return &KindRuntime{provider: cluster.NewProvider(cluster.ProviderWithDocker())}
}

// List returns the names of the kind clusters.
func (k *KindRuntime) List() ([]string, error) { return k.provider.List() }

// Create creates a cluster and waits for its control plane.
func (k *KindRuntime) Create(cfg *v1alpha4.Cluster) error {
	return k.provider.Create(cfg.Name,
		cluster.CreateWithV1Alpha4Config(cfg),
		cluster.CreateWithWaitForReady(5*time.Minute),
	)
}

// Delete deletes a cluster and its kubeconfig entries.
func (k *KindRuntime) Delete(name string) error { return k.provider.Delete(name, "") }

// Kubeconfig returns the kubeconfig with the address on the host.
func (k *KindRuntime) Kubeconfig(name string) (string, error) {
	return k.provider.KubeConfig(name, false)
}

// NodeIP returns the IPv4 address of the control-plane node on the kind network.
func (k *KindRuntime) NodeIP(name string) (string, error) {
	nodes, err := k.provider.ListInternalNodes(name)
	if err != nil {
		return "", err
	}
	want := name + "-control-plane"
	for _, n := range nodes {
		if n.String() != want {
			continue
		}
		v4, _, err := n.IP()
		if err != nil {
			return "", err
		}
		return v4, nil
	}
	return "", fmt.Errorf("node %s not found", want)
}

// DockerReserved returns every subnet of the kind Docker network, plus the Lima host network.
// Before the first cluster exists the kind network is absent, and only the Lima prefix remains.
func DockerReserved(ctx context.Context) ([]netip.Prefix, error) {
	reserved := []netip.Prefix{netip.MustParsePrefix(limaHostPrefix)}
	out, err := exec.CommandContext(ctx, "docker", "network", "inspect", kindNetwork,
		"--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "No such network") {
			return reserved, nil
		}
		return nil, fmt.Errorf("docker network inspect %s: %w: %s", kindNetwork, err, strings.TrimSpace(string(out)))
	}
	for _, f := range strings.Fields(string(out)) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("parse kind network subnet %q: %w", f, err)
		}
		reserved = append(reserved, p)
	}
	return reserved, nil
}

// HTTPProber reads cluster state from the API server with the client certificate of the kubeconfig.
type HTTPProber struct{}

type kubeconfigFile struct {
	Clusters []struct {
		Cluster struct {
			Server string `json:"server"`
			CAData []byte `json:"certificate-authority-data"`
		} `json:"cluster"`
	} `json:"clusters"`
	Users []struct {
		User struct {
			CertData []byte `json:"client-certificate-data"`
			KeyData  []byte `json:"client-key-data"`
		} `json:"user"`
	} `json:"users"`
}

// Probe returns the subnets, issuer and JWKS that the cluster reports.
func (HTTPProber) Probe(ctx context.Context, kubeconfig string) (Observed, error) {
	var kc kubeconfigFile
	if err := yaml.Unmarshal([]byte(kubeconfig), &kc); err != nil {
		return Observed{}, fmt.Errorf("parse kubeconfig: %w", err)
	}
	if len(kc.Clusters) != 1 || len(kc.Users) != 1 {
		return Observed{}, errors.New("kubeconfig must hold one cluster and one user")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(kc.Clusters[0].Cluster.CAData) {
		return Observed{}, errors.New("kubeconfig has no usable certificate authority")
	}
	cert, err := tls.X509KeyPair(kc.Users[0].User.CertData, kc.Users[0].User.KeyData)
	if err != nil {
		return Observed{}, fmt.Errorf("load client certificate: %w", err)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		}},
	}
	server := strings.TrimSuffix(kc.Clusters[0].Cluster.Server, "/")
	get := func(path string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+path, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: %s", path, resp.Status)
		}
		return body, nil
	}

	obs := Observed{APIServer: server}

	body, err := get("/api/v1/namespaces/kube-system/configmaps/kubeadm-config")
	if err != nil {
		return Observed{}, err
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &cm); err != nil {
		return Observed{}, fmt.Errorf("parse kubeadm-config: %w", err)
	}
	var cc struct {
		Networking struct {
			PodSubnet     string `json:"podSubnet"`
			ServiceSubnet string `json:"serviceSubnet"`
		} `json:"networking"`
	}
	if err := yaml.Unmarshal([]byte(cm.Data["ClusterConfiguration"]), &cc); err != nil {
		return Observed{}, fmt.Errorf("parse ClusterConfiguration: %w", err)
	}
	obs.PodSubnet, obs.ServiceSubnet = cc.Networking.PodSubnet, cc.Networking.ServiceSubnet

	body, err = get("/.well-known/openid-configuration")
	if err != nil {
		return Observed{}, err
	}
	var disc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &disc); err != nil {
		return Observed{}, fmt.Errorf("parse openid-configuration: %w", err)
	}
	obs.Issuer = disc.Issuer

	body, err = get("/openid/v1/jwks")
	if err != nil {
		return Observed{}, err
	}
	if !json.Valid(body) {
		return Observed{}, errors.New("jwks is not JSON")
	}
	obs.JWKS = json.RawMessage(body)
	return obs, nil
}
