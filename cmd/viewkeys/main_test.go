package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const testNS = "central-view-system"

var (
	testAgents = []string{"dev-dev-cell-1", "dev-dev-cell-2"}
	testHost   = "argocd-agent-resource-proxy.central-view-system.svc"
)

func testConfig(rotate bool) config {
	return config{namespace: testNS, agents: testAgents, proxyHost: testHost, rotate: rotate}
}

// setNames are the Secrets that viewkeys keeps for testAgents.
var setNames = []string{"argocd-agent-ca", "argocd-agent-resource-proxy-tls", "argocd-agent-jwt", "argocd-secret",
	"cluster-dev-dev-cell-1", "cluster-dev-dev-cell-2"}

func runKeys(t *testing.T, client *fake.Clientset, cfg config) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(context.Background(), client, cfg, &out); err != nil {
		t.Fatalf("run: %v\noutput: %s", err, out.String())
	}
	return out.String()
}

func secretOf(t *testing.T, client *fake.Clientset, name string) *corev1.Secret {
	t.Helper()
	s, err := client.CoreV1().Secrets(testNS).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get Secret %s: %v", name, err)
	}
	return s
}

func secrets(t *testing.T, client *fake.Clientset) map[string]*corev1.Secret {
	t.Helper()
	list, err := client.CoreV1().Secrets(testNS).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*corev1.Secret{}
	for i := range list.Items {
		out[list.Items[i].Name] = &list.Items[i]
	}
	return out
}

func parseCert(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("no PEM certificate in %q", data)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A present argocd-agent-jwt stays byte-equal, and every other Secret of the set appears.
func TestKeysCreatesAbsentOnly(t *testing.T) {
	jwt := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "argocd-agent-jwt", Namespace: testNS},
		Data: map[string][]byte{"jwt.key": []byte("an existing key")}}
	client := fake.NewClientset(jwt)
	runKeys(t, client, testConfig(false))
	got := secrets(t, client)
	for _, name := range setNames {
		if got[name] == nil {
			t.Errorf("Secret %s is missing", name)
		}
	}
	if len(got) != len(setNames) {
		t.Errorf("got %d Secrets, want %d", len(got), len(setNames))
	}
	if string(got["argocd-agent-jwt"].Data["jwt.key"]) != "an existing key" || len(got["argocd-agent-jwt"].Data) != 1 {
		t.Errorf("the present argocd-agent-jwt changed: %v", got["argocd-agent-jwt"].Data)
	}

	// A second run changes nothing.
	before := secrets(t, client)
	runKeys(t, client, testConfig(false))
	for name, s := range secrets(t, client) {
		if !equalData(s.Data, before[name].Data) {
			t.Errorf("a second run changed Secret %s", name)
		}
	}
}

// A Create that returns AlreadyExists counts as done: the run succeeds and changes nothing.
func TestKeysCreateAlreadyExistsIsDone(t *testing.T) {
	seed := fake.NewClientset()
	runKeys(t, seed, testConfig(false))
	var objs []runtime.Object
	for _, s := range secrets(t, seed) {
		objs = append(objs, s.DeepCopy())
	}
	if len(objs) != len(setNames) {
		t.Fatalf("the seed run made %d Secrets, want %d", len(objs), len(setNames))
	}
	client := fake.NewClientset(objs...)
	before := secrets(t, client)
	client.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		name := a.(k8stesting.CreateAction).GetObject().(*corev1.Secret).Name
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, name)
	})
	runKeys(t, client, testConfig(false))
	for _, a := range client.Actions() {
		if a.GetVerb() == "delete" || a.GetVerb() == "update" || a.GetVerb() == "patch" {
			t.Errorf("unexpected %s of %s", a.GetVerb(), a.GetResource().Resource)
		}
	}
	for name, s := range secrets(t, client) {
		if !equalData(s.Data, before[name].Data) {
			t.Errorf("Secret %s changed", name)
		}
	}
}

// argocd-agent-ca holds the CA certificate in ca.crt and tls.crt, and no key.
func TestKeysKeepNoCAKey(t *testing.T) {
	client := fake.NewClientset()
	runKeys(t, client, testConfig(false))
	ca := secretOf(t, client, "argocd-agent-ca")
	if len(ca.Data) != 2 || ca.Data["ca.crt"] == nil || !bytes.Equal(ca.Data["ca.crt"], ca.Data["tls.crt"]) {
		t.Fatalf("argocd-agent-ca has keys %v, want ca.crt and tls.crt with the same certificate", keysOf(ca.Data))
	}
	if !parseCert(t, ca.Data["ca.crt"]).IsCA {
		t.Fatal("ca.crt is not a CA certificate")
	}
	for name, s := range secrets(t, client) {
		for k, v := range s.Data {
			if strings.Contains(string(v), "PRIVATE KEY") && name != "argocd-agent-jwt" && name != "argocd-agent-resource-proxy-tls" {
				t.Errorf("Secret %s key %s holds a private key", name, k)
			}
		}
	}
}

// When argocd-agent-ca exists and a Secret that its key must sign is missing, the run fails and
// names view:rotate-keys, because no copy of the CA key exists.
func TestKeysRefuseMissingLeafUnderKeptCA(t *testing.T) {
	seed := fake.NewClientset()
	runKeys(t, seed, testConfig(false))
	var objs []runtime.Object
	for name, s := range secrets(t, seed) {
		if name != "cluster-dev-dev-cell-2" {
			objs = append(objs, s.DeepCopy())
		}
	}
	client := fake.NewClientset(objs...)
	var out bytes.Buffer
	err := run(context.Background(), client, testConfig(false), &out)
	if err == nil || !strings.Contains(err.Error(), "view:rotate-keys") || !strings.Contains(err.Error(), "cluster-dev-dev-cell-2") {
		t.Fatalf("err %v, want a refusal that names cluster-dev-dev-cell-2 and view:rotate-keys", err)
	}
}

// With --rotate, every Secret of the set gets new content.
func TestKeysRotateReplacesAll(t *testing.T) {
	client := fake.NewClientset()
	runKeys(t, client, testConfig(false))
	before := secrets(t, client)
	runKeys(t, client, testConfig(true))
	after := secrets(t, client)
	for _, name := range setNames {
		if after[name] == nil {
			t.Errorf("Secret %s is missing after the rotation", name)
			continue
		}
		for k, v := range after[name].Data {
			if k == "name" || k == "server" {
				continue
			}
			if bytes.Equal(v, before[name].Data[k]) {
				t.Errorf("Secret %s key %s did not change", name, k)
			}
		}
	}
}

// The cluster Secret of an agent has the cluster label, the resource proxy URL with the agent
// name, and a client certificate with CN <agent> that the CA signs. The resource proxy
// certificate names the host and chains to the same CA.
func TestClusterSecretFormat(t *testing.T) {
	client := fake.NewClientset()
	runKeys(t, client, testConfig(false))
	ca := parseCert(t, secretOf(t, client, "argocd-agent-ca").Data["ca.crt"])
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	s := secretOf(t, client, "cluster-dev-dev-cell-1")
	if s.Labels["argocd.argoproj.io/secret-type"] != "cluster" || s.Labels["argocd-agent.argoproj-labs.io/agent-name"] != "dev-dev-cell-1" {
		t.Errorf("labels %v", s.Labels)
	}
	if s.Annotations["argocd.argoproj.io/skip-reconcile"] != "true" {
		t.Errorf("annotations %v, want argocd.argoproj.io/skip-reconcile true", s.Annotations)
	}
	if got, want := string(s.Data["server"]), "https://"+testHost+":9090?agentName=dev-dev-cell-1"; got != want {
		t.Errorf("server %q, want %q", got, want)
	}
	if string(s.Data["name"]) != "dev-dev-cell-1" {
		t.Errorf("name %q", s.Data["name"])
	}
	var conf struct {
		TLS struct {
			Insecure bool   `json:"insecure"`
			CertData []byte `json:"certData"`
			KeyData  []byte `json:"keyData"`
			CAData   []byte `json:"caData"`
		} `json:"tlsClientConfig"`
	}
	if err := json.Unmarshal(s.Data["config"], &conf); err != nil {
		t.Fatalf("config: %v", err)
	}
	if conf.TLS.Insecure || len(conf.TLS.KeyData) == 0 {
		t.Errorf("tlsClientConfig insecure %v, key %d bytes", conf.TLS.Insecure, len(conf.TLS.KeyData))
	}
	client1 := parseCert(t, conf.TLS.CertData)
	if client1.Subject.CommonName != "dev-dev-cell-1" {
		t.Errorf("client certificate CN %q", client1.Subject.CommonName)
	}
	if _, err := client1.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the client certificate does not chain to the CA: %v", err)
	}
	if !bytes.Equal(parseCert(t, conf.TLS.CAData).Raw, ca.Raw) {
		t.Error("caData is not the CA certificate")
	}

	proxy := secretOf(t, client, "argocd-agent-resource-proxy-tls")
	if proxy.Type != corev1.SecretTypeTLS {
		t.Errorf("argocd-agent-resource-proxy-tls has type %q", proxy.Type)
	}
	server := parseCert(t, proxy.Data["tls.crt"])
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, DNSName: testHost, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the resource proxy certificate does not serve %s under the CA: %v", testHost, err)
	}

	jwt := secretOf(t, client, "argocd-agent-jwt")
	block, _ := pem.Decode(jwt.Data["jwt.key"])
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("jwt.key holds no PKCS#8 PEM key")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("jwt.key: %v", err)
	}
	srv := secretOf(t, client, "argocd-secret")
	if len(srv.Data["server.secretkey"]) < 32 || srv.Labels["app.kubernetes.io/part-of"] != "argocd" {
		t.Errorf("argocd-secret: %d key bytes, labels %v", len(srv.Data["server.secretkey"]), srv.Labels)
	}
}

// Standard output holds one JSON line with the Secret names, and no PEM block.
func TestKeysNeverLogged(t *testing.T) {
	client := fake.NewClientset()
	for _, rotate := range []bool{false, true} {
		out := runKeys(t, client, testConfig(rotate))
		if strings.Contains(out, "-----BEGIN") || strings.Contains(out, "PRIVATE") {
			t.Fatalf("output holds key material: %s", out)
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		var res map[string]any
		if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &res) != nil {
			t.Fatalf("output %q, want one JSON line", out)
		}
	}
}

func TestParseRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--agents", "dev-dev-cell-1", "--resource-proxy-host", testHost},
		{"--namespace", testNS, "--resource-proxy-host", testHost},
		{"--namespace", testNS, "--agents", "dev-dev-cell-1"},
		{"--namespace", testNS, "--agents", "Dev_Cell", "--resource-proxy-host", testHost},
		{"--namespace", testNS, "--agents", "dev-dev-cell-1,", "--resource-proxy-host", testHost},
		{"--namespace", testNS, "--agents", "dev-dev-cell-1", "--resource-proxy-host", "a host"},
		{"--namespace", testNS, "--agents", "dev-dev-cell-1", "--resource-proxy-host", testHost, "extra"},
	} {
		if _, err := parse(args); err == nil {
			t.Errorf("parse(%q) succeeded", args)
		}
	}
	cfg, err := parse([]string{"--namespace", testNS, "--agents", "dev-dev-cell-1,dev-dev-cell-2", "--resource-proxy-host", testHost, "--rotate"})
	if err != nil || !cfg.rotate || len(cfg.agents) != 2 {
		t.Fatalf("parse: %+v, %v", cfg, err)
	}
}

func equalData(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
