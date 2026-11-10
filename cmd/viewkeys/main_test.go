package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

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

	// A second run changes nothing, and makes no key.
	before := secrets(t, client)
	client.ClearActions()
	runKeys(t, client, testConfig(false))
	for _, a := range client.Actions() {
		if a.GetVerb() != "get" {
			t.Errorf("the second run made a %s call", a.GetVerb())
		}
	}
	for name, s := range secrets(t, client) {
		if !equalData(s.Data, before[name].Data) {
			t.Errorf("a second run changed Secret %s", name)
		}
	}
}

// A Create that returns AlreadyExists for a Secret that the run could not read counts as done:
// the run succeeds and changes nothing.
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
	// The run reads argocd-agent-jwt as missing, as after a race with another run.
	client.PrependReactor("get", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.(k8stesting.GetAction).GetName() == "argocd-agent-jwt" {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "argocd-agent-jwt")
		}
		return false, nil, nil
	})
	out := runKeys(t, client, testConfig(false))
	creates := 0
	for _, a := range client.Actions() {
		switch a.GetVerb() {
		case "create":
			creates++
		case "delete", "update", "patch":
			t.Errorf("unexpected %s of %s", a.GetVerb(), a.GetResource().Resource)
		}
	}
	if creates != 1 {
		t.Errorf("the run made %d Create calls, want 1 for argocd-agent-jwt", creates)
	}
	if !strings.Contains(out, `"existing":["argocd-agent-jwt"`) {
		t.Errorf("output %s does not count argocd-agent-jwt as existing", out)
	}
	for name, s := range secrets(t, client) {
		if !equalData(s.Data, before[name].Data) {
			t.Errorf("Secret %s changed", name)
		}
	}
}

// consistent checks that every certificate Secret chains to argocd-agent-ca and carries its digest.
func consistent(t *testing.T, client *fake.Clientset) *x509.Certificate {
	t.Helper()
	ca := parseCert(t, secretOf(t, client, "argocd-agent-ca").Data["ca.crt"])
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	sum := sha256.Sum256(ca.Raw)
	for _, name := range setNames[1:] {
		if name == "argocd-agent-jwt" || name == "argocd-secret" {
			continue
		}
		s := secretOf(t, client, name)
		if s.Annotations["poc.internal/agent-ca-sha256"] != hex.EncodeToString(sum[:]) {
			t.Errorf("Secret %s has the CA digest %q, want %x", name, s.Annotations["poc.internal/agent-ca-sha256"], sum)
		}
		certPEM := s.Data["tls.crt"]
		if name != "argocd-agent-resource-proxy-tls" {
			var conf struct {
				TLS struct {
					CertData []byte `json:"certData"`
				} `json:"tlsClientConfig"`
			}
			if err := json.Unmarshal(s.Data["config"], &conf); err != nil {
				t.Fatal(err)
			}
			certPEM = conf.TLS.CertData
		}
		if _, err := parseCert(t, certPEM).Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Errorf("Secret %s does not chain to argocd-agent-ca: %v", name, err)
		}
	}
	return ca
}

// A run that fails one Create after the keys exist leaves no CA Secret, because the CA comes last.
// The next run, with no manual step, makes a consistent set.
func TestKeysRecoverAfterAFailedCreate(t *testing.T) {
	for _, failing := range []string{"argocd-agent-resource-proxy-tls", "cluster-dev-dev-cell-2", "argocd-agent-ca"} {
		t.Run(failing, func(t *testing.T) {
			client := fake.NewClientset()
			failed := false
			client.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
				if a.(k8stesting.CreateAction).GetObject().(*corev1.Secret).Name == failing && !failed {
					failed = true
					return true, nil, errors.New("etcdserver: request timed out")
				}
				return false, nil, nil
			})
			var out bytes.Buffer
			if err := run(context.Background(), client, testConfig(false), &out); err == nil || !strings.Contains(err.Error(), "request timed out") {
				t.Fatalf("run 1: err %v, want the injected failure", err)
			}
			if _, err := client.CoreV1().Secrets(testNS).Get(context.Background(), "argocd-agent-ca", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				t.Fatalf("run 1 left argocd-agent-ca behind (err %v), so a retry could not sign", err)
			}
			got := runKeys(t, client, testConfig(false))
			if !strings.Contains(got, `"new_ca_reason":"no argocd-agent-ca"`) {
				t.Errorf("run 2 output %s, want the reason no argocd-agent-ca", got)
			}
			consistent(t, client)
		})
	}
}

// Certificate Secrets of an earlier run, with no argocd-agent-ca, chain to a CA whose key is gone.
// One run replaces each of them under a new CA.
func TestKeysReplaceLeavesOfLostCA(t *testing.T) {
	seed := fake.NewClientset()
	runKeys(t, seed, testConfig(false))
	var objs []runtime.Object
	for name, s := range secrets(t, seed) {
		if name != "argocd-agent-ca" {
			objs = append(objs, s.DeepCopy())
		}
	}
	client := fake.NewClientset(objs...)
	before := secrets(t, client)
	out := runKeys(t, client, testConfig(false))
	var res struct{ Deleted, Created []string }
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	for _, leaf := range []string{"argocd-agent-resource-proxy-tls", "cluster-dev-dev-cell-1", "cluster-dev-dev-cell-2"} {
		if !slices.Contains(res.Deleted, leaf) || !slices.Contains(res.Created, leaf) {
			t.Errorf("output %s does not list %s as deleted and created", out, leaf)
		}
		if equalData(secretOf(t, client, leaf).Data, before[leaf].Data) {
			t.Errorf("Secret %s kept the content of the lost CA", leaf)
		}
	}
	consistent(t, client)
}

// A certificate Secret that comes back between the delete and the second Create stops the run.
func TestKeysLeafComesBack(t *testing.T) {
	client := fake.NewClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "argocd-agent-resource-proxy-tls", Namespace: testNS}})
	client.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if name := a.(k8stesting.CreateAction).GetObject().(*corev1.Secret).Name; name == "argocd-agent-resource-proxy-tls" {
			return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, name)
		}
		return false, nil, nil
	})
	var out bytes.Buffer
	if err := run(context.Background(), client, testConfig(false), &out); err == nil || !strings.Contains(err.Error(), "came back during the run") {
		t.Fatalf("err %v, want a stop that says the Secret came back", err)
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

// When a certificate Secret is missing, or one chains to another CA, the kept CA cannot sign a new
// one. The run then replaces the CA and every certificate Secret, with no manual step.
func TestKeysReplaceAllUnderAnInconsistentCA(t *testing.T) {
	other := fake.NewClientset()
	runKeys(t, other, testConfig(false))
	for _, tc := range []struct{ name, reason string }{
		{"missing", "cluster-dev-dev-cell-2 is missing"},
		{"foreign", "cluster-dev-dev-cell-2 names another CA"},
		{"unsigned", "cluster-dev-dev-cell-2 does not chain to argocd-agent-ca"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed := fake.NewClientset()
			runKeys(t, seed, testConfig(false))
			oldCA := secretOf(t, seed, "argocd-agent-ca").Data["ca.crt"]
			var objs []runtime.Object
			for name, s := range secrets(t, seed) {
				switch {
				case name != "cluster-dev-dev-cell-2":
					objs = append(objs, s.DeepCopy())
				case tc.name == "foreign":
					objs = append(objs, secretOf(t, other, name).DeepCopy())
				case tc.name == "unsigned":
					f := secretOf(t, other, name).DeepCopy()
					f.Annotations["poc.internal/agent-ca-sha256"] = s.Annotations["poc.internal/agent-ca-sha256"]
					objs = append(objs, f)
				}
			}
			client := fake.NewClientset(objs...)
			out := runKeys(t, client, testConfig(false))
			if !strings.Contains(out, tc.reason) {
				t.Errorf("output %s, want the reason %q", out, tc.reason)
			}
			if bytes.Equal(secretOf(t, client, "argocd-agent-ca").Data["ca.crt"], oldCA) {
				t.Error("the run kept the CA")
			}
			consistent(t, client)
		})
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
	if s.Annotations["managed-by"] != "argocd-agent" {
		t.Errorf("annotations %v, want managed-by argocd-agent", s.Annotations)
	}
	if !ca.MaxPathLenZero || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("the CA may sign intermediate CAs, or may not sign certificates")
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
	if life := client1.NotAfter.Sub(client1.NotBefore); life > 180*24*time.Hour+2*time.Minute {
		t.Errorf("the client certificate lives %s, want at most 180 days", life)
	}
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
		{"--namespace", testNS, "--agents", "dev-dev-cell-1,dev-dev-cell-1", "--resource-proxy-host", testHost},
	} {
		if _, err := parse(args); err == nil {
			t.Errorf("parse(%q) succeeded", args)
		}
	}
	var out bytes.Buffer
	if code := execute(context.Background(), []string{"--namespace", testNS}, &out); code != 2 || strings.Count(out.String(), "\n") != 1 {
		t.Errorf("execute with a bad argument: status %d, output %q; want status 2 and one line", code, out.String())
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
