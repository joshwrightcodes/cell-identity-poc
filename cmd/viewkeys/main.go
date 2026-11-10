// Command viewkeys makes the keys of the central Argo CD view inside the cluster. It runs as Job
// viewkeys in the namespace of the Argo CD Agent principal, before the principal starts.
//
//	viewkeys --namespace <ns> --agents <a,b> --resource-proxy-host <host> [--rotate]
//
// It creates each absent Secret of this set with Create, and counts AlreadyExists as done:
//   - argocd-agent-ca: the CA certificate in ca.crt and tls.crt. The CA key exists only in the
//     memory of this process, so no Secret holds it.
//   - argocd-agent-resource-proxy-tls: the server certificate of the resource proxy for the host.
//   - argocd-agent-jwt: the RSA key that signs the agent tokens of the principal.
//   - argocd-secret: server.secretkey of argocd-server.
//   - cluster-<agent> for each agent: the Argo CD cluster Secret that points argocd-server at the
//     resource proxy, with a client certificate whose CN is the agent name.
//
// The formats follow argocd-agentctl of Argo CD Agent v0.10.0 (cmd/ctl/ca.go, cmd/ctl/jwt.go and
// cmd/ctl/agent.go), as vendor/README.md records. Without the CA key, a new certificate needs a new
// CA. So when the CA Secret exists and a certificate Secret is missing, the run fails and names
// view:rotate-keys. --rotate deletes the whole set first, then creates it again.
//
// Standard output carries one JSON line with the Secret names on success, and one JSON error
// line on failure. No line holds key material.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
)

const (
	name = "viewkeys"

	caSecret    = "argocd-agent-ca"
	proxySecret = "argocd-agent-resource-proxy-tls"
	jwtSecret   = "argocd-agent-jwt"
	argoSecret  = "argocd-secret"
	proxyPort   = 9090

	// The validity of argocd-agentctl: 3650 days for the CA, 180 days for each leaf
	// (internal/tlsutil/generate.go of v0.10.0).
	caValidity   = 3650 * 24 * time.Hour
	leafValidity = 180 * 24 * time.Hour
	// jwtBits is the size of the JWT signing key of argocd-agentctl jwt create-key.
	jwtBits = 4096
	// secretKeyBytes is the size of server.secretkey.
	secretKeyBytes = 32
)

var (
	dnsLabel     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

type config struct {
	namespace, proxyHost string
	agents               []string
	rotate               bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.Stdout)
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, stdout io.Writer) int {
	cfg, err := parse(args)
	if err != nil {
		cli.Fail(stdout, name, err)
		return 2
	}
	return cli.Run(stdout, name, func(out io.Writer) error {
		rc, err := rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("in-cluster config: %w", err)
		}
		client, err := kubernetes.NewForConfig(rc)
		if err != nil {
			return err
		}
		return run(ctx, client, cfg, out)
	})
}

func parse(args []string) (config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	ns := fs.String("namespace", "", "namespace of the principal and argocd-server")
	agents := fs.String("agents", "", "comma-separated agent names, <env>-<cell>")
	host := fs.String("resource-proxy-host", "", "DNS name of the resource proxy Service")
	rotate := fs.Bool("rotate", false, "delete the whole set first, then create it again")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if !dnsLabel.MatchString(*ns) {
		return config{}, fmt.Errorf("--namespace %q is not a namespace name", *ns)
	}
	if len(*host) > 253 || !dnsSubdomain.MatchString(*host) {
		return config{}, fmt.Errorf("--resource-proxy-host %q is not a DNS name", *host)
	}
	cfg := config{namespace: *ns, proxyHost: *host, rotate: *rotate}
	for a := range strings.SplitSeq(*agents, ",") {
		if !dnsLabel.MatchString(a) {
			return config{}, fmt.Errorf("--agents holds %q, which is not an agent name", a)
		}
		if slices.Contains(cfg.agents, a) {
			return config{}, fmt.Errorf("--agents names %s twice", a)
		}
		cfg.agents = append(cfg.agents, a)
	}
	return cfg, nil
}

// result is the output line.
type result struct {
	Namespace string   `json:"namespace"`
	Deleted   []string `json:"deleted"`
	Created   []string `json:"created"`
	Existing  []string `json:"existing"`
}

func clusterSecretName(agent string) string { return "cluster-" + agent }

func run(ctx context.Context, client kubernetes.Interface, cfg config, out io.Writer) error {
	secrets := client.CoreV1().Secrets(cfg.namespace)
	res := result{Namespace: cfg.namespace, Deleted: []string{}, Created: []string{}, Existing: []string{}}
	leaves := []string{proxySecret}
	for _, a := range cfg.agents {
		leaves = append(leaves, clusterSecretName(a))
	}

	if cfg.rotate {
		for _, n := range append([]string{caSecret, jwtSecret, argoSecret}, leaves...) {
			err := secrets.Delete(ctx, n, metav1.DeleteOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete Secret %s: %w", n, err)
			}
			if err == nil {
				res.Deleted = append(res.Deleted, n)
			}
		}
	}

	// create creates one Secret. It reports whether the Secret was new.
	create := func(s *corev1.Secret) (bool, error) {
		s.Namespace = cfg.namespace
		if _, err := secrets.Create(ctx, s, metav1.CreateOptions{}); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return false, nil
			}
			return false, fmt.Errorf("create Secret %s: %w", s.Name, err)
		}
		return true, nil
	}
	record := func(n string, created bool) {
		if created {
			res.Created = append(res.Created, n)
		} else {
			res.Existing = append(res.Existing, n)
		}
	}

	for _, mk := range []func() (*corev1.Secret, error){jwtKey, serverKey} {
		s, err := mk()
		if err != nil {
			return err
		}
		created, err := create(s)
		if err != nil {
			return err
		}
		record(s.Name, created)
	}

	ca, err := newCA()
	if err != nil {
		return err
	}
	caCreated, err := create(ca.secret())
	if err != nil {
		return err
	}
	record(caSecret, caCreated)
	if !caCreated {
		// The stored CA is not the one in memory, so this run cannot sign. Every certificate Secret
		// must exist already.
		var missing []string
		for _, n := range leaves {
			if _, err := secrets.Get(ctx, n, metav1.GetOptions{}); err != nil {
				if !apierrors.IsNotFound(err) {
					return fmt.Errorf("get Secret %s: %w", n, err)
				}
				missing = append(missing, n)
				continue
			}
			res.Existing = append(res.Existing, n)
		}
		if len(missing) > 0 {
			return fmt.Errorf("secret %s exists, and %s is missing. No copy of the CA key exists, so a new certificate needs a new CA. Run: mise run view:rotate-keys",
				caSecret, strings.Join(missing, ", "))
		}
		return writeResult(out, res)
	}

	// The CA is new, so a certificate Secret that exists chains to a CA whose key is gone. Replace it.
	proxy, err := ca.serverSecret(cfg.proxyHost)
	if err != nil {
		return err
	}
	leafSecrets := []*corev1.Secret{proxy}
	for _, a := range cfg.agents {
		s, err := ca.clusterSecret(a, cfg.proxyHost)
		if err != nil {
			return err
		}
		leafSecrets = append(leafSecrets, s)
	}
	for _, s := range leafSecrets {
		created, err := create(s.DeepCopy())
		if err != nil {
			return err
		}
		if !created {
			if err := secrets.Delete(ctx, s.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete Secret %s, which chains to a lost CA: %w", s.Name, err)
			}
			res.Deleted = append(res.Deleted, s.Name)
			if created, err = create(s.DeepCopy()); err != nil {
				return err
			} else if !created {
				return fmt.Errorf("secret %s came back during the run. Run viewkeys again", s.Name)
			}
		}
		res.Created = append(res.Created, s.Name)
	}
	return writeResult(out, res)
}

func writeResult(out io.Writer, res result) error {
	line, err := json.Marshal(res)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s\n", line)
	return err
}

func jwtKey() (*corev1.Secret, error) {
	key, err := rsa.GenerateKey(rand.Reader, jwtBits)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: jwtSecret},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"jwt.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})},
	}, nil
}

// serverKey makes argocd-secret. argocd-server reads only Secrets with the part-of label.
func serverKey() (*corev1.Secret, error) {
	b := make([]byte, secretKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: argoSecret, Labels: map[string]string{
			"app.kubernetes.io/name": argoSecret, "app.kubernetes.io/part-of": "argocd"}},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"server.secretkey": []byte(base64.StdEncoding.EncodeToString(b))},
	}, nil
}

type authority struct {
	cert *x509.Certificate
	pem  []byte
	key  crypto.Signer
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func newCA() (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: caSecret},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(caValidity),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: key}, nil
}

func (a *authority) secret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: caSecret},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"ca.crt": a.pem, "tls.crt": a.pem},
	}
}

// leaf signs a new certificate and returns it with its key, both as PEM.
func (a *authority) leaf(cn string, usage x509.ExtKeyUsage, dns []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(leafValidity),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, key.Public(), a.key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

// serverSecret is the TLS Secret of the resource proxy. The principal reads it with a check of
// the type kubernetes.io/tls (internal/tlsutil/kubernetes.go, TLSCertFromSecret).
func (a *authority) serverSecret(host string) (*corev1.Secret, error) {
	crt, key, err := a.leaf("argocd-agent-resource-proxy", x509.ExtKeyUsageServerAuth, []string{host})
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: proxySecret},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": crt, "tls.key": key},
	}, nil
}

// tlsClientConfig has the JSON names of the Argo CD v1alpha1.TLSClientConfig fields.
type tlsClientConfig struct {
	Insecure bool   `json:"insecure"`
	CertData []byte `json:"certData,omitempty"`
	KeyData  []byte `json:"keyData,omitempty"`
	CAData   []byte `json:"caData,omitempty"`
}

// clusterSecret is the Argo CD cluster Secret of one agent, as argocd-agentctl agent create
// writes it (cmd/ctl/agent.go and internal/argocd/cluster/conversion.go of v0.10.0).
func (a *authority) clusterSecret(agent, host string) (*corev1.Secret, error) {
	crt, key, err := a.leaf(agent, x509.ExtKeyUsageClientAuth, nil)
	if err != nil {
		return nil, err
	}
	conf, err := json.Marshal(struct {
		TLS tlsClientConfig `json:"tlsClientConfig"`
	}{tlsClientConfig{CertData: crt, KeyData: key, CAData: a.pem}})
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterSecretName(agent),
			Labels: map[string]string{
				"argocd.argoproj.io/secret-type":           "cluster",
				"argocd-agent.argoproj-labs.io/agent-name": agent,
			},
			Annotations: map[string]string{
				"managed-by":                        "argocd-agent",
				"argocd.argoproj.io/skip-reconcile": "true",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"name":   []byte(agent),
			"server": fmt.Appendf(nil, "https://%s:%d?agentName=%s", host, proxyPort, agent),
			"config": conf,
		},
	}, nil
}
