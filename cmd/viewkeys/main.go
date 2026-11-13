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
// cmd/ctl/agent.go), as vendor/README.md records. Each certificate Secret carries the SHA-256 of
// its CA in the annotation poc.internal/agent-ca-sha256. A run keeps the CA only when every
// certificate Secret exists, carries that digest and chains to the CA. Without the CA key, any
// other state needs a new CA, so the run makes a new CA, replaces every certificate Secret, and
// writes the CA Secret last. A run that stops half way therefore leaves no CA Secret or a CA that
// its leaves do not match, and the next run recovers. The output then names the reason, so the
// caller restarts the pods that read the certificates. --rotate deletes the whole set first.
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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
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
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
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
	// caDigestAnnotation on each certificate Secret holds the SHA-256 of the CA that signed it.
	caDigestAnnotation = "poc.internal/agent-ca-sha256"
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
	// Reason says why the run made a new CA, and is empty when it kept the CA.
	Reason string `json:"new_ca_reason,omitempty"`
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
		// The CA goes first. A run that stops here then finds no CA, and makes the whole set again.
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
	// replace creates a Secret, and replaces the one that exists.
	replace := func(s *corev1.Secret) error {
		created, err := create(s.DeepCopy())
		if err != nil {
			return err
		}
		if !created {
			if err := secrets.Delete(ctx, s.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete Secret %s: %w", s.Name, err)
			}
			res.Deleted = append(res.Deleted, s.Name)
			if created, err = create(s.DeepCopy()); err != nil {
				return err
			} else if !created {
				return fmt.Errorf("secret %s came back during the run. Run viewkeys again", s.Name)
			}
		}
		res.Created = append(res.Created, s.Name)
		return nil
	}

	// The two keys that no CA signs. The run makes a key only for a Secret that it cannot read.
	for _, k := range []struct {
		name string
		make func() (*corev1.Secret, error)
	}{{jwtSecret, jwtKey}, {argoSecret, serverKey}} {
		if _, err := secrets.Get(ctx, k.name, metav1.GetOptions{}); err == nil {
			res.Existing = append(res.Existing, k.name)
			continue
		} else if !apierrors.IsNotFound(err) {
			return fmt.Errorf("get Secret %s: %w", k.name, err)
		}
		s, err := k.make()
		if err != nil {
			return err
		}
		created, err := create(s)
		if err != nil {
			return err
		}
		if created {
			res.Created = append(res.Created, k.name)
		} else {
			res.Existing = append(res.Existing, k.name)
		}
	}

	// A kept CA stays only when every certificate Secret exists, carries the digest of that CA,
	// and chains to it. The CA key is gone, so any other state needs a new CA and new leaves.
	keep, err := keptCA(ctx, secrets, leaves)
	if err != nil {
		return err
	}
	if keep == "" {
		res.Existing = append(res.Existing, caSecret)
		res.Existing = append(res.Existing, leaves...)
		return writeResult(out, res)
	}
	res.Reason = keep

	ca, err := newCA()
	if err != nil {
		return err
	}
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
		if err := replace(s); err != nil {
			return err
		}
	}
	// The CA comes last. Until it is written, a run that stops leaves leaves without their CA, and
	// the next run replaces them.
	if err := replace(ca.secret()); err != nil {
		return err
	}
	return writeResult(out, res)
}

// keptCA returns "" when the CA Secret and every leaf of the set are consistent, and otherwise the
// reason why the run needs a new CA.
func keptCA(ctx context.Context, secrets typedcorev1.SecretInterface, leaves []string) (string, error) {
	s, err := secrets.Get(ctx, caSecret, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "no " + caSecret, nil
	} else if err != nil {
		return "", fmt.Errorf("get Secret %s: %w", caSecret, err)
	}
	ca, err := parsePEMCert(s.Data["ca.crt"])
	if err != nil {
		return caSecret + " holds no CA certificate", nil
	}
	digest := caDigest(ca)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, n := range leaves {
		leaf, err := secrets.Get(ctx, n, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return n + " is missing", nil
		} else if err != nil {
			return "", fmt.Errorf("get Secret %s: %w", n, err)
		}
		if leaf.Annotations[caDigestAnnotation] != digest {
			return n + " names another CA", nil
		}
		certPEM, usage := leaf.Data["tls.crt"], x509.ExtKeyUsageServerAuth
		if n != proxySecret {
			var conf struct {
				TLS tlsClientConfig `json:"tlsClientConfig"`
			}
			if json.Unmarshal(leaf.Data["config"], &conf) != nil {
				return n + " holds no cluster config", nil
			}
			certPEM, usage = conf.TLS.CertData, x509.ExtKeyUsageClientAuth
		}
		cert, err := parsePEMCert(certPEM)
		if err != nil {
			return n + " holds no certificate", nil
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return n + " does not chain to " + caSecret, nil
		}
	}
	return "", nil
}

func parsePEMCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// caDigest is the hex SHA-256 of the DER form of the CA certificate.
func caDigest(ca *x509.Certificate) string {
	sum := sha256.Sum256(ca.Raw)
	return hex.EncodeToString(sum[:])
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
		ObjectMeta: metav1.ObjectMeta{Name: proxySecret, Annotations: map[string]string{caDigestAnnotation: caDigest(a.cert)}},
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
				caDigestAnnotation:                  caDigest(a.cert),
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
