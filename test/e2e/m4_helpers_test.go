//go:build e2e

package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cmdrun"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

const (
	mgmtNamespace = "mgmt-system"
	mgmtdPod      = "mgmtd-0"
	envdID        = "spiffe://dev.env.poc.internal/envd"
	mgmtAPIID     = "spiffe://mgmt.poc.internal/api"
	hostsvcAddr   = "127.0.0.1:17443"
	mgmtdUID      = "65532"
)

// mgmtCtl runs `mise run mgmt -- <args>`, which runs mgmtd ctl in mgmtd-0, and returns the one JSON line that it prints.
func mgmtCtl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := mgmtCtlErr(args...)
	if err != nil {
		t.Fatalf("mise run mgmt -- %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func mgmtCtlErr(args ...string) (string, error) {
	res, err := cmdrun.Run(2*time.Minute, "", nil, "mise", append([]string{"run", "mgmt", "--"}, args...)...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit status %d", res.Code)
	}
	return strings.TrimSpace(res.Stdout), err
}

// mgmtStatus returns the status that mgmtd ctl status prints.
func mgmtStatus(t *testing.T) mgmt.Status {
	t.Helper()
	var s mgmt.Status
	if err := json.Unmarshal([]byte(mgmtCtl(t, "status")), &s); err != nil {
		t.Fatalf("mgmtd ctl status is no status object: %v", err)
	}
	return s
}

// mgmtSigningPub returns key spec.pub of ConfigMap mgmt-system/mgmt-signing-pub.
func mgmtSigningPub(t *testing.T) string {
	t.Helper()
	out, err := kubectl(t, mgmtCluster, "", "-n", mgmtNamespace, "get", "configmap", "mgmt-signing-pub", "-o", `jsonpath={.data.spec\.pub}`)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// ctlPub returns the key that mgmtd ctl pubkey prints.
func ctlPub(t *testing.T) string {
	t.Helper()
	var v map[string]string
	if err := json.Unmarshal([]byte(mgmtCtl(t, "pubkey")), &v); err != nil {
		t.Fatal(err)
	}
	return v["spec.pub"]
}

// staticSVID serves one SVID as an x509svid.Source.
type staticSVID struct{ svid *x509svid.SVID }

func (s staticSVID) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

// svidFor mints an X.509 SVID for id in cluster, and returns it as a source and as a TLS certificate.
func svidFor(t *testing.T, cluster, id string) (staticSVID, tls.Certificate) {
	t.Helper()
	certPEM, keyPEM := mintSVID(t, cluster, id, 10*time.Minute)
	svid, err := x509svid.Parse(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse the SVID of %s: %v", id, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return staticSVID{svid}, cert
}

// fetchSpec pulls the signed spec bundle from the API of mgmtd through a port-forward to Service mgmt-api, with the
// client certificate cert. It trusts the roots of management and checks the server ID.
func fetchSpec(t *testing.T, cert tls.Certificate) (mgmtapi.SpecBundle, error) {
	t.Helper()
	addr := portForward(t, mgmtCluster, mgmtNamespace, "svc/mgmt-api", 8446)
	pool := x509.NewCertPool()
	for _, r := range bundleRoots(t, mgmtCluster) {
		pool.AddCert(r)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{cert}, RootCAs: pool, InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool()}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
				return err
			}
			if len(cs.PeerCertificates[0].URIs) != 1 || cs.PeerCertificates[0].URIs[0].String() != mgmtAPIID {
				return io.ErrUnexpectedEOF
			}
			return nil
		}}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, DisableKeepAlives: true}}
	resp, err := client.Get("https://" + addr + mgmtapi.SpecPath(pocEnv))
	if err != nil {
		return mgmtapi.SpecBundle{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return mgmtapi.SpecBundle{}, &statusError{resp.StatusCode, string(body)}
	}
	var b mgmtapi.SpecBundle
	if err := json.Unmarshal(body, &b); err != nil {
		return mgmtapi.SpecBundle{}, err
	}
	return b, nil
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string { return "status " + strconv.Itoa(e.code) + ": " + e.body }

// setReplicas sets the replicas of a harness workload through scripts/harness-replicas.sh, never through kubectl scale.
func setReplicas(t *testing.T, cluster, ns, target string, n int) {
	t.Helper()
	out, err := command("", "bash", "../../scripts/harness-replicas.sh", cluster, ns, target, strconv.Itoa(n))
	if err != nil {
		t.Fatalf("harness-replicas.sh %s %s %s %d: %v\n%s", cluster, ns, target, n, err, out)
	}
}
