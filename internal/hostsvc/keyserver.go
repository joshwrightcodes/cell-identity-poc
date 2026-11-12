package hostsvc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/joshwrightcodes/cell-identity-poc/internal/connlimit"
	"github.com/joshwrightcodes/cell-identity-poc/internal/lograte"
	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// Fixed settings of the key server.
const (
	// KeyServerHost is the DNS name in the certificate of the key server. Pods reach the server
	// through this name.
	KeyServerHost = "host.docker.internal"
	// MgmtTrustDomain is the trust domain of the only caller.
	MgmtTrustDomain = "mgmt.poc.internal"

	maxConns        = 16
	maxActive       = 8
	maxSilent       = 128
	denialWindow    = 10 * time.Second
	denialMaxKeys   = 16
	shutdownTimeout = 5 * time.Second
)

// Connection timing of the key server. Tests shorten these values.
var (
	connMaxAge       = 30 * time.Second
	connGrace        = 5 * time.Second
	handshakeTimeout = 5 * time.Second
)

// SelfSignedCert makes an ECDSA P-256 key and a server certificate for host that is valid from one
// minute before now for 90 days. The key stays in memory.
func SelfSignedCert(host string, now time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// ServerTLS returns the TLS settings of the key server: TLS 1.3 only, and a client certificate
// that chains to clientRoots and carries exactly clientID. Session tickets are off, so each
// connection runs the client check again.
func ServerTLS(cert tls.Certificate, clientRoots x509bundle.Source, clientID spiffeid.ID) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAnyClientCert,
		VerifyPeerCertificate:  tlsconfig.VerifyPeerCertificate(clientRoots, tlsconfig.AuthorizeID(clientID)),
		SessionTicketsDisabled: true,
	}
}

// CheckLoopbackAddr returns an error unless addr is "host:port" with a loopback IP address.
func CheckLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not a loopback IP address", addr)
	}
	return nil
}

// ClientRoots holds the X.509 roots that a client certificate must chain to. LoadClientRoots reads
// them from a file once.
type ClientRoots struct {
	td     spiffeid.TrustDomain
	bundle *x509bundle.Bundle
	sum    string
}

// LoadClientRoots reads a PEM file of roots for trust domain td. Each root must be a CA that is
// valid now and carries exactly one URI SAN, spiffe://<td>, as `pkigen trust-bundle` writes it. The
// file must hold nothing else.
func LoadClientRoots(path string, td spiffeid.TrustDomain, now time.Time) (*ClientRoots, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("client bundle: %w", err)
	}
	want := "spiffe://" + td.Name()
	var certs []*x509.Certificate
	h := sha256.New()
	for rest := data; len(bytes.TrimSpace(rest)) > 0; {
		if i := bytes.Index(rest, []byte("-----BEGIN ")); i > 0 && len(bytes.TrimSpace(rest[:i])) != 0 {
			return nil, fmt.Errorf("client bundle %s holds something other than PEM certificates", path)
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("client bundle %s holds something other than PEM certificates", path)
		}
		n := len(certs) + 1
		c, err := x509.ParseCertificate(block.Bytes)
		switch {
		case err != nil:
			return nil, fmt.Errorf("client bundle %s: certificate %d: %w", path, n, err)
		case !c.BasicConstraintsValid || !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0:
			return nil, fmt.Errorf("client bundle %s: certificate %d is not a CA", path, n)
		case len(c.URIs) != 1 || c.URIs[0].String() != want:
			return nil, fmt.Errorf("client bundle %s: certificate %d has URI SAN %v, want %s", path, n, c.URIs, want)
		case now.Before(c.NotBefore) || now.After(c.NotAfter):
			return nil, fmt.Errorf("client bundle %s: certificate %d is not valid now", path, n)
		}
		certs = append(certs, c)
		h.Write(c.Raw)
		rest = next
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("client bundle %s holds no certificate", path)
	}
	return &ClientRoots{td: td, bundle: x509bundle.FromX509Authorities(td, certs), sum: hex.EncodeToString(h.Sum(nil))}, nil
}

// GetX509BundleForTrustDomain implements x509bundle.Source.
func (r *ClientRoots) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if td != r.td {
		return nil, fmt.Errorf("no bundle for trust domain %q", td)
	}
	return r.bundle, nil
}

// SHA256 returns the hex SHA-256 of the DER bytes of the roots, in file order, one after the other.
func (r *ClientRoots) SHA256() string { return r.sum }

// NewKeyHandler serves GET /v1/clusters/<name>/keys from cache. A name that known refuses gets
// 404 before any lookup. Other methods get 405, and a failed lookup gets 502 with a fixed JSON
// error. Denial log lines are limited to one for each reason in each window.
func NewKeyHandler(cache *KeyCache, known func(string) bool, log *slog.Logger) http.Handler {
	return newKeyHandler(cache, known, log).routes()
}

func newKeyHandler(cache *KeyCache, known func(string) bool, log *slog.Logger) *keyHandler {
	return &keyHandler{cache: cache, known: known, log: log, ins: noopInstruments(),
		limit: lograte.New(denialWindow, denialMaxKeys, cache.now)}
}

func (h *keyHandler) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(mgmtapi.KeysPattern, func(w http.ResponseWriter, r *http.Request) {
		h.observe(w, r, h.keys)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.observe(w, r, func(w http.ResponseWriter, r *http.Request, outcome *string) {
			h.deny(w, r, http.StatusNotFound, "not_found", nil, outcome)
		})
	})
	return mux
}

type keyHandler struct {
	cache *KeyCache
	known func(string) bool
	log   *slog.Logger
	limit *lograte.Limiter
	ins   *instruments
}

func (h *keyHandler) keys(w http.ResponseWriter, r *http.Request, outcome *string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.deny(w, r, http.StatusMethodNotAllowed, "method_not_allowed", nil, outcome)
		return
	}
	cluster := r.PathValue("cluster")
	if !h.known(cluster) {
		h.deny(w, r, http.StatusNotFound, "unknown_cluster", nil, outcome)
		return
	}
	keys, err := h.cache.Get(r.Context(), cluster)
	if err != nil {
		h.deny(w, r, http.StatusBadGateway, "lookup_failed", err, outcome)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (h *keyHandler) deny(w http.ResponseWriter, r *http.Request, status int, reason string, err error, outcome *string) {
	*outcome = reason
	writeJSON(w, status, map[string]string{"error": reason})
	_, ok, suppressed, held := h.limit.Allow(reason)
	for _, k := range held {
		h.log.Warn("denials held back", "reason", k.Key, "suppressed", k.Suppressed)
	}
	if !ok {
		return
	}
	attrs := []any{"reason", reason, "status", status, "method", r.Method, "suppressed", suppressed}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	h.log.Warn("request denied", attrs...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// NewKeyServer returns the HTTP server of the key handler, with the limits of the host service.
// Errors of the server go to logger as JSON, at most one line in each window.
func NewKeyServer(h http.Handler, tc *tls.Config, logger *slog.Logger) *http.Server {
	limit := lograte.New(denialWindow, denialMaxKeys, time.Now)
	errLog := log.New(writerFunc(func(p []byte) (int, error) {
		_, ok, suppressed, _ := limit.Allow("server_error")
		if ok {
			logger.Warn("server error", "error", strings.TrimSpace(string(p)), "suppressed", suppressed)
		}
		return len(p), nil
	}), "", 0)
	return &http.Server{
		Handler:           connlimit.MaxAge(h),
		TLSConfig:         tc,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ConnContext:       connlimit.ConnContext,
		ErrorLog:          errLog,
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// ServeKeys serves srv on ln, with TLS from srv.TLSConfig. The TLS handshake and the check of the
// client certificate run before a connection takes one of the 16 connection slots, in a small pool
// of pending handshakes (see newHandshakeListener). The slots count only verified peers, and each
// connection has a maximum age. It returns nil after ctx ends and the server has shut down. Failed
// and evicted handshakes go to log, at most one line of each kind in each window.
func ServeKeys(ctx context.Context, srv *http.Server, ln net.Listener, logger *slog.Logger) error {
	limit := lograte.New(denialWindow, denialMaxKeys, time.Now)
	report := func(kind string, err error) {
		_, ok, suppressed, _ := limit.Allow(kind)
		if ok {
			logger.Warn("handshake refused", "reason", kind, "error", err.Error(), "suppressed", suppressed)
		}
	}
	hl := newHandshakeListener(ln, srv.TLSConfig, maxSilent, maxActive, handshakeTimeout, report)
	limited := connlimit.Listen(hl, maxConns, connMaxAge, connGrace, nil)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if srv.Shutdown(sctx) != nil {
				_ = srv.Close()
			}
		case <-done:
		}
	}()
	err := srv.Serve(limited)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
