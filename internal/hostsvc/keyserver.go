package hostsvc

import (
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
	"sync"
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
	maxConnAge      = 30 * time.Second
	maxConnGrace    = 5 * time.Second
	denialWindow    = 10 * time.Second
	denialMaxKeys   = 16
	shutdownTimeout = 5 * time.Second
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

// BundleFile serves the X.509 roots of one trust domain from a file. It reads the file again
// when the file changes, and keeps the last good roots when a new read fails.
type BundleFile struct {
	path string
	td   spiffeid.TrustDomain

	mu     sync.Mutex
	mod    time.Time
	size   int64
	bundle *x509bundle.Bundle
}

// NewBundleFile reads and checks the file. It fails when the file is missing, is not PEM
// certificates, holds no root, or holds a root that is not a CA or that names another trust domain.
func NewBundleFile(path string, td spiffeid.TrustDomain) (*BundleFile, error) {
	b := &BundleFile{path: path, td: td}
	if err := b.reload(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *BundleFile) reload() error {
	info, err := os.Stat(b.path)
	if err != nil {
		return fmt.Errorf("client bundle: %w", err)
	}
	data, err := os.ReadFile(b.path)
	if err != nil {
		return fmt.Errorf("client bundle: %w", err)
	}
	bundle, err := x509bundle.Parse(b.td, data)
	if err != nil {
		return fmt.Errorf("client bundle %s: %w", b.path, err)
	}
	if bundle.Empty() {
		return fmt.Errorf("client bundle %s holds no root certificate", b.path)
	}
	for _, c := range bundle.X509Authorities() {
		if !c.IsCA {
			return fmt.Errorf("client bundle %s holds a certificate that is not a CA", b.path)
		}
		for _, u := range c.URIs {
			if u.Scheme == "spiffe" && !strings.EqualFold(u.Host, b.td.Name()) {
				return fmt.Errorf("client bundle %s is for trust domain %q, want %q", b.path, u.Host, b.td.Name())
			}
		}
	}
	b.bundle, b.mod, b.size = bundle, info.ModTime(), info.Size()
	return nil
}

// GetX509BundleForTrustDomain implements x509bundle.Source.
func (b *BundleFile) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if td != b.td {
		return nil, fmt.Errorf("no bundle for trust domain %q", td)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if info, err := os.Stat(b.path); err == nil && (!info.ModTime().Equal(b.mod) || info.Size() != b.size) {
		_ = b.reload()
	}
	return b.bundle, nil
}

// RootSHA256 returns the hex SHA-256 of the DER bytes of the roots, one after the other.
func (b *BundleFile) RootSHA256() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := sha256.New()
	for _, c := range b.bundle.X509Authorities() {
		h.Write(c.Raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NewKeyHandler serves GET /v1/clusters/<name>/keys from cache. A name that known refuses gets
// 404 before any lookup. Other methods get 405, and a failed lookup gets 502 with a fixed JSON
// error. Denial log lines are limited to one for each reason in each window.
func NewKeyHandler(cache *KeyCache, known func(string) bool, log *slog.Logger) http.Handler {
	h := &keyHandler{cache: cache, known: known, log: log, limit: lograte.New(denialWindow, denialMaxKeys, cache.now)}
	mux := http.NewServeMux()
	mux.HandleFunc(mgmtapi.KeysPattern, h.keys)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.deny(w, r, http.StatusNotFound, "not_found", nil)
	})
	return mux
}

type keyHandler struct {
	cache *KeyCache
	known func(string) bool
	log   *slog.Logger
	limit *lograte.Limiter
}

func (h *keyHandler) keys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.deny(w, r, http.StatusMethodNotAllowed, "method_not_allowed", nil)
		return
	}
	cluster := r.PathValue("cluster")
	if !h.known(cluster) {
		h.deny(w, r, http.StatusNotFound, "unknown_cluster", nil)
		return
	}
	keys, err := h.cache.Get(r.Context(), cluster)
	if err != nil {
		h.deny(w, r, http.StatusBadGateway, "lookup_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (h *keyHandler) deny(w http.ResponseWriter, r *http.Request, status int, reason string, err error) {
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
// Errors of the server go to log as JSON, at most one line in each window.
func NewKeyServer(h http.Handler, tc *tls.Config, logger *slog.Logger) *http.Server {
	limit := lograte.New(denialWindow, 1, time.Now)
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

// ServeKeys serves srv on ln, with TLS from srv.TLSConfig, at most 16 connections and a maximum
// connection age. It returns nil after ctx ends and the server has shut down.
func ServeKeys(ctx context.Context, srv *http.Server, ln net.Listener) error {
	limited := connlimit.Listen(ln, maxConns, maxConnAge, maxConnGrace, nil)
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
	err := srv.Serve(tls.NewListener(limited, srv.TLSConfig))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
