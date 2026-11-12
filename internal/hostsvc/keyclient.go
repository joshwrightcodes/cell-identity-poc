package hostsvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/mgmtapi"
)

// maxKeysBody is the largest answer that the key client reads.
const maxKeysBody = 256 << 10

var errPinMismatch = errors.New("server certificate does not match the pin")

// KeyClientConfig configures a KeyClient. Pin is the SHA-256 of the DER bytes of the server
// certificate, 32 bytes. SVIDs supplies the client certificate. A zero Timeout means 10 seconds.
type KeyClientConfig struct {
	Addr       string
	ServerName string
	Pin        []byte
	SVIDs      x509svid.Source
	Timeout    time.Duration
}

// PinFromPEM returns the SHA-256 of the DER bytes of the first certificate in pemBytes.
func PinFromPEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("pin is not a PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return sum[:], nil
}

// KeyClient reads the keys of a cluster from the host service. It trusts one server certificate,
// the pinned one, and presents the SVID of this process.
type KeyClient struct {
	addr   string
	client *http.Client
}

// NewKeyClient checks cfg and returns a client.
func NewKeyClient(cfg KeyClientConfig) (*KeyClient, error) {
	switch {
	case cfg.Addr == "":
		return nil, errors.New("key client needs an address")
	case cfg.ServerName == "":
		return nil, errors.New("key client needs a server name")
	case len(cfg.Pin) != sha256.Size:
		return nil, fmt.Errorf("key client pin must be %d bytes", sha256.Size)
	case cfg.SVIDs == nil:
		return nil, errors.New("key client needs an SVID source")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	pin := bytes.Clone(cfg.Pin)
	tc := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: cfg.ServerName,
		// The pin check in VerifyConnection replaces the chain check, because the server
		// certificate is self-signed.
		InsecureSkipVerify:   true,
		GetClientCertificate: tlsconfig.GetClientCertificate(cfg.SVIDs),
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errPinMismatch
			}
			leaf := cs.PeerCertificates[0]
			sum := sha256.Sum256(leaf.Raw)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errPinMismatch
			}
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return fmt.Errorf("pinned server certificate is not valid now")
			}
			return nil
		},
	}
	return &KeyClient{
		addr: cfg.Addr,
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig:     tc,
				DisableKeepAlives:   true,
				TLSHandshakeTimeout: cfg.Timeout,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Keys returns the keys of cluster. The error is a *mgmtapi.KeyError with ReasonIssuerUntrusted
// for a certificate that does not match the pin or an answer for another cluster, and with
// ReasonIssuerUnavailable for every other failure.
func (c *KeyClient) Keys(ctx context.Context, cluster string) (mgmtapi.ClusterKeys, error) {
	keys, err := c.fetch(ctx, cluster)
	if err == nil {
		return keys, nil
	}
	var ke *mgmtapi.KeyError
	if errors.As(err, &ke) {
		return mgmtapi.ClusterKeys{}, err
	}
	if errors.Is(err, errPinMismatch) {
		return mgmtapi.ClusterKeys{}, &mgmtapi.KeyError{Reason: mgmtapi.ReasonIssuerUntrusted, Err: errPinMismatch}
	}
	return mgmtapi.ClusterKeys{}, &mgmtapi.KeyError{Reason: mgmtapi.ReasonIssuerUnavailable, Err: err}
}

func (c *KeyClient) fetch(ctx context.Context, cluster string) (mgmtapi.ClusterKeys, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.addr+mgmtapi.KeysPath(cluster), nil)
	if err != nil {
		return mgmtapi.ClusterKeys{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return mgmtapi.ClusterKeys{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return mgmtapi.ClusterKeys{}, fmt.Errorf("host service answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysBody+1))
	if err != nil {
		return mgmtapi.ClusterKeys{}, err
	}
	if len(body) > maxKeysBody {
		return mgmtapi.ClusterKeys{}, fmt.Errorf("answer is larger than %d bytes", maxKeysBody)
	}
	var keys mgmtapi.ClusterKeys
	if err := jsonv2.Unmarshal(body, &keys, jsonv2.RejectUnknownMembers(true)); err != nil {
		return mgmtapi.ClusterKeys{}, fmt.Errorf("decode answer: %w", err)
	}
	if keys.Name != cluster {
		return mgmtapi.ClusterKeys{}, &mgmtapi.KeyError{
			Reason: mgmtapi.ReasonIssuerUntrusted,
			Err:    fmt.Errorf("answer is for cluster %q, want %q", keys.Name, cluster),
		}
	}
	if err := checkKeySet(keys.JWKS); err != nil {
		return mgmtapi.ClusterKeys{}, err
	}
	return keys, nil
}

// checkKeySet requires a JSON object with a keys member that go-jose reads as a key set.
func checkKeySet(raw json.RawMessage) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return fmt.Errorf("jwks is not a JSON object: %w", err)
	}
	if _, ok := members["keys"]; !ok {
		return errors.New("jwks has no keys member")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return fmt.Errorf("jwks is not a key set: %w", err)
	}
	return nil
}
