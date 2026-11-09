package clusterjwt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

// The wire contract between an agent of type cluster_jwt and the server plugin. The agent plugin
// and cmd/attestprobe use the same names, so a change here reaches both sides.

// Payload is the JSON that the agent sends first. It names the cell that attests.
type Payload struct {
	Cell string `json:"cell"`
}

// Response is the JSON that the agent sends after the challenge. The challenge itself is the
// nonce as raw bytes: NonceBytes random bytes in base64url without padding.
type Response struct {
	Token string `json:"token"`
}

const (
	// NonceBytes is the number of random bytes in a nonce that the server sends.
	NonceBytes = 32
	// MaxNonceLength bounds the challenge that an agent accepts.
	MaxNonceLength = 128
	audiencePrefix = "spire-"
)

// Names of the downward API variables that identify the pod of an agent.
const (
	EnvPodName        = "POD_NAME"
	EnvPodUID         = "POD_UID"
	EnvPodNamespace   = "POD_NAMESPACE"
	EnvServiceAccount = "SERVICE_ACCOUNT"
)

var nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Audience returns the one audience that a token for the attestation in env with nonce carries.
func Audience(env, nonce string) string {
	return audiencePrefix + env + "/" + nonce
}

// ValidNonce reports whether a challenge has the form of a nonce: base64url characters, not
// empty, and at most MaxNonceLength bytes.
func ValidNonce(nonce string) bool {
	return nonce != "" && len(nonce) <= MaxNonceLength && nonceRE.MatchString(nonce)
}

// maxMessage bounds the payload and the challenge response. A service account token is far smaller.
const maxMessage = 16 << 10

// decodeStrict decodes one JSON object and rejects unknown fields and trailing data.
func decodeStrict(data []byte, v any) error {
	if len(data) == 0 || len(data) > maxMessage {
		return errors.New("message has a bad size")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after object")
	}
	return nil
}

// nonceHash returns the first 16 bytes of the SHA-256 of nonce, in hex.
func nonceHash(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:16])
}
