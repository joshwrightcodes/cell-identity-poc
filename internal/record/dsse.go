package record

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// The sentinels that VerifyEnvelope wraps. A caller tells the failure classes apart with errors.Is.
var (
	// ErrPayloadType means the payload type of the envelope differs from the expected type.
	ErrPayloadType = errors.New("unexpected payload type")
	// ErrSignature means no signature verifies under a trusted key, or the envelope has none.
	ErrSignature = errors.New("no signature verifies under a trusted key")
	// ErrDecode means the envelope, or the payload it carries, cannot be decoded.
	ErrDecode = errors.New("cannot decode")
)

type envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// pae returns the DSSE v1 pre-authentication encoding of a payload type and body.
func pae(payloadType string, body []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(body), body)
}

// signPayload signs body as a cell record.
func signPayload(body []byte, key ed25519.PrivateKey) ([]byte, error) {
	return SignEnvelope(PayloadType, body, key)
}

// SignEnvelope returns a DSSE envelope that carries body under payloadType, signed with key.
func SignEnvelope(payloadType string, body []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key is not an Ed25519 private key")
	}
	sig := ed25519.Sign(key, pae(payloadType, body))
	return json.Marshal(envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(body),
		Signatures:  []signature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
}

// VerifyEnvelope checks the payload type field against payloadType, then accepts the envelope when
// any signature verifies under any key. The pre-authentication encoding uses payloadType, never the
// envelope field. It returns the raw payload. The error wraps ErrDecode, ErrPayloadType or ErrSignature.
func VerifyEnvelope(data []byte, payloadType string, keys []ed25519.PublicKey) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%w envelope: %v", ErrDecode, err)
	}
	if env.PayloadType != payloadType {
		return nil, fmt.Errorf("%w %q", ErrPayloadType, env.PayloadType)
	}
	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("%w: envelope has no signatures", ErrSignature)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w payload: %v", ErrDecode, err)
	}
	msg := pae(payloadType, body)
	for _, s := range env.Signatures {
		raw, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		for _, k := range keys {
			if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, raw) {
				return body, nil
			}
		}
	}
	return nil, ErrSignature
}
