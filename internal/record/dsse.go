package record

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

func signPayload(body []byte, key ed25519.PrivateKey) ([]byte, error) {
	sig := ed25519.Sign(key, pae(PayloadType, body))
	return json.Marshal(envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(body),
		Signatures:  []signature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
}

// verifyPayload checks the payload type, then accepts the envelope when any signature
// verifies under any key. It returns the raw payload.
func verifyPayload(data []byte, keys []ed25519.PublicKey) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("unexpected payload type %q", env.PayloadType)
	}
	if len(env.Signatures) == 0 {
		return nil, errors.New("envelope has no signatures")
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	msg := pae(env.PayloadType, body)
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
	return nil, errors.New("no signature verifies under a trusted key")
}
