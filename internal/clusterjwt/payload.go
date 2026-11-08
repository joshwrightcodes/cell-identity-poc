package clusterjwt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

// Payload is the JSON that the agent sends first. It names the cell that attests.
type Payload struct {
	Cell string `json:"cell"`
}

// Response is the JSON that the agent sends after the challenge. The challenge itself is the
// nonce as raw bytes: 32 random bytes in base64url without padding.
type Response struct {
	Token string `json:"token"`
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
