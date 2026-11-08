// Package record defines the signed cell record that the management plane publishes.
package record

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
)

// PayloadType is the DSSE payload type of a cell record.
const PayloadType = "application/vnd.poc.cell-record+json"

// Subject names a service account that the cell may present.
type Subject struct {
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
}

// Cell is the trust anchor for one cell. Verifiers use Issuer and JWKS to check cell tokens.
type Cell struct {
	Name     string          `json:"name"`
	Env      string          `json:"env"`
	Issuer   string          `json:"issuer"`
	JWKS     json.RawMessage `json:"jwks"`
	Subjects []Subject       `json:"subjects"`
	Revoked  bool            `json:"revoked"`
	Epoch    uint64          `json:"epoch"`
	Counter  uint64          `json:"counter"`
}

// Sign returns a DSSE envelope that holds the cell record signed with key.
func Sign(c Cell, key ed25519.PrivateKey) ([]byte, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode record: %w", err)
	}
	return signPayload(body, key)
}

// Verify checks the envelope against the trusted keys and returns the cell record.
// The keyid field is ignored, and one valid signature from any trusted key is enough.
func Verify(envelope []byte, keys []ed25519.PublicKey) (Cell, error) {
	body, err := verifyPayload(envelope, keys)
	if err != nil {
		return Cell{}, err
	}
	var c Cell
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Cell{}, fmt.Errorf("decode record: %w", err)
	}
	if dec.More() {
		return Cell{}, errors.New("decode record: trailing data after object")
	}
	if err := c.validate(); err != nil {
		return Cell{}, err
	}
	return c, nil
}

func (c Cell) validate() error {
	if c.Name == "" || c.Env == "" || c.Issuer == "" {
		return errors.New("record needs a name, env and issuer")
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(c.JWKS, &set); err != nil || len(set.Keys) == 0 {
		return errors.New("record jwks must be a JSON key set with at least one key")
	}
	return nil
}
