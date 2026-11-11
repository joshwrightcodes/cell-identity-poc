// Package mgmtapi holds the wire types, paths and reason strings that the management plane, envd
// and celld share.
package mgmtapi

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// SpecBundle is the answer to a spec pull: the signed spec envelope and one signed record envelope
// for each cell name in the spec.
type SpecBundle struct {
	Spec    json.RawMessage            `json:"spec"`
	Records map[string]json.RawMessage `json:"records"`
}

// NonceResponse is the answer to a nonce request. Bound tells whether the cell has a record.
type NonceResponse struct {
	Nonce     string    `json:"nonce"`
	Audience  string    `json:"audience"`
	ExpiresAt time.Time `json:"expiresAt"`
	Bound     bool      `json:"bound"`
}

// BindRequest carries a nonce and the pod-bound token whose audience is BindAudience of that nonce.
type BindRequest struct {
	Nonce string `json:"nonce"`
	Token string `json:"token"`
}

// The values of BindResponse.Status.
const (
	StatusBound        = "bound"
	StatusAlreadyBound = "already_bound"
	StatusKeysUpdated  = "keys_updated"
)

// BindResponse reports what a bind did and the revision of the record after it.
type BindResponse struct {
	Status string        `json:"status"`
	Record spec.Revision `json:"record"`
}

// StatusReport is what envd tells the management plane after each round.
type StatusReport struct {
	Applied     spec.Revision `json:"applied"`
	LastRefusal *Refusal      `json:"lastRefusal,omitempty"`
	StoreError  string        `json:"storeError,omitempty"`
}

// Refusal records the last spec that envd refused.
type Refusal struct {
	Reason   string        `json:"reason"`
	Revision spec.Revision `json:"revision"`
	At       time.Time     `json:"at"`
}

// Denied is the body of every HTTP 403 from the management plane.
type Denied struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id"`
}

// ClusterKeys is the answer of the host service: the issuer and the public keys of one cluster.
type ClusterKeys struct {
	Name   string          `json:"name"`
	Issuer string          `json:"issuer"`
	JWKS   json.RawMessage `json:"jwks"`
}

// BindAudience returns the one audience of a bind token for cell and nonce.
func BindAudience(cell, nonce string) string {
	return "mgmt-bind/" + cell + "/" + nonce
}

// SpecPath is the path of the signed spec bundle of an environment.
func SpecPath(env string) string { return "/v1/envs/" + url.PathEscape(env) + "/spec" }

// StatusPath is the path where envd reports the status of an environment.
func StatusPath(env string) string { return "/v1/envs/" + url.PathEscape(env) + "/status" }

// NoncePath is the path where a cell asks for a bind nonce.
func NoncePath(cell string) string { return "/v1/cells/" + url.PathEscape(cell) + "/nonce" }

// BindPath is the path where a cell sends its bind request.
func BindPath(cell string) string { return "/v1/cells/" + url.PathEscape(cell) + "/bind" }

// KeysPath is the path of the host service route that returns the keys of a cluster.
func KeysPath(cluster string) string { return "/v1/clusters/" + url.PathEscape(cluster) + "/keys" }
