// Package bundle holds the shared contracts of signed bundle sets: the set and its version, the
// in-toto attestation that approves a set for one target, the allow-list data, the deterministic
// bundle layer and the root bundle.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
)

// Limits shared by every reader and writer of bundles.
const (
	MaxComponents     = 32
	MaxNameLen        = 40
	MinWave           = -10
	MaxWave           = 20
	MaxIgnoreEntries  = 8
	MaxManifestBytes  = 16 << 10
	MaxConfigBytes    = 4 << 10
	MaxLayerBytes     = 8 << 20
	MaxUnpackedBytes  = 32 << 20
	MaxObjects        = 2000
	maxNamespaceLabel = 63
)

// Version orders the signed sets of one target: the epoch first, then the counter.
type Version struct {
	Epoch   uint64 `json:"epoch"`
	Counter uint64 `json:"counter"`
}

// Compare returns -1, 0 or 1 when v is below, equal to or above o.
func (v Version) Compare(o Version) int {
	switch {
	case v.Epoch != o.Epoch:
		if v.Epoch < o.Epoch {
			return -1
		}
		return 1
	case v.Counter < o.Counter:
		return -1
	case v.Counter > o.Counter:
		return 1
	}
	return 0
}

// Component is one bundle of a set. Digest is the OCI manifest digest, as sha256:<64 hex>.
type Component struct {
	Name              string          `json:"name"`
	Wave              int             `json:"wave"`
	Namespace         string          `json:"namespace"`
	Digest            string          `json:"digest"`
	IgnoreDifferences json.RawMessage `json:"ignoreDifferences,omitempty"`
}

// Set is the decoded form of one signed set.
type Set struct {
	Version    Version
	Components []Component
}

var (
	labelRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ignoreEntry is the shape of one ignoreDifferences entry. The strict decoder refuses any other key.
type ignoreEntry struct {
	Group                 string   `json:"group"`
	Kind                  string   `json:"kind"`
	Name                  string   `json:"name"`
	Namespace             string   `json:"namespace"`
	JSONPointers          []string `json:"jsonPointers"`
	JQPathExpressions     []string `json:"jqPathExpressions"`
	ManagedFieldsManagers []string `json:"managedFieldsManagers"`
}

// ParseComponents decodes the component list that mgmtd reads and checks every rule of a set:
// 1 to 32 components, names that are DNS labels of at most 40 characters in strictly ascending
// order, a wave from -10 to 20, a digest as sha256:<64 lowercase hex>, and an ignoreDifferences
// list of at most 8 entries with known keys only. Every failure wraps record.ErrDecode.
func ParseComponents(raw json.RawMessage) ([]Component, error) {
	var cs []Component
	if err := record.DecodeStrict(raw, &cs); err != nil {
		return nil, fmt.Errorf("components: %w", err)
	}
	if err := validateComponents(cs); err != nil {
		return nil, err
	}
	return cs, nil
}

// validateComponents checks the rules of a set, and puts each ignoreDifferences list in compact form.
func validateComponents(cs []Component) error {
	if len(cs) < 1 || len(cs) > MaxComponents {
		return fmt.Errorf("%w components: %d components are outside 1 to %d", record.ErrDecode, len(cs), MaxComponents)
	}
	for i := range cs {
		c := &cs[i]
		switch {
		case len(c.Name) > MaxNameLen || !labelRE.MatchString(c.Name):
			return fmt.Errorf("%w components: name %q is not a DNS label of at most %d characters", record.ErrDecode, c.Name, MaxNameLen)
		case c.Name == "root":
			return fmt.Errorf("%w components: name root is taken by the root bundle", record.ErrDecode)
		case i > 0 && cs[i-1].Name >= c.Name:
			return fmt.Errorf("%w components: name %q is not above %q", record.ErrDecode, c.Name, cs[i-1].Name)
		case c.Wave < MinWave || c.Wave > MaxWave:
			return fmt.Errorf("%w components: wave %d of %q is outside %d to %d", record.ErrDecode, c.Wave, c.Name, MinWave, MaxWave)
		case len(c.Namespace) > maxNamespaceLabel || !labelRE.MatchString(c.Namespace):
			return fmt.Errorf("%w components: namespace %q of %q is not a DNS label", record.ErrDecode, c.Namespace, c.Name)
		case !digestRE.MatchString(c.Digest):
			return fmt.Errorf("%w components: digest of %q is not sha256:<64 lowercase hex>", record.ErrDecode, c.Name)
		}
		if c.IgnoreDifferences == nil {
			continue
		}
		var entries []ignoreEntry
		if err := record.DecodeStrict(c.IgnoreDifferences, &entries); err != nil {
			return fmt.Errorf("ignoreDifferences of %q: %w", c.Name, err)
		}
		if len(entries) < 1 || len(entries) > MaxIgnoreEntries {
			return fmt.Errorf("%w components: ignoreDifferences of %q has %d entries, outside 1 to %d", record.ErrDecode, c.Name, len(entries), MaxIgnoreEntries)
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, c.IgnoreDifferences); err != nil {
			return fmt.Errorf("%w components: ignoreDifferences of %q: %v", record.ErrDecode, c.Name, err)
		}
		c.IgnoreDifferences = buf.Bytes()
	}
	return nil
}

// ContentSHA256 returns the lowercase hex SHA-256 of the JSON encoding of the components with
// their digests. The version is not part of it.
func ContentSHA256(s Set) string {
	b, err := json.Marshal(s.Components)
	if err != nil {
		panic("bundle: encode components: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
