package cellproxy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const (
	signersFile  = "signers.pub"
	recordSuffix = ".dsse.json"
	// maxRegistryFile bounds each file that LoadRegistry reads.
	maxRegistryFile = 1 << 20
)

// Registry holds the signed cell records that decide which sources the server accepts.
type Registry struct {
	cells   []record.Cell
	signers int
	keys    []ed25519.PublicKey
}

// RegistrySource gives the registry that is current now. A *Registry is its own source, and a
// *RegistryWatcher gives the last good reload.
type RegistrySource interface{ Current() *Registry }

// Current returns r.
func (r *Registry) Current() *Registry { return r }

// Record returns the record of the cell with the highest revision. It reports false when the
// registry holds no record of that name, or when any record of that name is revoked.
func (r *Registry) Record(cell string) (record.Cell, bool) {
	var best record.Cell
	found := false
	for _, c := range r.cells {
		if c.Name != cell {
			continue
		}
		if c.Revoked {
			return record.Cell{}, false
		}
		if !found || revisionOf(c).Compare(revisionOf(best)) > 0 {
			best, found = c, true
		}
	}
	return best, found
}

func revisionOf(c record.Cell) spec.Revision {
	return spec.Revision{Epoch: c.Epoch, Counter: c.Counter}
}

// LoadRegistry reads signers.pub, one base64 Ed25519 key for each line, and every *.dsse.json
// file in dir. It fails on any record that does not verify under those keys, on a record whose
// name or environment ParseSource could never give, on no keys and on no records.
func LoadRegistry(dir string) (*Registry, error) {
	keys, err := readSigners(filepath.Join(dir, signersFile))
	if err != nil {
		return nil, err
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*"+recordSuffix))
	if err != nil {
		return nil, err
	}
	reg := &Registry{signers: len(keys), keys: keys}
	for _, path := range paths {
		data, err := readBounded(path)
		if err != nil {
			return nil, err
		}
		c, err := record.Verify(data, keys)
		if err == nil {
			err = checkCellName(c.Name, c.Env)
		}
		if err != nil {
			return nil, fmt.Errorf("record %s: %w", filepath.Base(path), err)
		}
		reg.cells = append(reg.cells, c)
	}
	if len(reg.cells) == 0 {
		return nil, fmt.Errorf("no *%s record in %s", recordSuffix, dir)
	}
	return reg, nil
}

func readSigners(path string) ([]ed25519.PublicKey, error) {
	data, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	s := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; s.Scan(); n++ {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s line %d is not a base64 Ed25519 public key", signersFile, n)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s holds no key", signersFile)
	}
	return keys, nil
}

func readBounded(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxRegistryFile {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", filepath.Base(path), maxRegistryFile)
	}
	return os.ReadFile(path)
}

// Allows reports whether the registry accepts s. A cell source needs a record of its name and
// environment, and no revoked record of its name. An environment source needs a record of its
// environment.
func (r *Registry) Allows(s Source) bool {
	switch s.Plane {
	case PlaneCell:
		found := false
		for _, c := range r.cells {
			if c.Name != s.Cell {
				continue
			}
			if c.Revoked {
				return false
			}
			found = found || c.Env == s.Env
		}
		return found
	case PlaneEnvironment:
		return slices.ContainsFunc(r.cells, func(c record.Cell) bool { return c.Env == s.Env })
	}
	return false
}

// ContentSHA256 is the hex SHA-256 of the sorted lines "<name> <env> <revoked>", each with a
// newline. It does not depend on the signer keys.
func (r *Registry) ContentSHA256() string {
	lines := make([]string, 0, len(r.cells))
	for _, c := range r.cells {
		lines = append(lines, c.Name+" "+c.Env+" "+strconv.FormatBool(c.Revoked)+"\n")
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(sum[:])
}

// RegistryStats counts what a registry holds, for the start-up log.
type RegistryStats struct{ Records, Revoked, Signers int }

// Stats returns the counts of the registry.
func (r *Registry) Stats() RegistryStats {
	st := RegistryStats{Records: len(r.cells), Signers: r.signers}
	for _, c := range r.cells {
		if c.Revoked {
			st.Revoked++
		}
	}
	return st
}
