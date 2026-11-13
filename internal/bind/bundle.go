package bind

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// FileBundle returns a source for the trust bundle of td in the PEM file at path. It reads the
// file at each lookup, so a bundle that the file receives later takes effect at the next attempt.
func FileBundle(path string, td spiffeid.TrustDomain) x509bundle.Source {
	return fileBundle{path: path, td: td}
}

type fileBundle struct {
	path string
	td   spiffeid.TrustDomain
}

func (f fileBundle) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if td != f.td {
		return nil, fmt.Errorf("no bundle for trust domain %q", td)
	}
	return x509bundle.Load(f.td, f.path)
}
