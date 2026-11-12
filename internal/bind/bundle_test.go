package bind

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

func TestFileBundleReadsAtEachLookup(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString(mgmtTD)
	path := filepath.Join(t.TempDir(), "bundle.pem")
	src := FileBundle(path, td)
	if _, err := src.GetX509BundleForTrustDomain(td); err == nil {
		t.Fatal("a missing file gave a bundle")
	}
	pem, err := spiffetest.NewCA(t, mgmtTD).Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := src.GetX509BundleForTrustDomain(td); err != nil || len(b.X509Authorities()) != 1 {
		t.Fatalf("bundle %v, err %v", b, err)
	}
	if _, err := src.GetX509BundleForTrustDomain(spiffeid.RequireTrustDomainFromString("other.test")); err == nil {
		t.Fatal("another trust domain gave a bundle")
	}
}
