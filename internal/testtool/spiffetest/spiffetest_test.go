package spiffetest_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

func TestCAIssuesVerifiableSVIDs(t *testing.T) {
	ca := spiffetest.NewCA(t, "mgmt.poc.internal")
	id := "spiffe://mgmt.poc.internal/api"
	svid := ca.SVID(t, id)
	if svid.ID.String() != id {
		t.Fatalf("id %s", svid.ID)
	}
	got, _, err := x509svid.Verify(svid.Certificates, ca.Bundle())
	if err != nil || got.String() != id {
		t.Fatalf("verify: %v", err)
	}
	src, err := ca.Source(t, id).GetX509SVID()
	if err != nil || src.ID.String() != id {
		t.Fatalf("source: %v", err)
	}
	other := spiffetest.NewCA(t, "mgmt.poc.internal")
	if _, _, err := x509svid.Verify(svid.Certificates, other.Bundle()); err == nil {
		t.Fatal("a foreign CA must not verify the SVID")
	}
}
