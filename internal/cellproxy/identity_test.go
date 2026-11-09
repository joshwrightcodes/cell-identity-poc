package cellproxy

import (
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// parse runs spiffeid parsing and ParseSource, so a test row can hold an ID that go-spiffe
// already refuses, such as one with an empty segment.
func parse(s string) (Source, error) {
	id, err := spiffeid.FromString(s)
	if err != nil {
		return Source{}, err
	}
	return ParseSource(id)
}

func TestParseSource(t *testing.T) {
	good := map[string]Source{
		"spiffe://dev.env.poc.internal/cell/dev-cell-1/otel": {Env: "dev", Cluster: "dev-cell-1", Plane: "cell", Cell: "dev-cell-1", Role: "otel"},
		"spiffe://dev.env.poc.internal/cp/otel":              {Env: "dev", Cluster: "dev-cp", Plane: "environment", Role: "otel"},
	}
	for id, want := range good {
		t.Run(id, func(t *testing.T) {
			got, err := parse(id)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
	bad := []string{
		"spiffe://dev.env.poc.internal/cell/dev-cell-1/otel/x",
		"spiffe://dev.env.poc.internal/cell/dev-cell-1",
		"spiffe://dev.env.poc.internal/cell/Dev-Cell-1/otel",
		"spiffe://dev.env.poc.internal/cell//otel",
		"spiffe://dev.env.poc.internal/cellx/dev-cell-1/otel",
		"spiffe://dev.env.poc.internal/cell/management/otel",
		"spiffe://dev.env.poc.internal/cell/dev-cp/otel",
		"spiffe://dev.env.poc.internal/cell/rogue/otel",
		"spiffe://dev.env.poc.internal/cell/" + strings.Repeat("a", 60) + "/otel",
		"spiffe://dev.mesh.poc.internal/cell/dev-cell-1/otel",
		"spiffe://mgmt.poc.internal/cell/dev-cell-1/otel",
	}
	for _, id := range bad {
		t.Run(id, func(t *testing.T) {
			if got, err := parse(id); err == nil {
				t.Fatalf("got %+v, want an error", got)
			}
		})
	}
	t.Run("59-character cell name", func(t *testing.T) {
		if _, err := parse("spiffe://dev.env.poc.internal/cell/" + strings.Repeat("a", 59) + "/otel"); err != nil {
			t.Fatal(err)
		}
	})
}
