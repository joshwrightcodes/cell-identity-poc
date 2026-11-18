package envd

import (
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cellproxy"
	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool/spiffetest"
)

// TestM7EnvdRefusesFakeMgmt serves the bundle from a fake mgmtd that holds an SVID with the ID of the real
// one, under a CA that envd does not trust (a), and from a fake that holds an SVID of the dev-cp CA with the
// same path (c). Each pull fails with peer_untrusted in the error field of the pull failed line, and neither
// fake receives a request. A fake with the real chain and a wrong ID gives peer_not_allowed.
func TestM7EnvdRefusesFakeMgmt(t *testing.T) {
	f := newFx(t)
	mgmtCA := spiffetest.NewCA(t, "mgmt.poc.internal")
	devCA := spiffetest.NewCA(t, "dev.env.poc.internal")
	client := devCA.Source(t, "spiffe://dev.env.poc.internal/envd")
	want := spiffeid.RequireFromString("spiffe://mgmt.poc.internal/api")

	pull := func(t *testing.T, serverCA *spiffetest.CA, id string) (string, int32) {
		t.Helper()
		cfg := tlsconfig.MTLSServerConfig(serverCA.Source(t, id), devCA.Bundle(), tlsconfig.AuthorizeAny())
		u := newUpstream(t, firstBundle(f, rev(1, 2)), cfg)
		clk := newClock(2)
		store := &memStore{}
		logs := &syncBuffer{}
		p := NewPuller(PullerConfig{Client: NewClient(cellproxy.ClientTLS(client, mgmtCA.Bundle(), want)), BaseURL: u.url,
			Env: testEnv, Keys: f.keys(), Store: store, Log: newLog(logs), Now: clk.Now, Sleep: clk.Sleep})
		runRounds(t, p, clk)
		if len(store.saves()) != 0 {
			t.Fatalf("a pull from the fake saved %v", store.saves())
		}
		var errField string
		for _, l := range logs.lines() {
			if l["msg"] == "pull failed" {
				errField, _ = l["error"].(string)
			}
		}
		return errField, u.hits.Load()
	}

	for _, tc := range []struct {
		name, id, reason string
		ca               *spiffetest.CA
	}{
		{"self_made_ca_with_the_mgmtd_id", "spiffe://mgmt.poc.internal/api", "peer_untrusted", spiffetest.NewCA(t, "mgmt.poc.internal")},
		{"dev_cp_ca_with_the_mgmtd_path", "spiffe://dev.env.poc.internal/api", "peer_untrusted", devCA},
		{"mgmt_ca_with_another_id", "spiffe://mgmt.poc.internal/telemetry", "peer_not_allowed", mgmtCA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, hits := pull(t, tc.ca, tc.id)
			if !strings.Contains(got, tc.reason+":") {
				t.Errorf("the pull failed line has error %q, want it to name %s", got, tc.reason)
			}
			if hits != 0 {
				t.Errorf("the fake received %d requests, want none", hits)
			}
		})
	}
}
