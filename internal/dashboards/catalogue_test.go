package dashboards

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repoRoot = "../.."

func TestCatalogueMatchesInstruments(t *testing.T) {
	found, err := ScanInstruments(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string][]Instrument{}
	for _, in := range found {
		byName[in.Name] = append(byName[in.Name], in)
	}
	for _, m := range Catalogue {
		if m.ThirdParty {
			continue
		}
		matches := byName[m.Instrument]
		if len(matches) == 0 {
			t.Errorf("catalogue entry %s: no instrument call creates %q in internal/ or cmd/", m.Prom, m.Instrument)
			continue
		}
		ok := false
		for _, in := range matches {
			if in.Kind == m.Kind && in.Unit == m.Unit {
				ok = true
			}
		}
		if !ok {
			t.Errorf("catalogue entry %s: kind %q and unit %q, but the source has %+v", m.Prom, m.Kind, m.Unit, matches)
		}
	}
}

func TestCatalogueEntriesAreComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Catalogue {
		for _, n := range m.Names() {
			if seen[n] {
				t.Errorf("series name %s appears twice", n)
			}
			seen[n] = true
		}
		if m.Prom == "" || m.Origin == "" || len(m.Clusters) == 0 {
			t.Errorf("entry %+v needs a name, an origin and an emitter", m)
		}
		if m.ThirdParty && (m.Instrument != "" || !strings.ContainsAny(m.Origin, "0123456789")) {
			t.Errorf("third-party entry %s needs no instrument and an origin with a version, got %q", m.Prom, m.Origin)
		}
		if !m.ThirdParty && !contains(m.Names(), m.Prom) && !contains(m.Names(), m.Prom+"_bucket") {
			t.Errorf("entry %s does not match its instrument name %s", m.Prom, m.Instrument)
		}
	}
}

// The list holds the names of the M15 live inventory of 2026-11-25 (UTC). Most had series in Prometheus of lgtm-0 then.
// Names of counters and observed gauges that had not yet seen an event are in the list too, because their code defines them.
// istio_agent_cert_expiry_seconds was read on port 15020 only. The names that had series anchor the name translation.
func TestCatalogueNamesMatchTheLiveHarness(t *testing.T) {
	names := known()
	for _, n := range strings.Fields(`
		mgmtd_cells_valid mgmtd_spec_revision_lag cellgw_streams cellgw_outbox_items envd_revocations_held
		celld_svid_remaining_seconds celld_upstream_age_seconds envd_upstream_age_seconds argocd_app_info
		cell_proxy_tunnel_up mgmtd_keycheck_results_total agentban_bans_total
		spire_server_server_ca_sign_x509_svid_total mgmtd_report_retry_unknown_kid_total
		bundle_apply_outcomes_total store_proxy_denials_total argocd_app_sync_total istio_requests_total
		istio_agent_cert_expiry_seconds citadel_server_root_cert_expiry_timestamp
		cell_proxy_tunnel_responses_total cell_proxy_tunnel_refused_requests_total
		cellproxy_gateway_last_export_time_seconds otelcol_exporter_queue_size otelcol_exporter_queue_capacity
		envd_gateway_outbox cellgw_revocations_overlay envd_revocations_refused_total cellproxy_revoked_closed_total
		cellgw_refusals_total envd_spec_refusals_total cellctl_refusals_total cellproxy_gateway_exports_denied_total
		relay_connections_total cellgw_queue_depth cellgw_claims_total envd_reports_throttled_total cellctl_steps_total
		celld_ops_results_total cellproxy_gateway_exports_accepted_total cellproxy_gateway_attribute_overwrites_total
		cellproxy_gateway_upstream_failures_total relay_connections_open cellproxy_gateway_slots_used up`) {
		if _, ok := names[n]; !ok {
			t.Errorf("live name %s is not in the catalogue", n)
		}
	}
}

func TestScanResolvesConstantsOfThePackage(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "x")
	makeTree(t, root, dir)
	src := `package x

const (
	prefix  = "x."
	metricA = prefix + "a"
	unitS   = "s"
)

func f(m Meter) {
	m.Int64Counter(metricA)
	m.Float64Histogram("x.b", metric.WithDescription("d"), metric.WithUnit(unitS))
	m.Int64ObservableGauge("x.c", metric.WithInt64Callback(cb))
}
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ScanInstruments(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Instrument{
		"x.a": {Name: "x.a", Kind: KindCounter},
		"x.b": {Name: "x.b", Kind: KindHistogram, Unit: "s"},
		"x.c": {Name: "x.c", Kind: KindGauge},
	}
	if len(got) != len(want) {
		t.Fatalf("scan found %+v, want %d instruments", got, len(want))
	}
	for _, in := range got {
		w := want[in.Name]
		if in.Kind != w.Kind || in.Unit != w.Unit {
			t.Errorf("scan found %+v, want kind %q unit %q", in, w.Kind, w.Unit)
		}
	}
}

func TestScanRejectsAnInstrumentNameItCannotResolve(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "cmd", "y")
	makeTree(t, root, dir)
	src := "package y\n\nfunc f(m Meter, n string) { m.Int64Counter(n) }\n"
	if err := os.WriteFile(filepath.Join(dir, "y.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanInstruments(root); err == nil || !strings.Contains(err.Error(), "y.go:3") {
		t.Fatalf("scan error = %v, want one that names y.go:3", err)
	}
}

func TestScanFindsConstantNamedInstruments(t *testing.T) {
	found, err := ScanInstruments(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bundle.apply.outcomes", "cellproxy.gateway.attribute.overwrites"} {
		ok := false
		for _, in := range found {
			ok = ok || in.Name == name
		}
		if !ok {
			t.Errorf("scan did not resolve %s", name)
		}
	}
}

// makeTree creates the two scanned top directories of root, and dir inside one of them.
func makeTree(t *testing.T, root, dir string) {
	t.Helper()
	for _, d := range []string{filepath.Join(root, "internal"), filepath.Join(root, "cmd"), dir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}
