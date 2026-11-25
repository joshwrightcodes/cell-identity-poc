package dashboards

import (
	"reflect"
	"testing"
)

func TestPromName(t *testing.T) {
	tests := []struct {
		name                string
		instrument, kind, u string
		want                []string
	}{
		{"gauge with seconds", "celld.svid.remaining", KindGauge, "s", []string{"celld_svid_remaining_seconds"}},
		{"counter with a brace unit adds only total", "store_proxy.denials", KindCounter, "{request}", []string{"store_proxy_denials_total"}},
		{"counter with no unit", "cellgw.refusals", KindCounter, "", []string{"cellgw_refusals_total"}},
		{"histogram with seconds", "bundle.sync.delay", KindHistogram, "s",
			[]string{"bundle_sync_delay_seconds_bucket", "bundle_sync_delay_seconds_sum", "bundle_sync_delay_seconds_count"}},
		{"up down counter has no suffix", "relay.connections.open", KindUpDownCounter, "", []string{"relay_connections_open"}},
		{"up down counter with a brace unit", "cellproxy.gateway.slots.used", KindUpDownCounter, "{call}", []string{"cellproxy_gateway_slots_used"}},
		{"gauge with a brace unit", "cell_proxy.tunnel.up", KindGauge, "{tunnel}", []string{"cell_proxy_tunnel_up"}},
		{"dots in the middle", "cellproxy.gateway.last_export.time", KindGauge, "s", []string{"cellproxy_gateway_last_export_time_seconds"}},
		{"bytes", "x.size", KindGauge, "By", []string{"x_size_bytes"}},
		{"counter with seconds", "x.busy", KindCounter, "s", []string{"x_busy_seconds_total"}},
		{"name that ends in the unit already", "x.age_seconds", KindGauge, "s", []string{"x_age_seconds"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PromName(tc.instrument, tc.kind, tc.u); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("PromName(%q, %q, %q) = %v, want %v", tc.instrument, tc.kind, tc.u, got, tc.want)
			}
		})
	}
}
