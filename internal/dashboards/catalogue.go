package dashboards

import "strings"

// Metric is one metric that a dashboard or an alert rule may read.
// Prom is the Prometheus name. For a histogram it is the base name, and Names lists the three series.
// Clusters says which clusters emit the metric: ClusterManagement, ClusterControlPlane, ClusterCell or ClusterHost.
type Metric struct {
	Prom       string
	Instrument string
	Kind       string
	Unit       string
	Origin     string
	ThirdParty bool
	Clusters   []string
}

// Emitter values for Metric.Clusters.
const (
	ClusterManagement   = "management"
	ClusterControlPlane = "dev-cp"
	// ClusterCell stands for every cell cluster, such as dev-cell-1.
	ClusterCell = "cell"
	// ClusterHost is the host service on the Mac. It exports no telemetry today.
	ClusterHost = "host"
)

const originOwn = "cell-identity-poc"

// Names returns every Prometheus series name of the metric.
func (m Metric) Names() []string {
	if m.ThirdParty {
		return []string{m.Prom}
	}
	return PromName(m.Instrument, m.Kind, m.Unit)
}

// own describes an instrument of this repository. The Prometheus name follows from the instrument.
func own(instrument, kind, unit string, clusters ...string) Metric {
	return Metric{
		Prom:       strings.TrimSuffix(PromName(instrument, kind, unit)[0], "_bucket"),
		Instrument: instrument, Kind: kind, Unit: unit, Origin: originOwn, Clusters: clusters,
	}
}

// thirdParty describes a metric that a third-party component exposes and the collector scrapes.
func thirdParty(prom, kind, origin string, clusters ...string) Metric {
	return Metric{Prom: prom, Kind: kind, Origin: origin, ThirdParty: true, Clusters: clusters}
}

const (
	originArgoCD = "Argo CD v3.6.1"
	originIstio  = "Istio 1.30.8"
	originSPIRE  = "SPIRE v1.15.5"
	originOTel   = "OpenTelemetry Collector k8s 0.164.0"
	originProm   = "Prometheus 3.15.0 (scrape)"
)

var (
	allClusters = []string{ClusterManagement, ClusterControlPlane, ClusterCell}
	cpAndCell   = []string{ClusterControlPlane, ClusterCell}
)

// Catalogue lists the metrics that the dashboards and the alert rules may name.
var Catalogue = []Metric{
	own("agentban.bans", KindCounter, "", ClusterControlPlane),

	own("bundle.apply.duration", KindHistogram, "s", cpAndCell...),
	own("bundle.apply.outcomes", KindCounter, "", cpAndCell...),
	own("bundle.rollback.terminate.failures", KindCounter, "", cpAndCell...),
	own("bundle.store.refills", KindCounter, "", cpAndCell...),

	own("cell_proxy.tunnel.connects", KindCounter, "{connection}", ClusterManagement, ClusterCell),
	own("cell_proxy.tunnel.refused_requests", KindCounter, "{request}", ClusterManagement, ClusterCell),
	own("cell_proxy.tunnel.responses", KindCounter, "{response}", ClusterManagement, ClusterCell),
	own("cell_proxy.tunnel.up", KindGauge, "{tunnel}", ClusterManagement, ClusterCell),
	own("cellproxy.revoked.closed", KindCounter, "{connection}", allClusters...),
	own("store_proxy.denials", KindCounter, "{request}", allClusters...),

	own("cellproxy.gateway.attribute.overwrites", KindCounter, "{attribute}", ClusterManagement),
	own("cellproxy.gateway.exports.accepted", KindCounter, "{request}", ClusterManagement),
	own("cellproxy.gateway.exports.denied", KindCounter, "{request}", ClusterManagement),
	own("cellproxy.gateway.last_export.time", KindGauge, "s", ClusterManagement),
	own("cellproxy.gateway.slots.used", KindUpDownCounter, "{call}", ClusterManagement),
	own("cellproxy.gateway.upstream.failures", KindCounter, "{request}", ClusterManagement),

	own("cellctl.refusals", KindCounter, "", ClusterControlPlane),
	own("cellctl.steps", KindCounter, "", ClusterControlPlane),

	own("celld.bind.attempts", KindCounter, "", ClusterCell),
	own("celld.ops.results", KindCounter, "", ClusterCell),
	own("celld.svid.remaining", KindGauge, "s", ClusterCell),
	own("celld.svid.updates", KindCounter, "", ClusterCell),
	own("celld.upstream.age", KindGauge, "s", ClusterCell),

	own("cellgw.claims", KindCounter, "", ClusterControlPlane),
	own("cellgw.outbox.items", KindGauge, "", ClusterControlPlane),
	own("cellgw.queue.depth", KindGauge, "", ClusterControlPlane),
	own("cellgw.refusals", KindCounter, "", ClusterControlPlane),
	own("cellgw.revocations.overlay", KindGauge, "", ClusterControlPlane),
	own("cellgw.streams", KindGauge, "", ClusterControlPlane),

	own("envd.gateway.outbox", KindGauge, "", ClusterControlPlane),
	own("envd.relay.items", KindCounter, "", ClusterControlPlane),
	own("envd.reports.throttled", KindCounter, "", ClusterControlPlane),
	own("envd.revocations.held", KindGauge, "", ClusterControlPlane),
	own("envd.revocations.refused", KindCounter, "", ClusterControlPlane),
	own("envd.spec.counter", KindGauge, "", ClusterControlPlane),
	own("envd.spec.refusals", KindCounter, "", ClusterControlPlane),
	own("envd.upstream.age", KindGauge, "s", ClusterControlPlane),

	own("hostsvc.key.cache.hits", KindCounter, "", ClusterHost),
	own("hostsvc.key.handshake.refusals", KindCounter, "", ClusterHost),
	own("hostsvc.key.lookup.duration", KindHistogram, "s", ClusterHost),
	own("hostsvc.key.lookups", KindCounter, "", ClusterHost),
	own("hostsvc.key.requests", KindCounter, "", ClusterHost),
	own("hostsvc.steps", KindCounter, "", ClusterHost),

	own("mgmtd.bind.results", KindCounter, "", ClusterManagement),
	own("mgmtd.cells.valid", KindGauge, "", ClusterManagement),
	own("mgmtd.hostsvc.spec_push_age", KindGauge, "s", ClusterManagement),
	own("mgmtd.keycheck.results", KindCounter, "", ClusterManagement),
	own("mgmtd.report.items", KindCounter, "", ClusterManagement),
	own("mgmtd.report.retry_unknown_kid", KindCounter, "", ClusterManagement),
	own("mgmtd.spec.revision.lag", KindGauge, "", ClusterManagement),

	own("relay.connections", KindCounter, "", ClusterControlPlane),
	own("relay.connections.open", KindUpDownCounter, "", ClusterControlPlane),

	// Third-party names. Each one was read on the live harness in the M15 inventory of 2026-11-26.
	thirdParty("up", KindGauge, originProm, allClusters...),
	thirdParty("argocd_app_info", KindGauge, originArgoCD, allClusters...),
	thirdParty("argocd_app_sync_total", KindCounter, originArgoCD, allClusters...),
	thirdParty("istio_requests_total", KindCounter, originIstio, allClusters...),
	thirdParty("istio_agent_cert_expiry_seconds", KindGauge, originIstio+", scrape job on port 15020", allClusters...),
	thirdParty("citadel_server_root_cert_expiry_timestamp", KindGauge, originIstio, allClusters...),
	thirdParty("spire_server_server_ca_sign_x509_svid_total", KindCounter, originSPIRE, ClusterManagement, ClusterControlPlane),
	thirdParty("otelcol_exporter_queue_size", KindGauge, originOTel, allClusters...),
	thirdParty("otelcol_exporter_queue_capacity", KindGauge, originOTel, allClusters...),
}

// known returns every series name of the catalogue, with its metric.
func known() map[string]Metric {
	out := map[string]Metric{}
	for _, m := range Catalogue {
		for _, n := range m.Names() {
			out[n] = m
		}
	}
	return out
}
