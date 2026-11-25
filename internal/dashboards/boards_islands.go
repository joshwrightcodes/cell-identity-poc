package dashboards

func islandsBoard() Dashboard {
	b := newBoard("islands.json", "poc-islands", "Islands and revocation", "24h", clusterVar("Cluster"), cellVar())
	link := newPanel("state-timeline", "Link state by layer", "Each layer reads connected, or island when its upstream age is over 2 minutes.", 0, 0, 24, 8,
		series("(time() - max by (sender_cluster) ("+gw(`sender_cluster=~"$cluster"`)+")) > bool 120", "{{sender_cluster}} gateway export"),
		series(S("celld_upstream_age_seconds", cellRe)+" > bool 120", "{{platform_cell}} celld"),
		series(S("envd_upstream_age_seconds", pinCP, clusterRe)+" > bool 120", "dev-cp envd"))
	link.FieldConfig.Defaults = FieldDefaults{
		Color: map[string]any{"mode": "thresholds"}, Thresholds: thresholds(colGood, step{1, colWarning}),
		Mappings: []map[string]any{valueMap("value", [3]string{"0", "connected", colGood}, [3]string{"1", "island", colWarning})},
		Custom:   map[string]any{"fillOpacity": 80, "lineWidth": 0},
	}
	link.Options = map[string]any{
		"mergeValues": true, "showValue": "auto", "rowHeight": 0.9, "alignValue": "left",
		"legend": map[string]any{"displayMode": "list", "placement": "bottom", "showLegend": true},
	}
	b.add(link)
	b.add(timeSeries("Outbox during the island", "Items that the gateway and the envd outbox hold while a link is down.", 0, 8, 12, 8, "none",
		series("sum("+S("cellgw_outbox_items", pinCP)+")", "gateway outbox"),
		series("max("+S("envd_gateway_outbox", pinCP)+")", "envd outbox")))
	queue := timeSeries("dev-cp collector queue", "Exporter queue of the dev-cp collector. The dashed line is the cap.", 12, 8, 12, 8, "bytes",
		series("sum by (data_type) ("+S("otelcol_exporter_queue_size", pinCP)+")", "{{data_type}}"),
		series("sum("+S("otelcol_exporter_queue_capacity", pinCP)+")", "cap"))
	queue.FieldConfig.Overrides = append(queue.FieldConfig.Overrides, dashed("cap", colCrit))
	b.add(queue)
	b.add(stat("Overlay entries", "Revocations that the overlay holds, the entries that it refused in the time range, and the overlay of the gateway.", 0, 16, 12, 4, "none", thresholds(colNeutral),
		instant("sum("+S("envd_revocations_held", pinCP)+")", "held"),
		event(instant("sum(increase("+S("envd_revocations_refused_total", pinCP)+"["+rng+"]))", "refused"), false),
		instant("max("+S("cellgw_revocations_overlay", pinCP)+")", "gateway overlay")))
	b.add(stat("Revoked streams closed", "Open streams that the proxies closed because of a revoke, in the time range.", 12, 16, 12, 4, "none", thresholds(colNeutral),
		event(instant("sum(increase("+S("cellproxy_revoked_closed_total", clusterRe)+"["+rng+"]))", ""), false)))
	return b.d
}
