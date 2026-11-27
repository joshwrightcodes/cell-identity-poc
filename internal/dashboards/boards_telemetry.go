package dashboards

func telemetryBoard() Dashboard {
	sender := queryVar("cluster", "Sender", `label_values(`+gw()+`, sender_cluster)`)
	b := newBoard("telemetry.json", "poc-telemetry", "Telemetry pipeline", "6h", sender)
	s := func(i int, title, desc, unit string, th *Thresholds, ts ...Target) {
		x, w := col(i, 4)
		b.add(stat(title, desc, x, 0, w, 4, unit, th, ts...))
	}
	exports := func(name string, matchers ...string) string {
		return "sum(" + Born(S(name, append([]string{pinMgmt, `sender_cluster=~"$cluster"`}, matchers...)...), rng) + ")"
	}
	accepted, denied := exports("cellproxy_gateway_exports_accepted_total"), exports("cellproxy_gateway_exports_denied_total")
	s(0, "Exports accepted", "Share of export requests that the gateway accepted in the time range.", "percent", thresholds(colCrit, step{95, colWarning}, step{99, colGood}),
		instant("100 * "+accepted+" / ("+accepted+" + ("+denied+" or vector(0)))", ""))
	s(1, "Source tags overwritten", "Source attributes that the gateway replaced in the time range.", "none", thresholds(colGood, step{1, colCrit}),
		event(instant(exports("cellproxy_gateway_attribute_overwrites_total"), ""), false))
	s(2, "Upstream failures", "Exports that the gateway could not pass upstream in the time range.", "none", thresholds(colGood, step{1, colCrit}),
		event(instant("sum("+Born(S("cellproxy_gateway_upstream_failures_total", pinMgmt), rng)+")", ""), false))
	s(3, "Relay slots used", "Connections that the relay holds open, of 256, and the call slots of the telemetry gateway.", "none", thresholds(colGood, step{205, colWarning}, step{243, colCrit}),
		instant("sum("+S("relay_connections_open", pinCP)+")", "relay of 256"),
		instant("sum("+S("cellproxy_gateway_slots_used", pinMgmt, `sender_cluster=~"$cluster"`)+")", "gateway of 16"))

	slots := b.d.Panels[3]
	slots.FieldConfig.Overrides = append(slots.FieldConfig.Overrides, Override{
		Matcher:    FieldMatcher{ID: "byName", Options: "gateway of 16"},
		Properties: []Property{{ID: "thresholds", Value: thresholds(colGood, step{12, colWarning}, step{16, colCrit})}},
	})
	b.d.Panels[3] = slots

	age := coloured(timeSeries("Seconds since the last export, by sender", "Seconds since the gateway last accepted a metrics export from each sender. The dashed line marks stale.", 0, 4, 24, 9, "s",
		series("time() - max by (sender_cluster) ("+gw(`sender_cluster=~"$cluster"`)+")", "{{sender_cluster}}"),
		series(constLine(gw(`sender_cluster=~"$cluster"`), 30), "stale at 30 s")),
		dashed("stale at 30 s", colCrit))
	b.add(age)
	return b.d
}
