package dashboards

// stateOf gives each cell a number: 1 valid, 2 not valid, 3 revoked. The number sorts and maps to a word, where the labels would not.
func stateOf() string {
	m := func(matchers ...string) string {
		return `label_replace(` + newest(S("mgmtd_cell_state", append([]string{pinMgmt}, matchers...)...), S("mgmtd_cell_state", pinMgmt), freshFast, "cell") + `, "cluster", "$1", "cell", "(.+)")`
	}
	return `max by (cluster) (` + m(`revoked="true"`) + ` * 3 or ` + m(`revoked="false"`, `valid="true"`) + ` * 1 or ` + m(`revoked="false"`, `valid="false"`) + ` * 2)`
}

// cellCount counts the cells of mgmtd_cell_state that match. A change of a label starts a new series, so it counts each cell once.
func cellCount(matchers ...string) string {
	return "count(count by (cell) (" + newest(S("mgmtd_cell_state", append([]string{pinMgmt}, matchers...)...), S("mgmtd_cell_state", pinMgmt), freshFast, "cell") + "))"
}

// orZero keeps a count that has no series at 0, with the labels of the grouping.
func orZero(count, all string) string { return count + " or 0 * " + all }

func cellHealthBoard() Dashboard {
	b := newBoard("cell-health.json", "poc-cell-health", "Cell health overview", "6h", clusterVar("Cluster"), cellVar())
	s := func(i int, title, desc, unit string, th *Thresholds, ts ...Target) {
		x, w := col(i, 6)
		b.add(stat(title, desc, x, 0, w, 4, unit, th, ts...))
	}
	s(0, "Cells valid", "Cells whose record is valid and not revoked, of the cells in the intent. Each cell counts once.", "none", thresholds(colNeutral),
		instant(cellCount(`valid="true"`, `revoked="false"`)+" or 0 * "+cellCount(), "valid"),
		instant(cellCount(), "of"))
	s(1, "Spec revision lag", "Spec revisions that the cells have not yet applied.", "none", thresholds(colGood, step{1, colWarning}),
		instant("max("+S("mgmtd_spec_revision_lag", pinMgmt)+")", ""))
	s(2, "Gateway streams", "Open cell streams at the gateway of dev-cp.", "none", thresholds(colNeutral),
		instant("sum("+fresh(S("cellgw_streams", pinCP, `cell=~"$cell"`), freshFast)+")", ""))
	s(3, "Outbox items", "Items that the gateway holds for the cells.", "none", thresholds(colGood, step{1, colWarning}),
		instant("sum("+S("cellgw_outbox_items", pinCP)+")", ""))
	s(4, "Islands now", "Layers whose upstream age is over 2 minutes.", "none", thresholds(colGood, step{1, colWarning}),
		event(instant("count("+IslandAge(islandBoard())+" > 120)", ""), false))
	s(5, "Revoked cells", "Cells that the record marks revoked, and the revocations that the overlay holds.", "none", thresholds(colGood, step{1, colCrit}),
		event(instant(cellCount(`revoked="true"`), "revoked"), false),
		instant("sum("+S("envd_revocations_held", pinCP)+")", "overlay held"))

	state := tableColumn{Title: "State", Expr: stateOf(), Map: valueMap("value",
		[3]string{"1", "valid", colGood}, [3]string{"2", "not valid", colSerious}, [3]string{"3", "revoked", colCrit})}
	byCell := func(expr, from string) string {
		return `label_replace(` + expr + `, "cluster", "$1", "` + from + `", "(.+)")`
	}
	// one gives a cluster one row, even while an old series of a restarted pod lives on.
	one := func(expr, from string) string { return "max by (cluster) (" + byCell(expr, from) + ")" }
	cells := table("Cells", "One row for each cluster. A column that does not apply shows n/a.", 0, 4, 24, 9, "cluster", "Cell", "Cell",
		state,
		tableColumn{Title: "SVID left", Unit: "s", Expr: one(S("celld_svid_remaining_seconds", cellRe), "platform_cell")},
		tableColumn{Title: "Upstream age", Unit: "s", Expr: one(S("celld_upstream_age_seconds", cellRe), "platform_cell") + " or " +
			one(S("envd_upstream_age_seconds", pinCP, clusterRe), "k8s_cluster_name")},
		tableColumn{Title: "Stream", Expr: one("sum by (cell) ("+fresh(S("cellgw_streams", pinCP, `cell=~"$cell"`), freshFast)+")", "cell") + " or " +
			one("0 * "+fresh(S("mgmtd_cell_state", pinMgmt), freshFast), "cell")},
		tableColumn{Title: "Apps synced", Expr: orZero(byCell(`count by (k8s_cluster_name) (`+S("argocd_app_info", `job="argocd"`, clusterRe, `sync_status="Synced"`)+`)`, "k8s_cluster_name"),
			byCell(`count by (k8s_cluster_name) (`+S("argocd_app_info", `job="argocd"`, clusterRe)+`)`, "k8s_cluster_name"))},
		tableColumn{Title: "Apps total", Expr: byCell(`count by (k8s_cluster_name) (`+S("argocd_app_info", `job="argocd"`, clusterRe)+`)`, "k8s_cluster_name")},
		tableColumn{Title: "Bundle applied", Unit: "s", Labels: [][2]string{{"version", "Bundle version"}, {"root_digest", "Bundle digest"}}, LabelMap: bootstrapMap(),
			Expr: byCell(`label_replace(time() - max by (k8s_cluster_name, version, root_digest) (`+newest(S("bundle_set_applied_seconds", clusterRe), S("bundle_set_applied_seconds", clusterRe), freshSlow, "k8s_cluster_name, role")+`), "root_digest", "$1", "root_digest", "(?:sha256:)?(.{12}).*")`, "k8s_cluster_name")},
		tableColumn{Title: "Last telemetry", Unit: "s", Expr: byCell(`time() - max by (sender_cluster) (`+gw(`sender_cluster=~"$cluster"`)+`)`, "sender_cluster")},
		tableColumn{Title: "Mesh tunnel", Expr: one(S("cell_proxy_tunnel_up", pinMgmt, `side="hub"`, `cell=~"$cell"`), "cell"),
			Map: valueMap("value", [3]string{"0", "down", colCrit}, [3]string{"1", "up", colGood})},
	)
	b.add(widths(cells, map[string]int{"Cell": 100, "State": 90, "SVID left": 100, "Upstream age": 110, "Stream": 70, "Apps synced": 100,
		"Apps total": 90, "Bundle version": 120, "Bundle digest": 120, "Bundle applied": 120, "Last telemetry": 120, "Mesh tunnel": 100}))

	svid := coloured(timeSeries("celld SVID remaining", "Time left on the SVID of each celld. The dashed line is a quarter of the SVID lifetime.", 0, 13, 12, 8, "s",
		series(S("celld_svid_remaining_seconds", cellRe), "{{platform_cell}}"),
		series("max(0.25 * "+S("celld_svid_lifetime_seconds", cellRe)+")", "alert at 25%")),
		dashed("alert at 25%", colCrit))
	b.add(svid)
	age := coloured(timeSeries("Upstream age by layer", "Seconds since each layer last heard from upstream. The dashed line is the island threshold.", 12, 13, 12, 8, "s",
		series(S("celld_upstream_age_seconds", cellRe), "{{platform_cell}}"),
		series(S("envd_upstream_age_seconds", pinCP, clusterRe), "dev-cp"),
		series(constLine(S("celld_upstream_age_seconds", cellRe), 120), "island at 2 min")),
		dashed("island at 2 min", colWarning))
	b.add(age)
	return b.d
}

// bootstrapMap shows the version of the bootstrap state, which reports 0.0, as a word.
func bootstrapMap() map[string]any {
	return valueMap("value", [3]string{"0.0", "bootstrap", colNeutral})
}
