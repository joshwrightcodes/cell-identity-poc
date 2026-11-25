package dashboards

func argocdBoard() Dashboard {
	b := newBoard("argocd-bundles.json", "poc-argocd-bundles", "Argo CD and bundle sets", "7d", clusterVar("Target"))
	s := func(i int, title, desc string, th *Thresholds, ts ...Target) {
		x, w := col(i, 4)
		b.add(stat(title, desc, x, 0, w, 4, "none", th, ts...))
	}
	apps := func(extra ...string) string {
		return "count(" + S("argocd_app_info", append([]string{`job="argocd"`, clusterRe}, extra...)...) + ")"
	}
	s(0, "Applications synced", "Argo CD applications in sync, of all applications.", thresholds(colNeutral),
		instant(apps(`sync_status="Synced"`)+" or 0 * "+apps(), "synced"), instant(apps(), "of"))
	s(1, "Applications healthy", "Argo CD applications that are healthy, of all applications.", thresholds(colNeutral),
		instant(apps(`health_status="Healthy"`)+" or 0 * "+apps(), "healthy"), instant(apps(), "of"))
	s(2, "Rollbacks 7 days", "Bundle sets that the appliers rolled back in the last 7 days.", thresholds(colGood, step{1, colCrit}),
		event(instant("sum("+Born(S("bundle_apply_outcomes_total", clusterRe, `outcome="rolled_back"`), "7d")+")", ""), false))
	s(3, "Store denials", "Requests that the bundle store proxy refused in the time range.", thresholds(colGood, step{1, colWarning}),
		event(instant("sum("+Born(S("store_proxy_denials_total", clusterRe), rng)+")", ""), false))

	sets := table("Signed sets by target", "The signed set of each applier, sorted by the numeric Applied time. Version 0.0 is the bootstrap state.", 0, 4, 14, 9,
		"k8s_cluster_name", "Target", "Applied",
		tableColumn{Title: "Applied", Unit: "s",
			Labels:   [][2]string{{"role", "Role"}, {"version", "Set"}, {"root_digest", "Root digest"}, {"state", "Result"}},
			LabelMap: bootstrapMap(),
			Expr: "time() - max by (k8s_cluster_name, role, version, root_digest, state) (" +
				fresh(S("bundle_set_applied_seconds", clusterRe), freshSlow) + ")"},
		tableColumn{Title: "Apply time", Unit: "s",
			Expr: "sum by (k8s_cluster_name) (increase(" + S("bundle_sync_delay_seconds_sum", clusterRe) + "[" + rng + "])) / " +
				"sum by (k8s_cluster_name) (increase(" + S("bundle_sync_delay_seconds_count", clusterRe) + "[" + rng + "]))"},
	)
	b.add(setOrder(sets, "Target", "Set", "Root digest", "Applied", "Apply time", "Result"))
	b.add(coloured(barGauge("Sync time after a tag move", "Median time from a tag move of deploy to the end of the health wait.", 14, 4, 10, 9, "s",
		event(instant("histogram_quantile(0.5, sum by (k8s_cluster_name, le) (increase("+S("bundle_sync_delay_seconds_bucket", clusterRe)+"["+rng+"])))", "{{k8s_cluster_name}}"), true))))
	b.add(coloured(timeSeries("Sync operations per hour", "Argo CD sync operations in each hour.", 0, 13, 24, 8, "none",
		series("sum by (k8s_cluster_name) (increase("+S("argocd_app_sync_total", clusterRe)+"[1h]))", "{{k8s_cluster_name}}"))))
	return b.d
}
