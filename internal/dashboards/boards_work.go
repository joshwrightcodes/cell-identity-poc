package dashboards

func workBoard() Dashboard {
	kind := Variable{
		Name: "kind", Label: "Step state", Type: "custom", Query: "admitting,bootstrapping,creating,failed,queued", Definition: "admitting,bootstrapping,creating,failed,queued",
		Multi: true, IncludeAll: true, Sort: 1, Current: &Current{Text: "All", Value: "$__all"},
	}
	b := newBoard("work.json", "poc-work", "Work and provisioning steps", "24h", clusterVar("Cluster"), cellVar(), kind)
	s := func(i int, title, desc string, th *Thresholds, ts ...Target) {
		x, w := col(i, 4)
		b.add(stat(title, desc, x, 0, w, 4, "none", th, ts...))
	}
	s(0, "Queue depth", "Operations that the gateway holds in the queue of a cell. The gauge has no series while every queue is empty.", thresholds(colGood, step{1, colWarning}),
		event(instant("sum("+fresh(S("cellgw_queue_depth", pinCP), freshFast)+")", ""), false))
	s(1, "Claims 24 h", "Operations that the cells claimed in the last 24 hours.", thresholds(colNeutral),
		event(instant("sum("+Born(S("cellgw_claims_total", pinCP), "24h")+")", ""), false))
	s(2, "Throttled reports", "Reports that envd throttled in the time range.", thresholds(colGood, step{1, colWarning}),
		event(instant("sum("+Born(S("envd_reports_throttled_total", pinCP), rng)+")", ""), false))
	s(3, "Steps in flight", "Steps that the cell controller tracks and that have no final state.", thresholds(colNeutral),
		event(instant("sum("+fresh(S("cellctl_steps_open", pinCP, `state=~"$kind"`), freshSlow)+")", ""), false))

	b.add(timeSeries("Operation results by outcome", "Operations that each celld finished in each hour, by outcome.", 0, 4, 16, 9, "none",
		series("sum by (outcome) (increase("+S("celld_ops_results_total", cellRe)+"[1h]))", "{{outcome}}")))
	stages := barGauge("Step stages, last provision", "Median time that steps spent in each stage in the time range.", 16, 4, 8, 9, "s",
		event(instant("histogram_quantile(0.5, sum by (stage, le) (increase("+S("cellctl_step_stage_duration_seconds_bucket", pinCP)+"["+rng+"])))", "{{stage}}"), true))
	b.add(stages)
	return b.d
}
