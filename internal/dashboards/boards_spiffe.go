package dashboards

func spiffeBoard() Dashboard {
	domain := queryVar("trust_domain", "Trust domain", `label_values(trust_ca_not_after_seconds{`+notSynth+`}, trust_domain)`)
	b := newBoard("spiffe.json", "poc-spiffe", "SPIFFE and SPIRE", "24h", clusterVar("Cluster"), cellVar(), domain)
	s := func(i int, title, desc, unit string, th *Thresholds, ts ...Target) {
		x, w := col(i, 6)
		b.add(stat(title, desc, x, 0, w, 4, unit, th, ts...))
	}
	attest := func(result string) string {
		return "sum(increase(" + S("cluster_jwt_attestations_total", pinCP, `result="`+result+`"`) + "[" + rng + "]))"
	}
	s(0, "Attestations", "Attestations that the cluster_jwt plugin accepted in the time range.", "none", thresholds(colNeutral),
		event(instant(attest("accepted"), ""), false))
	s(1, "Refused attestations", "Attestations that the cluster_jwt plugin refused in the time range.", "none", thresholds(colGood, step{1, colWarning}),
		event(instant(attest("refused"), ""), false))
	s(2, "Agents per cell", "Unbanned agents of each cell. A series that stops reporting leaves the panel within a minute.", "none", thresholds(colNeutral),
		instant("sum by (cell) ("+fresh(S("agentban_agents", pinCP, `cell=~"$cell"`), freshFast)+")", "{{cell}}"))
	s(3, "Intermediate CA expires", "Days until the intermediate CA expires. Warning under 14 days, critical under 7 days.", "d",
		thresholds(colCrit, step{7, colWarning}, step{14, colGood}),
		instant("(min("+fresh(S("trust_ca_not_after_seconds", clusterRe, `ca="intermediate"`, `trust_domain=~"$trust_domain"`), freshSlow)+") - time()) / 86400", ""))
	s(4, "Key checks", "Key checks of mgmtd that found no change or updated the keys, of all key checks in the time range.", "none", thresholds(colNeutral),
		instant("sum(increase("+S("mgmtd_keycheck_results_total", pinMgmt, `result=~"unchanged|keys_updated"`)+"["+rng+"]))", "ok"),
		instant("sum(increase("+S("mgmtd_keycheck_results_total", pinMgmt)+"["+rng+"]))", "of"))
	s(5, "Agent bans", "Agents that the ban container banned in the time range.", "none", thresholds(colGood, step{1, colWarning}),
		event(instant("sum(increase("+S("agentban_bans_total", pinCP)+"["+rng+"]))", ""), false))

	refusals := barGauge("Attestation refusals by reason", "Refused attestations in the time range, by the reason of the plugin.", 0, 4, 10, 8, "none",
		event(instant("sum by (reason) (increase("+S("cluster_jwt_attestations_total", pinCP, `result="refused"`)+"["+rng+"]))", "{{reason}}"), true))
	refusals.FieldConfig.Defaults.Color = map[string]any{"mode": "fixed", "fixedColor": colWarning}
	b.add(refusals)
	b.add(coloured(timeSeries("SVIDs issued per 10 min", "X.509 SVIDs that each SPIRE server signed in each 10 minutes.", 10, 4, 14, 8, "none",
		series("sum by (k8s_cluster_name) (increase("+S("spire_server_server_ca_sign_x509_svid_total", clusterRe)+"[10m]))", "{{k8s_cluster_name}}"))))
	hints := timeSeries("unknown_kid hints per hour", "Report items that mgmtd retried because the key id was unknown, in each hour.", 0, 12, 12, 8, "none",
		event(series("sum(increase("+S("mgmtd_report_retry_unknown_kid_total", pinMgmt)+"[1h]))", "retries"), false))
	hints.FieldConfig.Defaults.Custom["fillOpacity"] = 40
	b.add(hints)
	anchors := `(max by (trust_domain, ca, sha256, source, k8s_cluster_name) (` +
		fresh(S("trust_ca_not_after_seconds", clusterRe, `trust_domain=~"$trust_domain"`, `ca!="issuing"`), freshSlow) + `) - time())` +
		` or label_replace(label_replace(label_replace(` + S("citadel_server_root_cert_expiry_timestamp", clusterRe) + ` - time(),` +
		` "trust_domain", "$1.mesh", "k8s_cluster_name", "(.+)"), "ca", "mesh root", "", ""), "source", "istiod", "", "")`
	b.add(table("Trust anchors", "CA certificates that the clusters report, and the mesh roots. Expires is the time left. Pinned by is the cluster that reports the row.",
		12, 12, 12, 8, "", "", "Pinned by",
		tableColumn{Title: "Expires", Unit: "s", Expr: anchors, Labels: [][2]string{
			{"trust_domain", "Trust domain"}, {"ca", "CA"}, {"sha256", "Root"}, {"source", "Source"}, {"k8s_cluster_name", "Pinned by"}}},
	))
	return b.d
}
