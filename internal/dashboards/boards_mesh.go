package dashboards

func meshBoard() Dashboard {
	b := newBoard("mesh.json", "poc-mesh", "Mesh and Kiali", "6h", clusterVar("Cluster"), cellVar())
	b.d.Links = []Link{{Title: "Open in Kiali", URL: KialiURL, Type: "link", Icon: "external link", TargetBlank: true}}
	s := func(i int, title, desc, unit string, th *Thresholds, ts ...Target) {
		x, w := col(i, 4)
		b.add(stat(title, desc, x, 0, w, 4, unit, th, ts...))
	}
	req := func(extra ...string) string {
		return "sum(" + Born(S("istio_requests_total", append([]string{clusterRe, `reporter="destination"`}, extra...)...), rng) + ")"
	}
	// share is the share of the requests in the time range that do not match bad. It reads -1 ("no requests") while the range holds
	// no request, and it stays empty when no sample of the counter arrived in the last 2 minutes, so a broken scrape is not a green 100.
	share := func(bad string) string {
		all := req()
		fresh2 := fresh(S("istio_requests_total", clusterRe, `reporter="destination"`), "2m")
		return "((100 - 100 * (" + req(bad) + " or vector(0)) / (" + all + " > 0)) or (0 * " + all + " - 1)) and on() count(" + fresh2 + ")"
	}
	noRequests := []map[string]any{valueMap("value", [3]string{"-1", "no requests", colNeutral}), nullAsNA()}
	for i, m := range []struct {
		title, desc, bad string
		th               *Thresholds
	}{
		{"mTLS share of requests", "Share of mesh requests in the time range that arrive over mutual TLS. It reads no requests while the range holds none.",
			`connection_security_policy!="mutual_tls"`, thresholds(colCrit, step{99, colWarning}, step{100, colGood})},
		{"Request success", "Share of mesh requests in the time range with no 5xx answer. It reads no requests while the range holds none.",
			`response_code=~"5.."`, thresholds(colCrit, step{95, colWarning}, step{99, colGood})},
	} {
		x, w := col(i, 4)
		p := stat(m.title, m.desc, x, 0, w, 4, "percent", m.th, instant(share(m.bad), ""))
		p.FieldConfig.Defaults.Mappings = noRequests
		b.add(p)
	}
	tunnels := func() string { return S("cell_proxy_tunnel_up", pinMgmt, `side="hub"`, `cell=~"$cell"`) }
	s(2, "Kiali tunnels up", "Kiali tunnels that are up, of all tunnels.", "none", thresholds(colNeutral),
		instant("sum("+tunnels()+")", "up"), instant("count("+tunnels()+")", "of"))
	s(3, "Shortest proxy cert life", "Hours until the first proxy certificate expires.", "h", thresholds(colCrit, step{1, colWarning}, step{6, colGood}),
		instant("min("+S("istio_agent_cert_expiry_seconds", clusterRe, `resource_name="default"`)+") / 3600", ""))

	b.add(coloured(timeSeries("Requests per second by mesh", "Requests per second that each mesh reports at the destination.", 0, 4, 16, 9, "reqps",
		series("sum by (k8s_cluster_name) (rate("+S("istio_requests_total", clusterRe, `reporter="destination"`)+"["+rate+"]))", "{{k8s_cluster_name}}"))))
	b.add(barGauge("Tunnel answers to Kiali", "Answers of each hub tunnel by status, and the requests that the tunnels refused by reason.", 16, 4, 8, 9, "none",
		instant("sum by (status) ("+Born(S("cell_proxy_tunnel_responses_total", pinMgmt, `side="hub"`, `cell=~"$cell"`), rng)+")", "{{status}}"),
		instant("sum by (reason) ("+Born(S("cell_proxy_tunnel_refused_requests_total", clusterRe), rng)+")", "refused: {{reason}}")))
	return b.d
}

// KialiURL is the address of Kiali on the Mac, through the port forward of the harness.
const KialiURL = "http://127.0.0.1:20001/kiali"
