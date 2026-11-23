package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// proxyCertKubectl answers the reads of check_proxy_cert_life. The pods of each namespace come from $STUB_DIR/pods-<namespace>.json. exec prints the agent metrics of the pod from
// $STUB_DIR/metrics-<pod>. The stub records every call in $STUB_DIR/calls and refuses any verb other than get and exec.
const proxyCertKubectl = `#!/usr/bin/env bash
d="$STUB_DIR"
echo "kubectl $*" >>"$d/calls"
args=" $* "
case "$args" in
  *" -n apps-demo get pods -o json "*) cat "$d/pods-apps-demo.json" ;;
  *" -n istio-egress get pods -o json "*) cat "$d/pods-istio-egress.json" ;;
  *" exec "*)
    pod=""; prev=""
    for a in "$@"; do [[ "$prev" == exec ]] && pod="$a"; prev="$a"; done
    [[ -f "$d/metrics-$pod" ]] || { echo "error: unable to upgrade connection" >&2; exit 1; }
    cat "$d/metrics-$pod" ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

func podsJSON(items ...string) string { return `{"items":[` + strings.Join(items, ",") + `]}` }

// nativePod has istio-proxy as an init container. regularPod has it as a container.
func nativePod(name, phase string) string {
	return `{"metadata":{"name":"` + name + `"},"status":{"phase":"` + phase + `"},"spec":{"initContainers":[{"name":"istio-validation"},{"name":"istio-proxy"}],"containers":[{"name":"app"}]}}`
}

func regularPod(name string) string {
	return `{"metadata":{"name":"` + name + `"},"status":{"phase":"Running"},"spec":{"containers":[{"name":"app"},{"name":"istio-proxy"}]}}`
}

func noProxyPod(name string) string {
	return `{"metadata":{"name":"` + name + `"},"status":{"phase":"Running"},"spec":{"containers":[{"name":"app"}]}}`
}

func certMetric(v string) string {
	return "# TYPE istio_agent_cert_expiry_seconds gauge\nistio_agent_cert_expiry_seconds{resource_name=\"ROOTCA\"} 99\nistio_agent_cert_expiry_seconds{resource_name=\"default\"} " + v + "\n"
}

// TestVerifyProxyCertLife: check_proxy_cert_life fails when any istio-proxy has a workload certificate with 1 hour or less left, or shows no
// readable metric, and it reads only. It covers both sidecar forms, skips pods that are not Running or have no proxy, and fails when it finds no proxy.
func TestVerifyProxyCertLife(t *testing.T) {
	t.Parallel()
	testtool.Need(t, "bash", "awk")
	lib, _ := filepath.Abs("../../scripts/lib.sh")
	verify, _ := filepath.Abs("../../scripts/verify.sh")
	for _, tc := range []struct {
		name    string
		demo    string
		egress  string
		metrics map[string]string
		want    []string // substrings of the output of a failing check. Empty means the check passes.
	}{
		{"every proxy has a fresh certificate", podsJSON(nativePod("echo-1", "Running"), regularPod("client-1"), noProxyPod("plaintext-1")), podsJSON(regularPod("gw-1")),
			map[string]string{"echo-1": certMetric("82989.6"), "client-1": certMetric("43000"), "gw-1": certMetric("8.2e+04")}, nil},
		{"a native sidecar has an expired certificate", podsJSON(nativePod("echo-1", "Running"), regularPod("client-1")), podsJSON(regularPod("gw-1")),
			map[string]string{"echo-1": certMetric("-19000.5"), "client-1": certMetric("43000"), "gw-1": certMetric("43000")}, []string{"echo-1", "apps-demo"}},
		{"a regular sidecar in the gateway namespace has under 1 hour", podsJSON(nativePod("echo-1", "Running")), podsJSON(regularPod("gw-1")),
			map[string]string{"echo-1": certMetric("43000"), "gw-1": certMetric("3599")}, []string{"gw-1", "istio-egress"}},
		{"exactly 1 hour fails", podsJSON(nativePod("echo-1", "Running")), podsJSON(regularPod("gw-1")),
			map[string]string{"echo-1": certMetric("3600"), "gw-1": certMetric("43000")}, []string{"echo-1"}},
		{"just over 1 hour passes", podsJSON(nativePod("echo-1", "Running")), podsJSON(regularPod("gw-1")),
			map[string]string{"echo-1": certMetric("3601"), "gw-1": certMetric("43000")}, nil},
		{"a proxy with no default metric fails", podsJSON(nativePod("echo-1", "Running")), podsJSON(regularPod("gw-1")),
			map[string]string{"echo-1": "istio_agent_process_start_time 1\n", "gw-1": certMetric("43000")}, []string{"echo-1", "no istio_agent_cert_expiry_seconds"}},
		{"a proxy that does not answer fails", podsJSON(nativePod("echo-1", "Running")), podsJSON(regularPod("gw-1")),
			map[string]string{"gw-1": certMetric("43000")}, []string{"echo-1", "could not read"}},
		{"a pod that is not Running is skipped", podsJSON(nativePod("echo-1", "Running"), nativePod("echo-old", "Pending")), podsJSON(regularPod("gw-1")),
			map[string]string{"echo-1": certMetric("43000"), "gw-1": certMetric("43000")}, nil},
		{"a gauge line with another label before resource_name is read", podsJSON(nativePod("echo-1", "Running")), podsJSON(regularPod("gw-1")),
			map[string]string{"echo-1": "istio_agent_cert_expiry_seconds{pod=\"x\",resource_name=\"default\"} 100\n", "gw-1": certMetric("43000")}, []string{"echo-1", "100 s left"}},
		{"no proxy at all fails", podsJSON(noProxyPod("plaintext-1")), podsJSON(), nil, []string{"no running istio-proxy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, stubs := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(stubs, "kubectl"), []byte(proxyCertKubectl), 0o755); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{"pods-apps-demo.json": tc.demo, "pods-istio-egress.json": tc.egress}
			for pod, m := range tc.metrics {
				files["metrics-"+pod] = m
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			script := `source "$1"; eval "$(sed -n "/^check_proxy_cert_life()/,/^}/p" "$2")"; check_proxy_cert_life`
			cmd := exec.Command("bash", "-c", script, "_", lib, verify)
			cmd.Env = []string{"PATH=" + stubs + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cp", "STUB_DIR=" + dir}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("the check failed: %v\n%s", err, out.String())
				}
			} else {
				if err == nil {
					t.Fatalf("the check passed, want a failure with %q\n%s", tc.want, out.String())
				}
				for _, w := range tc.want {
					if !strings.Contains(out.String(), w) {
						t.Errorf("output lacks %q:\n%s", w, out.String())
					}
				}
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
			for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
				if strings.Contains(line, " exec ") && (!strings.Contains(line, "curl -sf -m 3 ") || !strings.Contains(line, "X-Prometheus-Scrape-Timeout-Seconds: 2")) {
					t.Errorf("the exec has no time limit on curl: %s", line)
				}
				if line != "" && !strings.Contains(line, " get pods ") && !strings.Contains(line, " exec ") {
					t.Errorf("the check made a call that is neither get nor exec: %s", line)
				}
				for _, verb := range []string{" delete ", " patch ", " apply ", " rollout ", " replace ", " scale "} {
					if strings.Contains(line, verb) {
						t.Errorf("the check changed the cluster: %s", line)
					}
				}
			}
		})
	}
}

// TestVerifyRunsProxyCertCheck: scripts/verify.sh runs check_proxy_cert_life next to the trust domain check, and the function never deletes a pod.
func TestVerifyRunsProxyCertCheck(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../scripts/verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "check_proxy_cert_life\n") || !strings.Contains(text, `check "Mesh certificates use the cell trust domain" check_trust_domain`) {
		t.Fatal("scripts/verify.sh does not run check_proxy_cert_life")
	}
	trust := strings.Index(text, `check "Mesh certificates use the cell trust domain" check_trust_domain`)
	life := strings.Index(text, " check_proxy_cert_life\n")
	if life < trust || life-trust > 400 {
		t.Errorf("check_proxy_cert_life runs %d bytes after the trust domain check, want it right after", life-trust)
	}
	start := strings.Index(text, "check_proxy_cert_life() {")
	end := strings.Index(text[start:], "\n}\n")
	if start < 0 || end < 0 {
		t.Fatal("scripts/verify.sh has no function check_proxy_cert_life")
	}
	body := text[start : start+end]
	for _, banned := range []string{" delete ", " patch ", " apply ", " rollout ", "restart-mesh"} {
		if strings.Contains(body, banned) {
			t.Errorf("check_proxy_cert_life contains %q, but it must only read", banned)
		}
	}
}
