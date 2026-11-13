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

// statusKubectl stands in for kubectl and docker in obs:uplink-status. STUB_COLLECTOR_READY, STUB_COLLECTOR_LOG,
// STUB_UPLINK_READY, STUB_ACCEPTED, STUB_DENIED and STUB_AGE set what each hop reports.
const statusKubectl = `#!/usr/bin/env bash
args=" $* "
case "$args" in
  *" get statefulset otel-collector "*) printf '%s' "${STUB_COLLECTOR_READY-1}" ;;
  *" logs otel-collector-0 "*) printf '%s\n' "${STUB_COLLECTOR_LOG:-}" ;;
  *" get pv -o json "*) echo '{"items":[{"spec":{"claimRef":{"name":"queue-otel-collector-0","namespace":"observability-system"},"local":{"path":"/q"}}}]}' ;;
  *" get deployment otel-uplink "*) printf '%s' "${STUB_UPLINK_READY-1}" ;;
  *" logs deploy/otel-uplink "*) printf '%s\n' "${STUB_UPLINK_LOG:-}" ;;
  *" exec lgtm-0 "*)
    q="$(sed -n 's/^query=//p' <<<"$*" | head -1)"
    case "$args" in
      *"exports_accepted_total"*) printf '{"data":{"result":[{"value":[0,"%s"]}]}}' "${STUB_ACCEPTED-10}" ;;
      *"exports_denied_total"*) printf '{"data":{"result":[{"value":[0,"%s"]}]}}' "${STUB_DENIED-0}" ;;
      *"upstream_failures_total"*) echo '{"data":{"result":[{"value":[0,"0"]}]}}' ;;
      *"timestamp(up"*) printf '{"data":{"result":[{"value":[0,"%s"]}]}}' "${STUB_AGE-5}" ;;
    esac ;;
  *" exec dev-cell-1-control-plane "*|*" dev-cell-1-control-plane "*) echo "512 /q" ;;
esac
exit 0
`

func statusRun(t *testing.T, args []string, env ...string) (string, int) {
	t.Helper()
	testtool.Need(t, "yq", "jq", "bash")
	bin := t.TempDir()
	for _, name := range []string{"kubectl", "docker"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(statusKubectl), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script, err := filepath.Abs("../../scripts/uplink-status.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CELL=dev-cell-1"}, env...)
	var out bytes.Buffer
	cmd.Stdout = &out
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return out.String(), code
}

// TestUplinkStatusNamesTheFirstFailingHop checks that the task reports a healthy path, and that each broken
// hop gets its own verdict, in the order collector, uplink, gateway, collector export, store. A stale store names the collector log.
func TestUplinkStatusNamesTheFirstFailingHop(t *testing.T) {
	out, code := statusRun(t, []string{"dev-cell-1"})
	if m := oneJSONLine(t, out); code != 0 || m["verdict"] != "every hop is healthy" {
		t.Fatalf("exit %d, output %v, want a healthy path", code, m)
	}
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"collector drops data", []string{`STUB_COLLECTOR_LOG={"msg":"Exporting failed. Dropping data."}`}, "collector:"},
		{"collector not ready", []string{"STUB_COLLECTOR_READY="}, "collector:"},
		{"uplink not ready", []string{"STUB_UPLINK_READY="}, "uplink:"},
		{"uplink errors", []string{`STUB_UPLINK_LOG={"level":"ERROR","msg":"dial"}`}, "uplink:"},
		{"gateway accepts nothing", []string{"STUB_ACCEPTED=0"}, "gateway or relay:"},
		{"gateway refuses", []string{"STUB_DENIED=3"}, "gateway or relay:"},
		{"collector retries the export", []string{`STUB_COLLECTOR_LOG={"msg":"Exporting failed. Will retry the request after interval."}`}, "collector export:"},
		{"store is stale", []string{"STUB_AGE=900"}, "store:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := statusRun(t, []string{"dev-cell-1"}, tc.env...)
			m := oneJSONLine(t, out)
			if v, _ := m["verdict"].(string); code != 1 || !strings.HasPrefix(v, tc.want) {
				t.Errorf("exit %d, verdict %q, want status 1 and a verdict that starts with %q", code, m["verdict"], tc.want)
			}
		})
	}
}

// TestUplinkStatusRefusesAnUnknownCluster checks that a wrong argument prints one JSON error line.
func TestUplinkStatusRefusesAnUnknownCluster(t *testing.T) {
	out, code := statusRun(t, []string{"rogue"})
	if m := oneJSONLine(t, out); code != 1 || m["level"] != "ERROR" || !strings.Contains(m["error"].(string), "Usage: mise run obs:uplink-status <cluster>") {
		t.Errorf("exit %d, output %v", code, m)
	}
}
