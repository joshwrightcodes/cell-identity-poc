package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tokenScanKubectl answers the reads of gate-token-scan.sh. Each cluster has the same pods, in namespace ns: cellgw-0 (cellgw
// image), celld-a (celld image, restarted once), proxy-b (a cell-proxy container next to a sidecar of another image), and
// other-c (an image that the scan skips). The log of a pod comes from the file $STUB_DIR/log-<pod>[-previous], and each
// call is recorded.
const tokenScanKubectl = `#!/usr/bin/env bash
echo "kubectl $*" >>"$STUB_DIR/calls"
case " $* " in
  *" get pods -A -o json "*)
    cat <<'JSON'
{"items":[
 {"metadata":{"namespace":"ns","name":"cellgw-0"},"spec":{"containers":[{"name":"cellgw","image":"localhost:5001/cellgw@sha256:aa"}]},"status":{"containerStatuses":[{"name":"cellgw","restartCount":0}]}},
 {"metadata":{"namespace":"ns","name":"celld-a"},"spec":{"containers":[{"name":"celld","image":"localhost:5001/celld@sha256:bb"}]},"status":{"containerStatuses":[{"name":"celld","restartCount":1}]}},
 {"metadata":{"namespace":"ns","name":"proxy-b"},"spec":{"containers":[{"name":"side","image":"docker.io/library/busybox:1"},{"name":"cell-proxy","image":"localhost:5001/cell-proxy@sha256:cc"}]},"status":{"containerStatuses":[{"name":"side","restartCount":0},{"name":"cell-proxy","restartCount":0}]}},
 {"metadata":{"namespace":"ns","name":"other-c"},"spec":{"containers":[{"name":"x","image":"localhost:5001/netprobe@sha256:dd"}]},"status":{"containerStatuses":[{"name":"x","restartCount":0}]}}
]}
JSON
    ;;
  *" logs "*)
    pod=""; prev=""
    for a in "$@"; do [[ "$a" == cellgw-0 || "$a" == celld-a || "$a" == proxy-b || "$a" == other-c ]] && pod="$a"; [[ "$a" == --previous ]] && prev="-previous"; done
    [[ " $* " == *" --since-time=2026-11-15T01:02:03Z "* ]] || { echo "no --since-time: $*" >&2; exit 2; }
    cat "$STUB_DIR/log-$pod$prev" 2>/dev/null || true ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// TestGateTokenScan: the scan reads the log of each container that runs cellgw, envd, mgmtd, celld or cell-proxy in each cluster since the
// start time, and the previous log of a restarted container. A compact JWS (eyJ, a dot, eyJ, a dot) fails the scan with the cluster, the
// pod, the container and the line number, and never prints the line. A base64 JSON object with no JWS shape does not.
func TestGateTokenScan(t *testing.T) {
	const jws = "eyJhbGciOiJSUzI1NiIsImtpZCI6IngifQ.eyJhdWQiOlsibWdtdCJdfQ.c2ln"
	for _, tc := range []struct {
		name  string
		logs  map[string]string
		code  int
		want  []string
		deny  []string
		calls []string
	}{
		{name: "clean logs", logs: map[string]string{"log-cellgw-0": "a\nb\n", "log-celld-a": "c\n"},
			calls: []string{"logs celld-a", "--previous", "logs cellgw-0", "logs proxy-b -c cell-proxy"}},
		{name: "a base64 JSON object is no token", logs: map[string]string{"log-cellgw-0": `{"payload":"eyJ0eXBlIjoiZGVtbyJ9"}` + "\n"}},
		{name: "a token in the log of cellgw", logs: map[string]string{"log-cellgw-0": "ok\nok\nsent " + jws + " now\n"}, code: 1,
			want: []string{"dev-cp ns/cellgw-0 cellgw line 3"}, deny: []string{jws, "eyJhbGci"}},
		{name: "a token in the previous log of a restarted celld", logs: map[string]string{"log-celld-a-previous": "x\n" + jws + "\n"}, code: 1,
			want: []string{"ns/celld-a celld line 2 (previous log)"}, deny: []string{jws}},
		{name: "a token in a container of another image is not scanned", logs: map[string]string{"log-other-c": jws + "\n", "log-proxy-b": jws + "\n"}, code: 1,
			want: []string{"ns/proxy-b cell-proxy line 1"}, deny: []string{"other-c", "side"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tc.logs {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out, errOut, code := runScript(t, "gate-token-scan.sh", map[string]string{"kubectl": tokenScanKubectl}, []string{"STUB_DIR=" + dir}, "2026-11-15T01:02:03Z")
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tc.code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("stdout %q lacks %q", out, w)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(out+errOut, d) {
					t.Errorf("the output holds %q", d)
				}
			}
			b, _ := os.ReadFile(filepath.Join(dir, "calls"))
			for _, c := range tc.calls {
				if !strings.Contains(string(b), c) {
					t.Errorf("calls %q lack %q", b, c)
				}
			}
			if strings.Contains(string(b), "logs other-c") || strings.Contains(string(b), "-c side") {
				t.Errorf("calls %q read a log of another image", b)
			}
		})
	}
}
