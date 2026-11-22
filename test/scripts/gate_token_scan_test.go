package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
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
 {"metadata":{"namespace":"ns","name":"cc-d"},"spec":{"containers":[{"name":"cell-controller","image":"localhost:5001/cell-controller@sha256:ee"}]},"status":{"containerStatuses":[{"name":"cell-controller","restartCount":0}]}},
 {"metadata":{"namespace":"ns","name":"other-c"},"spec":{"containers":[{"name":"x","image":"localhost:5001/netprobe@sha256:dd"}]},"status":{"containerStatuses":[{"name":"x","restartCount":0}]}}
]}
JSON
    ;;
  *" logs "*)
    pod=""; prev=""
    for a in "$@"; do [[ "$a" == cellgw-0 || "$a" == celld-a || "$a" == proxy-b || "$a" == other-c || "$a" == cc-d ]] && pod="$a"; [[ "$a" == --previous ]] && prev="-previous"; done
    [[ " $* " == *" --since-time=2026-11-15T01:02:03Z "* ]] || { echo "no --since-time: $*" >&2; exit 2; }
    cat "$STUB_DIR/log-$pod$prev" 2>/dev/null || true ;;
  *) echo "unexpected kubectl call: $*" >&2; exit 2 ;;
esac
`

// TestGateTokenScan: the scan reads the log of each container that runs cellgw, envd, mgmtd, celld, cell-proxy or cell-controller in each cluster since the
// start time, and the previous log of a restarted container. A compact JWS (eyJ, a dot, eyJ, a dot) fails the scan with the cluster, the
// pod, the container and the line number, and never prints the line. A base64 JSON object with no JWS shape does not.
func TestGateTokenScan(t *testing.T) {
	const jws = "eyJhbGciOiJSUzI1NiIsImtpZCI6IngifQ.eyJhdWQiOlsibWdtdCJdfQ.c2ln"
	for _, tc := range []struct {
		name string
		logs map[string]string
		// stepLogs are the step logs of the host service, by file name.
		stepLogs map[string]string
		code     int
		want     []string
		deny     []string
		calls    []string
	}{
		{name: "clean logs", logs: map[string]string{"log-cellgw-0": "a\nb\n", "log-celld-a": "c\n"},
			calls: []string{"logs celld-a", "--previous", "logs cellgw-0", "logs proxy-b -c cell-proxy"}},
		{name: "a token in the log of the cell controller", logs: map[string]string{"log-cc-d": "ok\nsent " + jws + "\n"}, code: 1,
			want: []string{"ns/cc-d cell-controller line 2"}, deny: []string{jws}, calls: []string{"logs cc-d -c cell-controller"}},
		{name: "a private key in the log of cellgw", logs: map[string]string{"log-cellgw-0": "ok\n-----BEGIN EC PRIVATE KEY-----\n"}, code: 1,
			want: []string{"dev-cp ns/cellgw-0 cellgw line 2"}, deny: []string{"BEGIN EC"}},
		{name: "a token in a step log", stepLogs: map[string]string{"aaaa.log": "== creating attempt 1\nx\n" + "sent " + "eyJhbGciOiJSUzI1NiIsImtpZCI6IngifQ.eyJhdWQiOlsibWdtdCJdfQ.c2ln" + "\n", "bbbb.log": "clean\n"}, code: 1,
			want: []string{"step log: ", "aaaa.log line 3"}, deny: []string{"eyJhbGci", "bbbb.log"}},
		{name: "a private key in a step log", stepLogs: map[string]string{"cccc.log": "ok\n-----BEGIN PRIVATE KEY-----\nAAAA\n"}, code: 1,
			want: []string{"cccc.log line 2"}, deny: []string{"AAAA"}},
		{name: "a clean step log", stepLogs: map[string]string{"dddd.log": "== admitting attempt 1 CELL=dev-cp at 2026-11-17T00:00:00Z\nok\n"}},
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
			steps := t.TempDir()
			for name, body := range tc.stepLogs {
				if err := os.WriteFile(filepath.Join(steps, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			stubs := map[string]string{"kubectl": tokenScanKubectl}
			for name, body := range liveStubs {
				stubs[name] = body
			}
			out, errOut, code := runScript(t, "gate-token-scan.sh", stubs, []string{"STUB_DIR=" + dir, "HOSTSVC_STEPS_DIR=" + steps}, "2026-11-15T01:02:03Z")
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

// TestTokenScanFindsSeed: a line that holds the operator seed prefix, in a container log, a step log or a gate file, fails the scan
// with its place and line number, and the scan never prints the line. The fixture is the prefix and a text that is no seed, so no
// line of the repository parses as a key.
func TestTokenScanFindsSeed(t *testing.T) {
	const body = "fixture-not-a-seed"
	seed := revoke.SeedPrefix + body
	if _, err := revoke.ParseSeed(strings.NewReader(seed + "\n")); err == nil {
		t.Fatal("the fixture parses as a seed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "log-cellgw-0"), []byte("ok\n"+seed+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	steps := t.TempDir()
	if err := os.WriteFile(filepath.Join(steps, "eeee.log"), []byte("a\nb\nread "+seed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	build := t.TempDir()
	if err := os.MkdirAll(filepath.Join(build, "gate"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(build, "gate", "m8-samples.jsonl"), []byte("{}\n{\"x\":\""+seed+"\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stubs := map[string]string{"kubectl": tokenScanKubectl}
	for name, b := range liveStubs {
		stubs[name] = b
	}
	out, errOut, code := runScript(t, "gate-token-scan.sh", stubs, []string{"STUB_DIR=" + dir, "HOSTSVC_STEPS_DIR=" + steps, "POC_BUILD_ROOT=" + build}, "2026-11-15T01:02:03Z")
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout %s\nstderr %s", code, out, errOut)
	}
	for _, w := range []string{"dev-cp ns/cellgw-0 cellgw line 2", "eeee.log line 3", "gate file: build/gate/m8-samples.jsonl line 2"} {
		if !strings.Contains(out, w) {
			t.Errorf("stdout %q lacks %q", out, w)
		}
	}
	for _, d := range []string{revoke.SeedPrefix, body} {
		if strings.Contains(out+errOut, d) {
			t.Errorf("the output holds %q", d)
		}
	}
}
