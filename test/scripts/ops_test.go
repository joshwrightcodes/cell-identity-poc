package scripts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const opsID = "0123456789abcdef0123456789abcdef"

// opsMgmt stands in for mgmt.sh. op get prints the operation OPS_OP for opsID, and for another ID the error that mgmtd gives for an
// unknown operation. OPS_MGMT_FAIL makes every call fail with that text and no reason. op close prints a final operation.
const opsMgmt = `#!/usr/bin/env bash
echo "mgmt $*" >>"$STUB_DIR/calls"
[[ -z "${OPS_MGMT_FAIL:-}" ]] || { echo '{"level":"ERROR","msg":"mgmt failed","error":"'"$OPS_MGMT_FAIL"'"}'; exit 1; }
case "$1 $2" in
  "op get")
    if [[ "$3" == "$OPS_ID" && -n "${OPS_OP:-}" ]]; then printf '%s\n' "$OPS_OP"; exit 0; fi
    echo '{"level":"ERROR","msg":"mgmtd failed","error":"unknown operation","reason":"operation_unknown"}'; exit 1 ;;
  "op close")
    [[ "$3" == "$OPS_ID" ]] || { echo '{"level":"ERROR","msg":"mgmtd failed","error":"unknown operation","reason":"operation_unknown"}'; exit 1; }
    echo '{"id":"'"$3"'","state":"final","final":"refused"}' ;;
  *) echo "unexpected mgmt call: $*" >&2; exit 2 ;;
esac
`

// opsGw stands in for gw.sh. The queue of dev-cell-1 holds OPS_ROWS_1 and the queue of dev-cell-2 holds OPS_ROWS_2, each a JSON array of rows.
const opsGw = `#!/usr/bin/env bash
echo "gw $*" >>"$STUB_DIR/calls"
[[ "$1" == queue && "$2" == --cell ]] || { echo "unexpected gw call: $*" >&2; exit 2; }
var="OPS_ROWS_${3//-/_}"
echo '{"cell":"'"$3"'","items":'"${!var:-[]}"'}'
`

func runOps(t *testing.T, env []string, args ...string) (out string, calls []string, code int) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"mgmt": opsMgmt, "gw": opsGw} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	out, _, code = runScript(t, "ops.sh", nil, append([]string{"STUB_DIR=" + dir, "OPS_ID=" + opsID,
		"MGMT_SCRIPT=" + filepath.Join(dir, "mgmt"), "GW_SCRIPT=" + filepath.Join(dir, "gw")}, env...), args...)
	b, _ := os.ReadFile(filepath.Join(dir, "calls"))
	return out, strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", "|")), code
}

func opsCalls(calls []string) string { return strings.Join(calls, " ") }

// TestOpsTrace checks that trace reads the cell from the operation at mgmtd and then reads the queue of that cell alone. It
// keeps only the rows with the ID and leaves the envelopes out. For an ID that mgmtd does not hold, it reads the queue of
// each cell of the topology and finds the row of a forged operation.
func TestOpsTrace(t *testing.T) {
	row := func(id string) string {
		return `{"opId":"` + id + `","state":"leased","fence":{"epoch":1,"counter":4},"holder":"celld-1","claims":2,"keyEpoch":1}`
	}
	other := `{"opId":"ffffffffffffffffffffffffffffffff","state":"done","claims":1}`
	op := `{"id":"` + opsID + `","cell":"dev-cell-2","kind":"demo.append","state":"open","served":true,"envelope":{"payload":"AAAA"},"envelopes":["AAAA"]}`

	t.Run("an operation that mgmtd holds", func(t *testing.T) {
		out, calls, code := runOps(t, []string{"OPS_OP=" + op, "OPS_ROWS_dev_cell_2=[" + other + "," + row(opsID) + "]", "OPS_ROWS_dev_cell_1=[" + row(opsID) + "]"}, "trace", opsID)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		var got struct {
			ID    string
			Op    map[string]any
			Queue []map[string]any
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil || strings.Count(strings.TrimSpace(out), "\n") != 0 {
			t.Fatalf("the output is not one JSON line: %q (%v)", out, err)
		}
		if got.ID != opsID || got.Op["cell"] != "dev-cell-2" || got.Op["envelope"] != nil || got.Op["envelopes"] != nil {
			t.Errorf("op %v, want the operation of dev-cell-2 without its envelopes", got.Op)
		}
		if len(got.Queue) != 1 || got.Queue[0]["cell"] != "dev-cell-2" || got.Queue[0]["opId"] != opsID || got.Queue[0]["claims"] != float64(2) {
			t.Errorf("queue %v, want the one row of dev-cell-2 with the ID", got.Queue)
		}
		if want := "mgmt op get " + opsID + "|gw queue --cell dev-cell-2"; opsCalls(calls) != want {
			t.Errorf("calls %q, want %q", opsCalls(calls), want)
		}
	})
	t.Run("an ID that mgmtd does not hold, with a row in the queue of one cell", func(t *testing.T) {
		out, calls, code := runOps(t, []string{"OPS_ROWS_dev_cell_1=[" + row(opsID) + "]"}, "trace", opsID)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		var got struct {
			Op    any
			Queue []map[string]any
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		if got.Op != nil || len(got.Queue) != 1 || got.Queue[0]["cell"] != "dev-cell-1" {
			t.Errorf("op %v and queue %v, want no op and the row of dev-cell-1", got.Op, got.Queue)
		}
		for _, c := range []string{"gw queue --cell dev-cell-1", "gw queue --cell dev-cell-2"} {
			if !strings.Contains(opsCalls(calls), c) {
				t.Errorf("calls %q lack %q", opsCalls(calls), c)
			}
		}
	})
	t.Run("an ID that nobody holds gives an empty queue", func(t *testing.T) {
		out, _, code := runOps(t, nil, "trace", opsID)
		if code != 0 || !strings.Contains(out, `"op":null`) || !strings.Contains(out, `"queue":[]`) {
			t.Errorf("exit %d, output %q, want op null and an empty queue", code, out)
		}
	})
	t.Run("another failure of mgmtd is no unknown ID", func(t *testing.T) {
		out, calls, code := runOps(t, []string{"OPS_MGMT_FAIL=pod mgmtd-0 is absent"}, "trace", opsID)
		if code != 1 || !strings.Contains(out, `"level":"ERROR"`) || !strings.Contains(out, "pod mgmtd-0 is absent") {
			t.Errorf("exit %d, output %q, want one JSON error line with the reason", code, out)
		}
		if strings.Contains(opsCalls(calls), "gw ") {
			t.Errorf("calls %q read a queue after mgmtd failed", opsCalls(calls))
		}
	})
	for name, args := range map[string][]string{"no ID": {"trace"}, "an ID with the wrong shape": {"trace", "x"}, "two IDs": {"trace", opsID, opsID}, "an unknown command": {"nope", opsID}} {
		t.Run(name, func(t *testing.T) {
			out, calls, code := runOps(t, nil, args...)
			if code != 1 || !strings.Contains(out, `"level":"ERROR"`) || len(calls) != 0 {
				t.Errorf("exit %d, output %q, calls %v, want one JSON error line and no call", code, out, calls)
			}
		})
	}
}

// TestOpsClose checks that close passes the ID to mgmtd and prints its answer, and that a failure gives one JSON error line.
func TestOpsClose(t *testing.T) {
	out, calls, code := runOps(t, nil, "close", opsID)
	if code != 0 || !strings.Contains(out, `"final":"refused"`) || opsCalls(calls) != "mgmt op close "+opsID {
		t.Errorf("exit %d, output %q, calls %v, want the answer of mgmtd after one close call", code, out, calls)
	}
	out, _, code = runOps(t, []string{"OPS_MGMT_FAIL=the operation is final"}, "close", opsID)
	if code != 1 || !strings.Contains(out, `"level":"ERROR"`) || !strings.Contains(out, "the operation is final") {
		t.Errorf("exit %d, output %q, want one JSON error line that holds the reason", code, out)
	}
	out, calls, code = runOps(t, nil, "close")
	if code != 1 || !strings.Contains(out, "needs one operation ID") || len(calls) != 0 {
		t.Errorf("exit %d, output %q, calls %v, want an error and no call", code, out, calls)
	}
}
