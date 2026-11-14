package mgmtapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
	"github.com/joshwrightcodes/cell-identity-poc/internal/step"
)

func keysOf(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestStepWireJSONNames(t *testing.T) {
	at := time.Unix(1_800_000_000, 0).UTC()
	for _, tc := range []struct {
		v    any
		keys []string
	}{
		{StepStatus{ID: "i", Cell: "c", State: StepQueued, Stage: "s", Reason: "r", Detail: "d", RequestID: "q", NodeIP: "n",
			Attempts: 1, UpdatedAt: at, RetryAt: at, LastHostError: &HostErrorInfo{Reason: "r", At: at}},
			[]string{"id", "cell", "state", "stage", "reason", "detail", "requestId", "nodeIP", "attempts", "updatedAt", "retryAt", "lastHostError"}},
		{HostErrorInfo{Reason: "r", At: at}, []string{"reason", "at"}},
		{PortalRequest{Cells: []string{"c"}, BootstrapSHA256: "b"}, []string{"cells", "bootstrapSHA256"}},
		{PortalResult{RequestID: "q", Revision: spec.Revision{Epoch: 1, Counter: 1}, Steps: []PortalStep{{Cell: "c", StepID: "s"}}, AlreadyRequested: []string{"c"}},
			[]string{"requestId", "revision", "steps", "alreadyRequested"}},
		{PortalStep{Cell: "c", StepID: "s"}, []string{"cell", "stepID"}},
		{SpecBundle{Spec: json.RawMessage(`{}`), Records: map[string]json.RawMessage{}, Steps: map[string]json.RawMessage{"c": json.RawMessage(`{}`)}},
			[]string{"spec", "records", "steps"}},
		{StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 1}, Steps: []StepStatus{{ID: "i"}}, StepsAt: at},
			[]string{"applied", "steps", "stepsAt"}},
	} {
		m := keysOf(t, tc.v)
		if len(m) != len(tc.keys) {
			t.Errorf("%T encodes %v, want keys %v", tc.v, m, tc.keys)
		}
		for _, k := range tc.keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%T lacks key %q", tc.v, k)
			}
		}
	}
}

func TestPortalResultEmptyListsEncodeAsArrays(t *testing.T) {
	m := keysOf(t, PortalResult{RequestID: "q", Revision: spec.Revision{Epoch: 1, Counter: 1}})
	if string(m["steps"]) != "[]" || string(m["alreadyRequested"]) != "[]" {
		t.Fatalf("got %v", m)
	}
	m = keysOf(t, &PortalResult{Steps: []PortalStep{{Cell: "c", StepID: "s"}}, AlreadyRequested: []string{"d"}})
	if string(m["steps"]) != `[{"cell":"c","stepID":"s"}]` || string(m["alreadyRequested"]) != `["d"]` {
		t.Fatalf("got %v", m)
	}
}

func TestStepStatusOmitsZeroTimes(t *testing.T) {
	m := keysOf(t, StepStatus{ID: "i", Cell: "c", State: StepQueued})
	for _, k := range []string{"updatedAt", "retryAt", "lastHostError"} {
		if _, ok := m[k]; ok {
			t.Errorf("zero %s is encoded", k)
		}
	}
}

func TestSpecBundleOmitsEmptySteps(t *testing.T) {
	m := keysOf(t, SpecBundle{Spec: json.RawMessage(`{}`), Records: map[string]json.RawMessage{}})
	if _, ok := m["steps"]; ok || len(m) != 2 {
		t.Fatalf("got %v", m)
	}
}

func TestStatusReportNoStepKeys(t *testing.T) {
	raw, err := json.Marshal(StatusReport{Applied: spec.Revision{Epoch: 1, Counter: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"applied":{"epoch":1,"counter":1}}` {
		t.Fatalf("got %s", raw)
	}
	for _, k := range []string{"steps", "stepsAt"} {
		if strings.Contains(string(raw), k) {
			t.Errorf("report with no steps has %s: %s", k, raw)
		}
	}
}

func TestStepPaths(t *testing.T) {
	id := strings.Repeat("ab", 16)
	if got := StepPath(id); got != "/v1/steps/"+id {
		t.Errorf("StepPath %q", got)
	}
	if got := StepPath("a b/c"); got != "/v1/steps/a%20b%2Fc" {
		t.Errorf("StepPath escape %q", got)
	}
	if HostSpecPath != "/v1/spec" {
		t.Errorf("HostSpecPath %q", HostSpecPath)
	}
	if StepPattern != "/v1/steps/{id}" {
		t.Errorf("StepPattern %q", StepPattern)
	}
	var got string
	mux := http.NewServeMux()
	mux.HandleFunc(StepPattern, func(w http.ResponseWriter, r *http.Request) { got = r.PathValue("id") })
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, StepPath(id), nil))
	if got != id {
		t.Errorf("PathValue %q", got)
	}
}

func TestStepReasonStrings(t *testing.T) {
	for got, want := range map[string]string{
		ReasonStepInvalid: "step_invalid", ReasonStepUnindexed: "step_unindexed",
		ReasonAlreadyRequested: "already_requested", ReasonNotRequested: "not_requested", ReasonBootstrapInvalid: "bootstrap_invalid",
		ReasonStepOpen: "step_open", ReasonNoStep: "no_step", ReasonTooManyCells: "too_many_cells", ReasonTestDigestOnly: "test_digest_only",
		ReasonHostsvcUntrusted: "hostsvc_untrusted", ReasonHostsvcUnavailable: "hostsvc_unavailable",
		ReasonHostsvcDenied: "hostsvc_denied", ReasonHostsvcBusy: "hostsvc_busy",
		ReasonRecordNotApplied: "record_not_applied", ReasonNoStatus: "no_status", ReasonStatusStale: "status_stale", ReasonKeysFailed: "keys_failed",
		StepQueued: "queued", StepCreating: "creating", StepAdmitting: "admitting", StepBootstrapping: "bootstrapping",
		StepDone: "done", StepFailed: "failed", StepFailedFinal: "failed_final", StepCancelled: "cancelled", StepRefused: "refused",
	} {
		if got != want {
			t.Errorf("constant %q, want %q", got, want)
		}
	}
	if ReasonStepInvalid != step.Code || ReasonStepUnindexed != step.DetailStepUnindexed {
		t.Error("envd reasons differ from the step package")
	}
	if ReasonCellUnknown != "cell_unknown" || ReasonNotBound != "not_bound" {
		t.Error("existing reasons changed")
	}
}

func TestHostErrorRetry(t *testing.T) {
	for _, tc := range []struct {
		reason string
		retry  bool
	}{
		{ReasonHostsvcBusy, true},
		{ReasonHostsvcUnavailable, true},
		{ReasonHostsvcUntrusted, false},
		{ReasonHostsvcDenied, false},
		{"other", false},
	} {
		if got := (&HostError{Reason: tc.reason}).Retry(); got != tc.retry {
			t.Errorf("%s: Retry() = %v, want %v", tc.reason, got, tc.retry)
		}
	}
	var err error = &HostError{Reason: ReasonHostsvcDenied, RequestID: "0123456789abcdef", Status: 403}
	var he *HostError
	if !errors.As(err, &he) || !strings.Contains(err.Error(), "hostsvc_denied") || !strings.Contains(err.Error(), "0123456789abcdef") {
		t.Fatalf("Error() = %q", err.Error())
	}
	if (&HostError{Reason: ReasonHostsvcBusy, RetryAfter: 30 * time.Second}).RetryAfter != 30*time.Second {
		t.Fatal("RetryAfter")
	}
}

func TestValidStepStatus(t *testing.T) {
	good := func() StepStatus {
		return StepStatus{ID: strings.Repeat("ab", 16), Cell: "dev-cell-1", State: StepQueued}
	}
	if !ValidStepStatus(good()) {
		t.Fatal("the base status must be valid")
	}
	type row struct {
		name string
		mod  func(*StepStatus)
		ok   bool
	}
	rows := []row{
		{"request_id_16_hex", func(s *StepStatus) { s.RequestID = "0123456789abcdef" }, true},
		{"request_id_15_hex", func(s *StepStatus) { s.RequestID = "0123456789abcde" }, false},
		{"request_id_upper", func(s *StepStatus) { s.RequestID = "0123456789ABCDEF" }, false},
		{"node_ip_v4", func(s *StepStatus) { s.NodeIP = "172.18.0.5" }, true},
		{"node_ip_v6", func(s *StepStatus) { s.NodeIP = "fd00::1" }, false},
		{"node_ip_text", func(s *StepStatus) { s.NodeIP = "node" }, false},
		{"node_ip_mapped", func(s *StepStatus) { s.NodeIP = "::ffff:10.0.0.1" }, false},
		{"attempts_3", func(s *StepStatus) { s.Attempts = 3 }, true},
		{"attempts_4", func(s *StepStatus) { s.Attempts = 4 }, false},
		{"attempts_negative", func(s *StepStatus) { s.Attempts = -1 }, false},
		{"id_31_hex", func(s *StepStatus) { s.ID = strings.Repeat("a", 31) }, false},
		{"id_upper", func(s *StepStatus) { s.ID = strings.Repeat("AB", 16) }, false},
		{"cell_upper", func(s *StepStatus) { s.Cell = "Dev" }, false},
		{"cell_60_chars", func(s *StepStatus) { s.Cell = strings.Repeat("a", 60) }, false},
		{"state_empty", func(s *StepStatus) { s.State = "" }, false},
		{"state_unknown", func(s *StepStatus) { s.State = "running" }, false},
		{"reason_step_invalid", func(s *StepStatus) { s.State = StepRefused; s.Reason = ReasonStepInvalid }, true},
		{"reason_hostsvc_busy", func(s *StepStatus) { s.Reason = ReasonHostsvcBusy }, true},
		{"reason_hostsvc_untrusted", func(s *StepStatus) { s.Reason = ReasonHostsvcUntrusted }, true},
		{"reason_hostsvc_unavailable", func(s *StepStatus) { s.Reason = ReasonHostsvcUnavailable }, true},
		{"reason_hostsvc_denied", func(s *StepStatus) { s.Reason = ReasonHostsvcDenied }, true},
		{"last_host_error_untrusted", func(s *StepStatus) { s.LastHostError = &HostErrorInfo{Reason: ReasonHostsvcUntrusted} }, true},
		{"last_host_error_unavailable", func(s *StepStatus) { s.LastHostError = &HostErrorInfo{Reason: ReasonHostsvcUnavailable} }, true},
		{"last_host_error_denied", func(s *StepStatus) { s.LastHostError = &HostErrorInfo{Reason: ReasonHostsvcDenied} }, true},
		{"last_host_error_busy", func(s *StepStatus) { s.LastHostError = &HostErrorInfo{Reason: ReasonHostsvcBusy} }, true},
		{"last_host_error_unknown", func(s *StepStatus) { s.LastHostError = &HostErrorInfo{Reason: "boom"} }, false},
		{"last_host_error_empty", func(s *StepStatus) { s.LastHostError = &HostErrorInfo{} }, false},
		{"last_host_error_step_invalid", func(s *StepStatus) { s.LastHostError = &HostErrorInfo{Reason: step.Code} }, false},
		{"last_host_error_free_text", func(s *StepStatus) { s.LastHostError = &HostErrorInfo{Reason: strings.Repeat("x", 65536) + "\n"} }, false},
		{"stage_empty", func(s *StepStatus) { s.Stage = "" }, true},
		{"stage_creating", func(s *StepStatus) { s.Stage = StageCreating }, true},
		{"stage_admitting", func(s *StepStatus) { s.Stage = StageAdmitting }, true},
		{"stage_bootstrapping", func(s *StepStatus) { s.Stage = StageBootstrapping }, true},
		{"stage_done", func(s *StepStatus) { s.Stage = "done" }, false},
		{"stage_free_text", func(s *StepStatus) { s.Stage = "\x1b[2J\nrun: mise run harness:down" }, false},
		{"reason_unknown", func(s *StepStatus) { s.Reason = "boom" }, false},
		{"detail_unknown", func(s *StepStatus) { s.Detail = "boom" }, false},
		{"detail_free_text", func(s *StepStatus) { s.Detail = "exit status 1\n" }, false},
	}
	for _, st := range []string{StepQueued, StepCreating, StepAdmitting, StepBootstrapping, StepDone, StepFailed, StepFailedFinal, StepCancelled, StepRefused} {
		st := st
		rows = append(rows, row{"state_" + st, func(s *StepStatus) { s.State = st }, true})
	}
	for _, d := range step.Details() {
		d := d
		rows = append(rows, row{"detail_" + d, func(s *StepStatus) { s.Detail = d }, true})
	}
	for _, d := range []string{"timeout", "interrupted", "stage_failed"} {
		d := d
		rows = append(rows, row{"b03_detail_" + d, func(s *StepStatus) { s.State = StepFailed; s.Detail = d }, true})
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s := good()
			r.mod(&s)
			if got := ValidStepStatus(s); got != r.ok {
				t.Fatalf("ValidStepStatus(%+v) = %v, want %v", s, got, r.ok)
			}
		})
	}
}
