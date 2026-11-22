//go:build e2e

package e2e

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/bundle"
	"github.com/joshwrightcodes/cell-identity-poc/internal/cmdrun"
	"github.com/joshwrightcodes/cell-identity-poc/internal/op"
)

// statusAttemptMax bounds one run of a mise task in this file. harness:status takes about 2 minutes.
const statusAttemptMax = 6 * time.Minute

// statusSampleMax is the age limit of a Prometheus sample in harness:status.
const statusSampleMax = 5 * time.Minute

// statusRetryWindow is how long TestM3StatusHealthy waits for a healthy status.
const statusRetryWindow = 10 * time.Minute

// miseRotateMax bounds the tasks that rotate a key or a password. Each one restarts workloads and waits for them.
const miseRotateMax = 10 * time.Minute

// runMiseBounded runs a mise task in the repository root under limit, with CELL set when cell is not empty. It ends
// the whole process group of the task when the limit passes, and fails the test then. It returns the standard output,
// the standard error and the exit status.
func runMiseBounded(t *testing.T, limit time.Duration, cell string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var env []string
	if cell != "" {
		env = []string{"CELL=" + cell}
	}
	res, err := cmdrun.Run(limit, "../..", env, "mise", append([]string{"run"}, args...)...)
	if err != nil {
		t.Fatalf("mise run %s: %v\nstdout: %s\nstderr: %s", strings.Join(args, " "), err, res.Stdout, res.Stderr)
	}
	return res.Stdout, res.Stderr, res.Code
}

// runMise runs a mise task for at most statusAttemptMax.
func runMise(t *testing.T, cell string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return runMiseBounded(t, statusAttemptMax, cell, args...)
}

// statusObject is the part of one object of harness:status that the test reads.
type statusObject struct {
	Cluster string `json:"cluster"`
	OK      bool   `json:"ok"`
	Verify  struct {
		OK     bool     `json:"ok"`
		Failed []string `json:"failed"`
	} `json:"verify"`
	Problems []string `json:"problems"`
	Agents   *struct {
		Expected  []string `json:"expected"`
		Connected []string `json:"connected"`
		Missing   []string `json:"missing"`
	} `json:"agents"`
	Samples map[string]float64 `json:"samples"`
	Kiali   *struct {
		Ready      bool     `json:"ready"`
		Accessible []string `json:"accessible"`
		Missing    []string `json:"missing"`
	} `json:"kiali"`
	// The M9 fields of the dev-cp object.
	Island *struct {
		Environment bool     `json:"environment"`
		Cells       []string `json:"cells"`
	} `json:"island"`
	Overlay *struct {
		Held   []json.RawMessage `json:"held"`
		Inputs []json.RawMessage `json:"inputs"`
	} `json:"overlay"`
	Bans *struct {
		Ready    bool `json:"ready"`
		Restarts int  `json:"restarts"`
	} `json:"bans"`
	SVIDTTL *struct {
		Live       string `json:"live"`
		Configured string `json:"configured"`
		Marker     bool   `json:"marker"`
	} `json:"svidTTL"`
}

// statusOnce runs harness:status and returns the object of each cluster by name, and the exit status.
func statusOnce(t *testing.T) (map[string]statusObject, string, int) {
	t.Helper()
	stdout, stderr, code := runMise(t, "", "harness:status")
	objs := map[string]statusObject{}
	for line := range strings.SplitSeq(strings.TrimSpace(stdout), "\n") {
		var o statusObject
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			t.Fatalf("a line of standard output is no JSON object: %q\nstderr: %s", line, stderr)
		}
		objs[o.Cluster] = o
	}
	return objs, stdout, code
}

// TestM3StatusHealthy checks that harness:status exits 0 on a healthy harness. The management object lists
// both agents, a Prometheus sample younger than 5 minutes for each registered cluster, and both cells in
// Kiali. obs:uplink-status counts the exporter failures of the last 5 minutes, and the restart of the management
// SPIRE server in an earlier test causes some, so the test reads the status again for up to 10 minutes.
func TestM3StatusHealthy(t *testing.T) {
	var objs map[string]statusObject
	var stdout string
	var code int
	deadline := time.Now().Add(statusRetryWindow)
	for attempt := 1; ; attempt++ {
		objs, stdout, code = statusOnce(t)
		if code == 0 || time.Now().After(deadline) {
			break
		}
		t.Logf("attempt %d: harness:status exited %d:\n%s", attempt, code, stdout)
		time.Sleep(30 * time.Second)
	}
	if code != 0 {
		t.Fatalf("harness:status exited %d, want 0:\n%s", code, stdout)
	}
	for _, cluster := range clustersWith(t, "") {
		o, ok := objs[cluster]
		if !ok || !o.OK || !o.Verify.OK {
			t.Errorf("object of %s is %+v (present %v), want ok with a passing cell:verify", cluster, o, ok)
		}
	}
	if cp := objs["dev-cp"]; cp.Island == nil || cp.Overlay == nil || cp.Bans == nil || cp.SVIDTTL == nil {
		t.Errorf("the dev-cp object lacks island, overlay, bans or svidTTL:\n%s", stdout)
	} else if cp.Island.Environment || len(cp.Island.Cells) > 0 || !cp.Bans.Ready || cp.SVIDTTL.Live == "" {
		t.Errorf("dev-cp island %+v, bans %+v, svidTTL %+v, want a connected environment, no cell without a stream, a Ready ban container and a live lifetime", *cp.Island, *cp.Bans, *cp.SVIDTTL)
	}
	mgmt := objs[mgmtCluster]
	if mgmt.Agents == nil || mgmt.Kiali == nil {
		t.Fatalf("the management object has no agents or kiali field:\n%s", stdout)
	}
	for _, cell := range viewCells(t) {
		if !slices.Contains(mgmt.Agents.Connected, agentName(cell)) {
			t.Errorf("agents.connected is %v, want %s", mgmt.Agents.Connected, agentName(cell))
		}
	}
	for _, cluster := range clustersWith(t, "") {
		age, ok := mgmt.Samples[cluster]
		if !ok || age >= statusSampleMax.Seconds() {
			t.Errorf("samples[%s] is %v (present %v), want an age under %s", cluster, age, ok, statusSampleMax)
		}
	}
	for _, cell := range meshCells(t) {
		if !slices.Contains(mgmt.Kiali.Accessible, cell) {
			t.Errorf("kiali.accessible is %v, want %s", mgmt.Kiali.Accessible, cell)
		}
	}
}

// TestM3VerifyDetectsPeerRootDrift changes one byte of ConfigMap mgmt-root of the mesh-view tunnel in
// dev-cell-1. cell:verify then fails the check of that ConfigMap and prints the command to repair it. The
// tunnel process reads the file once at start, so the running tunnel keeps its roots. The test restores
// the ConfigMap in t.Cleanup. It applies the change server-side with the manager of the harness apply, so
// the restore leaves the same field managers.
func TestM3VerifyDetectsPeerRootDrift(t *testing.T) {
	const cell, ns, name = "dev-cell-1", "mesh-view-system", "mgmt-root"
	out, err := kubectl(t, cell, "", "-n", ns, "get", "configmap", name, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var cm map[string]any
	if err := json.Unmarshal([]byte(out), &cm); err != nil {
		t.Fatal(err)
	}
	meta := cm["metadata"].(map[string]any)
	for _, k := range []string{"resourceVersion", "uid", "creationTimestamp", "managedFields", "selfLink"} {
		delete(meta, k)
	}
	data := cm["data"].(map[string]any)
	orig, _ := data["root.crt"].(string)
	// Change one base64 character after the first header line.
	i := strings.Index(orig, "\n") + 5
	if i < 5 || i >= len(orig) {
		t.Fatalf("ConfigMap %s/%s holds no PEM body: %q", ns, name, orig)
	}
	flipped := "A"
	if orig[i] == 'A' {
		flipped = "B"
	}
	apply := func(root string) error {
		data["root.crt"] = root
		body, err := json.Marshal(cm)
		if err != nil {
			return err
		}
		_, err = kubectl(t, cell, string(body), "apply", "--server-side", "--force-conflicts", "-f", "-")
		return err
	}
	t.Cleanup(func() {
		if err := apply(orig); err != nil {
			t.Errorf("could not restore ConfigMap %s/%s in %s: %v", ns, name, cell, err)
		}
	})
	if err := apply(orig[:i] + flipped + orig[i+1:]); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runMise(t, cell, "cell:verify")
	// The bundle drift check of mesh-view prints the same command, so the test asserts the check under test: its
	// own FAIL line, its detail line and its repair line, in that order.
	const check = "FAIL  The peer root ConfigMap of the mesh-view tunnel holds the live roots of management\n" +
		"      ConfigMap mesh-view-system/mgmt-root holds other roots than the live bundle of management.\n" +
		"      Run: CELL=dev-cell-1 mise run cell:up"
	if code == 0 || !strings.Contains(stdout, check) {
		t.Fatalf("cell:verify exited %d, want the FAIL line, the detail line and the repair line of the peer root check:\n%s\nstdout:\n%s\nstderr:\n%s", code, check, stdout, stderr)
	}
}

// TestM4StatusShowsSpec checks that harness:status reports the management plane: the signed and applied revisions
// agree with mgmtd ctl status, the report of envd is younger than 60 seconds, each cell with cell-identity is bound, and
// the host service runs. It reads the status again for up to the retry window, because a report or a bind can lag.
func TestM4StatusShowsSpec(t *testing.T) {
	type plane struct {
		Signed       map[string]uint64 `json:"signed"`
		Applied      map[string]uint64 `json:"applied"`
		LastReportAt time.Time         `json:"lastReportAt"`
		Restore      bool              `json:"restoreActive"`
		Cells        []struct {
			Name  string `json:"name"`
			Bound bool   `json:"bound"`
		} `json:"cells"`
		Hostsvc struct {
			Running bool   `json:"running"`
			Check   string `json:"check"`
		} `json:"hostsvc"`
		Error string `json:"error"`
	}
	var (
		p      plane
		stdout string
		code   int
	)
	deadline := time.Now().Add(statusRetryWindow)
	for attempt := 1; ; attempt++ {
		_, stdout, code = statusOnce(t)
		for line := range strings.SplitSeq(strings.TrimSpace(stdout), "\n") {
			var o struct {
				Cluster    string `json:"cluster"`
				Management plane  `json:"management"`
			}
			if json.Unmarshal([]byte(line), &o) == nil && o.Cluster == mgmtCluster {
				p = o.Management
			}
		}
		if code == 0 || time.Now().After(deadline) {
			break
		}
		t.Logf("attempt %d: harness:status exited %d:\n%s", attempt, code, stdout)
		time.Sleep(30 * time.Second)
	}
	if code != 0 {
		t.Fatalf("harness:status exited %d, want 0:\n%s", code, stdout)
	}
	live := mgmtStatus(t)
	if p.Error != "" || p.Signed["epoch"] != live.Signed.Epoch || p.Signed["counter"] != live.Signed.Counter ||
		p.Applied["epoch"] != live.Applied.Epoch || p.Applied["counter"] != live.Applied.Counter {
		t.Errorf("management %+v, want the signed %v and applied %v revisions of mgmtd ctl status", p, live.Signed, live.Applied)
	}
	if age := time.Since(p.LastReportAt); p.LastReportAt.IsZero() || age > time.Minute+statusSampleMax {
		t.Errorf("lastReportAt is %v, want a report from envd in the last %v", p.LastReportAt, time.Minute+statusSampleMax)
	}
	if p.Restore {
		t.Error("restoreActive is true, want false")
	}
	if !p.Hostsvc.Running || p.Hostsvc.Check != "" {
		t.Errorf("hostsvc %+v, want a running service with an empty check", p.Hostsvc)
	}
	bound := map[string]bool{}
	for _, c := range p.Cells {
		bound[c.Name] = c.Bound
	}
	for _, cell := range clustersWith(t, agentCellSet) {
		if !bound[cell] {
			t.Errorf("cell %s is not bound in %+v", cell, p.Cells)
		}
	}
}

// TestM5StatusShowsWork checks that harness:status reports signed work: the dev-cp object holds the gateway with an epoch that
// equals cellgw ctl status, an open stream and a recent sync, and each bound cell of the management object holds a status that is
// younger than two minutes. It reads the status again for up to the retry window, because a report can lag.
func TestM5StatusShowsWork(t *testing.T) {
	type object struct {
		Cluster string `json:"cluster"`
		Gateway struct {
			Epoch          uint64         `json:"epoch"`
			SyncedAt       time.Time      `json:"syncedAt"`
			OutboxItems    int            `json:"outboxItems"`
			Streams        map[string]int `json:"streams"`
			StoreError     string         `json:"storeError"`
			Error          string         `json:"error"`
			EpochChangedAt time.Time      `json:"epochChangedAt"`
		} `json:"gateway"`
		Management struct {
			Cells []struct {
				Name         string    `json:"name"`
				Bound        bool      `json:"bound"`
				LastStatusAt time.Time `json:"lastStatusAt"`
				Records      *int      `json:"records"`
				OpenOps      *int      `json:"openOps"`
				ExpiredOps   *int      `json:"expiredOps"`
				ForgedSeen   *int      `json:"forgedSeen"`
			} `json:"cells"`
		} `json:"management"`
	}
	var (
		objs   = map[string]object{}
		stdout string
		code   int
	)
	deadline := time.Now().Add(statusRetryWindow)
	for attempt := 1; ; attempt++ {
		_, stdout, code = statusOnce(t)
		objs = map[string]object{}
		for line := range strings.SplitSeq(strings.TrimSpace(stdout), "\n") {
			var o object
			if json.Unmarshal([]byte(line), &o) == nil {
				objs[o.Cluster] = o
			}
		}
		if code == 0 || time.Now().After(deadline) {
			break
		}
		t.Logf("attempt %d: harness:status exited %d:\n%s", attempt, code, stdout)
		time.Sleep(30 * time.Second)
	}
	if code != 0 {
		t.Fatalf("harness:status exited %d, want 0:\n%s", code, stdout)
	}
	g := objs[spireCluster].Gateway
	live := gwStatus(t)
	if g.Error != "" || g.Epoch == 0 || g.Epoch != live.Epoch || g.StoreError != "" {
		t.Errorf("gateway %+v, want the epoch %d of cellgw ctl status, no store error and no error", g, live.Epoch)
	}
	if g.SyncedAt.IsZero() || time.Since(g.SyncedAt) > 2*time.Minute+statusSampleMax {
		t.Errorf("gateway syncedAt is %v, want a sync in the last 2 minutes", g.SyncedAt)
	}
	cells := clustersWith(t, agentCellSet)
	for _, cell := range cells {
		if g.Streams[cell] < 1 {
			t.Errorf("gateway streams %v hold no stream of %s", g.Streams, cell)
		}
	}
	seen := map[string]bool{}
	for _, c := range objs[mgmtCluster].Management.Cells {
		seen[c.Name] = true
		if !c.Bound {
			continue
		}
		if c.LastStatusAt.IsZero() || time.Since(c.LastStatusAt) > 2*time.Minute+statusSampleMax {
			t.Errorf("cell %s has lastStatusAt %v, want a status in the last 2 minutes", c.Name, c.LastStatusAt)
		}
		if c.Records == nil || c.OpenOps == nil || c.ExpiredOps == nil || c.ForgedSeen == nil {
			t.Errorf("cell %s lacks a work field: %+v", c.Name, c)
		}
	}
	for _, cell := range cells {
		if !seen[cell] {
			t.Errorf("the management object lists no cell %s", cell)
		}
	}
}

// TestM6StatusShowsCells checks harness:status on a provisioned harness. It exits 0, and each cell has an object that is not absent, is ok and
// holds applications, verify and telemetry. mgmtd holds each cell as requested, valid and with no open step, and the journal of the host service
// holds no step that runs a stage, so the problems of provisioning name nothing. The status reads again for up to the retry window, because a
// report can lag after a link or an admit stage.
func TestM6StatusShowsCells(t *testing.T) {
	type object struct {
		Cluster      string `json:"cluster"`
		OK           bool   `json:"ok"`
		Absent       bool   `json:"absent"`
		Applications *struct {
			Total int `json:"total"`
		} `json:"applications"`
		Verify *struct {
			OK bool `json:"ok"`
		} `json:"verify"`
		Telemetry *struct {
			OK bool `json:"ok"`
		} `json:"telemetry"`
		Problems []string `json:"problems"`
	}
	var (
		objs   map[string]object
		stdout string
		code   int
	)
	deadline := time.Now().Add(statusRetryWindow)
	for attempt := 1; ; attempt++ {
		_, stdout, code = statusOnce(t)
		objs = map[string]object{}
		for line := range strings.SplitSeq(strings.TrimSpace(stdout), "\n") {
			var o object
			if json.Unmarshal([]byte(line), &o) == nil {
				objs[o.Cluster] = o
			}
		}
		if code == 0 || time.Now().After(deadline) {
			break
		}
		t.Logf("attempt %d: harness:status exited %d:\n%s", attempt, code, stdout)
		time.Sleep(30 * time.Second)
	}
	if code != 0 {
		t.Fatalf("harness:status exited %d, want 0:\n%s", code, stdout)
	}
	status := mgmtStatus(t)
	for _, cell := range clustersWith(t, agentCellSet) {
		o, ok := objs[cell]
		if !ok || o.Absent || !o.OK || o.Applications == nil || o.Verify == nil || o.Telemetry == nil || len(o.Problems) != 0 {
			t.Errorf("object of %s is %+v (present %v), want an ok object that is not absent, with applications, verify and telemetry", cell, o, ok)
		}
		found := false
		for _, c := range status.Cells {
			if c.Name != cell {
				continue
			}
			found = true
			if !c.Requested || !c.Valid || (c.Step != nil && c.Step.DoneAt.IsZero()) {
				t.Errorf("mgmtd holds %s as requested %v, valid %v, step %+v, want requested, valid and no open step", cell, c.Requested, c.Valid, c.Step)
			}
		}
		if !found {
			t.Errorf("mgmtd lists no cell %s", cell)
		}
	}
	for id, st := range hostSteps(t) {
		switch st.State {
		case "creating", "admitting", "bootstrapping":
			t.Errorf("step %s of %s runs the stage %s, and a healthy harness has no stage that runs", id, st.Cell, st.State)
		}
	}
}

// TestM8StatusShowsBundles checks that harness:status exits 0 with a signed, healthy bundle state in each live cell and in dev-cp, and that mgmtd reports
// for each of them the bundle state, the root digest of its last signed set and the allow-list digest that the engine in this checkout runs. It reads the
// status again for up to the retry window, because a report can lag.
func TestM8StatusShowsBundles(t *testing.T) {
	var (
		objs   map[string]statusObject
		stdout string
		code   int
	)
	deadline := time.Now().Add(statusRetryWindow)
	for attempt := 1; ; attempt++ {
		objs, stdout, code = statusOnce(t)
		if code == 0 || time.Now().After(deadline) {
			break
		}
		t.Logf("attempt %d: harness:status exited %d:\n%s", attempt, code, stdout)
		time.Sleep(30 * time.Second)
	}
	if code != 0 {
		t.Fatalf("harness:status exited %d, want 0:\n%s", code, stdout)
	}
	status := mgmtStatus(t)
	check := func(name string, last *op.Result, shown *op.BundleStatus, signedRoot string) {
		t.Helper()
		if shown == nil {
			t.Errorf("mgmtd holds no bundle status for %s", name)
			return
		}
		if shown.State != "healthy" {
			t.Errorf("the bundle state of %s is %q, want healthy", name, shown.State)
		}
		if shown.AllowSHA256 != bundle.AllowSHA256() {
			t.Errorf("%s runs the allow list %q, want %q", name, shown.AllowSHA256, bundle.AllowSHA256())
		}
		if signedRoot != "" && shown.RootDigest != signedRoot {
			t.Errorf("%s runs the root %s, and the last signed set has the root %s", name, shown.RootDigest, signedRoot)
		}
		if last == nil || (last.Outcome != op.OutcomeApplied && last.Outcome != op.OutcomeAlreadyApplied) {
			t.Errorf("the last signed set of %s has the result %+v, want applied or already_applied", name, last)
		}
	}
	for _, cell := range clustersWith(t, agentCellSet) {
		if o, ok := objs[cell]; !ok || !o.OK || len(o.Problems) != 0 {
			t.Errorf("object of %s is %+v (present %v), want an ok object with no problem", cell, o, ok)
		}
		found := false
		for _, c := range status.Cells {
			if c.Name != cell {
				continue
			}
			found = true
			if c.Bundle == nil {
				t.Errorf("mgmtd holds no signed set for %s", cell)
				continue
			}
			check(cell, c.Bundle.Result, c.BundleStatus, c.Bundle.RootDigest)
		}
		if !found {
			t.Errorf("mgmtd lists no cell %s", cell)
		}
	}
	if o, ok := objs[spireCluster]; !ok || !o.OK || len(o.Problems) != 0 {
		t.Errorf("object of %s is %+v (present %v), want an ok object with no problem", spireCluster, o, ok)
	}
	if status.PlaneBundle == nil {
		t.Errorf("mgmtd holds no signed set for %s", spireCluster)
	} else {
		check(spireCluster, status.PlaneBundle.Result, status.PlaneBundleStatus, status.PlaneBundle.RootDigest)
	}
}
