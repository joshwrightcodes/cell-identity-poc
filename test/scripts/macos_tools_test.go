package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// awakeProbe is a script that calls keep_awake with its arguments and then prints one line, so a test can count how often the body runs.
const awakeProbe = `#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
keep_awake "$@"
echo "body $* awake=${POC_KEEP_AWAKE:-}"
`

// minimalPath links the tools that scripts/lib.sh needs from the PATH before the canaries into a new directory, so a test can run a script on
// a PATH with no caffeinate and no pmset, also on a Mac that ships both in /usr/bin.
func minimalPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"bash", "env", "sed", "sort", "dirname", "basename", "yq", "jq", "cat", "tr", "ls", "paste", "grep", "mkdir", "rm",
		"head", "tail", "awk", "cut", "wc", "uniq", "mktemp"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if err := os.Symlink(path, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestKeepAwakeOnDarwinOnly: keep_awake runs the script again once under caffeinate -ims on macOS, with POC_KEEP_AWAKE=1 as the guard, so the
// body runs once and never loops. On macOS without caffeinate it fails. On another system it logs and returns.
func TestKeepAwakeOnDarwinOnly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, uname, body string
		guard, noTool     bool
		caffeinate        int
	}{
		{name: "Linux", uname: "Linux", body: "body a b awake=\n"},
		{name: "Darwin", uname: "Darwin", body: "body a b awake=1\n", caffeinate: 1},
		{name: "Darwin under the guard", uname: "Darwin", guard: true, body: "body a b awake=1\n"},
		{name: "Darwin without caffeinate", uname: "Darwin", noTool: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newM9Rig(t)
			r.write("scripts/awake-probe.sh", awakeProbe)
			env := []string{"STUB_UNAME=" + tc.uname}
			if tc.guard {
				env = append(env, "POC_KEEP_AWAKE=1")
			}
			cmd := r.command(filepath.Join(r.root, "scripts", "awake-probe.sh"), env, "a", "b")
			if tc.noTool {
				only := t.TempDir()
				if err := os.Symlink(filepath.Join(r.bin, "uname"), filepath.Join(only, "uname")); err != nil {
					t.Fatal(err)
				}
				cmd.Env = append(cmd.Env, "PATH="+only+string(os.PathListSeparator)+minimalPath(t))
			}
			out, errOut, code := r.exec(cmd)
			calls := r.calls()
			if tc.noTool {
				if code == 0 || out != "" || !strings.Contains(errOut, "caffeinate") {
					t.Fatalf("exit %d, stdout %q, stderr %q; want a failure that names caffeinate, before the body", code, out, errOut)
				}
				return
			}
			if code != 0 || out != tc.body {
				t.Fatalf("exit %d, stdout %q, want %q\nstderr %s", code, out, tc.body, errOut)
			}
			if n := strings.Count(calls, "caffeinate "); n != tc.caffeinate {
				t.Errorf("%d caffeinate calls, want %d:\n%s", n, tc.caffeinate, calls)
			}
			if tc.caffeinate == 1 && !strings.Contains(calls, "caffeinate -ims bash "+filepath.Join(r.root, "scripts", "awake-probe.sh")+" a b") {
				t.Errorf("caffeinate did not run the script with its arguments:\n%s", calls)
			}
			if tc.guard && !strings.Contains(errOut, "POC_KEEP_AWAKE=1") {
				t.Errorf("stderr %q lacks the log line of a run that the guard skips", errOut)
			}
			if tc.uname != "Darwin" && !strings.Contains(errOut, "not macOS") {
				t.Errorf("stderr %q lacks the log line of a host that is not macOS", errOut)
			}
		})
	}
}

// TestBatteryRefused: gate.sh m9 and poc-gate.sh refuse a start on a Mac on battery power, before any check or gate, unless GATE_ALLOW_BATTERY=1.
// On AC power, and on a host that is not macOS, they go on, and a host that is not macOS never runs pmset.
func TestBatteryRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, script, arg, uname, power string
		allow, refused                  bool
	}{
		{name: "gate m9 on battery", script: "gate.sh", arg: "m9", uname: "Darwin", power: "Battery Power", refused: true},
		{name: "gate m9 on battery, allowed", script: "gate.sh", arg: "m9", uname: "Darwin", power: "Battery Power", allow: true},
		{name: "gate m9 on AC power", script: "gate.sh", arg: "m9", uname: "Darwin", power: "AC Power"},
		{name: "gate m9 on Linux", script: "gate.sh", arg: "m9", uname: "Linux", power: "Battery Power"},
		{name: "poc:gate on battery", script: "poc-gate.sh", arg: "slow", uname: "Darwin", power: "Battery Power", refused: true},
		{name: "poc:gate on AC power", script: "poc-gate.sh", arg: "slow", uname: "Darwin", power: "AC Power"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			env := []string{"STUB_UNAME=" + tc.uname, "STUB_POWER=" + tc.power}
			if tc.allow {
				env = append(env, "GATE_ALLOW_BATTERY=1")
			}
			_, errOut, code := r.run(tc.script, env, tc.arg)
			calls := r.calls()
			started := strings.Contains(calls, "m6 repair") || strings.Contains(calls, "mise run gate:")
			if tc.refused {
				if code == 0 || started || !strings.Contains(errOut, "battery") || !strings.Contains(errOut, "GATE_ALLOW_BATTERY=1") {
					t.Fatalf("exit %d, started %v, stderr %q; want a refusal that names GATE_ALLOW_BATTERY=1 before any check", code, started, errOut)
				}
				return
			}
			if code != 0 || !started {
				t.Fatalf("exit %d, started %v\nstderr %s\ncalls %s", code, started, errOut, calls)
			}
			if tc.uname != "Darwin" && strings.Contains(calls, "pmset") {
				t.Errorf("a host that is not macOS ran pmset:\n%s", calls)
			}
		})
	}
}

// TestMacOnlyToolsGuarded: no script, cell setting or mise task calls caffeinate or pmset outside keep_awake, on_battery and sleep_report in scripts/lib.sh,
// and each of these three functions checks uname -s and command -v before it calls its tool. A comment may name a tool.
func TestMacOnlyToolsGuarded(t *testing.T) {
	t.Parallel()
	tool := regexp.MustCompile(`\b(caffeinate|pmset)\b`)
	files, _ := filepath.Glob("../../scripts/*.sh")
	for _, pattern := range []string{"../../components/*/*.sh", "../../harness/*", "../../cells/*.env", "../../mise.toml"} {
		more, _ := filepath.Glob(pattern)
		files = append(files, more...)
	}
	if len(files) < 10 {
		t.Fatalf("found %d scripts", len(files))
	}
	bodies := map[string][]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fn := ""
		for i, line := range strings.Split(string(b), "\n") {
			if filepath.Base(f) == "lib.sh" {
				switch {
				case line == "keep_awake() {" || line == "on_battery() {" || line == "sleep_report() {":
					fn = strings.TrimSuffix(line, "() {")
					continue
				case fn != "" && line == "}":
					fn = ""
					continue
				case fn != "":
					bodies[fn] = append(bodies[fn], line)
					continue
				}
			}
			if s := strings.TrimSpace(line); !strings.HasPrefix(s, "#") && tool.MatchString(s) {
				t.Errorf("%s line %d calls a macOS tool outside keep_awake, on_battery and sleep_report of scripts/lib.sh: %s", filepath.Base(f), i+1, s)
			}
		}
	}
	for fn, name := range map[string]string{"keep_awake": "caffeinate", "on_battery": "pmset", "sleep_report": "pmset"} {
		body := bodies[fn]
		if len(body) == 0 {
			t.Errorf("scripts/lib.sh has no function %s", fn)
			continue
		}
		unameAt, commandAt, useAt := -1, -1, -1
		for i, line := range body {
			s := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(s, "#"):
			case unameAt < 0 && strings.Contains(s, "uname -s"):
				unameAt = i
			case commandAt < 0 && strings.Contains(s, "command -v "+name):
				commandAt = i
			case useAt < 0 && regexp.MustCompile(`\b`+name+` -`).MatchString(s) && !strings.HasPrefix(s, "log "):
				useAt = i
			}
		}
		if unameAt < 0 || commandAt < unameAt || useAt < commandAt {
			t.Errorf("%s must check uname -s, then command -v %s, then call %s (lines %d, %d, %d)", fn, name, name, unameAt, commandAt, useAt)
		}
	}
}

// TestEveryGateKeepsAwakeAndRefusesBattery: gate.sh holds the keep-awake and refuses a start on battery power for a gate other than m9, before the
// tests, unless GATE_ALLOW_BATTERY=1. A host that is not macOS runs the gate with no caffeinate.
func TestEveryGateKeepsAwakeAndRefusesBattery(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, milestone, uname, power string
		allow, refused                bool
	}{
		{name: "m1 on battery", milestone: "m1", uname: "Darwin", power: "Battery Power", refused: true},
		{name: "m5 on battery", milestone: "m5", uname: "Darwin", power: "Battery Power", refused: true},
		{name: "m1 on battery, allowed", milestone: "m1", uname: "Darwin", power: "Battery Power", allow: true},
		{name: "m1 on AC power", milestone: "m1", uname: "Darwin", power: "AC Power"},
		{name: "m1 on Linux", milestone: "m1", uname: "Linux", power: "Battery Power"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			env := []string{"STUB_UNAME=" + tc.uname, "STUB_POWER=" + tc.power}
			if tc.allow {
				env = append(env, "GATE_ALLOW_BATTERY=1")
			}
			_, errOut, code := r.run("gate.sh", env, tc.milestone)
			calls := r.calls()
			if strings.Count(calls, "caffeinate -ims bash ") != map[bool]int{true: 1}[tc.uname == "Darwin"] {
				t.Errorf("caffeinate calls do not match the host %s:\n%s", tc.uname, calls)
			}
			if tc.refused {
				if code == 0 || len(goRuns(calls)) != 0 || !strings.Contains(errOut, "GATE_ALLOW_BATTERY=1") {
					t.Fatalf("exit %d, %d test runs, stderr %q; want a refusal before the tests", code, len(goRuns(calls)), errOut)
				}
				for _, l := range strings.Split(calls, "\n") {
					if strings.HasPrefix(l, "docker ") || strings.HasPrefix(l, "kubectl ") {
						t.Fatalf("a live step ran before the refusal: %s\n%s", l, calls)
					}
				}
				return
			}
			if code != 0 || len(goRuns(calls)) != 1 {
				t.Fatalf("exit %d, %d test runs\nstderr %s", code, len(goRuns(calls)), errOut)
			}
		})
	}
}

// TestGateReportsSleeps: at the end of a gate that passes, fails, or runs the m9 tier, gate.sh prints the Sleep and DarkWake lines that
// pmset -g log recorded since the start, and leaves out the lines before the start and the other events. It says so when there is none.
func TestGateReportsSleeps(t *testing.T) {
	t.Parallel()
	const pmLog = "2000-01-01 00:00:00 +0000 Sleep               \tEntering Sleep state due to 'Clamshell Sleep' OLD\n" +
		"2999-01-01 00:00:00 +0000 Sleep               \tEntering Sleep state due to 'Clamshell Sleep' NEWSLEEP\n" +
		"2999-01-01 00:19:00 +0000 DarkWake            \tDarkWake from Deep Idle NEWDARK\n" +
		"2999-01-01 00:20:00 +0000 Assertions          \tPID 1 Created caffeinate NEWOTHER\n"
	const oldOnly = "2000-01-01 00:00:00 +0000 Sleep               \tEntering Sleep state OLD\n"
	for _, tc := range []struct {
		name, milestone, uname, log string
		fail, want, none            bool
	}{
		{name: "m1 passes", milestone: "m1", uname: "Darwin", log: pmLog, want: true},
		{name: "m1 fails", milestone: "m1", uname: "Darwin", log: pmLog, fail: true, want: true},
		{name: "m1 with no sleep", milestone: "m1", uname: "Darwin", log: oldOnly, none: true},
		{name: "m9 passes", milestone: "m9", uname: "Darwin", log: pmLog, want: true},
		{name: "m1 on Linux", milestone: "m1", uname: "Linux", log: pmLog},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGateM9Rig(t)
			r.state("pmset-log", tc.log)
			env := []string{"STUB_UNAME=" + tc.uname}
			if tc.fail {
				env = append(env, "STUB_FAIL_TESTS=M1")
			}
			_, errOut, code := r.run("gate.sh", env, tc.milestone)
			if (code != 0) != tc.fail {
				t.Fatalf("exit %d, want a failure: %v\n%s", code, tc.fail, errOut)
			}
			if got := strings.Contains(errOut, "NEWSLEEP") && strings.Contains(errOut, "NEWDARK"); got != tc.want {
				t.Errorf("sleep lines printed %v, want %v\n%s", got, tc.want, errOut)
			}
			for _, bad := range []string{"OLD", "NEWOTHER"} {
				if strings.Contains(errOut, bad) {
					t.Errorf("stderr prints %s, which is not a sleep since the start\n%s", bad, errOut)
				}
			}
			if said := strings.Contains(errOut, "shows no sleep"); said != tc.none {
				t.Errorf("stderr says no sleep: %v, want %v\n%s", said, tc.none, errOut)
			}
		})
	}
}
