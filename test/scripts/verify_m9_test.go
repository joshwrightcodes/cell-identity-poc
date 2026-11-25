package scripts

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

// runCheck runs one function of scripts/verify-lib.sh in dev-cp, as cell:verify does, with the stubs of the rig.
func (r *revokeRig) runCheck(fn string, env ...string) (string, int) {
	r.t.Helper()
	repo, err := filepath.Abs("../..")
	if err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1/scripts/lib.sh"; source "$1/scripts/verify-lib.sh"; set +e; `+fn, "_", repo)
	cmd.Env = append(r.env(env...), "CELL=dev-cp")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			r.t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return out.String(), code
}

func (r *revokeRig) remove(ctx, ns, name string) {
	r.t.Helper()
	if err := os.Remove(filepath.Join(r.stub, "k", ctx, ns, name+".json")); err != nil {
		r.t.Fatal(err)
	}
}

// TestVerifyOperatorPins: check_operator_pins compares the pin of envd, of the gateway, of server.conf and of mgmtd with operator-pub.
func TestVerifyOperatorPins(t *testing.T) {
	t.Parallel()
	other := opPub(opNewKey(t))
	for _, tc := range []struct {
		name   string
		change func(r *revokeRig)
		want   []string // empty: the check passes
	}{
		{name: "every pin holds the key"},
		{name: "a rotation pins both keys", change: func(r *revokeRig) {
			r.put("kind-management", "mgmt-system", "operator-pub", map[string]string{"spec.pub": opPub(r.key), "next.pub": other, "spec.name": r.name})
			r.pinDevCP(other, opPub(r.key))
			r.pinMgmtd(opPub(r.key), other)
		}},
		{name: "a rotation where the gateway pins the old key alone", change: func(r *revokeRig) {
			r.put("kind-management", "mgmt-system", "operator-pub", map[string]string{"spec.pub": opPub(r.key), "next.pub": other, "spec.name": r.name})
			r.pinDevCP(opPub(r.key), other)
			r.pinMgmtd(opPub(r.key), other)
			r.put("kind-dev-cp", "gateway-system", "operator-key", map[string]string{"keys.pub": opPub(r.key) + "\n"})
		}, want: []string{"dev-cp gateway-system/operator-key", "OPERATOR_KEY_ACCEPT_CHANGE=1 CELL=dev-cp mise run cell:up"}},
		{name: "envd pins another key", change: func(r *revokeRig) {
			r.put("kind-dev-cp", "envd-system", "operator-key", map[string]string{"keys.pub": other + "\n"})
		}, want: []string{"dev-cp envd-system/operator-key", "mise run operator:check-key"}},
		{name: "the gateway pins another key", change: func(r *revokeRig) {
			r.put("kind-dev-cp", "gateway-system", "operator-key", map[string]string{"keys.pub": other + "\n"})
		}, want: []string{"dev-cp gateway-system/operator-key"}},
		{name: "server.conf pins another key", change: func(r *revokeRig) {
			r.put("kind-dev-cp", "spire-system", "spire-server", map[string]string{"server.conf": "NodeAttestor \"cluster_jwt\" {\n  plugin_data {\n    operator_public_keys = [\"" + other + "\"]\n  }\n}\n"})
		}, want: []string{"dev-cp spire-system/spire-server operator_public_keys"}},
		{name: "server.conf pins no key while a cell is live", change: func(r *revokeRig) {
			r.put("kind-dev-cp", "spire-system", "spire-server", map[string]string{"server.conf": "NodeAttestor \"cluster_jwt\" {\n  plugin_data {\n  }\n}\n"})
		}, want: []string{"dev-cp spire-system/spire-server operator_public_keys (absent)"}},
		{name: "server.conf holds no cluster_jwt section while no cell is live", change: func(r *revokeRig) {
			r.put("kind-dev-cp", "spire-system", "spire-server", map[string]string{"server.conf": "plugins {\n  NodeAttestor \"k8s_psat\" {\n  }\n}\n"})
		}},
		{name: "mgmtd pins another key", change: func(r *revokeRig) { r.pinMgmtd(other) },
			want: []string{"management mgmt-system/operator-key", "OPERATOR_KEY_ACCEPT_CHANGE=1 CELL=management LINK_ONLY=mgmt-api mise run cell:link"}},
		{name: "the pin of envd is absent", change: func(r *revokeRig) { r.remove("kind-dev-cp", "envd-system", "operator-key") },
			want: []string{"dev-cp envd-system/operator-key (absent)"}},
		{name: "operator-pub is absent", change: func(r *revokeRig) { r.remove("kind-management", "mgmt-system", "operator-pub") },
			want: []string{"operator-pub is absent", "mise run operator:create-key"}},
		{name: "management does not answer", change: func(*revokeRig) {}, want: []string{"could not read ConfigMap mgmt-system/operator-pub"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRevokeRig(t)
			var env []string
			if tc.name == "management does not answer" {
				env = []string{"STUB_DOWN=kind-management"}
			}
			if tc.change != nil {
				tc.change(r)
			}
			out, code := r.runCheck("check_operator_pins", env...)
			if len(tc.want) == 0 {
				if code != 0 {
					t.Fatalf("the check fails on %s: exit %d\n%s", tc.name, code, out)
				}
				return
			}
			if code == 0 {
				t.Fatalf("the check passes though %s", tc.name)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output %q lacks %q", out, w)
				}
			}
		})
	}
}

// TestVerifyOperatorPinsNamesOnlyTheDifferingPins: one wrong pin is the only name in the failure.
func TestVerifyOperatorPinsNamesOnlyTheDifferingPins(t *testing.T) {
	t.Parallel()
	r := newRevokeRig(t)
	r.put("kind-dev-cp", "envd-system", "operator-key", map[string]string{"keys.pub": opPub(opNewKey(t)) + "\n"})
	out, code := r.runCheck("check_operator_pins")
	if code == 0 || !strings.Contains(out, "dev-cp envd-system/operator-key") {
		t.Fatalf("exit %d, output %q", code, out)
	}
	for _, name := range []string{"gateway-system", "operator_public_keys", "mgmt-system/operator-key"} {
		if strings.Contains(out, name) {
			t.Errorf("output names the pin %s that holds the right key: %s", name, out)
		}
	}
}

func writePod(r *revokeRig, body string) {
	r.t.Helper()
	dir := filepath.Join(r.stub, "k", "kind-dev-cp", "spire-system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pod-spire-server-0.json"), []byte(body), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// TestVerifyAgentBan: with a live cell, the container agent-ban in spire-server-0 of dev-cp must be present, Ready and at restart count 0. With
// no live cell the render leaves the container out, and a present container must still be Ready.
func TestVerifyAgentBan(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		pod  string // empty: no pod
		env  []string
		want []string
	}{
		{name: "ready with no restart", pod: statusPod(true, 0)},
		{name: "not ready", pod: statusPod(false, 0), want: []string{"ready=false", "restart count 0", "logs spire-server-0 -c agent-ban"}},
		{name: "ready after a restart", pod: statusPod(true, 2), want: []string{"ready=true", "restart count 2"}},
		{name: "absent container", pod: `{"status":{"containerStatuses":[{"name":"spire-server","ready":true,"restartCount":0}]}}`, want: []string{"no container agent-ban", "CELL=dev-cp mise run cell:up"}},
		{name: "absent container with no live cell", pod: `{"status":{"containerStatuses":[{"name":"spire-server","ready":true,"restartCount":0}]}}`, env: []string{"STUB_KIND=management dev-cp rogue"}},
		{name: "absent container when kind fails", pod: `{"status":{"containerStatuses":[{"name":"spire-server","ready":true,"restartCount":0}]}}`, env: []string{"STUB_KIND_FAIL=1", "KIND_CLUSTERS_PAUSE=0"}, want: []string{"cluster"}},
		{name: "not ready with no live cell", pod: statusPod(false, 0), env: []string{"STUB_KIND=management dev-cp rogue"}, want: []string{"ready=false", "restart count 0"}},
		{name: "another container that restarted", pod: `{"status":{"containerStatuses":[{"name":"spire-server","ready":true,"restartCount":4},{"name":"agent-ban","ready":true,"restartCount":0}]}}`},
		{name: "no pod", want: []string{"could not read pod spire-server-0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRevokeRig(t)
			if tc.pod != "" {
				writePod(r, tc.pod)
			}
			out, code := r.runCheck("check_agent_ban", tc.env...)
			if len(tc.want) == 0 {
				if code != 0 {
					t.Fatalf("the check fails: exit %d\n%s", code, out)
				}
				return
			}
			if code == 0 {
				t.Fatalf("the check passes though %s", tc.name)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output %q lacks %q", out, w)
				}
			}
		})
	}
}

// TestVerifyOverlayInputs: every key of local-revocations must hold an entry that one of the pinned operator keys signed, for this env,
// under the key <id>.json. The check runs the real operatorctl verify.
func TestVerifyOverlayInputs(t *testing.T) {
	t.Parallel()
	next := opNewKey(t)
	signed := func(r *revokeRig, key ed25519.PrivateKey, env string) (string, string) {
		id := "00112233445566" + map[string]string{"dev": "77", "prod": "88"}[env]
		b, err := revoke.Sign(revoke.Entry{ID: id, Env: env, Cell: "dev-cell-2", Record: spec.Revision{Epoch: 2, Counter: 5}, IssuedAt: time.Now().UTC().Truncate(time.Second)}, key)
		if err != nil {
			t.Fatal(err)
		}
		return id, string(b)
	}
	for _, tc := range []struct {
		name  string
		setup func(r *revokeRig)
		want  []string
	}{
		{name: "no ConfigMap", setup: func(*revokeRig) {}},
		{name: "an entry of the pinned key", setup: func(r *revokeRig) {
			id, e := signed(r, r.key, "dev")
			r.put("kind-dev-cp", "envd-system", "local-revocations", map[string]string{id + ".json": e})
		}},
		{name: "an entry of the next key during a rotation", setup: func(r *revokeRig) {
			r.pinDevCP(opPub(r.key), opPub(next))
			id, e := signed(r, next, "dev")
			r.put("kind-dev-cp", "envd-system", "local-revocations", map[string]string{id + ".json": e})
		}},
		{name: "an entry of a key that is not pinned", setup: func(r *revokeRig) {
			id, e := signed(r, next, "dev")
			r.put("kind-dev-cp", "envd-system", "local-revocations", map[string]string{id + ".json": e})
		}, want: []string{"00112233445566" + "77.json", "does not verify", "mise run revoke -- local --cell <cell>"}},
		{name: "an entry for another env", setup: func(r *revokeRig) {
			id, e := signed(r, r.key, "prod")
			r.put("kind-dev-cp", "envd-system", "local-revocations", map[string]string{id + ".json": e})
		}, want: []string{"names the env prod"}},
		{name: "an entry under another key", setup: func(r *revokeRig) {
			_, e := signed(r, r.key, "dev")
			r.put("kind-dev-cp", "envd-system", "local-revocations", map[string]string{"other.json": e})
		}, want: []string{"other.json", "not <id>.json"}},
		{name: "a key with no entry", setup: func(r *revokeRig) {
			r.put("kind-dev-cp", "envd-system", "local-revocations", map[string]string{"junk.json": "{"})
		}, want: []string{"junk.json", "does not verify"}},
		{name: "envd pins no key", setup: func(r *revokeRig) {
			r.put("kind-dev-cp", "envd-system", "operator-key", map[string]string{"keys.pub": ""})
			id, e := signed(r, r.key, "dev")
			r.put("kind-dev-cp", "envd-system", "local-revocations", map[string]string{id + ".json": e})
		}, want: []string{"envd pins no operator key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRevokeRig(t)
			tc.setup(r)
			out, code := r.runCheck("check_overlay_inputs")
			if len(tc.want) == 0 {
				if code != 0 {
					t.Fatalf("the check fails: exit %d\n%s", code, out)
				}
				return
			}
			if code == 0 {
				t.Fatalf("the check passes though %s", tc.name)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output %q lacks %q", out, w)
				}
			}
		})
	}
}
