package render

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// pluginEnvRE finds the env setting in the plugin_data of the cluster_jwt NodeAttestor.
var pluginEnvRE = regexp.MustCompile(`(?s)NodeAttestor "cluster_jwt" \{.*?plugin_data \{[^}]*?\benv = "([^"]*)"`)

// pluginEnv returns the env setting of the cluster_jwt plugin in a SPIRE config.
func pluginEnv(t *testing.T, text string) string {
	t.Helper()
	m := pluginEnvRE.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("config has no env in the cluster_jwt plugin_data:\n%s", text)
	}
	return m[1]
}

// TestEnvironmentNameHasOneSource renders the server, the agent and the central view with POC_ENV
// from cells/common.env and with another value. The server plugin, the agent plugin, the record
// signers, the principal --auth pattern and the agent namespaces must follow the variable in both
// cases, so no render holds its own copy of the name.
func TestEnvironmentNameHasOneSource(t *testing.T) {
	for _, env := range []string{commonEnv(t, "POC_ENV"), "other-env"} {
		t.Run(env, func(t *testing.T) {
			server := render(t, "POC_ENV="+env, "SPIRE_AGENT_CELLS=dev-cell-1 dev-cell-2", "SPIRE_CELL_SUBJECTS="+cellEnv(t, "dev-cp", "SPIRE_CELL_SUBJECTS"))
			if server.err != nil {
				t.Fatalf("spire-server render failed: %v\n%s", server.err, server.stderr)
			}
			conf := get[string](t, docs(t, server.stdout)["ConfigMap/spire-server"], "data", "server.conf")
			if got := pluginEnv(t, conf); got != env {
				t.Fatalf("server plugin env is %q, want %q", got, env)
			}
			for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
				want := "run record:fixture -- --cluster " + cell + " --subject cell-identity-system/celld --subject argocd/argocd-agent" +
					" --subject observability-system/otel-uplink --subject mesh-view-system/mesh-view --env " + env
				if !strings.Contains(server.log, want) {
					t.Fatalf("the render did not sign the record of %s for env %s; want %q in:\n%s", cell, env, want, server.log)
				}
			}

			agent := renderCellIdentity(t, "POC_ENV="+env)
			if agent.err != nil {
				t.Fatalf("cell-identity render failed: %v\n%s", agent.err, agent.stderr)
			}
			text := get[string](t, docsIn(t, agent.stdout, "cell-identity-system")["ConfigMap/spire-agent"], "data", "agent.conf")
			if got := pluginEnv(t, text); got != env {
				t.Fatalf("agent plugin env is %q, want %q", got, env)
			}

			// The central view: the --auth pattern, the agent namespaces and the registry --env.
			view := renderCentralView(t, "POC_ENV="+env)
			if view.err != nil {
				t.Fatalf("central-view render failed: %v\n%s", view.err, view.stderr)
			}
			objs := viewDocs(t, view.stdout)
			args := fmt.Sprint(get[[]any](t, named(t, get[[]any](t, principalTemplate(t, objs), "spec", "containers"), "argocd-agent-principal"), "args"))
			for _, want := range []string{"--auth=header:x-cell-agent:^(" + strings.ReplaceAll(env, ".", `\.`) + "-[a-z0-9-]{1,59})$",
				"--allowed-namespaces=" + env + "-dev-cell-1," + env + "-dev-cell-2"} {
				if !strings.Contains(args, want) {
					t.Fatalf("principal args %s lack %s", args, want)
				}
			}
			for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
				if objs["Namespace "+env+"-"+cell] == nil {
					t.Fatalf("the view renders no agent namespace %s-%s", env, cell)
				}
				if want := "run record:fixture -- --cluster " + cell + " --env " + env; !strings.Contains(view.log, want) {
					t.Fatalf("the view did not sign the record of %s for env %s; want %q in:\n%s", cell, env, want, view.log)
				}
			}
		})
	}
}

// cellEnv returns the value of a setting in cells/<cluster>.env, without its quotes.
func cellEnv(t *testing.T, cluster, name string) string {
	t.Helper()
	data, err := os.ReadFile("../../cells/" + cluster + ".env")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, name+"="); ok {
			return strings.Trim(v, `"`)
		}
	}
	t.Fatalf("cells/%s.env sets no %s", cluster, name)
	return ""
}
