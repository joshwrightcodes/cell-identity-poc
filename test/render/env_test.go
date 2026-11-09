package render

import (
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

// TestEnvironmentNameHasOneSource renders the server and the agent with POC_ENV from
// cells/common.env and with another value. The server plugin, the agent plugin and the record
// signer must follow the variable in both cases, so no render holds its own copy of the name.
func TestEnvironmentNameHasOneSource(t *testing.T) {
	for _, env := range []string{commonEnv(t, "POC_ENV"), "other-env"} {
		t.Run(env, func(t *testing.T) {
			server := render(t, "POC_ENV="+env, "SPIRE_AGENT_CELLS=dev-cell-1 dev-cell-2")
			if server.err != nil {
				t.Fatalf("spire-server render failed: %v\n%s", server.err, server.stderr)
			}
			conf := get[string](t, docs(t, server.stdout)["ConfigMap/spire-server"], "data", "server.conf")
			if got := pluginEnv(t, conf); got != env {
				t.Fatalf("server plugin env is %q, want %q", got, env)
			}
			for _, cell := range []string{"dev-cell-1", "dev-cell-2"} {
				want := "run record:fixture -- --cluster " + cell + " --subject cell-identity-system/celld --env " + env
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
		})
	}
}
