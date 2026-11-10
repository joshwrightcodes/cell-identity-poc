package render

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
)

// guardAudiencePattern is the audience pattern that the view guard of one environment holds. It
// follows clusterjwt.Audience and clusterjwt.MaxNonceLength.
func guardAudiencePattern(env string) string {
	return fmt.Sprintf("^%s[A-Za-z0-9_-]{1,%d}$", clusterjwt.Audience(env, ""), clusterjwt.MaxNonceLength)
}

// TestRenderAgentGuard renders the view guard with the default environment and with another one.
// The policy covers every write, delete and connect request of the agent ServiceAccount, the
// binding denies, and the audience pattern follows the environment and the nonce limit of the
// plugin.
func TestRenderAgentGuard(t *testing.T) {
	for _, env := range []string{commonEnv(t, "POC_ENV"), "other-env"} {
		t.Run(env, func(t *testing.T) {
			r := renderAgent(t, "dev-cell-1", "POC_ENV="+env)
			if r.err != nil {
				t.Fatalf("render failed: %v\n%s", r.err, r.stderr)
			}
			objs := objectsIn(t, strings.ReplaceAll(r.stdout, "@CELL_NAME@", "dev-cell-1"))
			policy := objs["ValidatingAdmissionPolicy argocd-agent-read-only"]
			binding := objs["ValidatingAdmissionPolicyBinding argocd-agent-read-only"]
			if policy == nil || binding == nil {
				t.Fatalf("the render holds no policy or no binding: %v", keysOfObjects(objs))
			}
			for key, o := range map[string]object{"policy": policy, "binding": binding} {
				if v, _ := lookup(o, "metadata", "labels", "cell.poc.internal/harness"); v != "argocd-agent" {
					t.Errorf("the %s has no harness label argocd-agent", key)
				}
			}
			if got := fmt.Sprint(lookupOr(binding, "spec", "validationActions")); got != "[Deny]" {
				t.Errorf("the binding actions are %s, want [Deny]", got)
			}
			if got := lookupOr(binding, "spec", "policyName"); got != "argocd-agent-read-only" {
				t.Errorf("the binding names the policy %v", got)
			}
			if _, ok := lookup(binding, "spec", "matchResources"); ok {
				t.Error("the binding narrows the policy with matchResources, want the whole cluster")
			}
			if got := lookupOr(policy, "spec", "failurePolicy"); got != "Fail" {
				t.Errorf("failurePolicy is %v, want Fail", got)
			}
			rules := get[[]any](t, policy, "spec", "matchConstraints", "resourceRules")
			if len(rules) != 1 {
				t.Fatalf("the policy has %d resource rules, want 1", len(rules))
			}
			for field, want := range map[string]string{"apiGroups": "[*]", "apiVersions": "[*]", "resources": "[*/*]", "operations": "[CREATE UPDATE DELETE CONNECT]"} {
				if got := fmt.Sprint(lookupOr(rules[0], field)); got != want {
					t.Errorf("resourceRules %s is %s, want %s", field, got, want)
				}
			}
			cond := get[[]any](t, policy, "spec", "matchConditions")
			if len(cond) != 1 || lookupOr(cond[0], "expression") != `request.userInfo.username == "system:serviceaccount:argocd:argocd-agent"` {
				t.Errorf("match conditions %v, want the agent ServiceAccount only", cond)
			}
			validations := get[[]any](t, policy, "spec", "validations")
			if len(validations) != 3 {
				t.Fatalf("the policy has %d validations, want 3", len(validations))
			}
			expr := func(i int) string { return get[string](t, validations[i], "expression") }
			if expr(0) != "!(request.operation in ['DELETE', 'CONNECT'])" || expr(1) != "request.operation != 'UPDATE'" {
				t.Errorf("the delete, connect and update validations are %q and %q", expr(0), expr(1))
			}
			token := expr(2)
			if !strings.HasPrefix(token, "request.operation != 'CREATE' || (") {
				t.Errorf("the create validation does not start with a CREATE test: %s", token)
			}
			if want := "matches('" + guardAudiencePattern(env) + "')"; !strings.Contains(token, want) {
				t.Errorf("the create validation lacks %s:\n%s", want, token)
			}
			for _, clause := range []string{
				"request.resource.group == ''", "request.resource.resource == 'serviceaccounts'", "request.subResource == 'token'",
				"request.namespace == 'argocd'", "request.name == 'argocd-agent'", "object.spec.audiences.size() == 1",
				"object.spec.boundObjectRef.kind == 'Pod'",
				"request.userInfo.extra['authentication.kubernetes.io/pod-name'] == [object.spec.boundObjectRef.name]",
				"request.userInfo.extra['authentication.kubernetes.io/pod-uid'] == [object.spec.boundObjectRef.uid]",
			} {
				if !strings.Contains(token, clause) {
					t.Errorf("the create validation lacks %q", clause)
				}
			}
			if strings.Contains(token, "@POC_ENV@") || strings.Contains(r.stdout, "@POC_ENV@") {
				t.Error("the render leaves @POC_ENV@ in place")
			}
			for _, v := range validations {
				if lookupOr(v, "reason") != "Forbidden" {
					t.Errorf("a validation has the reason %v, want Forbidden", lookupOr(v, "reason"))
				}
			}
		})
	}
}

// TestGuardPatternMatchesPluginAudience checks the pattern against the audience of the plugin, for
// a nonce at the limit and one byte over it.
func TestGuardPatternMatchesPluginAudience(t *testing.T) {
	re := regexp.MustCompile(guardAudiencePattern("dev"))
	for nonce, want := range map[string]bool{
		"abc_DEF-123": true,
		strings.Repeat("a", clusterjwt.MaxNonceLength):   true,
		strings.Repeat("a", clusterjwt.MaxNonceLength+1): false,
		"": false, "a.b": false, "a/b": false,
	} {
		if got := re.MatchString(clusterjwt.Audience("dev", nonce)); got != want {
			t.Errorf("nonce of %d bytes %q: match %v, want %v", len(nonce), nonce[:min(len(nonce), 12)], got, want)
		}
		if got := clusterjwt.ValidNonce(nonce); got != want {
			t.Errorf("ValidNonce(%q) = %v, want %v", nonce[:min(len(nonce), 12)], got, want)
		}
	}
	if re.MatchString(clusterjwt.Audience("other", "abc")) {
		t.Error("the pattern of dev matches an audience of another environment")
	}
}
