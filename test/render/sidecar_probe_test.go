package render

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"sigs.k8s.io/yaml"

	"github.com/joshwrightcodes/cell-identity-poc/internal/testtool"
)

// These tests pin the liveness probe that the istiod injection settings add to istio-proxy. After a long pause of the VM, istio-agent
// misses its renewal timer and serves an expired workload certificate. The probe reads the wall-clock gauge of the agent and fails
// when less than 2 hours remain, so the kubelet restarts the container and the agent fetches a new certificate. The pod stays.

const certProbeTemplate = "cert-liveness"

// injectorConfig is the config of the injector ConfigMap.
type injectorConfig struct {
	DefaultTemplates []string          `json:"defaultTemplates"`
	Templates        map[string]string `json:"templates"`
}

// injectorConfigs returns the injector config in the istiod render of each cluster.
func injectorConfigs(t *testing.T) map[string]injectorConfig {
	t.Helper()
	out := map[string]injectorConfig{}
	for _, cr := range renderAll(t) {
		for _, c := range cr.components {
			if c.name != "istiod" {
				continue
			}
			for _, o := range c.objs {
				if o["kind"] != "ConfigMap" || lookupOr(o, "metadata", "name") != "istio-sidecar-injector" {
					continue
				}
				raw, _ := lookupOr(o, "data", "config").(string)
				var cfg injectorConfig
				if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
					t.Fatalf("%s: the injector config does not parse: %v", cr.name, err)
				}
				out[cr.name] = cfg
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no render holds the ConfigMap istio-sidecar-injector")
	}
	return out
}

// applyCertTemplate runs the template as the injector does for one default template: it renders the text with the pod data and merges
// the result into the pod with a strategic merge patch against corev1.Pod (pkg/kube/inject applyOverlayYAML).
func applyCertTemplate(t *testing.T, text string, native bool, base corev1.Pod) corev1.Pod {
	t.Helper()
	tpl, err := template.New("inject").Funcs(template.FuncMap{
		"default": func(def, v any) any {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
			return def
		},
	}).Parse(text)
	if err != nil {
		t.Fatalf("the template does not parse: %v", err)
	}
	var buf bytes.Buffer
	data := map[string]any{"ObjectMeta": map[string]any{"Annotations": map[string]string{}}, "NativeSidecars": native}
	if err := tpl.Execute(&buf, data); err != nil {
		t.Fatalf("the template does not run: %v", err)
	}
	overlay, err := yaml.YAMLToJSON(buf.Bytes())
	if err != nil {
		t.Fatalf("the template output is not YAML: %v\n%s", err, buf.String())
	}
	orig, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := strategicpatch.StrategicMergePatch(orig, overlay, corev1.Pod{})
	if err != nil {
		t.Fatalf("the merge fails: %v", err)
	}
	var pod corev1.Pod
	if err := json.Unmarshal(merged, &pod); err != nil {
		t.Fatal(err)
	}
	return pod
}

// TestSidecarCertLivenessProbe: every cluster lists the template in defaultTemplates after sidecar, and the template adds the probe to
// istio-proxy both as a native sidecar (initContainers, restartPolicy Always) and as a regular container. The merge keeps the fields that
// the sidecar template set.
func TestSidecarCertLivenessProbe(t *testing.T) {
	testtool.Need(t, "yq", "jq", "helm", "kustomize", "bash", "tar", "go")
	for cluster, cfg := range injectorConfigs(t) {
		if got := strings.Join(cfg.DefaultTemplates, ","); got != "sidecar,"+certProbeTemplate {
			t.Errorf("%s: defaultTemplates is %q, want sidecar,%s", cluster, got, certProbeTemplate)
		}
		text, ok := cfg.Templates[certProbeTemplate]
		if !ok {
			t.Errorf("%s: the injector has no template %s", cluster, certProbeTemplate)
			continue
		}
		always := corev1.ContainerRestartPolicyAlways
		proxy := func() corev1.Container {
			return corev1.Container{Name: "istio-proxy", Image: "docker.io/istio/proxyv2:1.30.8", RestartPolicy: nil,
				ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz/ready"}}}}
		}
		native := proxy()
		native.RestartPolicy = &always
		forms := []struct {
			name   string
			native bool
			base   corev1.Pod
			find   func(p corev1.Pod) (corev1.Container, bool)
		}{
			{"native sidecar", true, corev1.Pod{Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "istio-validation", Image: "v"}, native},
				Containers:     []corev1.Container{{Name: "app", Image: "a"}}}},
				func(p corev1.Pod) (corev1.Container, bool) {
					return findContainer(p.Spec.InitContainers, "istio-proxy")
				}},
			{"regular sidecar", false, corev1.Pod{Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "istio-validation", Image: "v"}},
				Containers:     []corev1.Container{{Name: "app", Image: "a"}, proxy()}}},
				func(p corev1.Pod) (corev1.Container, bool) { return findContainer(p.Spec.Containers, "istio-proxy") }},
		}
		for _, f := range forms {
			pod := applyCertTemplate(t, text, f.native, f.base)
			c, ok := f.find(pod)
			if !ok {
				t.Errorf("%s, %s: istio-proxy is missing after the merge", cluster, f.name)
				continue
			}
			p := c.LivenessProbe
			if p == nil || p.Exec == nil {
				t.Errorf("%s, %s: istio-proxy has no exec liveness probe", cluster, f.name)
				continue
			}
			script := strings.Join(p.Exec.Command, " ")
			for _, want := range []string{"istio_agent_cert_expiry_seconds", "localhost:15020", "7200"} {
				if !strings.Contains(script, want) {
					t.Errorf("%s, %s: the probe command lacks %q: %s", cluster, f.name, want, script)
				}
			}
			if p.PeriodSeconds != 60 || p.FailureThreshold != 2 || p.TimeoutSeconds != 5 {
				t.Errorf("%s, %s: probe period/failureThreshold/timeout are %d/%d/%d, want 60/2/5", cluster, f.name, p.PeriodSeconds, p.FailureThreshold, p.TimeoutSeconds)
			}
			if c.Image != "docker.io/istio/proxyv2:1.30.8" || c.ReadinessProbe == nil {
				t.Errorf("%s, %s: the merge dropped fields of the sidecar template: %+v", cluster, f.name, c)
			}
			if f.native && (c.RestartPolicy == nil || *c.RestartPolicy != always) {
				t.Errorf("%s, %s: the merge lost restartPolicy Always", cluster, f.name)
			}
			if got := len(pod.Spec.InitContainers) + len(pod.Spec.Containers); got != len(f.base.Spec.InitContainers)+len(f.base.Spec.Containers) {
				t.Errorf("%s, %s: the merge changed the container count to %d", cluster, f.name, got)
			}
		}
	}
}

func findContainer(list []corev1.Container, name string) (corev1.Container, bool) {
	for _, c := range list {
		if c.Name == name {
			return c, true
		}
	}
	return corev1.Container{}, false
}

// TestSidecarCertLivenessCommand runs the probe command with a stub curl that prints agent metrics. It fails only with a certificate that has
// less than the minimum left, and it passes when the agent shows no metric yet or does not answer, so start-up and an island with istiod down
// never restart the container.
func TestSidecarCertLivenessCommand(t *testing.T) {
	testtool.Need(t, "yq", "jq", "helm", "kustomize", "bash", "tar", "go", "sh", "awk")
	var command []string
	for _, cfg := range injectorConfigs(t) {
		pod := applyCertTemplate(t, cfg.Templates[certProbeTemplate], true, corev1.Pod{Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "istio-proxy", Image: "i"}}}})
		if len(pod.Spec.InitContainers) == 1 && pod.Spec.InitContainers[0].LivenessProbe != nil && pod.Spec.InitContainers[0].LivenessProbe.Exec != nil {
			command = pod.Spec.InitContainers[0].LivenessProbe.Exec.Command
		}
		break
	}
	if len(command) == 0 {
		t.Fatal("the template sets no exec probe command")
	}
	dir := t.TempDir()
	stub := "#!/bin/sh\n[ \"$STUB_CURL_FAIL\" = 1 ] && exit 7\nprintf '%s' \"$STUB_METRICS\"\n"
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	other := "# TYPE istio_agent_cert_expiry_seconds gauge\nistio_agent_cert_expiry_seconds{resource_name=\"ROOTCA\"} 10\nistio_agent_process_start_time 1\n"
	for _, tc := range []struct {
		name, metrics string
		curlFail      bool
		env           []string
		wantOK        bool
	}{
		{"a fresh certificate", other + "istio_agent_cert_expiry_seconds{resource_name=\"default\"} 82989.6\n", false, nil, true},
		{"a value in scientific notation", "istio_agent_cert_expiry_seconds{resource_name=\"default\"} 8.29896e+04\n", false, nil, true},
		{"1 hour left", "istio_agent_cert_expiry_seconds{resource_name=\"default\"} 3600\n", false, nil, false},
		{"just under 2 hours", "istio_agent_cert_expiry_seconds{resource_name=\"default\"} 7199\n", false, nil, false},
		{"just over 2 hours", "istio_agent_cert_expiry_seconds{resource_name=\"default\"} 7201\n", false, nil, true},
		{"an expired certificate", "istio_agent_cert_expiry_seconds{resource_name=\"default\"} -19000.5\n", false, nil, false},
		{"no default metric yet, as at start-up", other, false, nil, true},
		{"the agent does not answer", "", true, nil, true},
		{"a lower minimum from the environment", "istio_agent_cert_expiry_seconds{resource_name=\"default\"} 3600\n", false, []string{"CERT_MIN_SECONDS=600"}, true},
		{"a higher minimum from the environment", "istio_agent_cert_expiry_seconds{resource_name=\"default\"} 82989\n", false, []string{"CERT_MIN_SECONDS=90000"}, false},
	} {
		cmd := exec.Command(command[0], command[1:]...)
		fail := "0"
		if tc.curlFail {
			fail = "1"
		}
		cmd.Env = append([]string{"PATH=" + dir + string(os.PathListSeparator) + "/usr/bin:/bin", "STUB_METRICS=" + tc.metrics, "STUB_CURL_FAIL=" + fail}, tc.env...)
		out, err := cmd.CombinedOutput()
		if (err == nil) != tc.wantOK {
			t.Errorf("%s: probe ok=%v (%v), want %v\n%s", tc.name, err == nil, err, tc.wantOK, out)
		}
	}
}
