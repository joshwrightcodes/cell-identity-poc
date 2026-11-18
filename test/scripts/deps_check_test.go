package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// depsGo stands in for go in deps-check.sh. It answers only `go list`: the binary listing of ./cmd/... from
// $STUB_DIR/deps-<GOOS>-<GOARCH>, else $STUB_DIR/deps, and the import listing of ./... with the e2e tag from
// $STUB_DIR/imports-<GOOS>-<GOARCH>, else $STUB_DIR/imports. The file $STUB_DIR/fail-deps or fail-imports makes that
// listing fail. It records each call with the platform variables.
const depsGo = `#!/usr/bin/env bash
echo "go $* GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=$CGO_ENABLED" >>"$STUB_DIR/calls"
[[ "$1" == list ]] || { echo "unexpected go call: $*" >&2; exit 2; }
case " $* " in
  *" -tags e2e "*" ./... "*) f=imports ;;
  *" ./cmd/... "*) f=deps ;;
  *) echo "unexpected go call: $*" >&2; exit 2 ;;
esac
[[ -e "$STUB_DIR/fail-$f" ]] && { echo "go: listing failed" >&2; exit 1; }
p="$STUB_DIR/$f-$GOOS-$GOARCH"
[[ -e "$p" ]] || p="$STUB_DIR/$f"
cat "$p"
`

const (
	depsModule = "github.com/joshwrightcodes/cell-identity-poc"
	depsOPA    = "github.com/open-policy-agent/opa"
)

// cleanDeps is a binary listing that keeps every rule: celld and envd compile OPA, including the internal wasm capability
// package and the in-memory store, and no binary compiles a Prometheus package.
func cleanDeps() []string {
	m := depsModule
	return []string{
		m + "/cmd/celld errors fmt " + depsOPA + "/v1/rego " + depsOPA + "/v1/ast go.opentelemetry.io/otel " + m + "/internal/bundleapply",
		m + "/cmd/envd errors " + depsOPA + "/v1/rego " + depsOPA + "/internal/wasm/sdk/opa/capabilities " + depsOPA + "/v1/storage/inmem",
		m + "/cmd/mgmtd errors go.opentelemetry.io/otel/sdk/metric github.com/prometheusx/other",
		m + "/cmd/cellgw errors modernc.org/sqlite",
	}
}

// cleanImports is an import listing that keeps every rule: only internal/bundleapply and its subpackages import OPA.
func cleanImports() []string {
	m := depsModule
	return []string{
		m + "/internal/bundleapply context " + depsOPA + "/v1/rego " + depsOPA + "/v1/ast testing",
		m + "/internal/bundleapply/policy embed " + depsOPA + "/v1/ast",
		m + "/internal/mgmt context",
		m + "/internal/empty",
		m + "/test/e2e testing",
	}
}

func runDepsCheck(t *testing.T, files map[string][]string, env ...string) (stdout, stderr, calls string, code int) {
	t.Helper()
	dir := t.TempDir()
	for name, lines := range files {
		body := strings.Join(lines, "\n")
		if lines != nil {
			body += "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stdout, stderr, code = runScript(t, "deps-check.sh", map[string]string{"go": depsGo}, append([]string{"STUB_DIR=" + dir}, env...))
	b, _ := os.ReadFile(filepath.Join(dir, "calls"))
	return stdout, stderr, string(b), code
}

func wantLines(t *testing.T, text string, want, deny []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("output lacks %q:\n%s", w, text)
		}
	}
	for _, d := range deny {
		if strings.Contains(text, d) {
			t.Errorf("output holds %q:\n%s", d, text)
		}
	}
}

// TestDepsCheckClean: listings that keep every rule pass. The script lists the binaries and the imports with the e2e tag
// for linux/arm64 with cgo off and for darwin/arm64 with cgo on, and prints the count of binary listings.
func TestDepsCheckClean(t *testing.T) {
	stdout, stderr, calls, code := runDepsCheck(t, map[string][]string{"deps": cleanDeps(), "imports": cleanImports()})
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, want exit 0 and no stderr", code, stderr)
	}
	wantLines(t, stdout, []string{"deps-check: ok, 8 binary listings on linux/arm64 darwin/arm64"}, nil)
	wantLines(t, calls, []string{
		"go list -f {{.ImportPath}}{{range .Deps}} {{.}}{{end}} ./cmd/... GOOS=linux GOARCH=arm64 CGO_ENABLED=0",
		"go list -f {{.ImportPath}}{{range .Deps}} {{.}}{{end}} ./cmd/... GOOS=darwin GOARCH=arm64 CGO_ENABLED=1",
		"go list -tags e2e -f {{.ImportPath}}{{range .Imports}} {{.}}{{end}}{{range .TestImports}} {{.}}{{end}}{{range .XTestImports}} {{.}}{{end}} ./... GOOS=linux GOARCH=arm64 CGO_ENABLED=0",
		"./... GOOS=darwin GOARCH=arm64 CGO_ENABLED=1",
	}, nil)
	if n := strings.Count(calls, "\n"); n != 4 {
		t.Errorf("%d go calls, want 4:\n%s", n, calls)
	}
}

// TestDepsCheckPrometheus: a binary that compiles a github.com/prometheus/ package fails with one line that names the
// binary, the package and the platform. Each platform is checked on its own.
func TestDepsCheckPrometheus(t *testing.T) {
	prom := depsModule + "/cmd/cellgw errors github.com/prometheus/client_golang/prometheus github.com/prometheus/common/expfmt"
	t.Run("both platforms", func(t *testing.T) {
		_, stderr, _, code := runDepsCheck(t, map[string][]string{"deps": append(cleanDeps(), prom), "imports": cleanImports()})
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, stderr)
		}
		wantLines(t, stderr, []string{
			"deps-check: prometheus: cellgw compiles github.com/prometheus/client_golang/prometheus (linux/arm64)",
			"deps-check: prometheus: cellgw compiles github.com/prometheus/client_golang/prometheus (darwin/arm64)",
			"deps-check: 2 rule failures",
		}, []string{"mgmtd", "expfmt"})
	})
	t.Run("darwin only", func(t *testing.T) {
		_, stderr, _, code := runDepsCheck(t, map[string][]string{"deps": cleanDeps(), "deps-darwin-arm64": append(cleanDeps(), prom), "imports": cleanImports()})
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, stderr)
		}
		wantLines(t, stderr, []string{"prometheus: cellgw compiles github.com/prometheus/client_golang/prometheus (darwin/arm64)", "1 rule failures"},
			[]string{"(linux/arm64)"})
	})
}

// TestDepsCheckOpaSDK: an import of opa/v1/sdk, opa/v1/plugins, opa/v1/runtime or opa/v1/storage/disk fails, even in
// internal/bundleapply, and so does a binary that compiles one of them or a package below one of them.
func TestDepsCheckOpaSDK(t *testing.T) {
	for _, pkg := range []string{"v1/sdk", "v1/plugins", "v1/runtime", "v1/storage/disk"} {
		t.Run("import of "+pkg, func(t *testing.T) {
			imports := append(cleanImports(), depsModule+"/internal/bundleapply/engine context "+depsOPA+"/"+pkg)
			_, stderr, _, code := runDepsCheck(t, map[string][]string{"deps": cleanDeps(), "imports": imports})
			if code != 1 {
				t.Fatalf("exit %d, want 1:\n%s", code, stderr)
			}
			wantLines(t, stderr, []string{
				"deps-check: opa_forbidden: internal/bundleapply/engine imports " + depsOPA + "/" + pkg + " (linux/arm64)",
				"deps-check: opa_forbidden: internal/bundleapply/engine imports " + depsOPA + "/" + pkg + " (darwin/arm64)",
				"deps-check: 2 rule failures",
			}, []string{"opa_outside"})
		})
	}
	t.Run("a binary compiles a package below v1/plugins", func(t *testing.T) {
		deps := cleanDeps()
		deps[0] += " " + depsOPA + "/v1/plugins/bundle"
		_, stderr, _, code := runDepsCheck(t, map[string][]string{"deps": deps, "imports": cleanImports()})
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, stderr)
		}
		wantLines(t, stderr, []string{"deps-check: opa_forbidden: celld compiles " + depsOPA + "/v1/plugins/bundle (linux/arm64)"},
			[]string{"opa_outside"})
	})
	t.Run("a name that only starts like a forbidden package", func(t *testing.T) {
		imports := append(cleanImports(), depsModule+"/internal/bundleapply/engine "+depsOPA+"/v1/sdkutil "+depsOPA+"/v1/storage/diskless")
		_, stderr, _, code := runDepsCheck(t, map[string][]string{"deps": cleanDeps(), "imports": imports})
		if code != 0 {
			t.Fatalf("exit %d, want 0:\n%s", code, stderr)
		}
	})
}

// TestDepsCheckOpaOutsideAppliers: a binary other than celld and envd that compiles an OPA package fails with one line for
// each platform. celld and envd may compile OPA.
func TestDepsCheckOpaOutsideAppliers(t *testing.T) {
	deps := cleanDeps()
	deps[2] += " " + depsOPA + "/v1/rego " + depsOPA + "/v1/ast"
	_, stderr, _, code := runDepsCheck(t, map[string][]string{"deps": deps, "imports": cleanImports()})
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, stderr)
	}
	wantLines(t, stderr, []string{
		"deps-check: opa_outside_appliers: mgmtd compiles " + depsOPA + "/v1/rego (linux/arm64)",
		"deps-check: opa_outside_appliers: mgmtd compiles " + depsOPA + "/v1/rego (darwin/arm64)",
		"deps-check: 2 rule failures",
	}, []string{"celld", "envd"})
}

// TestDepsCheckOpaOutsideBundleapply: a package outside internal/bundleapply that imports an OPA package fails, a test
// import counts, and a sibling whose name only starts with bundleapply is outside.
func TestDepsCheckOpaOutsideBundleapply(t *testing.T) {
	for _, tc := range []struct{ name, pkg string }{
		{"internal/mgmt", "internal/mgmt"},
		{"an e2e test", "test/e2e"},
		{"a sibling package", "internal/bundleapplyx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imports := append(cleanImports(), depsModule+"/"+tc.pkg+" context testing "+depsOPA+"/v1/ast")
			_, stderr, _, code := runDepsCheck(t, map[string][]string{"deps": cleanDeps(), "imports": imports})
			if code != 1 {
				t.Fatalf("exit %d, want 1:\n%s", code, stderr)
			}
			wantLines(t, stderr, []string{
				"deps-check: opa_outside_bundleapply: " + tc.pkg + " imports " + depsOPA + "/v1/ast (linux/arm64)",
				"deps-check: 2 rule failures",
			}, []string{"opa_forbidden"})
		})
	}
}

// TestDepsCheckGoListFails: a failed listing, or a listing with no binary, exits 2 and names the cause, so a broken
// toolchain never passes the lint.
func TestDepsCheckGoListFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string][]string
		want  string
	}{
		{"binary listing", map[string][]string{"fail-deps": nil, "imports": cleanImports()}, "deps-check: go list of ./cmd/... failed for linux/arm64"},
		{"import listing", map[string][]string{"deps": cleanDeps(), "fail-imports": nil}, "deps-check: go list of ./... failed for linux/arm64"},
		{"no binary", map[string][]string{"deps": nil, "imports": cleanImports()}, "deps-check: go list found no binary in ./cmd/..."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, _, code := runDepsCheck(t, tc.files)
			if code != 2 || stdout != "" {
				t.Fatalf("exit %d, stdout %q, want exit 2 and no stdout:\n%s", code, stdout, stderr)
			}
			wantLines(t, stderr, []string{tc.want}, nil)
		})
	}
}
