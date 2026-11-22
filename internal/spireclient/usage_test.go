package spireclient

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestClientsUseSharedOptions fails on a Workload API client built without
// the shared options. The one-shot FetchX509SVIDs in whoami is not a watcher.
func TestClientsUseSharedOptions(t *testing.T) {
	guarded := map[string]bool{"NewX509Source": true, "NewJWTSource": true, "WatchX509Context": true, "NewClient": true}
	fset := token.NewFileSet()
	for _, root := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
				strings.Contains(filepath.ToSlash(path), "internal/spireclient/") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !guarded[sel.Sel.Name] {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "workloadapi" {
					return true
				}
				found := false
				for _, a := range call.Args {
					ast.Inspect(a, func(m ast.Node) bool {
						if id, ok := m.(*ast.Ident); ok && id.Name == "spireclient" {
							found = true
						}
						return !found
					})
				}
				if !found {
					t.Errorf("%s: workloadapi.%s without spireclient options", fset.Position(call.Pos()), sel.Sel.Name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
