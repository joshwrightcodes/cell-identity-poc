package dashboards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Instrument is one OTel instrument call in the Go source.
type Instrument struct {
	Name string
	Kind string
	Unit string
	Pos  string
}

// instrumentKinds maps the Meter method names to a Kind.
var instrumentKinds = map[string]string{
	"Int64Counter": KindCounter, "Float64Counter": KindCounter,
	"Int64ObservableCounter": KindCounter, "Float64ObservableCounter": KindCounter,
	"Int64UpDownCounter": KindUpDownCounter, "Float64UpDownCounter": KindUpDownCounter,
	"Int64ObservableUpDownCounter": KindUpDownCounter, "Float64ObservableUpDownCounter": KindUpDownCounter,
	"Int64Gauge": KindGauge, "Float64Gauge": KindGauge,
	"Int64ObservableGauge": KindGauge, "Float64ObservableGauge": KindGauge,
	"Int64Histogram": KindHistogram, "Float64Histogram": KindHistogram,
}

// ScanInstruments finds every instrument call in the non-test Go files under root/internal and root/cmd.
// It resolves a name or unit that is a string literal or a string constant of the same package.
// A call whose name it cannot resolve is an error.
func ScanInstruments(root string) ([]Instrument, error) {
	dirs := map[string][]string{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			dirs[filepath.Dir(path)] = append(dirs[filepath.Dir(path)], path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	var out []Instrument
	var problems []string
	names := make([]string, 0, len(dirs))
	for d := range dirs {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, dir := range names {
		fset := token.NewFileSet()
		var files []*ast.File
		for _, p := range dirs[dir] {
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return nil, err
			}
			files = append(files, f)
		}
		consts := stringConsts(files)
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				kind, ok := instrumentKinds[sel.Sel.Name]
				if !ok || len(call.Args) == 0 {
					return true
				}
				pos := fset.Position(call.Pos())
				rel, _ := filepath.Rel(root, pos.Filename)
				where := fmt.Sprintf("%s:%d", rel, pos.Line)
				name, ok := constString(call.Args[0], consts)
				if !ok {
					problems = append(problems, where+": the instrument name is not a literal or a constant of the package")
					return true
				}
				unit := ""
				for _, a := range call.Args[1:] {
					uc, ok := a.(*ast.CallExpr)
					if !ok {
						continue
					}
					us, ok := uc.Fun.(*ast.SelectorExpr)
					if !ok || us.Sel.Name != "WithUnit" || len(uc.Args) != 1 {
						continue
					}
					u, ok := constString(uc.Args[0], consts)
					if !ok {
						problems = append(problems, where+": the unit is not a literal or a constant of the package")
						continue
					}
					unit = u
				}
				out = append(out, Instrument{Name: name, Kind: kind, Unit: unit, Pos: where})
				return true
			})
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("scan: %s", strings.Join(problems, "; "))
	}
	return out, nil
}

// stringConsts collects the string constants of a package, resolving constants that name other constants.
func stringConsts(files []*ast.File) map[string]string {
	raw := map[string]ast.Expr{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						raw[n.Name] = vs.Values[i]
					}
				}
			}
		}
	}
	out := map[string]string{}
	for range raw {
		for name, e := range raw {
			if _, done := out[name]; done {
				continue
			}
			if v, ok := constString(e, out); ok {
				out[name] = v
			}
		}
	}
	return out
}

func constString(e ast.Expr, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.Ident:
		s, ok := consts[v.Name]
		return s, ok
	case *ast.ParenExpr:
		return constString(v.X, consts)
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		a, ok1 := constString(v.X, consts)
		b, ok2 := constString(v.Y, consts)
		return a + b, ok1 && ok2
	}
	return "", false
}
