package dashboards

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Output paths under the output directory.
const (
	dashboardDir = "dashboards"
	rulesPath    = "alerting/rules.json"
	providerPath = "provider.yaml"
)

// providerYAML is the Grafana dashboard provider file. It matches the mount path of the lgtm pod.
const providerYAML = `apiVersion: 1
providers:
  - name: cell-identity-poc
    orgId: 1
    folder: Cell identity PoC
    folderUid: poc
    type: file
    disableDeletion: true
    allowUiUpdates: false
    updateIntervalSeconds: 60
    options:
      path: /otel-lgtm/poc-dashboards
`

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// render checks the boards and the rules and returns the output files by path, relative to the output directory.
func render(boards []Dashboard, rules RuleFile) (map[string][]byte, error) {
	if err := Check(boards, rules); err != nil {
		return nil, err
	}
	files := map[string][]byte{providerPath: []byte(providerYAML)}
	for _, b := range boards {
		data, err := marshal(b)
		if err != nil {
			return nil, err
		}
		files[dashboardDir+"/"+b.File] = data
	}
	data, err := marshal(rules)
	if err != nil {
		return nil, err
	}
	files[rulesPath] = data
	return files, nil
}

// Files returns the output files of the generator by path, relative to the output directory.
func Files() (map[string][]byte, error) { return render(Boards(), Rules()) }

// Write writes the generated files under dir and removes dashboard files that no board owns.
func Write(dir string) error {
	files, err := Files()
	if err != nil {
		return err
	}
	return writeFiles(dir, files)
}

func writeFiles(dir string, files map[string][]byte) error {
	stale, err := staleFiles(dir, files)
	if err != nil {
		return err
	}
	for _, name := range stale {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(files) {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, files[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

// staleFiles lists the files under dashboards/ that the output does not contain.
func staleFiles(dir string, files map[string][]byte) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(dir, dashboardDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := dashboardDir + "/" + e.Name()
		if _, ok := files[name]; !ok && !e.IsDir() {
			out = append(out, name)
		}
	}
	return out, nil
}

// Diff returns the paths under dir that differ from the generated output, in order.
// A missing file, a changed file and a file that no board owns each count.
func Diff(dir string) ([]string, error) {
	files, err := Files()
	if err != nil {
		return nil, err
	}
	return diffFiles(dir, files)
}

func diffFiles(dir string, files map[string][]byte) ([]string, error) {
	var out []string
	for _, name := range sortedKeys(files) {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if err != nil || !bytes.Equal(got, files[name]) {
			out = append(out, name)
		}
	}
	stale, err := staleFiles(dir, files)
	if err != nil {
		return nil, err
	}
	out = append(out, stale...)
	return out, nil
}
