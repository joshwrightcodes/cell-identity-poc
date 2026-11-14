package mgmt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodIntent = `{"env":"dev","bindSubject":{"namespace":"cell-identity-system","serviceAccount":"celld"},
"cells":[{"name":"dev-cell-1","subjects":[{"namespace":"cell-identity-system","serviceAccount":"celld"},{"namespace":"cell-identity-system","serviceAccount":"spire-agent"}],"cluster":{"podSubnet":"10.20.0.0/16","serviceSubnet":"10.21.0.0/16","issuer":"https://dev-cell-1.test"}}]}`

func writeIntent(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intent.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadIntent(t *testing.T) {
	in, err := LoadIntent(writeIntent(t, goodIntent))
	if err != nil {
		t.Fatal(err)
	}
	if in.Env != "dev" || in.BindSubject != celld || len(in.Cells) != 1 || in.Cells[0].Name != "dev-cell-1" || len(in.Cells[0].Subjects) != 2 {
		t.Fatalf("unexpected intent %+v", in)
	}

	bad := map[string]string{
		"unknown_member":  strings.Replace(goodIntent, `"env":"dev"`, `"env":"dev","extra":1`, 1),
		"duplicate_name":  strings.Replace(goodIntent, `"cells":[`, `"cells":[{"name":"dev-cell-1","subjects":[{"namespace":"cell-identity-system","serviceAccount":"celld"}]},`, 1),
		"reserved_cp":     strings.Replace(goodIntent, "dev-cell-1", "cp", 1),
		"reserved_dev_cp": strings.Replace(goodIntent, "dev-cell-1", "dev-cp", 1),
		"reserved_mgmt":   strings.Replace(goodIntent, "dev-cell-1", "management", 1),
		"reserved_rogue":  strings.Replace(goodIntent, "dev-cell-1", "rogue", 1),
		"uppercase":       strings.Replace(goodIntent, "dev-cell-1", "Dev-Cell", 1),
		"too_long":        strings.Replace(goodIntent, "dev-cell-1", strings.Repeat("a", 60), 1),
		"no_bind_subject": strings.Replace(goodIntent, `{"namespace":"cell-identity-system","serviceAccount":"celld"},{`, `{`, 1),
		"empty_bind":      strings.Replace(goodIntent, `"bindSubject":{"namespace":"cell-identity-system","serviceAccount":"celld"}`, `"bindSubject":{"namespace":"","serviceAccount":""}`, 1),
		"bad_env":         strings.Replace(goodIntent, `"env":"dev"`, `"env":"Dev_1"`, 1),
		"not_json":        `{`,
		"trailing":        goodIntent + `{}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadIntent(writeIntent(t, body)); err == nil {
				t.Fatal("intent accepted")
			}
		})
	}
	if _, err := LoadIntent(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("an absent file is accepted")
	}
}

func TestLoadIntentLongestName(t *testing.T) {
	name := strings.Repeat("a", 59)
	if _, err := LoadIntent(writeIntent(t, strings.Replace(goodIntent, "dev-cell-1", name, 1))); err != nil {
		t.Fatalf("a 59 character name: %v", err)
	}
}
