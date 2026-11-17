package cellproxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRegistry(t *testing.T) {
	pub, priv := signerKey(t)
	otherPub, otherPriv := signerKey(t)
	keys := []ed25519.PublicKey{pub}

	t.Run("two valid records", func(t *testing.T) {
		reg, err := LoadRegistry(writeRegistry(t, keys, priv, cell("dev-cell-1", false), cell("dev-cell-2", false)))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"dev-cell-1", "dev-cell-2"} {
			if !reg.Allows(Source{Env: "dev", Plane: "cell", Cell: name, Cluster: name, Role: "otel"}) {
				t.Fatalf("%s is not allowed", name)
			}
		}
		if reg.Allows(Source{Env: "dev", Plane: "cell", Cell: "dev-cell-3", Cluster: "dev-cell-3", Role: "otel"}) {
			t.Fatal("a cell with no record is allowed")
		}
		if reg.Allows(Source{Env: "prod", Plane: "cell", Cell: "dev-cell-1", Cluster: "dev-cell-1", Role: "otel"}) {
			t.Fatal("a cell of another environment is allowed")
		}
		if !reg.Allows(Source{Env: "dev", Plane: "environment", Cluster: "dev-cp", Role: "otel"}) {
			t.Fatal("the environment plane of dev is not allowed")
		}
		if reg.Allows(Source{Env: "prod", Plane: "environment", Cluster: "prod-cp", Role: "otel"}) {
			t.Fatal("the environment plane of an unknown environment is allowed")
		}
	})

	bad := map[string]func(t *testing.T) string{
		"signed by a key not in signers.pub": func(t *testing.T) string {
			dir := writeRegistry(t, keys, priv, cell("dev-cell-1", false))
			other := writeRegistry(t, []ed25519.PublicKey{otherPub}, otherPriv, cell("dev-cell-2", false))
			copyFile(t, filepath.Join(other, "dev-cell-2.dsse.json"), filepath.Join(dir, "dev-cell-2.dsse.json"))
			return dir
		},
		"one changed byte": func(t *testing.T) string {
			dir := writeRegistry(t, keys, priv, cell("dev-cell-1", false), cell("dev-cell-2", false))
			// The changed byte keeps a valid record, so only the signature check can refuse it.
			path := filepath.Join(dir, "dev-cell-2.dsse.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var env map[string]any
			if err := json.Unmarshal(data, &env); err != nil {
				t.Fatal(err)
			}
			payload, err := base64.StdEncoding.DecodeString(env["payload"].(string))
			if err != nil {
				t.Fatal(err)
			}
			changed := bytes.Replace(payload, []byte(`"dev-cell-2"`), []byte(`"dev-cell-3"`), 1)
			if bytes.Equal(changed, payload) {
				t.Fatal("the payload holds no cell name to change")
			}
			env["payload"] = base64.StdEncoding.EncodeToString(changed)
			if data, err = json.Marshal(env); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"no signers.pub": func(t *testing.T) string {
			return writeRegistry(t, nil, priv, cell("dev-cell-1", false))
		},
		"name with capitals": func(t *testing.T) string {
			c := cell("dev-cell-1", false)
			c.Name, c.Env = "Dev-Cell-2", "dev"
			return writeRegistry(t, keys, priv, c)
		},
		"name with a space": func(t *testing.T) string {
			c := cell("dev-cell-1", false)
			c.Name, c.Env = "dev-cell-2 ", "dev"
			return writeRegistry(t, keys, priv, c)
		},
		"env with a space": func(t *testing.T) string {
			c := cell("dev-cell-1", false)
			c.Name, c.Env = "dev-cell-2", "dev env"
			return writeRegistry(t, keys, priv, c)
		},
		"reserved name": func(t *testing.T) string {
			c := cell("dev-cell-1", false)
			c.Name, c.Env = "management", "dev"
			return writeRegistry(t, keys, priv, c)
		},
		"environment plane name": func(t *testing.T) string {
			c := cell("dev-cell-1", false)
			c.Name, c.Env = "dev-cp", "dev"
			return writeRegistry(t, keys, priv, c)
		},
		"60-character name": func(t *testing.T) string {
			c := cell("dev-cell-1", false)
			c.Name, c.Env = strings.Repeat("a", 60), "dev"
			return writeRegistry(t, keys, priv, c)
		},
	}
	for name, dir := range bad {
		t.Run(name, func(t *testing.T) {
			if reg, err := LoadRegistry(dir(t)); err == nil {
				t.Fatalf("LoadRegistry gave %v, want an error", reg)
			}
		})
	}

	t.Run("zero records admit no cell", func(t *testing.T) {
		reg, err := LoadRegistry(writeRegistry(t, keys, priv))
		if err != nil {
			t.Fatal(err)
		}
		if st := reg.Stats(); st.Records != 0 || st.Signers != 1 {
			t.Fatalf("stats %+v", st)
		}
		for _, s := range []Source{
			{Env: "dev", Plane: "cell", Cell: "dev-cell-1", Cluster: "dev-cell-1", Role: "otel"},
			{Env: "dev", Plane: "environment", Cluster: "dev-cp", Role: "otel"},
		} {
			if reg.Allows(s) {
				t.Fatalf("an empty registry allows %+v", s)
			}
		}
	})

	t.Run("revoked record wins", func(t *testing.T) {
		reg, err := LoadRegistry(writeRegistry(t, keys, priv, cell("dev-cell-1", false), cell("dev-cell-1", true)))
		if err != nil {
			t.Fatal(err)
		}
		if reg.Allows(Source{Env: "dev", Plane: "cell", Cell: "dev-cell-1", Cluster: "dev-cell-1", Role: "otel"}) {
			t.Fatal("a name with a revoked record is allowed")
		}
	})

	t.Run("stats", func(t *testing.T) {
		reg, err := LoadRegistry(writeRegistry(t, []ed25519.PublicKey{pub, otherPub}, priv, cell("dev-cell-1", false), cell("dev-cell-2", true)))
		if err != nil {
			t.Fatal(err)
		}
		if got := reg.Stats(); got != (RegistryStats{Records: 2, Revoked: 1, Signers: 2}) {
			t.Fatalf("stats %+v", got)
		}
	})

	t.Run("content hash", func(t *testing.T) {
		load := func(pub ed25519.PublicKey, priv ed25519.PrivateKey, revoked bool) string {
			reg, err := LoadRegistry(writeRegistry(t, []ed25519.PublicKey{pub}, priv, cell("dev-cell-1", false), cell("dev-cell-2", revoked)))
			if err != nil {
				t.Fatal(err)
			}
			return reg.ContentSHA256()
		}
		a, b := load(pub, priv, false), load(otherPub, otherPriv, false)
		if a != b {
			t.Fatalf("hash differs under another signer key: %s and %s", a, b)
		}
		if c := load(pub, priv, true); c == a {
			t.Fatal("hash is equal when one record is revoked")
		}
		// The hash covers the sorted lines "<name> <env> <revoked>", each with a newline, so a
		// render can compute the same value with sort and sha256sum.
		sum := sha256.Sum256([]byte("dev-cell-1 dev false\ndev-cell-2 dev false\n"))
		if want := hex.EncodeToString(sum[:]); a != want {
			t.Fatalf("hash is %s, want %s", a, want)
		}
	})
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
