package revoke

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSeedRoundTrip(t *testing.T) {
	if SeedPrefix != "OPERATOR-ED25519-SEED:" {
		t.Fatalf("prefix %q", SeedPrefix)
	}
	key := testKey(t, 7)
	line := FormatSeed(key)
	want := SeedPrefix + base64.StdEncoding.EncodeToString(key.Seed())
	if line != want {
		t.Fatalf("FormatSeed gives a line of %d bytes, want %d", len(line), len(want))
	}
	if strings.ContainsAny(line, "\r\n") {
		t.Error("FormatSeed holds a line break")
	}
	for _, in := range []string{line, line + "\n", line + "\r\n"} {
		got, err := ParseSeed(strings.NewReader(in))
		if err != nil {
			t.Fatalf("ParseSeed: %v", err)
		}
		if !got.Equal(key) {
			t.Error("ParseSeed returns another key")
		}
	}
	if FormatSeed(key[:10]) != "" {
		t.Error("FormatSeed formats a short key")
	}
}

// countReader counts the bytes that its reader hands out.
type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestParseSeedErrorsCarryNoInput(t *testing.T) {
	secret := testKey(t, 9)
	b64 := base64.StdEncoding.EncodeToString(secret.Seed())
	line := SeedPrefix + b64
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"newline_only", "\n"},
		{"no_prefix", b64 + "\n"},
		{"other_prefix", "OPERATOR-ED25519-KEY:" + b64 + "\n"},
		{"lower_prefix", strings.ToLower(SeedPrefix) + b64 + "\n"},
		{"url_base64", SeedPrefix + base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)) + "\n"},
		{"raw_base64", SeedPrefix + base64.RawStdEncoding.EncodeToString(secret.Seed()) + "\n"},
		{"bad_base64", SeedPrefix + b64[:20] + "!" + b64[21:] + "\n"},
		{"short_seed", SeedPrefix + base64.StdEncoding.EncodeToString(secret.Seed()[:31]) + "\n"},
		{"long_seed", SeedPrefix + base64.StdEncoding.EncodeToString(append(secret.Seed(), 1)) + "\n"},
		{"private_key", SeedPrefix + base64.StdEncoding.EncodeToString(secret) + "\n"},
		{"two_lines", line + "\n" + line + "\n"},
		{"blank_then_line", "\n" + line + "\n"},
		{"leading_space", " " + line + "\n"},
		{"trailing_space", line + " \n"},
		{"inner_space", SeedPrefix + " " + b64 + "\n"},
		{"nul", line + "\x00\n"},
		{"lone_cr", line + "\r"},
		{"cr_cr_lf", line + "\r\r\n"},
		{"too_long", line + "\n" + strings.Repeat("A", 400)},
		{"too_long_one_line", line + strings.Repeat("A", 400)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSeed(strings.NewReader(tc.in))
			if err == nil {
				t.Fatal("ParseSeed accepts the input")
			}
			checkNoInput(t, err.Error(), tc.in, b64)
		})
	}
	_, err := ParseSeed(failReader{})
	if err == nil {
		t.Fatal("a read error passes")
	}
	checkNoInput(t, err.Error(), "", b64)
}

// checkNoInput fails when msg holds the seed prefix, the start of the base64 seed, or any 6 bytes
// in a row of the input after its last colon, where the seed text lies.
func checkNoInput(t *testing.T, msg, in, b64 string) {
	t.Helper()
	if strings.Contains(msg, SeedPrefix) || strings.Contains(msg, "OPERATOR") || strings.Contains(msg, b64[:8]) {
		t.Errorf("error %q holds seed text", msg)
	}
	if i := strings.LastIndex(in, ":"); i >= 0 {
		in = in[i+1:]
	}
	for i := 0; i+6 <= len(in); i++ {
		w := in[i : i+6]
		if strings.Trim(w, " \n\r") != w || strings.Count(w, w[:1]) == len(w) {
			continue
		}
		if strings.Contains(msg, w) {
			t.Errorf("error %q holds input bytes %q", msg, w)
			return
		}
	}
}

func TestParseSeedReadsAtMost256Bytes(t *testing.T) {
	key := testKey(t, 7)
	in := FormatSeed(key) + "\n" + strings.Repeat("#", 1000)
	r := &countReader{r: strings.NewReader(in)}
	if _, err := ParseSeed(r); err == nil {
		t.Error("ParseSeed accepts trailing data")
	}
	if r.n > 256 {
		t.Errorf("ParseSeed read %d bytes", r.n)
	}
	r = &countReader{r: io.MultiReader(strings.NewReader(FormatSeed(key)+"\n"), failReader{})}
	if _, err := ParseSeed(r); err == nil {
		t.Error("a read error after the line passes")
	}
}

func TestParseKeys(t *testing.T) {
	a, b, c := pub(testKey(t, 1)), pub(testKey(t, 2)), pub(testKey(t, 3))
	enc := func(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }
	for _, tc := range []struct {
		name string
		text string
		want []ed25519.PublicKey
	}{
		{"one", enc(a), []ed25519.PublicKey{a}},
		{"one_newline", enc(a) + "\n", []ed25519.PublicKey{a}},
		{"two", enc(a) + "\n" + enc(b) + "\n", []ed25519.PublicKey{a, b}},
		{"two_no_newline", enc(b) + "\n" + enc(a), []ed25519.PublicKey{b, a}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKeys([]byte(tc.text))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d keys, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if !got[i].Equal(tc.want[i]) {
					t.Errorf("key %d differs", i)
				}
			}
		})
	}
	for _, tc := range []struct{ name, text string }{
		{"empty", ""},
		{"newline_only", "\n"},
		{"three_lines", enc(a) + "\n" + enc(b) + "\n" + enc(c) + "\n"},
		{"blank_middle", enc(a) + "\n\n" + enc(b) + "\n"},
		{"blank_first", "\n" + enc(a) + "\n"},
		{"duplicate", enc(a) + "\n" + enc(a) + "\n"},
		{"bad_base64", "not base64!\n"},
		{"url_base64", base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)) + "\n"},
		{"short_key", base64.StdEncoding.EncodeToString(a[:31]) + "\n"},
		{"seed_line", FormatSeed(testKey(t, 1)) + "\n"},
		{"crlf", enc(a) + "\r\n"},
		{"space", " " + enc(a) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseKeys([]byte(tc.text)); err == nil {
				t.Errorf("ParseKeys accepts it: %d keys", len(got))
			}
		})
	}
}

func TestKeySHA256(t *testing.T) {
	k := pub(testKey(t, 1))
	sum := sha256.Sum256(k)
	if got := KeySHA256(k); got != hex.EncodeToString(sum[:]) {
		t.Errorf("got %s", got)
	}
	if KeySHA256(pub(testKey(t, 2))) == KeySHA256(k) {
		t.Error("two keys share a digest")
	}
}

func TestWriteSeed(t *testing.T) {
	key := testKey(t, 7)
	var out bytes.Buffer
	if err := WriteSeed(&out, key); err != nil {
		t.Fatal(err)
	}
	if out.String() != FormatSeed(key)+"\n" {
		t.Error("WriteSeed differs from the line of FormatSeed")
	}
	got, err := ParseSeed(&out)
	if err != nil || !got.Equal(key) {
		t.Errorf("ParseSeed of WriteSeed: %v", err)
	}
	var none bytes.Buffer
	if err := WriteSeed(&none, key[:10]); err == nil || none.Len() != 0 {
		t.Errorf("a short key: %v, wrote %d bytes", err, none.Len())
	}
	if err := WriteSeed(failWriter{}, key); err == nil || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(key.Seed())[:8]) {
		t.Errorf("a write error: %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }
