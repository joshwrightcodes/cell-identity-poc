// Command operatorctl makes, reads and uses the operator key on this Mac. The operator key is an Ed25519 key that signs local
// revocation entries.
//
//	operatorctl keygen --public-file <path>
//	operatorctl pub < seed line
//	operatorctl sign --env <env> --cell <cell> --record <epoch>.<counter> < seed line
//	operatorctl verify --keys <file> < envelope
//
// keygen makes a new key. It writes the public key to the public file, one standard base64 line, and refuses a file that exists.
// Then it prints the seed line on standard output: OPERATOR-ED25519-SEED: and the standard base64 of the 32-byte seed. pub reads a
// seed line on standard input and prints the public key, one standard base64 line. sign reads a seed line on standard input and
// prints the DSSE envelope of a local revocation entry for the cell, with a random id, the record revision and the current time.
// verify reads an envelope on standard input, checks it against the keys file (one or two standard base64 keys, one on each line),
// and prints one JSON line with the entry and the SHA-256 of the key that verified it.
//
// The seed moves only through standard input and standard output, so a caller pipes it from or into the secret manager. On failure
// the command prints one JSON error line on standard output and exits 1. No error line holds a byte of standard input.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
	"github.com/joshwrightcodes/cell-identity-poc/internal/record"
	"github.com/joshwrightcodes/cell-identity-poc/internal/revoke"
	"github.com/joshwrightcodes/cell-identity-poc/internal/spec"
)

const usage = "usage: operatorctl keygen --public-file <path> | pub | sign --env <env> --cell <cell> --record <epoch>.<counter> | verify --keys <file>"

// maxKeysFile is the largest keys file that verify reads. Two keys of 44 characters with their line breaks fit many times.
const maxKeysFile = 1 << 10

var recordRE = regexp.MustCompile(`^[1-9][0-9]{0,18}\.[1-9][0-9]{0,18}$`)

func main() {
	os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, time.Now))
}

// execute runs one command. On failure it writes one compact JSON error line to stdout and returns 1.
func execute(args []string, stdin io.Reader, stdout io.Writer, now func() time.Time) int {
	return cli.Run(stdout, "operatorctl", func(out io.Writer) error { return dispatch(args, stdin, out, now) })
}

// invalidError is a refused envelope. Its line carries the reason and the detail of the envd admit rules.
type invalidError struct{ detail string }

func (e invalidError) Error() string {
	return "the envelope is no valid local revocation entry: " + e.detail
}
func (e invalidError) LogAttrs() []any {
	return []any{"reason", revoke.ReasonInvalid, "detail", e.detail}
}

// flags names the flags of each command.
var flags = map[string][]string{"keygen": {"public-file"}, "pub": nil, "sign": {"env", "cell", "record"}, "verify": {"keys"}}

func dispatch(args []string, stdin io.Reader, out io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	names, known := flags[args[0]]
	if !known {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	values := map[string]*string{}
	for _, n := range names {
		values[n] = fs.String(n, "", "")
	}
	// The error of the flag package quotes the argument, so the line carries the usage alone.
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errors.New(usage)
	}
	value := func(n string) string { return *values[n] }
	switch args[0] {
	case "keygen":
		return keygen(value("public-file"), out)
	case "pub":
		return pub(stdin, out)
	case "sign":
		return sign(stdin, out, value("env"), value("cell"), value("record"), now)
	default:
		return verify(stdin, out, value("keys"))
	}
}

func keygen(publicFile string, out io.Writer) error {
	if publicFile == "" {
		return errors.New("keygen needs --public-file")
	}
	pubKey, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("keygen: no random bytes")
	}
	defer clear(key)
	f, err := os.OpenFile(publicFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("keygen: create the public file: %w", err)
	}
	if _, err := io.WriteString(f, base64.StdEncoding.EncodeToString(pubKey)+"\n"); err != nil {
		f.Close()
		return fmt.Errorf("keygen: write the public file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("keygen: write the public file: %w", err)
	}
	return revoke.WriteSeed(out, key)
}

func pub(stdin io.Reader, out io.Writer) error {
	key, err := revoke.ParseSeed(stdin)
	if err != nil {
		return err
	}
	defer clear(key)
	_, err = io.WriteString(out, base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))+"\n")
	return err
}

func sign(stdin io.Reader, out io.Writer, env, cell, rec string, now func() time.Time) error {
	if !recordRE.MatchString(rec) {
		return errors.New("sign needs --record <epoch>.<counter>, two whole numbers of at least 1")
	}
	epochText, counterText, _ := strings.Cut(rec, ".")
	epoch, err1 := strconv.ParseUint(epochText, 10, 64)
	counter, err2 := strconv.ParseUint(counterText, 10, 64)
	if err1 != nil || err2 != nil {
		return errors.New("sign: --record is out of range")
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return errors.New("sign: no random bytes")
	}
	entry := revoke.Entry{ID: hex.EncodeToString(id[:]), Env: env, Cell: cell,
		Record: spec.Revision{Epoch: epoch, Counter: counter}, IssuedAt: now().UTC().Truncate(time.Second)}
	key, err := revoke.ParseSeed(stdin)
	if err != nil {
		return err
	}
	defer clear(key)
	envelope, err := revoke.Sign(entry, key)
	if err != nil {
		return err
	}
	_, err = out.Write(append(envelope, '\n'))
	return err
}

func verify(stdin io.Reader, out io.Writer, keysFile string) error {
	if keysFile == "" {
		return errors.New("verify needs --keys <file>")
	}
	f, err := os.Open(keysFile)
	if err != nil {
		return fmt.Errorf("verify: open the keys file: %w", err)
	}
	text, err := io.ReadAll(io.LimitReader(f, maxKeysFile+1))
	f.Close()
	if err != nil || len(text) > maxKeysFile {
		return errors.New("verify: the keys file cannot be read, or is too large")
	}
	keys, err := revoke.ParseKeys(text)
	if err != nil {
		return err
	}
	envelope, err := io.ReadAll(io.LimitReader(stdin, revoke.MaxEntryBytes+1))
	if err != nil {
		return errors.New("verify: read the envelope")
	}
	if len(envelope) > revoke.MaxEntryBytes {
		return invalidError{revoke.DetailDecode}
	}
	for _, k := range keys {
		e, err := revoke.Verify(envelope, []ed25519.PublicKey{k})
		switch {
		case err == nil:
			return json.NewEncoder(out).Encode(struct {
				revoke.Entry
				KeySHA256 string `json:"keySHA256"`
			}{e, revoke.KeySHA256(k)})
		case errors.Is(err, record.ErrSignature):
			continue
		default:
			// The text of a decode error can quote the input, so the line names the detail alone.
			return invalidError{revoke.DetailDecode}
		}
	}
	return invalidError{revoke.DetailSignature}
}
