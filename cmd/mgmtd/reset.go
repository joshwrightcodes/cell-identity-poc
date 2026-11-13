package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/joshwrightcodes/cell-identity-poc/internal/cli"
)

const resetUsage = "usage: mgmtd reset-state [--data-dir /var/lib/mgmtd]"

// The names of the files that reset-state moves. serve reads the same two files.
const (
	stateFileName = "state.json"
	keyFileName   = "ed25519.key"
)

type movedFile struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// resetState renames the state file and the signing key file in dir to <name>.reset-<unix time>.
// It deletes nothing. The state file moves first, so a failure between the two moves leaves a key
// without a state, and serve then makes a new key for the fresh state. A file that is absent is skipped.
func resetState(dir string, now time.Time) ([]movedFile, error) {
	info, err := os.Stat(dir)
	switch {
	case err != nil:
		return nil, fmt.Errorf("data directory: %w", err)
	case !info.IsDir():
		return nil, fmt.Errorf("data directory %s is not a directory", dir)
	}
	stamp := strconv.FormatInt(now.Unix(), 10)
	moved := []movedFile{}
	for _, n := range []string{stateFileName, keyFileName} {
		from, to := filepath.Join(dir, n), filepath.Join(dir, n+".reset-"+stamp)
		if _, err := os.Lstat(from); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return moved, fmt.Errorf("check %s: %w", n, err)
		}
		if _, err := os.Lstat(to); err == nil {
			return moved, fmt.Errorf("%s already exists", to)
		}
		if err := os.Rename(from, to); err != nil {
			return moved, fmt.Errorf("move %s aside: %w", n, err)
		}
		moved = append(moved, movedFile{From: from, To: to})
	}
	return moved, nil
}

// resetCommand runs mgmtd reset-state. It prints one JSON line with the moved files, or one error line.
func resetCommand(args []string, stdout io.Writer, now func() time.Time) int {
	fl := newFlags("reset-state")
	dir := fl.String("data-dir", "/var/lib/mgmtd", "directory of the signing key and the state")
	if err := parseFlags(fl, args); err != nil {
		cli.Fail(stdout, name, fmt.Errorf("%w; %s", err, resetUsage))
		return exitConfig
	}
	return cli.Run(stdout, name, func(out io.Writer) error {
		moved, err := resetState(*dir, now())
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Moved []movedFile `json:"moved"`
		}{moved})
	})
}
