package hostsvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// bootstrapPaths are the git pathspecs that the bootstrap digest covers.
var bootstrapPaths = []string{
	"bootstrap", "cells", "cmd", "components", "harness", "internal", "scripts", "vendor",
	"go.mod", "go.sum", "mise.toml", "mise.lock",
}

// ImagesEnvPath is the generated file that the bootstrap digest covers although git does not track it.
const ImagesEnvPath = "build/images.env"

// maxDigestFile is the largest file that the bootstrap digest reads.
const maxDigestFile = 4 << 20

// BootstrapDigest returns the lowercase hex SHA-256 of the listing of the bootstrap inputs under
// root, and the number of lines in it. A line is "<sha256 hex>  <path>\n" for each file that git
// tracks under the bootstrap paths, hashed from its working-tree content, and for build/images.env.
// A tracked file that is missing gives "deleted  <path>". Untracked files never count. Paths use
// "/" and are sorted by byte order. A symlink, a directory or a file above 4 MiB is an error.
func BootstrapDigest(root string) (sum string, files int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	args := append([]string{"-C", root, "ls-files", "-z", "--"}, bootstrapPaths...)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GIT_DIR=") || strings.HasPrefix(kv, "GIT_WORK_TREE=") || strings.HasPrefix(kv, "GIT_INDEX_FILE=")
	})
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("list tracked files: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	seen := map[string]bool{ImagesEnvPath: true}
	paths := []string{ImagesEnvPath}
	for _, p := range strings.Split(stdout.String(), "\x00") {
		if p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	h := sha256.New()
	for _, p := range paths {
		line, err := digestLine(root, p)
		if err != nil {
			return "", 0, err
		}
		_, _ = io.WriteString(h, line)
	}
	return hex.EncodeToString(h.Sum(nil)), len(paths), nil
}

func digestLine(root, p string) (string, error) {
	full := filepath.Join(root, filepath.FromSlash(p))
	fi, err := os.Lstat(full)
	switch {
	case errors.Is(err, os.ErrNotExist) && p != ImagesEnvPath:
		return "deleted  " + p + "\n", nil
	case err != nil:
		return "", fmt.Errorf("bootstrap input %s: %w", p, err)
	case fi.Mode()&os.ModeSymlink != 0:
		return "", fmt.Errorf("bootstrap input %s is a symbolic link", p)
	case !fi.Mode().IsRegular():
		return "", fmt.Errorf("bootstrap input %s is not a regular file", p)
	case fi.Size() > maxDigestFile:
		return "", fmt.Errorf("bootstrap input %s is larger than %d bytes", p, maxDigestFile)
	}
	f, err := os.Open(full)
	if err != nil {
		return "", fmt.Errorf("bootstrap input %s: %w", p, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxDigestFile+1))
	if err != nil {
		return "", fmt.Errorf("bootstrap input %s: %w", p, err)
	}
	if n > maxDigestFile {
		return "", fmt.Errorf("bootstrap input %s is larger than %d bytes", p, maxDigestFile)
	}
	return hex.EncodeToString(h.Sum(nil)) + "  " + p + "\n", nil
}
