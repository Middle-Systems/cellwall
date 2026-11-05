// Package safefs holds the two filesystem primitives kennel needs to write into a repository it
// does not trust: refusing to traverse symlinks, and replacing files atomically.
//
// A hostile repository can ship `.devcontainer -> /etc` or `.kennel/state -> ~/.ssh`; writing
// through such a link from a tool the user runs on the host would put files outside the project.
package safefs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SymlinkOnPath returns a description if any EXISTING component of root/rel is a symlink, or "" if
// the path is safe to create or write. Components that do not exist yet are fine.
func SymlinkOnPath(root, rel string) string {
	cur := root
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if seg == "" || seg == "." {
			continue
		}
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		if err != nil {
			return ""
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			r, _ := filepath.Rel(root, cur)
			return fmt.Sprintf("%s is a symlink; kennel never writes through symlinks", filepath.ToSlash(r))
		}
	}
	return ""
}

// WriteAtomic writes content to path via a temp file in the same directory and a rename, creating
// parent directories. A reader (the gateway watching its policy) never sees a partial file.
func WriteAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // project directories are meant to be readable
		return err
	}
	tmp, err := os.CreateTemp(dir, ".kennel-tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// WriteIfChanged is WriteAtomic that does nothing when the file already has exactly this content,
// so repeated runs leave modification times (and anything watching them) alone.
func WriteIfChanged(path string, content []byte, mode os.FileMode) (changed bool, err error) {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, content) { //nolint:gosec // caller-validated path
		return false, nil
	}
	return true, WriteAtomic(path, content, mode)
}
