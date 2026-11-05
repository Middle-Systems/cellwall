package safefs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSymlinkOnPath(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "real", "sub"), 0o755)
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skip("symlinks unavailable: ", err)
	}
	_ = os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "alias"))
	for rel, wantLink := range map[string]bool{
		"real/sub/file": false, "real": false, "new/dir/file": false, ".": false,
		"linked": true, "linked/x/y": true, "alias/sub": true, "real/../linked": true,
	} {
		got := SymlinkOnPath(root, rel) != ""
		if got != wantLink {
			t.Errorf("SymlinkOnPath(%q) symlink=%v, want %v", rel, got, wantLink)
		}
	}
}

func TestWriteAtomicAndIfChanged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a", "b", "f.txt")
	if err := WriteAtomic(p, []byte("one"), 0o640); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Fatal("content")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 && os.PathSeparator == '/' {
		t.Errorf("mode %v", fi.Mode())
	}
	before, _ := os.Stat(p)
	time.Sleep(10 * time.Millisecond)
	if changed, err := WriteIfChanged(p, []byte("one"), 0o640); err != nil || changed {
		t.Errorf("identical content must not be rewritten: %v %v", changed, err)
	}
	after, _ := os.Stat(p)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("mtime changed on a no-op")
	}
	if changed, err := WriteIfChanged(p, []byte("two"), 0o640); err != nil || !changed {
		t.Errorf("different content must be written: %v %v", changed, err)
	}
	// No temp files left behind.
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Errorf("leftovers: %v", entries)
	}
}
