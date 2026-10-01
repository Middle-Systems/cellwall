package config

import (
	"path"
	"strings"
	"testing"
)

// Anything NormalizeRelPath accepts is a clean, relative, in-workspace path with no specials.
func FuzzNormalizeRelPath(f *testing.F) {
	for _, s := range []string{"a", "./a/", "../a", "a/../b", "/etc", ".git/hooks", "a//b", "a*", "~", "", "a\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := NormalizeRelPath(in)
		if err != nil {
			return
		}
		// Note "..0" is a legitimate file name: only a segment that is exactly ".." escapes.
		if out == "" || out == "." || strings.HasPrefix(out, "/") || out == ".." || strings.HasPrefix(out, "../") || strings.Contains(out, "//") {
			t.Fatalf("unsafe result %q from %q", out, in)
		}
		if path.Clean(out) != out {
			t.Fatalf("not clean: %q", out)
		}
		for _, seg := range strings.Split(out, "/") {
			if seg == ".." || seg == "" {
				t.Fatalf("bad segment in %q", out)
			}
		}
		if strings.ContainsAny(out, "*?[]{}$`\\:\x00\n\r") {
			t.Fatalf("special character survived: %q", out)
		}
		again, err := NormalizeRelPath(out)
		if err != nil || again != out {
			t.Fatalf("not idempotent: %q -> %q", out, again)
		}
	})
}

// Parse and Validate must never panic, and a config that validates must have a safe protected set.
func FuzzParseValidate(f *testing.F) {
	for _, s := range []string{
		"version: 1\n", "version: 1\nproject: x\nports: [3000]\n",
		"version: 1\nunsafe: {unprotect: [.mcp.json]}\n", "version: 1\nsecrets:\n  - {name: a, source_file: ~/a}\n",
		"version: 1\nagent: {env: {A: b}}\n", "{}", "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse("fuzz", data, LayerProject, Default())
		if err != nil || c.Validate() != nil {
			return
		}
		for _, p := range c.ProtectedSet() {
			if _, err := NormalizeRelPath(p); err != nil {
				t.Fatalf("protected path %q is not safe: %v", p, err)
			}
		}
		_ = c.Relaxations()
		_ = c.Hash()
	})
}
