package pins

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPinsAreWellFormed(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	for name, ref := range All() {
		if !strings.Contains(ref, "@sha256:") {
			t.Errorf("%s is not pinned by digest: %s", name, ref)
		}
	}
	if digestRef.MatchString("debian:bookworm-slim") || digestRef.MatchString("debian@sha256:abc") {
		t.Error("tag-only or short-digest references must not pass")
	}
}

func TestClaudeLockMatchesVersionAndHasIntegrity(t *testing.T) {
	pkg, lock, ok := ClaudeLock(ClaudeCodeVersion)
	if !ok {
		t.Fatal("no lockfile for the shipped version")
	}
	if _, _, ok := ClaudeLock("0.0.1"); ok {
		t.Error("must not return a lockfile for a version it does not pin")
	}
	var p struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(pkg, &p); err != nil || p.Dependencies["@anthropic-ai/claude-code"] != ClaudeCodeVersion {
		t.Fatalf("package.json does not pin %s exactly: %v %v", ClaudeCodeVersion, p.Dependencies, err)
	}
	var l struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(lock, &l); err != nil {
		t.Fatal(err)
	}
	if l.LockfileVersion != 3 || len(l.Packages) < 3 {
		t.Fatalf("unexpected lockfile shape: v%d, %d packages", l.LockfileVersion, len(l.Packages))
	}
	for name, pk := range l.Packages {
		if name == "" {
			continue
		}
		if !strings.HasPrefix(pk.Integrity, "sha512-") {
			t.Errorf("%s has no sha512 integrity pin", name)
		}
		if pk.Version != ClaudeCodeVersion {
			t.Errorf("%s is %s, want %s", name, pk.Version, ClaudeCodeVersion)
		}
	}
	for _, want := range []string{"node_modules/@anthropic-ai/claude-code-linux-x64", "node_modules/@anthropic-ai/claude-code-linux-arm64"} {
		if _, ok := l.Packages[want]; !ok {
			t.Errorf("lockfile is missing %s: the image must build on amd64 and arm64", want)
		}
	}
}
