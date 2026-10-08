package policyedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-systems/cellwall/internal/policy"
)

const seed = `# my policy
version: 1

# Reviewed allowlists.
presets: [node]

# Your own rules.
rules: []
#  - host: api.example.com

limits: {}
`

func project(t *testing.T, policyYAML string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".cellwall"), 0o755); err != nil {
		t.Fatal(err)
	}
	if policyYAML != "" {
		if err := os.WriteFile(filepath.Join(root, ProjectFile), []byte(policyYAML), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRulesRejectsNonHostnames(t *testing.T) {
	for _, h := range []string{"https://example.com", "example.com:443", "a b", "", "1.2.3.4", "127.0.0.1", "2130706433", "exa_mple.com", "bücher.de"} {
		if _, err := (Edit{Action: policy.ActionAllow, Hosts: []string{h}}).Rules(); err == nil {
			t.Errorf("host %q should be rejected", h)
		}
	}
	if _, err := (Edit{Action: policy.ActionAllow, Hosts: []string{"Registry.Example.COM"}}).Rules(); err != nil {
		t.Errorf("mixed case host should be normalised, got %v", err)
	}
	if _, err := (Edit{Action: policy.ActionAllow, Hosts: []string{"a.com"}, Ports: []int{0}}).Rules(); err == nil {
		t.Error("port 0 should be rejected")
	}
}

func TestSessionAddReplaceAndRollback(t *testing.T) {
	root := project(t, seed)
	ch, err := ApplySession(root, Edit{Action: policy.ActionAllow, Hosts: []string{"a.example.com", "b.example.com"}})
	if err != nil || !ch.Changed {
		t.Fatalf("apply: %v changed=%v", err, ch.Changed)
	}
	s, err := LoadSession(root)
	if err != nil || len(s.Rules) != 2 {
		t.Fatalf("session = %+v, %v", s, err)
	}

	// Same request again changes nothing.
	ch2, err := ApplySession(root, Edit{Action: policy.ActionAllow, Hosts: []string{"a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if ch2.Changed {
		t.Error("re-adding an identical rule must not rewrite the file")
	}

	// deny then allow for the same host/ports leaves it allowed (the session deny is removed).
	if _, err := ApplySession(root, Edit{Action: policy.ActionDeny, Hosts: []string{"a.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplySession(root, Edit{Action: policy.ActionAllow, Hosts: []string{"a.example.com"}}); err != nil {
		t.Fatal(err)
	}
	s, _ = LoadSession(root)
	for _, r := range s.Rules {
		if r.Host == "a.example.com" && r.IsDeny() {
			t.Errorf("a stale session deny survived: %+v", s.Rules)
		}
	}

	ch3, err := ApplySession(root, Edit{Action: policy.ActionAllow, Hosts: []string{"c.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch3.Rollback(); err != nil {
		t.Fatal(err)
	}
	s, _ = LoadSession(root)
	for _, r := range s.Rules {
		if r.Host == "c.example.com" {
			t.Error("rollback did not restore the previous session file")
		}
	}
}

func TestSessionRollbackRemovesAFileThatDidNotExist(t *testing.T) {
	root := project(t, seed)
	ch, err := ApplySession(root, Edit{Action: policy.ActionAllow, Hosts: []string{"a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, SessionFile)); err == nil {
		t.Error("rollback left a session file behind")
	}
}

func TestSessionFileCannotCarryUnsafeOptions(t *testing.T) {
	root := project(t, seed)
	path := filepath.Join(root, SessionFile)
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	bad := "version: 1\nrules:\n  - host: evil.example.com\n    unsafe_allow_private: true\n"
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSession(root); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("an unsafe_* option in the session layer must be refused, got %v", err)
	}
}

func TestSaveKeepsCommentsAndIsIdempotent(t *testing.T) {
	root := project(t, seed)
	added, already, _, err := Save(root, Edit{Action: policy.ActionAllow, Hosts: []string{"registry.example.com"}, Note: "internal registry"})
	if err != nil || len(added) != 1 || len(already) != 0 {
		t.Fatalf("save: added=%v already=%v err=%v", added, already, err)
	}
	b, _ := os.ReadFile(filepath.Join(root, ProjectFile))
	text := string(b)
	for _, want := range []string{"# my policy", "# Reviewed allowlists.", "presets:", "registry.example.com", "internal registry"} {
		if !strings.Contains(text, want) {
			t.Errorf("saved policy lost %q:\n%s", want, text)
		}
	}
	p, err := policy.Parse("policy.yaml", b)
	if err != nil || p.Validate(false) != nil || len(p.Rules) != 1 || p.Rules[0].Host != "registry.example.com" {
		t.Fatalf("saved policy is not what was asked: %+v err=%v", p, err)
	}

	added, already, _, err = Save(root, Edit{Action: policy.ActionAllow, Hosts: []string{"registry.example.com"}})
	if err != nil || len(added) != 0 || len(already) != 1 {
		t.Fatalf("second save should add nothing: added=%v already=%v err=%v", added, already, err)
	}
	b2, _ := os.ReadFile(filepath.Join(root, ProjectFile))
	if string(b2) != text {
		t.Error("a no-op save rewrote the file")
	}
}

func TestSaveIntoPoliciesWithoutAnEmptyRulesList(t *testing.T) {
	for name, src := range map[string]string{
		"no rules key":   "version: 1\npresets: [node]\n",
		"existing rules": "version: 1\nrules:\n  - host: a.example.com\n    ports: [443, 8443]\n",
	} {
		root := project(t, src)
		if _, _, _, err := Save(root, Edit{Action: policy.ActionDeny, Hosts: []string{"tracker.example.com"}}); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		b, _ := os.ReadFile(filepath.Join(root, ProjectFile))
		p, err := policy.Parse("p", b)
		if err != nil || p.Validate(false) != nil {
			t.Errorf("%s: result invalid: %v\n%s", name, err, b)
			continue
		}
		last := p.Rules[len(p.Rules)-1]
		if last.Host != "tracker.example.com" || !last.IsDeny() {
			t.Errorf("%s: last rule = %+v", name, last)
		}
	}
}

func TestSaveWithoutPolicyFileExplainsTheNextStep(t *testing.T) {
	root := project(t, "")
	_, _, _, err := Save(root, Edit{Action: policy.ActionAllow, Hosts: []string{"a.example.com"}})
	if err == nil || !strings.Contains(err.Error(), "cellwall init") {
		t.Fatalf("want a pointer to `cellwall init`, got %v", err)
	}
}

func TestNothingIsWrittenThroughASymlink(t *testing.T) {
	root := project(t, seed)
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, ".cellwall", "state")); err != nil {
		t.Skip("symlinks unavailable: ", err)
	}
	if _, err := ApplySession(root, Edit{Action: policy.ActionAllow, Hosts: []string{"a.example.com"}}); err == nil {
		t.Fatal("writing the session layer through a symlinked state dir must fail")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Errorf("a file was written through the symlink: %v", entries)
	}
}
