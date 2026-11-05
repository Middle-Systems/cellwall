package gen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-systems/kennel/internal/config"
	"github.com/middle-systems/kennel/internal/detect"
)

func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "test", "fixtures", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("missing fixture %s", name)
	}
	return p
}

// inputsFor mirrors what `init` does for a fixture: detect, plan, then a validated config.
func inputsFor(t *testing.T, fixture string, mutate func(*config.Config)) (Inputs, []string) {
	t.Helper()
	root := fixtureDir(t, fixture)
	res, err := detect.Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	gi := detect.ParseGitIgnore(readIfExists(filepath.Join(root, ".gitignore")))
	plan := detect.PlanFor(res, gi.Ignored, func(d string) bool {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(d)))
		return err == nil && len(entries) > 0
	})
	cfg := config.Default()
	cfg.Project = strings.ReplaceAll(fixture, ".", "-")
	cfg.Ports = plan.Ports
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config for %s invalid: %v", fixture, err)
	}
	return Inputs{Config: cfg, Detect: res, Plan: plan}, plan.Presets
}

func readIfExists(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func contentOf(t *testing.T, files []File, path string) string {
	t.Helper()
	for _, f := range files {
		if f.Path == path {
			return string(f.Content)
		}
	}
	var have []string
	for _, f := range files {
		have = append(have, f.Path)
	}
	t.Fatalf("no file %s among %v", path, have)
	return ""
}
