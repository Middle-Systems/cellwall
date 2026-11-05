package gen

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDumpForReading writes the rendered files for a fixture to $KENNEL_DUMP when set (a
// development aid for reading generator output; skipped otherwise).
func TestDumpForReading(t *testing.T) {
	out := os.Getenv("KENNEL_DUMP")
	if out == "" {
		t.Skip("set KENNEL_DUMP=<dir> to dump generated files")
	}
	fixture := os.Getenv("KENNEL_DUMP_FIXTURE")
	if fixture == "" {
		fixture = "node-vite"
	}
	in, presets := inputsFor(t, fixture, nil)
	files, err := Committed(in, presets)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		p := filepath.Join(out, filepath.FromSlash(f.Path))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, f.Content, f.Mode); err != nil {
			t.Fatal(err)
		}
	}
}
