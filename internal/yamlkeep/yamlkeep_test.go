package yamlkeep

import "testing"

func TestBlankLinesAreRestored(t *testing.T) {
	orig := "# header\nversion: 1\n\n# stacks\nstacks: auto\n\nagent:\n  preset: claude\n\nworkspace:\n  mode: volume\n\nports: []\n"
	// What yaml.v3 writes after `ports add 5173`: comments kept, blank lines gone, value changed.
	out := "# header\nversion: 1\n# stacks\nstacks: auto\nagent:\n  preset: claude\nworkspace:\n  mode: volume\nports: [5173]\n"
	want := "# header\nversion: 1\n\n# stacks\nstacks: auto\n\nagent:\n  preset: claude\n\nworkspace:\n  mode: volume\nports: [5173]\n"
	if got := string(BlankLines([]byte(orig), []byte(out))); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestBlankLinesLeavesUnchangedAndNewContentAlone(t *testing.T) {
	orig := "a: 1\n\nb: 2\n"
	if got := string(BlankLines([]byte(orig), []byte(orig))); got != orig {
		t.Errorf("unchanged input was altered: %q", got)
	}
	// A line the edit added keeps no blank line; the original ones still come back.
	got := string(BlankLines([]byte(orig), []byte("a: 1\nnew: 3\nb: 2\n")))
	if got != "a: 1\nnew: 3\n\nb: 2\n" {
		t.Errorf("got %q", got)
	}
}

func TestBlankLinesHandlesCRLFSources(t *testing.T) {
	got := string(BlankLines([]byte("a: 1\r\n\r\nb: 2\r\n"), []byte("a: 1\nb: 2\n")))
	if got != "a: 1\n\nb: 2\n" {
		t.Errorf("got %q", got)
	}
}
