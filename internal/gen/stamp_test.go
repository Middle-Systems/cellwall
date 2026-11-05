package gen

import (
	"strings"
	"testing"
)

func TestStampRoundTrip(t *testing.T) {
	for _, tc := range []struct{ comment, body string }{
		{"#", "FROM debian\nRUN true\n"},
		{"//", "{\n  \"name\": \"x\"\n}\n"},
		{"#", "#!/bin/sh\nset -eu\nexec \"$@\"\n"},
		{"#", ""},
	} {
		s := Stamp(tc.comment, tc.body)
		if got := Inspect([]byte(s)); got != Pristine {
			t.Errorf("%q: %v", tc.body, got)
		}
	}
	// The shebang stays on line one.
	if s := Stamp("#", "#!/bin/sh\necho hi\n"); !strings.HasPrefix(s, "#!/bin/sh\n# kennel:generated sha256=") {
		t.Errorf("shebang moved: %q", s)
	}
}

func TestInspectDetectsEditsAndForeignFiles(t *testing.T) {
	s := Stamp("#", "a: 1\nb: 2\n")
	if Inspect([]byte(strings.Replace(s, "a: 1", "a: 9", 1))) != Edited {
		t.Error("an edited body must be reported as Edited")
	}
	if Inspect([]byte(s+"c: 3\n")) != Edited {
		t.Error("appended content is an edit")
	}
	// Tampering with the hash itself is also detected.
	if Inspect([]byte(strings.Replace(s, "sha256=", "sha256=0", 1))) == Pristine {
		t.Error("a malformed marker must not count as pristine")
	}
	for _, foreign := range []string{"", "FROM debian\n", "# just a comment\n", "# kennel:generated sha256=short\nx\n", "x\ny\n# kennel:generated sha256=" + strings.Repeat("a", 64) + "\n"} {
		if got := Inspect([]byte(foreign)); got != Unstamped {
			t.Errorf("%q should be unstamped, got %v", foreign, got)
		}
	}
	// CRLF checkouts (Windows) must not turn pristine files into "edited" ones silently: they ARE
	// different bytes, so they are reported as edited, which is why .gitattributes forces LF.
	if Inspect([]byte(strings.ReplaceAll(s, "\n", "\r\n"))) == Pristine {
		t.Error("CRLF-converted content is not byte-identical")
	}
}
