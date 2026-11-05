package gen

import (
	"strings"
	"testing"
)

func TestComposePathTranslatesWindowsPaths(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Users\me\my proj`:  "C:/Users/me/my proj",
		`D:/already/slashed`:   "D:/already/slashed",
		`\\wsl$\Ubuntu\home\x`: "//wsl$/Ubuntu/home/x",
		"/home/me/proj":        "/home/me/proj",
	} {
		if got := ComposePath(in); got != want {
			t.Errorf("ComposePath(%q) = %q, want %q", in, got, want)
		}
	}
	f, err := EnvFile(1000, 1000, `C:\Users\me\proj`, `C:\Users\me\proj\.kennel\state`, "img", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.Content), "KENNEL_WORKSPACE='C:/Users/me/proj'") || strings.Contains(string(f.Content), `\`) {
		t.Errorf("env file has backslashes:\n%s", f.Content)
	}
}
