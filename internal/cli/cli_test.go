package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/middle-systems/kennel/internal/version"
)

func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := NewRootCmd(&out, &errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

func TestVersionText(t *testing.T) {
	out, _, err := run(t, "version")
	if err != nil || !strings.HasPrefix(out, "kennel "+version.Version) {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestVersionJSON(t *testing.T) {
	out, _, err := run(t, "version", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var info version.Info
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("invalid json %q: %v", out, err)
	}
	if info.Version != version.Version || info.OS == "" {
		t.Errorf("info = %+v", info)
	}
}

func TestUnknownFlagIsError(t *testing.T) {
	if _, _, err := run(t, "version", "--nope"); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestDoctorJSONIsValid(t *testing.T) {
	// Result depends on the host, so only assert the shape; failures surface as ExitError.
	out, _, err := run(t, "doctor", "--json")
	if err != nil {
		var ee *ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("unexpected error type: %v", err)
		}
	}
	var rep struct {
		Results []struct{ ID, Status string } `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Results) == 0 {
		t.Fatalf("bad doctor json %q: %v", out, err)
	}
}
