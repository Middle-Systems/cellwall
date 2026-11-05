//go:build e2e

package e2e

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

type verifyReport struct {
	Results []struct {
		ID     int    `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"results"`
	Failed bool `json:"failed"`
}

func (p *project) verify(args ...string) (verifyReport, result) {
	p.t.Helper()
	r := p.cw("", append([]string{"verify", "--json"}, args...)...)
	var rep verifyReport
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
		p.t.Fatalf("verify --json: %v\nstdout:\n%s\nstderr:\n%s", err, r.out, r.err)
	}
	return rep, r
}

func statuses(rep verifyReport) map[string]string {
	m := map[string]string{}
	for _, r := range rep.Results {
		m[r.Name] = r.Status
	}
	return m
}

// TestVerifyCommand runs `kennel verify --strict` against the real topology: every check of spec
// section 10 must PASS (a skip fails in strict mode), and then proves the suite is not vacuous by
// breaking the sandbox on purpose and requiring it to notice.
func TestVerifyCommand(t *testing.T) {
	requireDocker(t)
	p := newProject(t, "node-vite") // node-vite configures preview port 5173
	p.must(p.cw("", "init"), "init")
	p.must(p.cw("", "up"), "up")

	t.Run("a correctly configured sandbox passes all 12 checks", func(t *testing.T) {
		rep, r := p.verify("--strict")
		if len(rep.Results) != 12 {
			t.Fatalf("want 12 checks, got %d", len(rep.Results))
		}
		for _, res := range rep.Results {
			if res.Status != "pass" {
				t.Errorf("%d %s: %s: %s", res.ID, res.Name, res.Status, res.Detail)
			}
		}
		if rep.Failed || r.code != 0 {
			t.Errorf("verify exit %d, failed=%v", r.code, rep.Failed)
		}
	})

	t.Run("verify leaves no session rule behind", func(t *testing.T) {
		out := p.must(p.cw("", "status", "--json"), "status").out
		if strings.Contains(out, "session rule") {
			t.Errorf("the temporary rules were not removed:\n%s", out)
		}
	})

	t.Run("read-only mode skips only the checks that edit policy", func(t *testing.T) {
		rep, r := p.verify("--read-only")
		st := statuses(rep)
		if st["internal-addresses"] != "skip" || st["hot-reload"] != "skip" {
			t.Errorf("statuses: %v", st)
		}
		if r.code != 0 {
			t.Errorf("skips alone must not fail a non-strict run, exit %d", r.code)
		}
		if _, strict := p.verify("--read-only", "--strict"); strict.code == 0 {
			t.Error("--strict must fail when checks are skipped")
		}
	})

	t.Run("an agent given a route to the internet is caught", func(t *testing.T) {
		project := strings.TrimSpace(p.must(p.cw("", "status", "--json"), "status").out)
		var st struct {
			Network struct {
				Name string `json:"name"`
			} `json:"network"`
		}
		if err := json.Unmarshal([]byte(project), &st); err != nil {
			t.Fatal(err)
		}
		egress := strings.TrimSuffix(st.Network.Name, "_sandbox") + "_egress"
		agent := strings.TrimSuffix(st.Network.Name, "_sandbox") + "-agent-1"
		if out, err := exec.Command("docker", "network", "connect", egress, agent).CombinedOutput(); err != nil {
			t.Fatalf("docker network connect: %v\n%s", err, out)
		}
		defer func() { _ = exec.Command("docker", "network", "disconnect", egress, agent).Run() }()

		rep, r := p.verify("--only", "direct-egress,dns-leak,host-isolation")
		st2 := statuses(rep)
		if st2["direct-egress"] != "fail" || st2["dns-leak"] != "fail" {
			t.Errorf("a sandbox with an internet route must fail direct-egress and dns-leak: %v", st2)
		}
		if r.code == 0 {
			t.Error("verify must exit non-zero when a check fails")
		}
	})

	t.Run("and passes again once the hole is closed", func(t *testing.T) {
		rep, r := p.verify("--strict", "--only", "direct-egress,dns-leak,host-isolation")
		if rep.Failed || r.code != 0 {
			t.Errorf("verify after repair: %+v", statuses(rep))
		}
	})
}
