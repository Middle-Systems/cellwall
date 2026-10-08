//go:build !windows

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-systems/cellwall/internal/audit"
)

const fakeDockerScript = `#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$*" in
  "info --format {{.ServerVersion}}") [ -n "$FAKE_INFO_FAIL" ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }; echo 29.0; exit 0;;
  "info --format {{.NCPU}}") echo 8; exit 0;;
  "image inspect"*) echo "<no value>"; exit 0;;
  *" ps --status running -q "*) [ "${FAKE_RUNNING:-1}" = 1 ] && echo cid; exit 0;;
  *" gateway status"*) echo '{"policy":{"policy_hash":"x"}}'; exit 0;;
  *" build"*) [ -n "$FAKE_BUILD_ERR" ] && { echo "$FAKE_BUILD_ERR" >&2; exit 1; }; exit 0;;
  *" up "*) [ -n "$FAKE_UP_ERR" ] && { echo "$FAKE_UP_ERR" >&2; exit 1; }; exit 0;;
  *" logs "*) echo "gateway-1  | audit: open log: permission denied"; exit 0;;
  *" exec "*) exit ${FAKE_EXIT:-0};;
esac
exit 0
`

// fakeEngine puts a recording `docker` on PATH and returns the path of its call log.
func fakeEngine(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fakeDockerScript), 0o755); err != nil { //nolint:gosec // test double
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls.log")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_LOG", log)
	for _, k := range []string{"FAKE_EXIT", "FAKE_RUNNING", "FAKE_UP_ERR", "FAKE_INFO_FAIL", "FAKE_BUILD_ERR"} {
		t.Setenv(k, "")
	}
	return log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	b, _ := os.ReadFile(log)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func firstIndex(lines []string, sub string) int {
	for i, l := range lines {
		if strings.Contains(l, sub) {
			return i
		}
	}
	return -1
}

// runWith runs the CLI with the given stdin (never the test process's terminal).
func runWith(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := NewRootCmd(&out, &errb)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

func initialisedProject(t *testing.T, fx string) string {
	t.Helper()
	dir := fixture(t, fx)
	if _, _, err := run(t, "init", "--project-dir", dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunStartsTheSandboxThenExecsThroughTheEntrypointAndPropagatesTheExitCode(t *testing.T) {
	log := fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	t.Setenv("FAKE_EXIT", "42")

	_, _, err := runWith(t, "", "run", "--project-dir", dir, "--no-tty", "--", "--model", "sonnet")
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 42 {
		t.Fatalf("want exit 42, got %v", err)
	}
	lines := calls(t, log)
	up, ex := firstIndex(lines, " up -d --wait"), firstIndex(lines, " exec -T agent")
	if up < 0 || ex < 0 || up > ex {
		t.Fatalf("up must come before exec:\n%s", strings.Join(lines, "\n"))
	}
	if !strings.Contains(lines[ex], "exec -T agent /usr/local/bin/cellwall-entrypoint claude --model sonnet") {
		t.Errorf("the agent must be started through the entrypoint with the user's arguments: %s", lines[ex])
	}
}

func TestRunWithExitZeroSucceeds(t *testing.T) {
	fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	if _, _, err := runWith(t, "", "run", "--project-dir", dir, "--no-tty"); err != nil {
		t.Fatal(err)
	}
}

func TestAnEmptyAgentCommandIsRefusedByConfigBeforeAnythingStarts(t *testing.T) {
	fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	cfg := filepath.Join(dir, ".cellwall", "config.yaml")
	b, _ := os.ReadFile(cfg)
	b = []byte(strings.Replace(string(b), `command: ["claude"]`, `command: []`, 1))
	if err := os.WriteFile(cfg, b, 0o644); err != nil {
		t.Fatal(err)
	}
	log := fakeEngine(t)
	_, _, err := runWith(t, "", "run", "--project-dir", dir, "--no-tty")
	if err == nil || !strings.Contains(err.Error(), "agent.command") {
		t.Fatalf("got %v", err)
	}
	if firstIndex(calls(t, log), " up ") >= 0 {
		t.Error("nothing should start with an invalid config")
	}
}

func TestRunBeforeInitSaysInit(t *testing.T) {
	fakeEngine(t)
	dir := fixture(t, "go-http")
	_, _, err := runWith(t, "", "run", "--project-dir", dir, "--no-tty")
	if err == nil || !strings.Contains(err.Error(), "cellwall init") {
		t.Fatalf("got %v", err)
	}
}

func TestShellNeedsARunningSandbox(t *testing.T) {
	fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	t.Setenv("FAKE_RUNNING", "0")
	_, _, err := runWith(t, "", "shell", "--project-dir", dir, "--no-tty")
	if err == nil || !strings.Contains(err.Error(), "cellwall up") {
		t.Fatalf("got %v", err)
	}
}

func TestUpFailureShowsTheGatewayLogAndANextStep(t *testing.T) {
	fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	t.Setenv("FAKE_UP_ERR", "dependency failed to start: container gateway is unhealthy")
	_, _, err := runWith(t, "", "up", "--project-dir", dir)
	if err == nil {
		t.Fatal("expected a failure")
	}
	for _, want := range []string{"did not start", "permission denied", "next:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestUpWithTheEngineDownSaysSo(t *testing.T) {
	log := fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	t.Setenv("FAKE_INFO_FAIL", "1")
	_, _, err := runWith(t, "", "up", "--project-dir", dir)
	if err == nil || !strings.Contains(err.Error(), "not reachable") || !strings.Contains(err.Error(), "cellwall doctor") {
		t.Fatalf("got %v", err)
	}
	if firstIndex(calls(t, log), " up ") >= 0 {
		t.Error("nothing should be started when the engine is down")
	}
	// And prepare must not have run: a failed `up` leaves no half-written state.
	if _, statErr := os.Stat(filepath.Join(dir, ".cellwall", "state")); statErr == nil {
		t.Error("state was written although the engine check failed")
	}
}

func TestDownVolumesNeedsAnExplicitYesWhenThereIsNoTerminal(t *testing.T) {
	log := fakeEngine(t)
	dir := initialisedProject(t, "go-http")

	_, errOut, err := runWith(t, "", "down", "--project-dir", dir, "--volumes")
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 1 || !strings.Contains(errOut, "--yes") {
		t.Fatalf("want a refusal naming --yes, got err=%v stderr=%q", err, errOut)
	}
	if firstIndex(calls(t, log), " down ") >= 0 {
		t.Error("down must not run without confirmation")
	}

	if _, _, err := runWith(t, "", "down", "--project-dir", dir, "--volumes", "--yes"); err != nil {
		t.Fatal(err)
	}
	if firstIndex(calls(t, log), "down --remove-orphans --timeout 10 --volumes") < 0 {
		t.Errorf("down --volumes was not invoked:\n%v", calls(t, log))
	}
	// Without --volumes there is nothing to confirm.
	if _, _, err := runWith(t, "", "down", "--project-dir", dir); err != nil {
		t.Fatal(err)
	}
}

func TestAllowAndDenyFromTheCommandLine(t *testing.T) {
	fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	t.Setenv("FAKE_RUNNING", "0")

	out, _, err := runWith(t, "", "allow", "--project-dir", dir, "registry.example.org", "other.example.org")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"allowed registry.example.org", "this session only", "next `cellwall up`", "undo with"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	out, _, err = runWith(t, "", "deny", "--project-dir", dir, "tracker.example.org", "--save")
	if err != nil || !strings.Contains(out, "saved to .cellwall/policy.yaml") {
		t.Fatalf("deny --save: %v\n%s", err, out)
	}
	pol, _ := os.ReadFile(filepath.Join(dir, ".cellwall", "policy.yaml"))
	if !strings.Contains(string(pol), "tracker.example.org") {
		t.Error("the saved deny is not in the committed policy")
	}

	out, _, err = runWith(t, "", "allow", "--project-dir", dir, "x.example.org", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]any
	if json.Unmarshal([]byte(out), &res) != nil {
		t.Errorf("--json output is not JSON: %s", out)
	}

	_, _, err = runWith(t, "", "allow", "--project-dir", dir, "https://nope.example.org/path")
	if err == nil || !strings.Contains(err.Error(), "not a hostname") {
		t.Errorf("a URL must be refused with an explanation, got %v", err)
	}
	if _, _, err = runWith(t, "", "allow", "--project-dir", dir); err == nil {
		t.Error("allow with no host must fail")
	}
}

func TestLogsDeniedGroupsAndSuggests(t *testing.T) {
	fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	auditDir := filepath.Join(dir, ".cellwall", "state", "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var lines []string
	add := func(age time.Duration, action, host string, port int, reason string) {
		b, _ := json.Marshal(audit.Record{TS: now.Add(-age), Event: "decision", Action: action, Host: host, Port: port, Reason: reason})
		lines = append(lines, string(b))
	}
	for i := 0; i < 3; i++ {
		add(time.Minute, "deny", "registry.example.org", 443, "default-deny")
	}
	add(2*time.Hour, "deny", "ancient.example.org", 443, "default-deny")
	add(time.Minute, "allow", "ok.example.org", 443, "rule")
	add(time.Minute, "deny", "10.1.2.3", 443, "ip-literal")
	if err := os.WriteFile(filepath.Join(auditDir, "audit.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, err := runWith(t, "", "logs", "--project-dir", dir, "--denied", "--since", "1h")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"3  registry.example.org:443", "cellwall allow registry.example.org", "no rule can fix this"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ancient.example.org") || strings.Contains(out, "ok.example.org") {
		t.Errorf("--since and --denied must filter:\n%s", out)
	}

	out, _, err = runWith(t, "", "logs", "--project-dir", dir, "--denied", "--json")
	var groups []map[string]any
	if err != nil || json.Unmarshal([]byte(out), &groups) != nil || len(groups) != 3 {
		t.Fatalf("--denied --json: %v %s", err, out)
	}

	out, _, err = runWith(t, "", "logs", "--project-dir", dir, "--json")
	if err != nil || len(strings.Split(strings.TrimSpace(out), "\n")) != 6 {
		t.Fatalf("--json should print one record per line: %v\n%s", err, out)
	}

	if _, _, err := runWith(t, "", "logs", "--project-dir", dir, "--since", "yesterday-ish"); err == nil {
		t.Error("a bad --since must be refused")
	}
}

func TestLogsBeforeTheSandboxHasRunIsNotAnError(t *testing.T) {
	fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	_, errOut, err := runWith(t, "", "logs", "--project-dir", dir, "--denied")
	if err != nil || !strings.Contains(errOut, "cellwall up") {
		t.Fatalf("err=%v stderr=%q", err, errOut)
	}
}

func TestStatusWithNothingRunning(t *testing.T) {
	fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	t.Setenv("FAKE_RUNNING", "0")
	out, _, err := runWith(t, "", "status", "--project-dir", dir)
	if err != nil || !strings.Contains(out, "not running") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	out, _, err = runWith(t, "", "status", "--project-dir", dir, "--json")
	var rep map[string]any
	if err != nil || json.Unmarshal([]byte(out), &rep) != nil {
		t.Fatalf("status --json: %v\n%s", err, out)
	}
}

func TestPortsAddRecreatesOnlyTheGatewayWhenRunning(t *testing.T) {
	log := fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	// 3000 is free on the machine running the test with overwhelming probability; the fake engine
	// pretends the sandbox is running, so the host-side port check is not the subject here.
	out, _, err := runWith(t, "", "ports", "add", "--project-dir", dir, "39173")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "added [39173]") || !strings.Contains(out, "gateway was recreated") {
		t.Errorf("output:\n%s", out)
	}
	if firstIndex(calls(t, log), "up -d --no-deps --wait gateway") < 0 {
		t.Errorf("only the gateway should be recreated:\n%v", calls(t, log))
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, ".cellwall", "config.yaml"))
	if !strings.Contains(string(cfg), "39173") {
		t.Errorf("config:\n%s", cfg)
	}

	out, _, err = runWith(t, "", "ports", "rm", "--project-dir", dir, "39173")
	if err != nil || !strings.Contains(out, "removed [39173]") {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	if _, _, err = runWith(t, "", "ports", "rm", "--project-dir", dir, "39173"); err == nil || !strings.Contains(err.Error(), "ports ls") {
		t.Errorf("removing a port twice should explain: %v", err)
	}
	if _, _, err = runWith(t, "", "ports", "add", "--project-dir", dir, "http"); err == nil {
		t.Error("a non-numeric port must be refused")
	}
}

func TestPortsAddWithTheSandboxDownOnlyEditsFiles(t *testing.T) {
	log := fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	t.Setenv("FAKE_RUNNING", "0")
	out, _, err := runWith(t, "", "ports", "add", "--project-dir", dir, "39174")
	if err != nil || !strings.Contains(out, "next `cellwall up`") {
		t.Fatalf("%v\n%s", err, out)
	}
	if firstIndex(calls(t, log), " up ") >= 0 {
		t.Error("nothing should be recreated when the sandbox is down")
	}
}

func TestPortsLsListsConfiguredPorts(t *testing.T) {
	fakeEngine(t)
	dir := initialisedProject(t, "node-vite")
	t.Setenv("FAKE_RUNNING", "0")
	out, _, err := runWith(t, "", "ports", "ls", "--project-dir", dir)
	if err != nil || !strings.Contains(out, "5173") || !strings.Contains(out, "agent not running") {
		t.Fatalf("%v\n%s", err, out)
	}
	out, _, err = runWith(t, "", "ports", "ls", "--project-dir", dir, "--json")
	var rep struct{ Ports []struct{ Port int } }
	if err != nil || json.Unmarshal([]byte(out), &rep) != nil || len(rep.Ports) != 1 || rep.Ports[0].Port != 5173 {
		t.Fatalf("json: %v\n%s", err, out)
	}
}

func TestUpAlwaysBuildsTheAgentImageBeforeStarting(t *testing.T) {
	log := fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	if _, _, err := runWith(t, "", "up", "--project-dir", dir); err != nil {
		t.Fatal(err)
	}
	lines := calls(t, log)
	b, u := firstIndex(lines, " build"), firstIndex(lines, " up -d --wait")
	if b < 0 || u < 0 || b > u {
		t.Fatalf("build must run before up so a stale image is never reused:\n%s", strings.Join(lines, "\n"))
	}
	if strings.Contains(lines[b], "--no-cache") {
		t.Error("a normal up must use the build cache")
	}
	if _, _, err := runWith(t, "", "up", "--project-dir", dir, "--rebuild"); err != nil {
		t.Fatal(err)
	}
	if firstIndex(calls(t, log), "--no-cache") < 0 {
		t.Error("--rebuild means a build without the cache")
	}
}

func TestAFailedImageBuildShowsItsOutputAndANextStep(t *testing.T) {
	log := fakeEngine(t)
	dir := initialisedProject(t, "go-http")
	t.Setenv("FAKE_BUILD_ERR", "E: Unable to locate package nope")
	_, errOut, err := runWith(t, "", "up", "--project-dir", dir)
	if err == nil || !strings.Contains(err.Error(), "building the agent image failed") || !strings.Contains(err.Error(), "next:") {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(errOut, "Unable to locate package") {
		t.Errorf("the held-back build output must be shown on failure, stderr=%q", errOut)
	}
	if firstIndex(calls(t, log), " up -d") >= 0 {
		t.Error("nothing should start after a failed build")
	}
}
