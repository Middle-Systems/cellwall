package volume

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// RefPrefix is where the agent's branches land on the host. Nothing outside this namespace is ever
// written by `fetch`.
const RefPrefix = "refs/kennel/"

// alwaysGated are paths that run on the host or in its tooling when someone later checks out,
// commits or builds, whether or not they are in protected_paths. Changes to them are held for
// confirmation like protected paths are.
var alwaysGated = []string{".gitmodules", ".gitattributes", ".husky", ".pre-commit-config.yaml"}

// Change is one path the agent's branch changes relative to the host's HEAD.
type Change struct {
	Status    string `json:"status"` // A, M, D, T
	Path      string `json:"path"`
	Protected bool   `json:"protected"`
}

// BranchReport describes one fetched branch.
type BranchReport struct {
	Branch  string   `json:"branch"`
	Ref     string   `json:"ref"`
	Commit  string   `json:"commit"`
	Commits int      `json:"commits"`
	Changes []Change `json:"changes"`
}

// Protected returns the changes that need confirmation.
func (b BranchReport) Protected() []Change {
	var out []Change
	for _, c := range b.Changes {
		if c.Protected {
			out = append(out, c)
		}
	}
	return out
}

// FetchResult is what `kennel fetch` found.
type FetchResult struct {
	Nothing    bool           `json:"nothing_new"`
	Branches   []BranchReport `json:"branches"`
	AgentDirty int            `json:"agent_uncommitted_files"`
}

// FetchOptions configures Fetch.
type FetchOptions struct {
	Layout    Layout
	Protected []string // config.ProtectedSet()
}

// Fetch brings the agent's new commits into refs/kennel/* on the host and reports what they
// change. It never touches the host's branches, index or working tree.
func Fetch(ctx context.Context, ag Agent, repo Repo, root string, o FetchOptions) (*FetchResult, error) {
	lay := o.Layout
	if lay.Work == "" {
		lay = DefaultLayout
	}
	st, err := LoadState(root)
	if err != nil {
		return nil, err
	}
	res := &FetchResult{}
	if status, err := agentOut(ctx, ag, "git", "-C", lay.Work, "status", "--porcelain=v1", "-z", "--untracked-files=normal"); err == nil {
		res.AgentDirty = len(splitNUL(status))
	}

	tmp, err := os.CreateTemp("", "kennel-fetch-*.bundle")
	if err != nil {
		return nil, err
	}
	bundlePath := tmp.Name()
	defer func() { _ = os.Remove(bundlePath) }()

	se, code, err := ag.Run(ctx, nil, tmp, "git", "-C", lay.Work, "bundle", "create", "-q", "-", "--branches", "^"+st.Base)
	_ = tmp.Close()
	if err != nil {
		return nil, err
	}
	if code != 0 {
		if strings.Contains(se, "empty bundle") {
			res.Nothing = true
			return res, nil
		}
		return nil, fmt.Errorf("the agent could not bundle its commits: %s", strings.TrimSpace(se))
	}

	// The bundle must apply to what the host already has; a bundle that does not is either stale
	// (the host history moved) or not what we asked for.
	if _, err := repo.hostGit(ctx, nil, nil, "bundle", "verify", bundlePath); err != nil {
		return nil, fmt.Errorf("the agent's commits do not apply to this repository: %w\n  next: the host history changed since the volume was seeded; fetch from a fresh volume (`kennel down --volumes` after saving what you need) or merge manually", err)
	}

	if err := importBundle(ctx, repo, bundlePath, st.Base); err != nil {
		return nil, err
	}
	after, err := refSnapshot(ctx, repo)
	if err != nil {
		return nil, err
	}

	gated := gatedSet(o.Protected)
	var names []string
	for ref := range after {
		names = append(names, ref)
	}
	sort.Strings(names)
	for _, ref := range names {
		br, err := report(ctx, repo, ref, after[ref], gated)
		if err != nil {
			return nil, err
		}
		if br.Commits > 0 || len(br.Changes) > 0 {
			res.Branches = append(res.Branches, br)
		}
	}
	res.Nothing = len(res.Branches) == 0
	return res, nil
}

// importBundle brings a verified bundle's objects and branches into the host repository.
//
// It deliberately does not use `git fetch <bundle>`: fetching from a bundle skips fsck whatever
// transfer.fsckObjects says (found by TestFetchRejectsObjectsThatFailFsck), and these objects come
// from the agent. Instead the pack inside the bundle goes through `git index-pack --strict`, which
// rejects hostile trees (an entry named .git, for one) before anything is stored, and only then
// are the namespaced refs written.
func importBundle(ctx context.Context, repo Repo, bundlePath, base string) error {
	heads, err := repo.out(ctx, "bundle", "list-heads", bundlePath)
	if err != nil {
		return fmt.Errorf("could not read the agent's bundle: %w", err)
	}
	type head struct{ sha, name string }
	var hs []head
	for _, line := range strings.Split(heads, "\n") {
		sha, name, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || !strings.HasPrefix(name, "refs/heads/") || !isHexSHA(sha) {
			continue // tags, HEAD and anything else the agent put in the bundle are ignored
		}
		dst := RefPrefix + strings.TrimPrefix(name, "refs/heads/")
		if _, err := repo.hostGit(ctx, nil, nil, "check-ref-format", dst); err != nil {
			return fmt.Errorf("the agent created a branch with an invalid name (%q): %w", name, err)
		}
		hs = append(hs, head{sha, dst})
	}
	if len(hs) == 0 {
		return nil
	}

	f, err := os.Open(bundlePath) //nolint:gosec // our own temp file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	br := bufio.NewReader(f)
	for { // skip the text header: it ends at the first empty line
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("the agent's bundle is truncated: %w", err)
		}
		if line == "\n" {
			break
		}
	}
	if _, err := repo.hostGit(ctx, br, nil, "index-pack", "--stdin", "--fix-thin", "--strict"); err != nil {
		return fmt.Errorf("the agent's commits failed git's integrity checks and were not stored: %w", err)
	}

	var updates bytes.Buffer
	for _, h := range hs {
		if _, err := repo.hostGit(ctx, nil, nil, "rev-list", "--quiet", "--objects", h.sha, "--not", base); err != nil {
			return fmt.Errorf("the agent's branch %s is missing objects: %w", h.name, err)
		}
		fmt.Fprintf(&updates, "update %s %s\n", h.name, h.sha)
	}
	if _, err := repo.hostGit(ctx, &updates, nil, "update-ref", "--stdin"); err != nil {
		return fmt.Errorf("could not record the fetched branches: %w", err)
	}
	return nil
}

func isHexSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func refSnapshot(ctx context.Context, repo Repo) (map[string]string, error) {
	out, err := repo.hostGit(ctx, nil, nil, "for-each-ref", "--format=%(refname)%00%(objectname)", RefPrefix)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if ref, sha, ok := strings.Cut(line, "\x00"); ok {
			m[ref] = sha
		}
	}
	return m, nil
}

// report computes what merging ref into the host's HEAD would change.
func report(ctx context.Context, repo Repo, ref, sha string, gated []string) (BranchReport, error) {
	br := BranchReport{Branch: strings.TrimPrefix(ref, RefPrefix), Ref: ref, Commit: sha}
	n, err := repo.out(ctx, "rev-list", "--count", "HEAD.."+ref)
	if err != nil {
		return br, err
	}
	br.Commits, _ = strconv.Atoi(n)
	out, err := repo.hostGit(ctx, nil, nil, "diff", "--name-status", "-z", "--no-renames", "HEAD..."+ref)
	if err != nil {
		return br, err
	}
	parts := splitNUL(out)
	for i := 0; i+1 < len(parts); i += 2 {
		br.Changes = append(br.Changes, Change{Status: parts[i], Path: parts[i+1], Protected: isGated(parts[i+1], gated)})
	}
	return br, nil
}

func gatedSet(protected []string) []string {
	return append(append([]string(nil), protected...), alwaysGated...)
}

// isGated reports whether path is one of the gated paths or lies inside one.
func isGated(path string, gated []string) bool {
	for _, g := range gated {
		g = strings.TrimSuffix(g, "/")
		if path == g || strings.HasPrefix(path, g+"/") {
			return true
		}
	}
	return false
}

// ProtectedError is returned by Apply when the branch changes gated paths and the caller has not
// confirmed.
type ProtectedError struct{ Changes []Change }

func (e *ProtectedError) Error() string {
	var ps []string
	for _, c := range e.Changes {
		ps = append(ps, c.Path)
	}
	return "the agent changed files that run on your machine: " + strings.Join(ps, ", ")
}

// Apply fast-forwards the host's current branch to the fetched ref. It refuses unless the working
// tree is clean and the move is a pure fast-forward, and it stops at changes to gated paths unless
// allowProtected is set. On success the seeding base moves up so later bundles stay small.
func Apply(ctx context.Context, repo Repo, root, branch string, protected []string, allowProtected bool) (*BranchReport, error) {
	ref := RefPrefix + branch
	sha, err := repo.out(ctx, "rev-parse", "--verify", "-q", ref+"^{commit}")
	if err != nil || sha == "" {
		return nil, fmt.Errorf("no fetched branch %q (run `kennel fetch` first; fetched branches: %s)", branch, strings.Join(fetchedNames(ctx, repo), ", "))
	}
	br, err := report(ctx, repo, ref, sha, gatedSet(protected))
	if err != nil {
		return nil, err
	}
	if p := br.Protected(); len(p) > 0 && !allowProtected {
		return &br, &ProtectedError{Changes: p}
	}
	if st, err := repo.out(ctx, "status", "--porcelain"); err != nil {
		return nil, err
	} else if st != "" {
		return nil, errors.New("your working tree has uncommitted changes, so nothing was merged\n  next: commit or stash them, then re-run `kennel fetch --apply`")
	}
	if _, err := repo.hostGit(ctx, nil, nil, "merge", "--ff-only", "--quiet", ref); err != nil {
		return nil, fmt.Errorf("%w\n  next: your branch has moved on since the volume was seeded, so this is not a fast-forward; merge it yourself: git merge %s", err, ref)
	}
	if cur, err := LoadState(root); err == nil {
		cur.Base = sha
		_ = SaveState(root, cur)
	}
	return &br, nil
}

func fetchedNames(ctx context.Context, repo Repo) []string {
	m, _ := refSnapshot(ctx, repo)
	var out []string
	for r := range m {
		out = append(out, strings.TrimPrefix(r, RefPrefix))
	}
	sort.Strings(out)
	return out
}

// Pending counts the agent's commits the host does not have, and its uncommitted files: what
// would be lost by deleting the workspace volume.
func Pending(ctx context.Context, ag Agent, repo Repo, lay Layout) (commits, dirty int, err error) {
	if lay.Work == "" {
		lay = DefaultLayout
	}
	heads, err := agentOut(ctx, ag, "git", "-C", lay.Work, "for-each-ref", "--format=%(objectname)", "refs/heads/")
	if err != nil {
		return 0, 0, err
	}
	seen := map[string]bool{}
	for _, sha := range strings.Fields(heads) {
		if seen[sha] {
			continue
		}
		seen[sha] = true
		if _, err := repo.hostGit(ctx, nil, nil, "cat-file", "-e", sha+"^{commit}"); err != nil {
			commits++
		}
	}
	if status, err := agentOut(ctx, ag, "git", "-C", lay.Work, "status", "--porcelain=v1", "-z"); err == nil {
		dirty = len(splitNUL(status))
	}
	return commits, dirty, nil
}

// Diff returns the unified diff of the gated paths for display before confirmation.
func Diff(ctx context.Context, repo Repo, branch string, paths []string) (string, error) {
	if len(paths) == 0 {
		return "", nil
	}
	args := append([]string{"diff", "--no-color", "HEAD..." + RefPrefix + branch, "--"}, paths...)
	var b bytes.Buffer
	if _, err := repo.hostGit(ctx, nil, &b, args...); err != nil {
		return "", err
	}
	return b.String(), nil
}
