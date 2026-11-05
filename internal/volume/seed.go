package volume

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Layout says where things are inside the agent container. The defaults are the real ones; tests
// point them at temporary directories.
type Layout struct {
	Work   string // the workspace, /workspace
	Bundle string // scratch path for the seed bundle (on the agent-home volume, not the small /tmp)
}

// DefaultLayout is the layout inside the generated agent container.
var DefaultLayout = Layout{Work: "/workspace", Bundle: "/home/dev/.kennel-seed.bundle"}

// SeedResult describes what seeding did.
type SeedResult struct {
	Already bool // the volume already held a repository; nothing was copied
	Branch  string
	Base    string
	Overlay int // modified or untracked files copied on top of HEAD
	Deleted int // tracked files deleted on the host and removed in the copy
}

// Seed copies the host repository into the workspace volume if the volume has no repository yet:
// the history of HEAD as a git bundle, then the uncommitted work (modified and untracked files not
// ignored by git, and deletions) as a tar stream. It is idempotent and never overwrites a volume
// that already holds a repository, because that is the agent's work.
func Seed(ctx context.Context, ag Agent, repo Repo, root string, lay Layout) (*SeedResult, error) {
	if lay.Work == "" {
		lay = DefaultLayout
	}
	if _, err := repo.out(ctx, "rev-parse", "--verify", "-q", "HEAD"); err != nil {
		return nil, errors.New("workspace.mode=volume needs a git repository with at least one commit: the agent works on a copy and its changes come back as commits\n  next: run `git init && git add -A && git commit -m initial` (or set workspace.mode to bind)")
	}
	if _, code, err := ag.Run(ctx, nil, nil, "git", "-C", lay.Work, "rev-parse", "--verify", "-q", "HEAD"); err != nil {
		return nil, err
	} else if code == 0 {
		return &SeedResult{Already: true}, nil
	}

	branch, berr := repo.out(ctx, "symbolic-ref", "--short", "-q", "HEAD")
	if berr != nil || branch == "" {
		branch = "main" // detached HEAD: the copy still needs a branch to commit on
	}
	base, err := repo.out(ctx, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}

	// 1. History: host `git bundle create - HEAD` -> a file on the agent-home volume.
	pr, pw := io.Pipe()
	bundleErr := make(chan error, 1)
	go func() {
		_, err := repo.hostGit(ctx, nil, pw, "bundle", "create", "-q", "-", "HEAD")
		_ = pw.CloseWithError(err)
		bundleErr <- err
	}()
	se, code, err := ag.Run(ctx, pr, nil, "sh", "-c", `cat > "$1"`, "sh", lay.Bundle)
	_ = pr.Close()
	if berr := <-bundleErr; berr != nil {
		return nil, fmt.Errorf("could not bundle the repository: %w", berr)
	}
	if err != nil || code != 0 {
		return nil, fmt.Errorf("could not copy the repository into the volume: %w: %s", err, strings.TrimSpace(se))
	}
	defer func() { _, _, _ = ag.Run(ctx, nil, nil, "rm", "-f", "--", lay.Bundle) }()

	steps := [][]string{
		{"git", "-C", lay.Work, "init", "-q", "-b", branch},
		{"git", "-C", lay.Work, "fetch", "-q", lay.Bundle, "HEAD:refs/kennel-seed"},
		{"git", "-C", lay.Work, "checkout", "-q", "-f", "-B", branch, "refs/kennel-seed"},
		{"git", "-C", lay.Work, "update-ref", "-d", "refs/kennel-seed"},
	}
	for _, s := range steps {
		if _, err := agentOut(ctx, ag, s...); err != nil {
			return nil, fmt.Errorf("seeding the workspace volume failed: %w", err)
		}
	}

	// 2. Uncommitted work.
	res := &SeedResult{Branch: branch, Base: base}
	if res.Overlay, res.Deleted, err = overlay(ctx, ag, repo, lay); err != nil {
		return nil, err
	}
	if err := SaveState(root, State{Base: base, Branch: branch}); err != nil {
		return nil, err
	}
	return res, nil
}

// overlay copies modified and untracked files onto the seeded checkout and removes files deleted on
// the host, so the agent starts from the working tree the user sees, not just from HEAD.
func overlay(ctx context.Context, ag Agent, repo Repo, lay Layout) (copied, deleted int, err error) {
	changed, err := repo.hostGit(ctx, nil, nil, "ls-files", "-z", "--modified", "--others", "--exclude-standard")
	if err != nil {
		return 0, 0, err
	}
	gone, err := repo.hostGit(ctx, nil, nil, "ls-files", "-z", "--deleted")
	if err != nil {
		return 0, 0, err
	}
	modes, _ := trackedModes(ctx, repo)

	var toCopy, toDelete []string
	for _, p := range splitNUL(changed) {
		fi, lerr := os.Lstat(filepath.Join(repo.Dir, filepath.FromSlash(p)))
		switch {
		case lerr != nil:
			toDelete = append(toDelete, p) // listed as modified but gone
		case fi.IsDir():
			// a submodule or nested repository: not copied
		default:
			toCopy = append(toCopy, p)
		}
	}
	toDelete = append(toDelete, splitNUL(gone)...)
	toDelete = dedupe(toDelete) // a deleted tracked file is listed by both --modified and --deleted

	if len(toCopy) > 0 {
		pr, pw := io.Pipe()
		werr := make(chan error, 1)
		go func() {
			err := writeTar(pw, repo.Dir, toCopy, modes)
			_ = pw.CloseWithError(err)
			werr <- err
		}()
		se, code, rerr := ag.Run(ctx, pr, nil, "tar", "-x", "-f", "-", "-C", lay.Work, "--no-same-owner")
		_ = pr.Close()
		if e := <-werr; e != nil {
			return 0, 0, fmt.Errorf("could not archive your uncommitted files: %w", e)
		}
		if rerr != nil || code != 0 {
			return 0, 0, fmt.Errorf("could not copy your uncommitted files into the volume: %w: %s", rerr, strings.TrimSpace(se))
		}
		copied = len(toCopy)
	}
	if len(toDelete) > 0 {
		var in bytes.Buffer
		for _, p := range toDelete {
			in.WriteString(p)
			in.WriteByte(0)
		}
		se, code, rerr := ag.Run(ctx, &in, nil, "sh", "-c", `cd "$1" && xargs -0 rm -f --`, "sh", lay.Work)
		if rerr != nil || code != 0 {
			return copied, 0, fmt.Errorf("could not apply your deletions in the volume: %w: %s", rerr, strings.TrimSpace(se))
		}
		deleted = len(toDelete)
	}
	return copied, deleted, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func splitNUL(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// trackedModes maps tracked paths to their git file mode so the executable bit survives hosts
// (Windows) that do not have one.
func trackedModes(ctx context.Context, repo Repo) (map[string]os.FileMode, error) {
	out, err := repo.hostGit(ctx, nil, nil, "ls-files", "-s", "-z")
	if err != nil {
		return nil, err
	}
	m := map[string]os.FileMode{}
	for _, rec := range splitNUL(out) {
		// "<mode> <sha> <stage>\t<path>"
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok {
			continue
		}
		if strings.HasPrefix(meta, "100755") {
			m[path] = 0o755
		} else {
			m[path] = 0o644
		}
	}
	return m, nil
}

// writeTar streams the named files, relative to dir, as a tar archive. Paths that could escape the
// destination are refused outright.
func writeTar(w io.Writer, dir string, paths []string, modes map[string]os.FileMode) error {
	tw := tar.NewWriter(w)
	for _, p := range paths {
		if !safeRel(p) {
			return fmt.Errorf("refusing path %q", p)
		}
		full := filepath.Join(dir, filepath.FromSlash(p))
		fi, err := os.Lstat(full)
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: p, ModTime: fi.ModTime(), Format: tar.FormatPAX}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(full)
			if err != nil {
				return err
			}
			hdr.Typeflag, hdr.Linkname, hdr.Mode = tar.TypeSymlink, filepath.ToSlash(target), 0o777
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
		case fi.Mode().IsRegular():
			mode := os.FileMode(0o644)
			if m, ok := modes[p]; ok {
				mode = m
			} else if fi.Mode().Perm()&0o111 != 0 {
				mode = 0o755
			}
			hdr.Typeflag, hdr.Mode, hdr.Size = tar.TypeReg, int64(mode), fi.Size()
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(full) //nolint:gosec // a path git listed inside the repository
			if err != nil {
				return err
			}
			_, cerr := io.Copy(tw, f)
			_ = f.Close()
			if cerr != nil {
				return cerr
			}
		default:
			// sockets, devices, fifos: not part of a repository
		}
	}
	return tw.Close()
}

// safeRel accepts only clean, relative, forward-slash paths that stay inside the destination.
func safeRel(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." || part == "" || part == "." {
			return false
		}
	}
	return true
}
