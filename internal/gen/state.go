package gen

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/middle-systems/kennel/internal/config"
)

// PathInfo is what the generator needs to know about a workspace path. It is injected so the
// protected-path logic is a pure function that tests can drive without touching disk.
type PathInfo struct {
	Exists    bool
	IsDir     bool
	IsSymlink bool
}

// Mount is one bind mount added to the agent.
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// ProtectedPlan is the outcome of planning protected-path mounts.
type ProtectedPlan struct {
	Mounts []Mount
	// Mounted lists the protected paths that will be read-only inside the agent.
	Mounted []string
	// Missing lists protected paths that do not exist yet. They are NOT created (that would dirty
	// the user's repository); `prepare` reports any that appear later (docs/decisions/0002).
	Missing []string
	// Symlinked lists protected paths that are symlinks. A symlink cannot be protected by a bind
	// mount: the agent could replace it, so this is reported loudly.
	Symlinked []string
}

// PlanProtected decides the read-only mounts for the effective protected set. For every protected
// path it also pins each existing parent directory as its own (writable) mount point, because a
// read-only submount does not stop its parent being renamed away and replaced: `mv .git .git.old`
// would otherwise let an agent plant hooks that the host later executes (spike S4).
//
// workspaceExpr is the compose expression for the workspace directory on the host.
func PlanProtected(protected []string, workspaceExpr string, stat func(rel string) PathInfo) ProtectedPlan {
	var plan ProtectedPlan
	ro := map[string]bool{}
	pinned := map[string]bool{}
	sorted := append([]string(nil), protected...)
	sort.Strings(sorted)

	for _, p := range sorted {
		info := stat(p)
		switch {
		case info.IsSymlink:
			plan.Symlinked = append(plan.Symlinked, p)
		case !info.Exists:
			plan.Missing = append(plan.Missing, p)
		default:
			ro[p] = true
			plan.Mounted = append(plan.Mounted, p)
		}
	}
	for _, p := range plan.Mounted {
		// Parents, shallowest first, excluding the workspace root (already a mount point).
		segs := strings.Split(p, "/")
		for i := 1; i < len(segs); i++ {
			parent := path.Join(segs[:i]...)
			if ro[parent] || pinned[parent] {
				continue
			}
			if pi := stat(parent); pi.Exists && pi.IsDir && !pi.IsSymlink {
				pinned[parent] = true
			}
		}
	}
	for parent := range pinned {
		plan.Mounts = append(plan.Mounts, Mount{Source: workspaceExpr + "/" + parent, Target: "/workspace/" + parent})
	}
	for _, p := range plan.Mounted {
		plan.Mounts = append(plan.Mounts, Mount{Source: workspaceExpr + "/" + p, Target: "/workspace/" + p, ReadOnly: true})
	}
	sort.SliceStable(plan.Mounts, func(i, j int) bool {
		a, b := plan.Mounts[i].Target, plan.Mounts[j].Target
		if da, db := strings.Count(a, "/"), strings.Count(b, "/"); da != db {
			return da < db
		}
		return a < b
	})
	return plan
}

// WorkspaceExpr is the compose expression for the host workspace directory under a layout, with the
// same relative default the committed compose.yaml uses.
func WorkspaceExpr(l Layout) string { return "${KENNEL_WORKSPACE:-" + l.ToRoot + "}" }

// SecretMount is a read-only secret file mount.
type SecretMount struct{ Source, Target string }

// OverrideInputs feeds the per-session compose override.
type OverrideInputs struct {
	Config *config.Config
	Mounts []Mount
	// Secrets are mounted from absolute host paths (already ~-expanded by the caller).
	SecretSources map[string]string
}

// Override renders compose.override.yaml.
func Override(in OverrideInputs) (File, error) {
	c := in.Config
	var secrets []SecretMount
	names := make([]string, 0, len(c.Secrets))
	for _, s := range c.Secrets {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	for _, n := range names {
		src, ok := in.SecretSources[n]
		if !ok {
			return File{}, fmt.Errorf("secret %q has no resolved source file", n)
		}
		secrets = append(secrets, SecretMount{Source: src, Target: "/run/secrets/" + n})
	}
	bind := c.Workspace.Mode == "bind"
	view := struct {
		Mounts    []Mount
		Secrets   []SecretMount
		HideState bool
		StateRel  string
	}{Secrets: secrets, HideState: bind, StateRel: StateDirRel}
	if bind {
		view.Mounts = in.Mounts
	}
	body, err := render("compose.override.yaml.tmpl", view)
	if err != nil {
		return File{}, err
	}
	return File{Path: StateDirRel + "/compose.override.yaml", Content: []byte(Stamp("#", body)), Mode: 0o644, Kind: Generated}, nil
}

// ComposePath renders a host path the way `docker compose` wants it in an env file. Docker Desktop
// accepts `C:/Users/me/proj` on Windows but not backslashes (they are escapes in the env-file
// syntax), so drive-letter and UNC paths get forward slashes whichever OS is generating them; a
// POSIX path is returned as it is (a backslash there is a legal filename character).
func ComposePath(p string) string {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') || strings.HasPrefix(p, `\\`) {
		return strings.ReplaceAll(p, `\`, "/")
	}
	return filepath.ToSlash(p)
}

// EnvFile renders compose.env, the variables `docker compose --env-file` needs. Values are
// single-quoted so compose does not interpolate `$` or split on spaces. gatewayImage should be a
// digest reference in a release build.
func EnvFile(uid, gid int, workspaceAbs, stateAbs, gatewayImage string, cpus float64) (File, error) {
	for _, v := range []string{workspaceAbs, stateAbs, gatewayImage} {
		if strings.ContainsAny(v, "'\n\r\x00") {
			return File{}, fmt.Errorf("value %q contains a quote or control character, which cannot be written to an env file safely", v)
		}
	}
	lines := []string{
		"KENNEL_GATEWAY_IMAGE='" + gatewayImage + "'",
		fmt.Sprintf("KENNEL_GID=%d", gid),
		"KENNEL_STATE='" + ComposePath(stateAbs) + "'",
		fmt.Sprintf("KENNEL_UID=%d", uid),
		"KENNEL_WORKSPACE='" + ComposePath(workspaceAbs) + "'",
	}
	if cpus > 0 {
		// Docker refuses to create a container whose CPU limit exceeds the engine's CPUs, so a
		// limit above that is clamped here (and reported by prepare) rather than failing `up`.
		lines = append(lines, "KENNEL_CPUS="+strconv.FormatFloat(cpus, 'f', -1, 64))
	}
	body := "# Written by `kennel prepare`; local to this machine.\n" + strings.Join(lines, "\n") + "\n"
	return File{Path: StateDirRel + "/compose.env", Content: []byte(Stamp("#", body)), Mode: 0o644, Kind: Generated}, nil
}

// StatFS adapts an on-disk project root to PlanProtected's stat function. It uses Lstat so a
// symlinked path is reported as a symlink and never followed.
func StatFS(root string) func(rel string) PathInfo {
	return func(rel string) PathInfo {
		fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return PathInfo{}
		}
		return PathInfo{Exists: true, IsDir: fi.IsDir(), IsSymlink: fi.Mode()&os.ModeSymlink != 0}
	}
}

// GitConfigWarnings inspects the text of .git/config for settings that make git run programs on
// the HOST, which an agent with write access to .git/config could abuse (docs/decisions/0002).
func GitConfigWarnings(gitConfig string) []string {
	var out []string
	lower := strings.ToLower(gitConfig)
	checks := []struct{ needle, msg string }{
		{"fsmonitor", "core.fsmonitor runs a program on the host whenever git inspects the repository"},
		{"sshcommand", "core.sshCommand runs a program on the host for ssh remotes"},
		{"hookspath", "core.hooksPath points git at hooks outside .git/hooks, which are not read-only inside the sandbox"},
		{"pager", "a pager setting runs a program on the host"},
		{"editor", "an editor setting runs a program on the host"},
		{"textconv", "a diff textconv driver runs a program on the host"},
		{"credential", "a credential helper runs a program on the host"},
	}
	for _, c := range checks {
		if strings.Contains(lower, c.needle) {
			out = append(out, ".git/config: "+c.msg)
		}
	}
	if strings.Contains(lower, "[alias]") {
		for _, line := range strings.Split(gitConfig, "\n") {
			if t := strings.TrimSpace(line); strings.Contains(t, "= !") || strings.Contains(t, "=!") {
				out = append(out, ".git/config: a shell alias (\"!…\") runs a program on the host when you use it")
				break
			}
		}
	}
	return out
}
