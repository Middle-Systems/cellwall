package config

import (
	"fmt"
	"math"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ValidationError lists every problem found, each prefixed with the offending key.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return e.Problems[0]
	}
	return fmt.Sprintf("%d problems:\n  - %s", len(e.Problems), strings.Join(e.Problems, "\n  - "))
}

// KnownStacks are the stack names `stacks:` and `init --stack` accept.
var KnownStacks = []string{"node", "python", "go", "rust", "java", "dotnet", "ruby", "php"}

var (
	projectRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,38}$`)
	versionRe   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	aptRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,60}$`)
	runtimeRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,30}$`)
	envNameRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	secretRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)
	memoryRe    = regexp.MustCompile(`^([1-9][0-9]*)([bkmg]?)$`)
	imageRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$`)
	digestInRef = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
)

// allowedCaps is the closed set of capabilities unsafe.cap_add may request. Anything that could
// reconfigure networking or escape (NET_ADMIN, NET_RAW, SYS_ADMIN, ...) is deliberately absent.
var allowedCaps = map[string]bool{"SYS_PTRACE": true}

// reservedEnv are names the agent's environment must not carry. Proxy variables would redirect the
// agent around its own gateway; loader and search-path variables are classic injection vectors;
// KENNEL_ is reserved for the tool.
func reservedEnv(name string) bool {
	u := strings.ToUpper(name)
	switch u {
	// Names the generator sets from typed options: control them there, not here.
	case "DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
		"ENABLE_CLAUDEAI_MCP_SERVERS", "DISABLE_AUTOUPDATER", "DO_NOT_TRACK", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
		"GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GOTOOLCHAIN", "CARGO_HOME", "RUSTUP_HOME", "PYTHONPYCACHEPREFIX":
		return true
	case "PATH", "HOME", "USER", "SHELL", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG", "BASH_ENV", "ENV", "IFS",
		"NODE_OPTIONS", "PYTHONSTARTUP", "PYTHONPATH", "RUBYOPT", "PERL5OPT", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS":
		return true
	}
	return strings.Contains(u, "PROXY") || strings.HasPrefix(u, "KENNEL_") || strings.HasPrefix(u, "DOCKER_") || strings.HasPrefix(u, "LD_")
}

// Validate checks the effective configuration. It is purely syntactic about host-specific things
// (secret files are not stat'ed here; `prepare` does that).
func (c *Config) Validate() error {
	var p []string
	bad := func(key, format string, args ...any) {
		p = append(p, key+": "+fmt.Sprintf(format, args...))
	}

	if c.Version != Version {
		bad("version", "must be %d (got %d)", Version, c.Version)
	}
	if c.Project != "" && !projectRe.MatchString(c.Project) {
		bad("project", "%q must be 1-39 lowercase letters, digits, '-' or '_', starting with a letter or digit", c.Project)
	}

	// Stacks.
	for _, s := range c.Stacks.Items {
		if !contains(KnownStacks, s) {
			bad("stacks", "unknown stack %q (known: %s)", s, strings.Join(KnownStacks, ", "))
		}
	}

	// Agent.
	switch c.Agent.Preset {
	case "claude", "none":
	default:
		bad("agent.preset", "must be \"claude\" or \"none\" (got %q)", c.Agent.Preset)
	}
	if len(c.Agent.Command) == 0 {
		bad("agent.command", "must have at least one element (it is an argv, not a shell string)")
	}
	for i, a := range c.Agent.Command {
		if a == "" || strings.ContainsAny(a, "\x00\n\r") {
			bad("agent.command", "element %d is empty or contains control characters", i)
		}
	}
	if c.Agent.Preset == "claude" && !versionRe.MatchString(c.Agent.Version) {
		bad("agent.version", "%q must be an exact version like 2.1.286 (a floating tag would defeat pinning)", c.Agent.Version)
	}
	if len(c.Agent.AptPackages) > 64 {
		bad("agent.apt_packages", "at most 64 packages")
	}
	seenApt := map[string]bool{}
	for _, a := range c.Agent.AptPackages {
		if !aptRe.MatchString(a) {
			bad("agent.apt_packages", "%q is not a valid Debian package name", a)
		}
		if seenApt[a] {
			bad("agent.apt_packages", "%q is listed twice", a)
		}
		seenApt[a] = true
	}
	if c.Agent.BaseImage != "" {
		switch {
		case !imageRe.MatchString(c.Agent.BaseImage):
			bad("agent.base_image", "%q is not a valid image reference", c.Agent.BaseImage)
		case !digestInRef.MatchString(c.Agent.BaseImage) && !c.Unsafe.UnpinnedBaseImage:
			bad("agent.base_image", "%q must be pinned by digest (repo:tag@sha256:...); set unsafe.unpinned_base_image to override", c.Agent.BaseImage)
		}
	}
	envKeys := make([]string, 0, len(c.Agent.Env))
	for k := range c.Agent.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, k := range envKeys {
		v := c.Agent.Env[k]
		switch {
		case !envNameRe.MatchString(k):
			bad("agent.env", "%q is not a valid variable name", k)
		case reservedEnv(k):
			bad("agent.env", "%q is reserved (proxy, loader, search-path and kennel variables cannot be set)", k)
		case strings.ContainsAny(v, "\x00\n\r"):
			bad("agent.env", "value of %q contains control characters", k)
		}
	}

	// Devcontainer location.
	if c.Devcontainer.Dir != DevcontainerDir && c.Devcontainer.Dir != DevcontainerMergeDir {
		bad("devcontainer.dir", "must be %q or %q (got %q)", DevcontainerDir, DevcontainerMergeDir, c.Devcontainer.Dir)
	}

	// Workspace.
	if c.Workspace.Mode != "bind" && c.Workspace.Mode != "volume" {
		bad("workspace.mode", "must be \"bind\" or \"volume\" (got %q)", c.Workspace.Mode)
	}
	if len(c.Workspace.CacheVolumes.Items) > 32 {
		bad("workspace.cache_volumes", "at most 32 paths")
	}
	seenCache := map[string]bool{}
	for _, cv := range c.Workspace.CacheVolumes.Items {
		n, err := NormalizeRelPath(cv)
		if err != nil {
			bad("workspace.cache_volumes", "%q: %v", cv, err)
			continue
		}
		if seenCache[n] {
			bad("workspace.cache_volumes", "%q is listed twice", cv)
		}
		seenCache[n] = true
		if isProtectedOrInside(n, c.ProtectedSet()) {
			bad("workspace.cache_volumes", "%q overlaps a protected path", cv)
		}
	}

	// Ports.
	if len(c.Ports) > 32 {
		bad("ports", "at most 32 preview ports")
	}
	seenPort := map[int]bool{}
	for _, port := range c.Ports {
		switch {
		case port < 1024 || port > 65535:
			bad("ports", "%d must be 1024-65535 (the gateway forwards as a non-root user)", port)
		case port == GatewayProxyPort || port == GatewayAdminPort:
			bad("ports", "%d is used by the gateway itself", port)
		case seenPort[port]:
			bad("ports", "%d is listed twice", port)
		}
		seenPort[port] = true
	}

	// Hardening.
	if c.Hardening.PidsLimit < 16 || c.Hardening.PidsLimit > 100000 {
		bad("hardening.pids_limit", "must be 16-100000 (got %d); unlimited is not available", c.Hardening.PidsLimit)
	}
	checkMem(&p, "hardening.memory", c.Hardening.Memory, 64<<20)
	if c.Hardening.CPUs < 0.1 || c.Hardening.CPUs > 256 || math.IsNaN(c.Hardening.CPUs) {
		bad("hardening.cpus", "must be between 0.1 and 256 (got %v)", c.Hardening.CPUs)
	}
	if c.Hardening.Runtime != "" && !runtimeRe.MatchString(c.Hardening.Runtime) {
		bad("hardening.runtime", "%q is not a valid runtime name", c.Hardening.Runtime)
	}

	// Gateway.
	checkMem(&p, "gateway.memory", c.Gateway.Memory, 32<<20)
	if c.Gateway.PidsLimit < 16 || c.Gateway.PidsLimit > 10000 {
		bad("gateway.pids_limit", "must be 16-10000 (got %d)", c.Gateway.PidsLimit)
	}
	if c.Gateway.AuditMaxSizeMB < 1 || c.Gateway.AuditMaxSizeMB > 10240 {
		bad("gateway.audit_max_size_mb", "must be 1-10240 (got %d)", c.Gateway.AuditMaxSizeMB)
	}
	if c.Gateway.AuditMaxFiles < 1 || c.Gateway.AuditMaxFiles > 100 {
		bad("gateway.audit_max_files", "must be 1-100 (got %d)", c.Gateway.AuditMaxFiles)
	}

	// Protected paths.
	for _, pp := range c.ProtectedPaths {
		if _, err := NormalizeRelPath(pp); err != nil {
			bad("protected_paths", "%q: %v", pp, err)
		}
	}
	defaults := map[string]bool{}
	for _, d := range DefaultProtected {
		defaults[d] = true
	}
	for _, up := range c.Unsafe.Unprotect {
		n, err := NormalizeRelPath(up)
		switch {
		case err != nil:
			bad("unsafe.unprotect", "%q: %v", up, err)
		case !defaults[n]:
			bad("unsafe.unprotect", "%q is not a built-in protected path (built-ins: %s)", up, strings.Join(DefaultProtected, ", "))
		}
	}

	// Secrets.
	seenSecret, seenSecretEnv := map[string]bool{}, map[string]bool{}
	for i, s := range c.Secrets {
		key := fmt.Sprintf("secrets[%d]", i)
		switch {
		case !secretRe.MatchString(s.Name):
			bad(key+".name", "%q must be lowercase letters, digits and '_', starting with a letter", s.Name)
		case seenSecret[s.Name]:
			bad(key+".name", "%q is declared twice", s.Name)
		}
		seenSecret[s.Name] = true
		absolute := strings.HasPrefix(s.SourceFile, "~/") || path.IsAbs(filepath.ToSlash(s.SourceFile)) || isWindowsAbs(s.SourceFile)
		if !absolute {
			bad(key+".source_file", "%q must be absolute or start with ~/ (a path inside the repository would put a secret in version control)", s.SourceFile)
		}
		if strings.ContainsAny(s.SourceFile, "\x00\n\r") {
			bad(key+".source_file", "contains control characters")
		}
		if s.Env != "" {
			switch {
			case !envNameRe.MatchString(s.Env):
				bad(key+".env", "%q is not a valid variable name", s.Env)
			case reservedEnv(s.Env):
				bad(key+".env", "%q is reserved", s.Env)
			case seenSecretEnv[s.Env]:
				bad(key+".env", "%q is set by two secrets", s.Env)
			}
			if _, clash := c.Agent.Env[s.Env]; clash {
				bad(key+".env", "%q is also set in agent.env", s.Env)
			}
			seenSecretEnv[s.Env] = true
		}
	}

	// Git identity.
	for _, kv := range [][2]string{{"git.user_name", c.Git.UserName}, {"git.user_email", c.Git.UserEmail}} {
		if len(kv[1]) > 200 || strings.ContainsAny(kv[1], "\x00\n\r") {
			bad(kv[0], "must be at most 200 characters with no control characters")
		}
	}

	// Unsafe.
	for _, cap := range c.Unsafe.CapAdd {
		if !allowedCaps[cap] {
			bad("unsafe.cap_add", "%q is not permitted (the only allowed capability is SYS_PTRACE; NET_ADMIN, NET_RAW and friends can never be granted)", cap)
		}
	}

	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func checkMem(p *[]string, key, v string, min int64) {
	n, err := ParseMemory(v)
	switch {
	case err != nil:
		*p = append(*p, key+": "+err.Error())
	case n < min:
		*p = append(*p, fmt.Sprintf("%s: %s is below the minimum of %s", key, v, humanBytes(min)))
	}
}

// ParseMemory parses a Docker-style memory string ("512m", "8g", "1048576") into bytes.
func ParseMemory(v string) (int64, error) {
	m := memoryRe.FindStringSubmatch(strings.ToLower(v))
	if m == nil {
		return 0, fmt.Errorf("%q must look like 512m or 8g", v)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is too large", v)
	}
	mult := int64(1)
	switch m[2] {
	case "k":
		mult = 1 << 10
	case "m":
		mult = 1 << 20
	case "g":
		mult = 1 << 30
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("%q is too large", v)
	}
	return n * mult, nil
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%dg", n>>30)
	case n >= 1<<20:
		return fmt.Sprintf("%dm", n>>20)
	}
	return fmt.Sprintf("%d", n)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func isWindowsAbs(s string) bool {
	return len(s) >= 3 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':' && (s[2] == '\\' || s[2] == '/')
}

// NormalizeRelPath cleans a workspace-relative path: forward slashes, no leading "./", no
// trailing slash. It rejects anything that could escape the workspace or is ambiguous.
func NormalizeRelPath(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("path is empty")
	}
	if strings.ContainsAny(s, "\x00\n\r") {
		return "", fmt.Errorf("path contains control characters")
	}
	if strings.ContainsAny(s, "*?[]{}$`\\:") {
		return "", fmt.Errorf("path must not contain glob or special characters")
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return "", fmt.Errorf("path must be relative to the workspace")
	}
	c := path.Clean(s)
	// Check the CLEANED form too: "./~/x" cleans to "~/x", and Docker Compose (like a shell)
	// expands a leading "~" in a bind source to the user's home directory.
	if strings.HasPrefix(c, "~") {
		return "", fmt.Errorf("path must not start with '~' (shells and compose expand it to the home directory)")
	}
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("path must stay inside the workspace")
	}
	if strings.Contains(s, "//") {
		return "", fmt.Errorf("path contains an empty segment")
	}
	for _, seg := range strings.Split(c, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path must stay inside the workspace")
		}
	}
	return c, nil
}

// isProtectedOrInside reports whether p is one of the protected paths or lies within or above one.
func isProtectedOrInside(p string, protected []string) bool {
	for _, pr := range protected {
		if p == pr || strings.HasPrefix(p, pr+"/") || strings.HasPrefix(pr, p+"/") {
			return true
		}
	}
	return false
}
