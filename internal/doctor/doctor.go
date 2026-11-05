// Package doctor runs host-side checks and reports actionable results.
//
// Every failing or warning result carries a Fix: what happened, why it matters, and the
// next command to run (the project's error UX rule).
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/middle-systems/kennel/internal/engine"
)

// Status is the outcome of one check.
type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
)

// Minimum engine versions. The sandbox topology depends on gateway_mode_ipv4=isolated
// (docs/decisions/0001-isolated-gateway-mode.md), which first appeared in Docker Engine 28.
const (
	MinEngineMajor  = 28
	MinComposeMajor = 2
)

// Result is one line of the report.
type Result struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// Report is the full set of results.
type Report struct {
	Results []Result `json:"results"`
}

// Failed reports whether any check failed. Warnings do not fail the report.
func (r Report) Failed() bool {
	for _, res := range r.Results {
		if res.Status == Fail {
			return true
		}
	}
	return false
}

// Options configures Run. Zero values use the real host.
type Options struct {
	Runner   engine.Runner
	GOOS     string
	GOARCH   string
	ReadFile func(string) ([]byte, error)
	// WantMemory/WantCPUs are the hardening defaults to compare against engine resources.
	WantMemoryBytes int64
	WantCPUs        int
	Timeout         time.Duration
}

func (o *Options) defaults() {
	if o.Runner == nil {
		o.Runner = engine.ExecRunner{}
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.GOARCH == "" {
		o.GOARCH = runtime.GOARCH
	}
	if o.ReadFile == nil {
		o.ReadFile = os.ReadFile
	}
	if o.WantMemoryBytes == 0 {
		o.WantMemoryBytes = 8 << 30
	}
	if o.WantCPUs == 0 {
		o.WantCPUs = 4
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
}

type dockerInfo struct {
	ServerVersion   string   `json:"ServerVersion"`
	OperatingSystem string   `json:"OperatingSystem"`
	Name            string   `json:"Name"`
	SecurityOptions []string `json:"SecurityOptions"`
	NCPU            int      `json:"NCPU"`
	MemTotal        int64    `json:"MemTotal"`
}

type dockerVersion struct {
	Server *struct {
		Version    string `json:"Version"`
		Components []struct {
			Name string `json:"Name"`
		} `json:"Components"`
	} `json:"Server"`
}

// Run executes all checks. It never returns an error: problems become Results.
func Run(ctx context.Context, opts Options) Report {
	opts.defaults()
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var rep Report
	add := func(r Result) { rep.Results = append(rep.Results, r) }

	add(Result{ID: "platform", Title: "Host platform", Status: Pass, Detail: platformDetail(opts)})
	if res, ok := wslCheck(opts); ok {
		add(res)
	}

	cliRes, cliOK := cliCheck(ctx, opts)
	add(cliRes)
	if !cliOK {
		add(Result{ID: "engine-daemon", Title: "Engine daemon", Status: Skip, Detail: "docker CLI not available"})
		add(composeCheck(ctx, opts))
		return rep
	}

	info, infoRes := daemonCheck(ctx, opts)
	add(infoRes)
	if info == nil {
		add(Result{ID: "engine-version", Title: "Engine supports host-isolated sandbox network", Status: Skip, Detail: "daemon unreachable"})
		add(composeCheck(ctx, opts))
		return rep
	}
	add(engineVersionCheck(info))
	add(composeCheck(ctx, opts))
	add(flavorCheck(ctx, opts, info))
	add(resourceCheck(opts, info))
	return rep
}

func platformDetail(o Options) string {
	d := o.GOOS + "/" + o.GOARCH
	if o.GOOS == "windows" || o.GOOS == "darwin" {
		d += " (containers run in a Linux VM: workspace.mode=volume is recommended)"
	}
	return d
}

func wslCheck(o Options) (Result, bool) {
	if o.GOOS != "linux" {
		return Result{}, false
	}
	b, err := o.ReadFile("/proc/version")
	if err != nil || !strings.Contains(strings.ToLower(string(b)), "microsoft") {
		return Result{}, false
	}
	return Result{
		ID: "wsl2", Title: "Running under WSL2", Status: Warn,
		Detail: "bind-mounting Windows drives (/mnt/c) is slow and weakens read-only mount guarantees untested so far",
		Fix:    "keep the repository inside the WSL2 filesystem (e.g. ~/src) or use workspace.mode=volume",
	}, true
}

func cliCheck(ctx context.Context, o Options) (Result, bool) {
	out, err := o.Runner.Run(ctx, "docker", "version", "--format", "{{.Client.Version}}")
	if errors.Is(err, engine.ErrNotFound) {
		return Result{
			ID: "engine-cli", Title: "docker CLI", Status: Fail,
			Detail: "`docker` was not found on PATH, so kennel cannot build or start the sandbox",
			Fix:    "install Docker Engine 28+ (Linux) or Docker Desktop / Colima / OrbStack (macOS, Windows), then re-run `kennel doctor`",
		}, false
	}
	// `docker version` exits non-zero when the daemon is down but still prints the client version.
	v := strings.TrimSpace(string(out))
	if v == "" && err != nil {
		return Result{ID: "engine-cli", Title: "docker CLI", Status: Fail, Detail: err.Error(),
			Fix: "run `docker version` to see the underlying error"}, false
	}
	return Result{ID: "engine-cli", Title: "docker CLI", Status: Pass, Detail: "client " + v}, true
}

func daemonCheck(ctx context.Context, o Options) (*dockerInfo, Result) {
	out, err := o.Runner.Run(ctx, "docker", "info", "--format", "{{json .}}")
	if err != nil {
		return nil, Result{
			ID: "engine-daemon", Title: "Engine daemon", Status: Fail,
			Detail: "could not reach the container engine: " + oneLine(err.Error()),
			Fix:    "start the engine (Docker Desktop / `colima start` / `sudo systemctl start docker`), then re-run `kennel doctor`",
		}
	}
	var info dockerInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, Result{ID: "engine-daemon", Title: "Engine daemon", Status: Fail,
			Detail: "unexpected `docker info` output: " + err.Error(),
			Fix:    "run `docker info` manually and report the output if it looks healthy"}
	}
	return &info, Result{ID: "engine-daemon", Title: "Engine daemon", Status: Pass,
		Detail: fmt.Sprintf("server %s on %s", info.ServerVersion, info.OperatingSystem)}
}

func engineVersionCheck(info *dockerInfo) Result {
	const title = "Engine supports host-isolated sandbox network"
	major, ok := majorVersion(info.ServerVersion)
	if !ok {
		return Result{ID: "engine-version", Title: title, Status: Warn,
			Detail: fmt.Sprintf("could not parse engine version %q", info.ServerVersion),
			Fix:    "run `kennel verify` after `kennel up`: it tests host isolation directly"}
	}
	if major < MinEngineMajor {
		return Result{ID: "engine-version", Title: title, Status: Fail,
			Detail: fmt.Sprintf("engine %s is older than %d; an `internal` network alone still lets the agent reach host services bound to 0.0.0.0 (docs/decisions/0001-isolated-gateway-mode.md)", info.ServerVersion, MinEngineMajor),
			Fix:    fmt.Sprintf("upgrade to Docker Engine %d or newer", MinEngineMajor)}
	}
	return Result{ID: "engine-version", Title: title, Status: Pass, Detail: "engine " + info.ServerVersion}
}

func composeCheck(ctx context.Context, o Options) Result {
	out, err := o.Runner.Run(ctx, "docker", "compose", "version", "--short")
	if err != nil {
		return Result{ID: "compose", Title: "Docker Compose v2", Status: Fail,
			Detail: "`docker compose` is not available",
			Fix:    "install the Compose v2 plugin (https://docs.docker.com/compose/install/); the legacy `docker-compose` v1 binary is not supported"}
	}
	v := strings.TrimSpace(string(out))
	if major, ok := majorVersion(v); ok && major < MinComposeMajor {
		return Result{ID: "compose", Title: "Docker Compose v2", Status: Fail,
			Detail: "found compose " + v, Fix: "upgrade the Compose plugin to v2 or newer"}
	}
	return Result{ID: "compose", Title: "Docker Compose v2", Status: Pass, Detail: "compose " + v}
}

func flavorCheck(ctx context.Context, o Options, info *dockerInfo) Result {
	const title = "Engine flavor"
	var notes []string
	status := Pass
	if out, err := o.Runner.Run(ctx, "docker", "version", "--format", "{{json .}}"); err == nil {
		var v dockerVersion
		if json.Unmarshal(out, &v) == nil && v.Server != nil {
			for _, c := range v.Server.Components {
				if strings.Contains(strings.ToLower(c.Name), "podman") {
					notes = append(notes, "Podman detected: best-effort support only; run `kennel verify` to confirm isolation")
					status = Warn
				}
			}
		}
	}
	for _, s := range info.SecurityOptions {
		if strings.Contains(s, "rootless") {
			notes = append(notes, "rootless engine: some hardening options (e.g. cgroup limits) may be unavailable")
			status = Warn
		}
	}
	if strings.Contains(info.OperatingSystem, "Docker Desktop") {
		notes = append(notes, "Docker Desktop: file sharing goes through a VM; prefer workspace.mode=volume")
	}
	if len(notes) == 0 {
		return Result{ID: "engine-flavor", Title: title, Status: Pass, Detail: "standard Docker Engine"}
	}
	r := Result{ID: "engine-flavor", Title: title, Status: status, Detail: strings.Join(notes, "; ")}
	if status == Warn {
		r.Fix = "see docs/platforms.md"
	}
	return r
}

func resourceCheck(o Options, info *dockerInfo) Result {
	const title = "Engine resources"
	detail := fmt.Sprintf("%d CPUs, %.1f GiB memory", info.NCPU, float64(info.MemTotal)/(1<<30))
	var short []string
	if info.NCPU > 0 && info.NCPU < o.WantCPUs {
		short = append(short, fmt.Sprintf("%d CPUs < default hardening.cpus=%d", info.NCPU, o.WantCPUs))
	}
	if info.MemTotal > 0 && info.MemTotal < o.WantMemoryBytes {
		short = append(short, fmt.Sprintf("%.1f GiB < default hardening.memory=8g", float64(info.MemTotal)/(1<<30)))
	}
	if len(short) == 0 {
		return Result{ID: "resources", Title: title, Status: Pass, Detail: detail}
	}
	return Result{ID: "resources", Title: title, Status: Warn, Detail: detail + " (" + strings.Join(short, "; ") + ")",
		Fix: "raise the VM's resources in your engine settings, or lower hardening.memory / hardening.cpus in .kennel/config.yaml"}
}

func majorVersion(v string) (int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	head, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(head)
	return n, err == nil
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
