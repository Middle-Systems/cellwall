package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/middle-systems/cellwall/internal/compose"
	"github.com/middle-systems/cellwall/internal/configedit"
	"github.com/middle-systems/cellwall/internal/detect"
	"github.com/middle-systems/cellwall/internal/gen"
	"github.com/middle-systems/cellwall/internal/prepare"
	"github.com/middle-systems/cellwall/internal/scaffold"
)

// PortInfo describes one preview port.
type PortInfo struct {
	Port int    `json:"port"`
	URL  string `json:"url"`
	// Listener is what the agent container is doing on that port: "all-interfaces" (reachable),
	// "loopback-only" (the gateway cannot reach it), or "none".
	Listener string `json:"listener"`
	Hint     string `json:"hint,omitempty"`
	// Published reports whether something accepts connections on the host's 127.0.0.1:port.
	Published bool `json:"published"`
}

// PortsReport is `cellwall ports ls`.
type PortsReport struct {
	Ports        []PortInfo `json:"ports"`
	AgentRunning bool       `json:"agent_running"`
	Warnings     []string   `json:"warnings"`
}

// Listener classes reported by ClassifyListeners.
const (
	ListenAll      = "all-interfaces"
	ListenLoopback = "loopback-only"
	ListenNone     = "none"
)

// ClassifyListeners reads the text of /proc/net/tcp and /proc/net/tcp6 and reports, for each
// listening port, whether anything listens on a non-loopback address.
func ClassifyListeners(procNet string) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(procNet, "\n") {
		f := strings.Fields(line)
		// sl local_address rem_address st ...; header lines and blanks fall out here.
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		host, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			continue
		}
		class := ListenAll
		if isLoopbackHex(host) {
			class = ListenLoopback
		}
		// A port with both kinds of listener is reachable.
		if prev, seen := out[int(port)]; !seen || prev == ListenLoopback {
			out[int(port)] = class
		}
	}
	return out
}

// isLoopbackHex recognises 127.0.0.0/8 (little-endian hex, as /proc prints it) and ::1.
func isLoopbackHex(h string) bool {
	switch len(h) {
	case 8:
		return strings.HasSuffix(strings.ToUpper(h), "7F") // last byte of the LE word is the first octet
	case 32:
		return strings.EqualFold(h, "00000000000000000000000001000000")
	}
	return false
}

// Ports lists the configured preview ports with what the agent is listening on.
func Ports(ctx context.Context, e Env, root string) (*PortsReport, error) {
	p, err := compose.Open(root, e.GlobalDir)
	if err != nil {
		return nil, err
	}
	r := &PortsReport{Ports: []PortInfo{}, Warnings: []string{}}
	hints := bindHints(root)

	var listeners map[int]string
	if up, _ := Running(ctx, e, p, compose.AgentService); up {
		r.AgentRunning = true
		out, err := p.Output(ctx, e.Runner, "exec", "-T", compose.AgentService, "sh", "-c", "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null")
		if err != nil {
			r.Warnings = append(r.Warnings, "could not inspect the agent's listeners: "+Brief(err))
		} else {
			listeners = ClassifyListeners(string(out))
		}
	}
	ports := slices.Clone(p.Cfg.Ports)
	slices.Sort(ports)
	for _, port := range ports {
		info := PortInfo{Port: port, URL: fmt.Sprintf("http://localhost:%d", port), Listener: ListenNone, Hint: hints[port], Published: dialable(port)}
		if c, ok := listeners[port]; ok {
			info.Listener = c
		}
		if info.Listener == ListenLoopback {
			msg := fmt.Sprintf("port %d: the dev server listens on localhost inside the container, so the gateway cannot reach it", port)
			if info.Hint != "" {
				msg += "; " + info.Hint
			} else {
				msg += "; make it listen on 0.0.0.0 (for example --host 0.0.0.0)"
			}
			r.Warnings = append(r.Warnings, msg)
		}
		r.Ports = append(r.Ports, info)
	}
	if len(ports) == 0 {
		r.Warnings = append(r.Warnings, "no preview ports are configured; add one with `cellwall ports add <port>`")
	}
	return r, nil
}

func dialable(port int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// bindHints maps preview ports to the framework-specific fix for "listens on localhost only".
func bindHints(root string) map[int]string {
	out := map[int]string{}
	res, err := detect.Detect(root)
	if err != nil {
		return out
	}
	for _, s := range res.Stacks {
		for _, fw := range s.Frameworks {
			if f, ok := detect.FrameworkFor(fw); ok {
				out[f.Port] = f.Name + ": " + f.BindHint
			}
		}
	}
	return out
}

// PortsChange is the result of adding or removing ports.
type PortsChange struct {
	Ports        []int    `json:"ports"`
	Added        []int    `json:"added"`
	Removed      []int    `json:"removed"`
	Written      []string `json:"written"`
	GatewayReset bool     `json:"gateway_recreated"`
	Warnings     []string `json:"warnings"`
}

// ChangePorts adds and removes preview ports: it edits config.yaml, regenerates the compose file
// (refusing, and undoing the edit, if that file was hand-edited), and recreates only the gateway.
func ChangePorts(ctx context.Context, e Env, root string, add, remove []int) (*PortsChange, error) {
	p, err := compose.Open(root, e.GlobalDir)
	if err != nil {
		return nil, err
	}
	have := slices.Clone(p.Cfg.Ports)
	res := &PortsChange{Added: []int{}, Removed: []int{}, Written: []string{}, Warnings: []string{}}

	want := slices.Clone(have)
	for _, a := range add {
		if !slices.Contains(want, a) {
			want = append(want, a)
			res.Added = append(res.Added, a)
		}
	}
	for _, r := range remove {
		i := slices.Index(want, r)
		if i < 0 {
			return nil, fmt.Errorf("port %d is not a configured preview port (configured: %v)\n  next: see `cellwall ports ls`", r, have)
		}
		want = slices.Delete(want, i, i+1)
		res.Removed = append(res.Removed, r)
	}
	slices.Sort(want)
	res.Ports = want
	if len(res.Added) == 0 && len(res.Removed) == 0 {
		return res, nil
	}

	ch, err := configedit.SetPorts(root, want)
	if err != nil {
		return nil, err
	}
	undo := func(cause error) error {
		if rerr := ch.Rollback(); rerr != nil {
			return errors.Join(cause, fmt.Errorf("could not undo the config change: %w", rerr))
		}
		return cause
	}

	// The edited config must still be valid (reserved ports, range, count).
	plan, err := scaffold.Build(scaffold.Options{Root: root, GlobalConfigDir: e.GlobalDir})
	if err != nil {
		return nil, undo(fmt.Errorf("%w\n  next: nothing was changed", err))
	}
	// A generated file that init would KEEP because a human edited it would silently miss the new
	// port (the preview would never be published), so that is as much a refusal as a conflict.
	var blocked []string
	for _, c := range plan.Conflicts() {
		blocked = append(blocked, c.File.Path)
	}
	for _, a := range plan.Actions {
		if a.Kind == scaffold.Keep && a.File.Kind == gen.Generated {
			blocked = append(blocked, a.File.Path)
		}
	}
	if len(blocked) > 0 {
		names := blocked
		return nil, undo(fmt.Errorf("cannot regenerate %s: it was edited or is not cellwall's\n  next: re-run with `cellwall init --force` after saving your changes elsewhere, or add the port by hand; nothing was changed", strings.Join(names, ", ")))
	}
	applied, err := plan.Apply()
	if err != nil {
		return nil, undo(err)
	}
	res.Written = applied.Written
	if res.Written == nil {
		res.Written = []string{}
	}

	if _, err := prepare.Run(prepare.Options{Root: root, GlobalConfigDir: e.GlobalDir}); err != nil {
		return nil, fmt.Errorf("%w\n  next: the config and compose file were updated; fix the problem and run `cellwall prepare`", err)
	}

	p, err = compose.Open(root, e.GlobalDir)
	if err != nil {
		return nil, err
	}
	if up, _ := Running(ctx, e, p, compose.GatewayService); up {
		if err := CheckHostPorts(res.Added); err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		}
		code, err := p.Run(ctx, compose.Streams{Out: e.logw(), Err: e.logw()}, "up", "-d", "--no-deps", "--wait", compose.GatewayService)
		if err != nil {
			return nil, err
		}
		if code != 0 {
			return nil, fmt.Errorf("the gateway could not be recreated (docker compose exited %d)\n  next: run `cellwall status`; the new port is configured and takes effect at the next `cellwall up`", code)
		}
		res.GatewayReset = true
	}
	return res, nil
}

// CheckHostPorts reports a preview port that something on this machine already uses, which would
// make `docker compose up` fail with an obscure "address already in use".
func CheckHostPorts(ports []int) error {
	var busy []string
	for _, port := range ports {
		var lc net.ListenConfig
		ln, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			busy = append(busy, strconv.Itoa(port))
			continue
		}
		_ = ln.Close()
	}
	if len(busy) == 0 {
		return nil
	}
	return fmt.Errorf("port(s) %s are already in use on this machine, so the preview cannot be published there\n  next: stop whatever uses it, or choose another with `cellwall ports rm %s` and `cellwall ports add <port>`", strings.Join(busy, ", "), busy[0])
}
