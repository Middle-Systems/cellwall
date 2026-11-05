package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/middle-systems/kennel/internal/compose"
	"github.com/middle-systems/kennel/internal/gen"
	"github.com/middle-systems/kennel/internal/policy"
	"github.com/middle-systems/kennel/internal/prepare"
	"github.com/middle-systems/kennel/internal/volume"
)

// Container is one service's state.
type Container struct {
	Service string `json:"service"`
	State   string `json:"state"`
	Health  string `json:"health,omitempty"`
	Image   string `json:"image,omitempty"`
}

// NetworkStatus describes the sandbox network's isolation as the engine reports it.
type NetworkStatus struct {
	Name     string `json:"name"`
	Found    bool   `json:"found"`
	Internal bool   `json:"internal"`
	Isolated bool   `json:"host_isolated"` // gateway_mode_ipv4=isolated (ADR 0001)
}

// PolicyStatus compares the policy on disk with the one the gateway is enforcing.
type PolicyStatus struct {
	OnDisk    string `json:"on_disk"`
	Active    string `json:"active,omitempty"`
	GatewayUp bool   `json:"gateway_running"`
	InSync    bool   `json:"in_sync"`
	Rules     int    `json:"rules"`
	Reloads   int    `json:"reloads"`
	Failures  int    `json:"reload_failures"`
	LastError string `json:"last_reload_error,omitempty"`
}

// VolumeStatus describes the workspace volume in volume mode.
type VolumeStatus struct {
	Seeded    bool   `json:"seeded"`
	Branch    string `json:"branch,omitempty"`
	Base      string `json:"base,omitempty"`
	Known     bool   `json:"pending_known"`
	Unfetched int    `json:"unfetched_commits"`
	Dirty     int    `json:"uncommitted_files"`
}

// StatusReport is what `kennel status` shows.
type StatusReport struct {
	Project       string        `json:"project"`
	Containers    []Container   `json:"containers"`
	Network       NetworkStatus `json:"network"`
	Policy        PolicyStatus  `json:"policy"`
	Relaxations   []string      `json:"relaxations"`
	WorkspaceMode string        `json:"workspace_mode"`
	Volume        *VolumeStatus `json:"volume,omitempty"`
	Ports         []int         `json:"ports"`
	Warnings      []string      `json:"warnings"`
}

// Status gathers the sandbox's state. It never changes anything and works when nothing runs.
func Status(ctx context.Context, e Env, root string) (*StatusReport, error) {
	p, err := compose.Open(root, e.GlobalDir)
	if err != nil {
		return nil, err
	}
	r := &StatusReport{
		Project: p.Cfg.Project, WorkspaceMode: p.Cfg.Workspace.Mode, Ports: p.Cfg.Ports,
		Containers: []Container{}, Relaxations: p.Cfg.Relaxations(), Warnings: []string{},
	}
	if r.Ports == nil {
		r.Ports = []int{}
	}

	if out, err := p.Output(ctx, e.Runner, "ps", "--all", "--format", "json"); err == nil {
		r.Containers = parsePS(out)
	} else {
		r.Warnings = append(r.Warnings, "could not list containers: "+Brief(err))
	}

	if p.Cfg.Workspace.Mode == "volume" {
		vs := &VolumeStatus{}
		if st, err := volume.LoadState(root); err == nil {
			vs.Seeded, vs.Branch, vs.Base = true, st.Branch, st.Base
		}
		vs.Unfetched, vs.Dirty, vs.Known, _ = AtRisk(ctx, e, root)
		r.Volume = vs
	}

	r.Network = inspectNetwork(ctx, e, p.Name+"_sandbox")
	if !r.Network.Found && len(r.Containers) > 0 {
		r.Warnings = append(r.Warnings, "the sandbox network "+r.Network.Name+" was not found")
	}
	if r.Network.Found && (!r.Network.Internal || !r.Network.Isolated) {
		r.Warnings = append(r.Warnings, "the sandbox network is NOT fully isolated (internal="+boolStr(r.Network.Internal)+", host_isolated="+boolStr(r.Network.Isolated)+"); run `kennel down` then `kennel up`")
	}

	// The policy on disk, as `prepare` last wrote it.
	if b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(gen.StateDirRel), "policy", "policy.json")); err == nil { //nolint:gosec // fixed location in the project's state dir
		if parsed, perr := policy.Parse("policy.json", b); perr == nil {
			if c, cerr := policy.Compile(parsed, true); cerr == nil {
				r.Policy.OnDisk = c.Hash
				r.Policy.Rules = len(c.Policy.Rules)
				r.Relaxations = append(r.Relaxations, policy.Relaxations(c.Findings)...)
			}
		}
	}
	if r.Policy.OnDisk == "" {
		r.Warnings = append(r.Warnings, "no policy has been prepared yet; run `kennel prepare` (or `kennel up`)")
	}
	r.Relaxations = append(r.Relaxations, prepare.SessionRules(root)...)

	if up, _ := Running(ctx, e, p, compose.GatewayService); up {
		r.Policy.GatewayUp = true
		if st, err := fetchGatewayStatus(ctx, e, p); err == nil {
			r.Policy.Active = st.Policy.PolicyHash
			r.Policy.Reloads, r.Policy.Failures, r.Policy.LastError = st.Policy.Reloads, st.Policy.Failures, st.Policy.LastError
			r.Policy.InSync = r.Policy.OnDisk != "" && st.Policy.PolicyHash == r.Policy.OnDisk
			if !r.Policy.InSync {
				r.Warnings = append(r.Warnings, "the gateway is enforcing a different policy than the one on disk; see `docker compose logs gateway` (a rejected edit keeps the last good policy)")
			}
		} else {
			r.Warnings = append(r.Warnings, "the gateway is running but did not answer: "+Brief(err)+" (an older gateway image? remove it with `docker rmi kennel-gateway:local` and run `kennel up`)")
		}
	}
	return r, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// parsePS accepts both shapes `docker compose ps --format json` has had: one JSON object per line,
// or a single JSON array.
func parsePS(out []byte) []Container {
	type row struct {
		Service string `json:"Service"`
		State   string `json:"State"`
		Health  string `json:"Health"`
		Image   string `json:"Image"`
	}
	var rows []row
	trimmed := bytes.TrimSpace(out)
	if bytes.HasPrefix(trimmed, []byte("[")) {
		_ = json.Unmarshal(trimmed, &rows)
	} else {
		for _, line := range strings.Split(string(trimmed), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var rw row
			if json.Unmarshal([]byte(line), &rw) == nil {
				rows = append(rows, rw)
			}
		}
	}
	cs := []Container{}
	for _, rw := range rows {
		cs = append(cs, Container(rw))
	}
	return cs
}

func inspectNetwork(ctx context.Context, e Env, name string) NetworkStatus {
	ns := NetworkStatus{Name: name}
	out, err := e.Runner.Run(ctx, "docker", "network", "inspect", "--format", "{{json .}}", name)
	if err != nil {
		return ns
	}
	var n struct {
		Internal bool              `json:"Internal"`
		Options  map[string]string `json:"Options"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &n) != nil {
		return ns
	}
	ns.Found, ns.Internal = true, n.Internal
	ns.Isolated = n.Options["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated"
	return ns
}
