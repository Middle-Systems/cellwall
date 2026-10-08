package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/middle-systems/cellwall/internal/compose"
	"github.com/middle-systems/cellwall/internal/policy"
	"github.com/middle-systems/cellwall/internal/policyedit"
	"github.com/middle-systems/cellwall/internal/prepare"
)

// EditOptions configures Edit.
type EditOptions struct {
	Edit policyedit.Edit
	Save bool          // write to the committed .cellwall/policy.yaml instead of the session layer
	Wait time.Duration // how long to wait for a running gateway to load the change; default 15s
}

// EditResult reports what an allow or deny did.
type EditResult struct {
	Hosts        []string
	Saved        bool
	AlreadySaved []string // hosts that --save found already present
	Warnings     []string // lint warnings about the new rules
	PolicyHash   string
	GatewayUp    bool          // the gateway was running
	Applied      bool          // the running gateway reported the new policy
	Waited       time.Duration // how long that took
	GatewayError string        // set when the gateway did not pick the change up
}

// Edit applies an allow or deny rule, recompiles the effective policy, and, when the gateway is
// running, waits until it reports the new policy. If the result is not what the user asked for
// (the policy does not compile, or a deny elsewhere still wins) the change is undone and the
// effective policy is restored, so a refused command leaves nothing behind.
func Edit(ctx context.Context, e Env, root string, o EditOptions) (*EditResult, error) {
	rules, err := o.Edit.Rules()
	if err != nil {
		return nil, err
	}
	var ch policyedit.Change
	res := &EditResult{Saved: o.Save}
	if o.Save {
		_, res.AlreadySaved, ch, err = policyedit.Save(root, o.Edit)
	} else {
		ch, err = policyedit.ApplySession(root, o.Edit)
	}
	if err != nil {
		return nil, err
	}

	pr, err := prepare.Run(prepare.Options{Root: root, GlobalConfigDir: e.GlobalDir})
	if err != nil {
		return nil, e.undo(root, ch, fmt.Errorf("%w\n  next: nothing was changed; adjust the host or use an exact hostname", err))
	}

	// Check the policy now decides the way the user asked.
	if o.Edit.Action == policy.ActionAllow {
		ports := o.Edit.Ports
		if len(ports) == 0 {
			ports = []int{443}
		}
		for _, r := range rules {
			if strings.Contains(r.Host, "*") {
				continue // a pattern has no single host to probe; its lint findings are reported below
			}
			for _, port := range ports {
				proto := policy.ProtoTunnel
				if port == 80 {
					proto = policy.ProtoHTTP
				}
				if d := pr.Policy.Match(r.Host, port, proto); !d.Allowed {
					return nil, e.undo(root, ch, notAllowedError(r.Host, port, d, pr))
				}
			}
		}
	}
	res.PolicyHash = pr.Policy.Hash

	hosts := map[string]bool{}
	for _, r := range rules {
		res.Hosts = append(res.Hosts, r.Host)
		hosts[r.Host] = true
	}
	for _, f := range pr.Policy.Findings {
		if f.Level == policy.LevelWarn && hosts[f.Host] {
			res.Warnings = append(res.Warnings, f.String())
		}
	}

	// Tell the running gateway's story: it reloads by content hash within a poll interval.
	p, err := compose.Open(root, e.GlobalDir)
	if err != nil {
		return res, nil //nolint:nilerr // without compose files there is no gateway to wait for
	}
	if up, _ := Running(ctx, e, p, compose.GatewayService); up {
		res.GatewayUp = true
		res.Applied, res.Waited, res.GatewayError = waitForPolicy(ctx, e, p, pr.Policy.Hash, o.Wait)
	}
	return res, nil
}

// undo reverts the edit and re-prepares so policy.json matches the restored files again.
func (e Env) undo(root string, ch policyedit.Change, cause error) error {
	if rerr := ch.Rollback(); rerr != nil {
		return errors.Join(cause, fmt.Errorf("could not undo the change: %w", rerr))
	}
	_, _ = prepare.Run(prepare.Options{Root: root, GlobalConfigDir: e.GlobalDir})
	return cause
}

func notAllowedError(host string, port int, d policy.Decision, pr *prepare.Result) error {
	switch d.Reason {
	case policy.ReasonExplicitDeny:
		where := "a deny rule"
		if d.Rule != nil {
			where = fmt.Sprintf("deny rule rules[%d] (%s, from %s)", d.Rule.Index, d.Rule.Rule.Host, sourceOf(d.Rule.Rule))
		}
		return fmt.Errorf("%s:%d is still denied by %s, and a deny always beats an allow\n  next: remove that deny in .cellwall/policy.yaml (or the preset/layer it comes from) if you really want this host, then re-run", host, port, where)
	case policy.ReasonHTTPNotAllow:
		return fmt.Errorf("%s:%d is plain HTTP, which cellwall refuses by default\n  next: use https (port 443). If plain HTTP is truly required, set unsafe_allow_http on a rule in .cellwall/policy.yaml by hand so it is reviewed", host, port)
	default:
		return fmt.Errorf("%s:%d would still be denied (%s)\n  next: run `cellwall policy lint` and check .cellwall/policy.yaml", host, port, d.Reason)
	}
}

func sourceOf(r policy.Rule) string {
	if r.Source == "" || r.Source == "policy" {
		return ".cellwall/policy.yaml or the session layer"
	}
	return strings.TrimPrefix(r.Source, "preset:") + " preset"
}

// waitForPolicy polls the gateway until it reports hash, or the wait expires.
func waitForPolicy(ctx context.Context, e Env, p *compose.Project, hash string, wait time.Duration) (applied bool, waited time.Duration, problem string) {
	if wait <= 0 {
		wait = 15 * time.Second
	}
	start := time.Now()
	deadline := start.Add(wait)
	var last *gatewayStatus
	var lastErr error
	for {
		st, err := fetchGatewayStatus(ctx, e, p)
		if err == nil {
			last = st
			if st.Policy.PolicyHash == hash {
				return true, time.Since(start), ""
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	switch {
	case last != nil && last.Policy.LastError != "":
		problem = "the gateway rejected the new policy and is still enforcing the old one: " + last.Policy.LastError
	case last != nil:
		problem = "the gateway had not loaded the new policy after " + wait.String()
	case lastErr != nil:
		problem = "could not ask the gateway: " + Brief(lastErr)
	}
	return false, time.Since(start), problem
}
