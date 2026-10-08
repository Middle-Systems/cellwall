// Package policyedit changes policy on behalf of `cellwall allow` and `cellwall deny`.
//
// There are two scopes. The session layer (.cellwall/state/session-policy.yaml) is local state: it
// is merged into the effective policy by `prepare`, is never committed, and cannot be reached from
// the sandbox (the state directory is hidden from the agent). The project layer
// (.cellwall/policy.yaml) is the committed file; `--save` appends to it, preserving comments.
//
// Neither scope can carry an unsafe_* option: relaxations are only honoured when a person writes
// them into the reviewed project policy by hand (ADR 0003).
package policyedit

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/middle-systems/cellwall/internal/policy"
	"github.com/middle-systems/cellwall/internal/safefs"
)

// Paths, relative to the project root.
const (
	SessionFile = ".cellwall/state/session-policy.yaml"
	ProjectFile = ".cellwall/policy.yaml"
)

const sessionHeader = "# Session rules added with `cellwall allow` / `cellwall deny`. Local state: not committed,\n" +
	"# not visible to the agent, merged into the effective policy by `cellwall prepare`.\n" +
	"# Use `--save` to put a rule in the committed .cellwall/policy.yaml instead.\n"

// Edit is one allow or deny request.
type Edit struct {
	Action string // policy.ActionAllow or policy.ActionDeny
	Hosts  []string
	Ports  []int
	Note   string
}

// Rules validates the request and returns the rules it stands for.
func (e Edit) Rules() ([]policy.Rule, error) {
	if e.Action != policy.ActionAllow && e.Action != policy.ActionDeny {
		return nil, fmt.Errorf("internal error: unknown action %q", e.Action)
	}
	if len(e.Hosts) == 0 {
		return nil, errors.New("no host given")
	}
	var out []policy.Rule
	seen := map[string]bool{}
	for _, h := range e.Hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return nil, errors.New("empty host")
		}
		if strings.Contains(h, "://") || strings.ContainsAny(h, "/:@ ") {
			return nil, fmt.Errorf("%q is not a hostname: give only the host (for a port use --port), e.g. registry.example.com", h)
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		r := policy.Rule{Host: h, Action: e.Action, Note: e.Note}
		if len(e.Ports) > 0 {
			r.Ports = slices.Clone(e.Ports)
			slices.Sort(r.Ports)
			r.Ports = slices.Compact(r.Ports)
		}
		out = append(out, r)
	}
	if err := (&policy.Policy{Version: policy.Version, Rules: out}).Validate(false); err != nil {
		return nil, err
	}
	return out, nil
}

// Change records what an edit did so it can be undone if the result does not compile.
type Change struct {
	Changed bool
	path    string
	prev    []byte
	existed bool
}

// Rollback restores the file to what it was before the edit.
func (c Change) Rollback() error {
	if !c.Changed {
		return nil
	}
	if !c.existed {
		if err := os.Remove(c.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return safefs.WriteAtomic(c.path, c.prev, 0o644)
}

// LoadSession returns the session layer, or nil when there is none.
func LoadSession(root string) (*policy.Policy, error) {
	path := filepath.Join(root, filepath.FromSlash(SessionFile))
	b, err := os.ReadFile(path) //nolint:gosec // fixed location under the project's own state dir
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := policy.Parse(path, b)
	if err != nil {
		return nil, fmt.Errorf("%w\n  next: fix or delete %s, then re-run the command", err, SessionFile)
	}
	if err := p.Validate(false); err != nil {
		return nil, err
	}
	for i, r := range p.Rules {
		if r.UnsafeAllowHTTP || r.UnsafeAllowPrivate || r.UnsafeAllowECH || r.UnsafeSkipTLSCheck || r.UnsafeDangerousWildcard {
			return nil, fmt.Errorf("%s: rules[%d] (%s) sets an unsafe_* option; those are only honoured in the reviewed project policy", SessionFile, i, r.Host)
		}
	}
	return p, nil
}

// ApplySession adds the rules to the session layer. A newer rule replaces an older one for the
// same host and ports, and an allow clears a session deny for exactly the same host and ports (and
// vice versa), so `deny x` then `allow x` leaves x allowed. Rules in the committed policy are never
// touched here: a deny there still wins, and the caller reports that.
func ApplySession(root string, e Edit) (Change, error) {
	rules, err := e.Rules()
	if err != nil {
		return Change{}, err
	}
	if why := safefs.SymlinkOnPath(root, SessionFile); why != "" {
		return Change{}, errors.New(why)
	}
	path := filepath.Join(root, filepath.FromSlash(SessionFile))
	cur, err := LoadSession(root)
	if err != nil {
		return Change{}, err
	}
	var prev []byte
	existed := false
	if b, rerr := os.ReadFile(path); rerr == nil { //nolint:gosec // see LoadSession
		prev, existed = b, true
	}
	if cur == nil {
		cur = &policy.Policy{Version: policy.Version}
	}

	next := slices.Clone(cur.Rules)
	for _, nr := range rules {
		if slices.ContainsFunc(next, func(r policy.Rule) bool { return sameRule(r, nr) }) {
			continue // already there exactly as asked: leave its position alone
		}
		next = slices.DeleteFunc(next, func(r policy.Rule) bool {
			return r.Host == nr.Host && slices.Equal(r.Ports, nr.Ports)
		})
		next = append(next, nr)
	}
	out := &policy.Policy{Version: policy.Version, Rules: next}
	body, err := marshal(out)
	if err != nil {
		return Change{}, err
	}
	if existed && bytes.Equal(body, prev) {
		return Change{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // the state dir must be readable by the gateway
		return Change{}, err
	}
	if err := safefs.WriteAtomic(path, body, 0o644); err != nil {
		return Change{}, err
	}
	return Change{Changed: true, path: path, prev: prev, existed: existed}, nil
}

func sameRule(a, b policy.Rule) bool {
	norm := func(act string) string {
		if act == "" {
			return policy.ActionAllow
		}
		return act
	}
	return a.Host == b.Host && norm(a.Action) == norm(b.Action) && slices.Equal(a.Ports, b.Ports) && a.Note == b.Note
}

func marshal(p *policy.Policy) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(sessionHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Save appends the rules to the committed project policy, keeping its comments. It reports the
// hosts that were already present (same host, action and ports) and added nothing for them.
func Save(root string, e Edit) (added, already []string, ch Change, err error) {
	rules, err := e.Rules()
	if err != nil {
		return nil, nil, Change{}, err
	}
	if why := safefs.SymlinkOnPath(root, ProjectFile); why != "" {
		return nil, nil, Change{}, errors.New(why)
	}
	path := filepath.Join(root, filepath.FromSlash(ProjectFile))
	src, err := os.ReadFile(path) //nolint:gosec // fixed location under the project
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, Change{}, fmt.Errorf("%s does not exist\n  next: run `cellwall init`, or omit --save to allow for this session only", ProjectFile)
	}
	if err != nil {
		return nil, nil, Change{}, err
	}
	existing, err := policy.Parse(path, src)
	if err != nil {
		return nil, nil, Change{}, err
	}

	var toAdd []policy.Rule
	for _, r := range rules {
		dup := slices.ContainsFunc(existing.Rules, func(x policy.Rule) bool {
			return x.Host == r.Host && (x.Action == r.Action || (x.Action == "" && r.Action == policy.ActionAllow)) &&
				slices.Equal(x.Ports, r.Ports) && !hasUnsafe(x)
		})
		if dup {
			already = append(already, r.Host)
			continue
		}
		toAdd = append(toAdd, r)
		added = append(added, r.Host)
	}
	if len(toAdd) == 0 {
		return nil, already, Change{}, nil
	}

	out, err := appendRules(src, toAdd)
	if err != nil {
		return nil, nil, Change{}, err
	}
	// Prove the result is a valid policy before it replaces the user's file.
	check, err := policy.Parse(path, out)
	if err != nil {
		return nil, nil, Change{}, fmt.Errorf("internal error: edited policy does not parse (%w); %s was not changed", err, ProjectFile)
	}
	if err := check.Validate(false); err != nil {
		return nil, nil, Change{}, fmt.Errorf("internal error: edited policy is invalid (%w); %s was not changed", err, ProjectFile)
	}
	if len(check.Rules) != len(existing.Rules)+len(toAdd) {
		return nil, nil, Change{}, fmt.Errorf("internal error: expected %d rules after the edit, found %d; %s was not changed", len(existing.Rules)+len(toAdd), len(check.Rules), ProjectFile)
	}
	if err := safefs.WriteAtomic(path, out, 0o644); err != nil {
		return nil, nil, Change{}, err
	}
	return added, already, Change{Changed: true, path: path, prev: src, existed: true}, nil
}

func hasUnsafe(r policy.Rule) bool {
	return r.UnsafeAllowHTTP || r.UnsafeAllowPrivate || r.UnsafeAllowECH || r.UnsafeSkipTLSCheck || r.UnsafeDangerousWildcard
}

// appendRules adds rules to the `rules:` sequence using the YAML node tree so comments and the
// user's other settings survive.
func appendRules(src []byte, rules []policy.Rule) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: expected a mapping at the top level", ProjectFile)
	}
	top := doc.Content[0]
	var seq *yaml.Node
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "rules" {
			seq = top.Content[i+1]
			break
		}
	}
	if seq == nil {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rules"}
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		top.Content = append(top.Content, key, seq)
	}
	if seq.Kind != yaml.SequenceNode {
		// `rules:` with no value is a null scalar.
		if seq.Kind == yaml.ScalarNode && seq.Tag == "!!null" {
			*seq = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", HeadComment: seq.HeadComment, LineComment: seq.LineComment, FootComment: seq.FootComment}
		} else {
			return nil, fmt.Errorf("%s: `rules` must be a list", ProjectFile)
		}
	}
	seq.Style = 0 // an empty `[]` is written in flow style; entries need block style
	for _, r := range rules {
		var n yaml.Node
		if err := n.Encode(r); err != nil {
			return nil, err
		}
		seq.Content = append(seq.Content, &n)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RemoveSession deletes the session allow/deny rules for the given hosts (every port variant) and
// removes the session file when nothing is left. It never touches the committed policy.
func RemoveSession(root string, hosts []string) (Change, error) {
	if why := safefs.SymlinkOnPath(root, SessionFile); why != "" {
		return Change{}, errors.New(why)
	}
	path := filepath.Join(root, filepath.FromSlash(SessionFile))
	cur, err := LoadSession(root)
	if err != nil || cur == nil {
		return Change{}, err
	}
	prev, rerr := os.ReadFile(path) //nolint:gosec // see LoadSession
	if rerr != nil {
		return Change{}, rerr
	}
	drop := map[string]bool{}
	for _, h := range hosts {
		drop[strings.ToLower(strings.TrimSpace(h))] = true
	}
	kept := slices.DeleteFunc(slices.Clone(cur.Rules), func(r policy.Rule) bool { return drop[r.Host] })
	if len(kept) == len(cur.Rules) {
		return Change{}, nil
	}
	if len(kept) == 0 {
		if err := os.Remove(path); err != nil {
			return Change{}, err
		}
		return Change{Changed: true, path: path, prev: prev, existed: true}, nil
	}
	body, err := marshal(&policy.Policy{Version: policy.Version, Rules: kept})
	if err != nil {
		return Change{}, err
	}
	if err := safefs.WriteAtomic(path, body, 0o644); err != nil {
		return Change{}, err
	}
	return Change{Changed: true, path: path, prev: prev, existed: true}, nil
}
