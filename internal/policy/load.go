package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// MaxPolicyBytes bounds how much of a policy file is parsed.
const MaxPolicyBytes = 1 << 20

// SyntaxError is a policy problem with a position, formatted like a compiler error.
type SyntaxError struct {
	File string
	Line int
	Col  int
	Msg  string
}

func (e *SyntaxError) Error() string {
	file := e.File
	if file == "" {
		file = "policy"
	}
	if e.Line == 0 {
		return fmt.Sprintf("%s: %s", file, e.Msg)
	}
	return fmt.Sprintf("%s:%d:%d: %s", file, e.Line, e.Col, e.Msg)
}

// schema describes the allowed keys of a mapping and what each value must be.
type schema struct {
	keys map[string]kind
}

type kind int

const (
	kScalar kind = iota
	kSeqScalar
	kSeqRule
	kMapLimits
)

var (
	policySchema = schema{keys: map[string]kind{
		"version": kScalar, "description": kScalar, "default": kScalar,
		"presets": kSeqScalar, "rules": kSeqRule, "limits": kMapLimits,
	}}
	ruleSchema = schema{keys: map[string]kind{
		"host": kScalar, "action": kScalar, "ports": kSeqScalar, "note": kScalar, "source": kScalar,
		"unsafe_allow_http": kScalar, "unsafe_allow_private": kScalar, "unsafe_allow_ech": kScalar,
		"unsafe_skip_tls_check": kScalar, "unsafe_allow_dangerous_wildcard": kScalar,
	}}
	limitsSchema = schema{keys: map[string]kind{
		"max_conns": kScalar, "idle_timeout": kScalar, "total_timeout": kScalar, "dial_timeout": kScalar,
		"handshake_timeout": kScalar, "max_bytes_per_conn": kScalar, "max_new_conns_per_host_per_min": kScalar,
		"max_label_len": kScalar, "max_host_len": kScalar, "deny_suspicious": kScalar,
	}}
)

// Parse reads a policy document (YAML or JSON) strictly: unknown keys, duplicate keys, anchors,
// aliases, explicit tags and multiple documents are all errors, each with line and column. It
// only checks structure; call Validate/Compile for semantics. file is used in error messages.
func Parse(file string, data []byte) (*Policy, error) {
	if len(data) > MaxPolicyBytes {
		return nil, &SyntaxError{File: file, Msg: fmt.Sprintf("policy file is %d bytes; the limit is %d", len(data), MaxPolicyBytes)}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &SyntaxError{File: file, Msg: "policy file is empty"}
		}
		return nil, wrapYAMLError(file, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, &SyntaxError{File: file, Line: extra.Line, Col: extra.Column, Msg: "multiple YAML documents are not allowed"}
	} else if !errors.Is(err, io.EOF) {
		return nil, wrapYAMLError(file, err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		return nil, &SyntaxError{File: file, Msg: "not a YAML document"}
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, &SyntaxError{File: file, Line: top.Line, Col: top.Column, Msg: "policy must be a mapping of keys to values"}
	}
	if err := checkMapping(file, top, policySchema, ""); err != nil {
		return nil, err
	}
	var p Policy
	if err := top.Decode(&p); err != nil {
		return nil, wrapYAMLError(file, err)
	}
	// Remember where each rule was written for later validation errors.
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value != "rules" || top.Content[i+1].Kind != yaml.SequenceNode {
			continue
		}
		for j, item := range top.Content[i+1].Content {
			if j < len(p.Rules) {
				p.Rules[j].file, p.Rules[j].line, p.Rules[j].col = file, item.Line, item.Column
			}
		}
	}
	return &p, nil
}

func wrapYAMLError(file string, err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) && len(te.Errors) > 0 {
		return &SyntaxError{File: file, Msg: strings.TrimPrefix(te.Errors[0], "yaml: ")}
	}
	msg := strings.TrimPrefix(err.Error(), "yaml: ")
	// "yaml: line 3: ..." -> keep the line number as position.
	if rest, ok := strings.CutPrefix(msg, "line "); ok {
		var line int
		if n, _ := fmt.Sscanf(rest, "%d:", &line); n == 1 {
			if _, after, found := strings.Cut(rest, ": "); found {
				return &SyntaxError{File: file, Line: line, Col: 1, Msg: after}
			}
		}
	}
	return &SyntaxError{File: file, Msg: msg}
}

func checkMapping(file string, n *yaml.Node, s schema, path string) error {
	if err := checkPlain(file, n); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if err := checkPlain(file, k); err != nil {
			return err
		}
		if k.Kind != yaml.ScalarNode {
			return &SyntaxError{File: file, Line: k.Line, Col: k.Column, Msg: "keys must be plain strings"}
		}
		want, ok := s.keys[k.Value]
		if !ok {
			msg := fmt.Sprintf("unknown key %q", path+k.Value)
			if guess := nearest(k.Value, s.keys); guess != "" {
				msg += fmt.Sprintf(" (did you mean %q?)", guess)
			}
			return &SyntaxError{File: file, Line: k.Line, Col: k.Column, Msg: msg}
		}
		if seen[k.Value] {
			return &SyntaxError{File: file, Line: k.Line, Col: k.Column, Msg: fmt.Sprintf("duplicate key %q", path+k.Value)}
		}
		seen[k.Value] = true
		if err := checkValue(file, v, want, path+k.Value); err != nil {
			return err
		}
	}
	return nil
}

func checkValue(file string, v *yaml.Node, want kind, path string) error {
	if err := checkPlain(file, v); err != nil {
		return err
	}
	bad := func(expect string) error {
		return &SyntaxError{File: file, Line: v.Line, Col: v.Column, Msg: fmt.Sprintf("%q must be %s", path, expect)}
	}
	switch want {
	case kScalar:
		if v.Kind != yaml.ScalarNode {
			return bad("a single value")
		}
	case kSeqScalar:
		if v.Kind != yaml.SequenceNode {
			return bad("a list")
		}
		for _, item := range v.Content {
			if err := checkPlain(file, item); err != nil {
				return err
			}
			if item.Kind != yaml.ScalarNode {
				return &SyntaxError{File: file, Line: item.Line, Col: item.Column, Msg: fmt.Sprintf("items of %q must be single values", path)}
			}
		}
	case kSeqRule:
		if v.Kind != yaml.SequenceNode {
			return bad("a list")
		}
		for i, item := range v.Content {
			if item.Kind != yaml.MappingNode {
				return &SyntaxError{File: file, Line: item.Line, Col: item.Column, Msg: fmt.Sprintf("%s[%d] must be a mapping with at least a \"host\" key", path, i)}
			}
			if err := checkMapping(file, item, ruleSchema, fmt.Sprintf("%s[%d].", path, i)); err != nil {
				return err
			}
		}
	case kMapLimits:
		if v.Kind != yaml.MappingNode {
			return bad("a mapping")
		}
		return checkMapping(file, v, limitsSchema, path+".")
	}
	return nil
}

// checkPlain rejects YAML features that let a document say one thing and mean another.
func checkPlain(file string, n *yaml.Node) error {
	switch {
	case n.Kind == yaml.AliasNode:
		return &SyntaxError{File: file, Line: n.Line, Col: n.Column, Msg: "YAML aliases are not allowed in policy files"}
	case n.Anchor != "":
		return &SyntaxError{File: file, Line: n.Line, Col: n.Column, Msg: "YAML anchors are not allowed in policy files"}
	case n.Style&yaml.TaggedStyle != 0:
		return &SyntaxError{File: file, Line: n.Line, Col: n.Column, Msg: "explicit YAML tags are not allowed in policy files"}
	}
	return nil
}

// nearest returns the allowed key within edit distance 2 of s, if any.
func nearest(s string, keys map[string]kind) string {
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	best, bestD := "", 3
	for _, k := range names {
		if d := editDistance(s, k); d < bestD {
			best, bestD = k, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
