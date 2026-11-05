package policy

import (
	"go.yaml.in/yaml/v3"

	"github.com/middle-systems/kennel/internal/strictyaml"
)

// MaxPolicyBytes bounds how much of a policy file is parsed.
const MaxPolicyBytes = strictyaml.MaxBytes

// SyntaxError is a policy problem with a position, formatted like a compiler error.
type SyntaxError = strictyaml.Error

var (
	limitsSchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"max_conns": {}, "idle_timeout": {}, "total_timeout": {}, "dial_timeout": {},
		"handshake_timeout": {}, "max_bytes_per_conn": {}, "max_new_conns_per_host_per_min": {},
		"max_label_len": {}, "max_host_len": {}, "deny_suspicious": {},
	}}
	ruleSchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"host": {}, "action": {}, "ports": {Kind: strictyaml.ScalarList}, "note": {}, "source": {},
		"unsafe_allow_http": {}, "unsafe_allow_private": {}, "unsafe_allow_ech": {},
		"unsafe_skip_tls_check": {}, "unsafe_allow_dangerous_wildcard": {},
	}}
	policySchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"version": {}, "description": {}, "default": {},
		"presets": {Kind: strictyaml.ScalarList},
		"rules":   {Kind: strictyaml.ObjectList, Sub: ruleSchema},
		"limits":  {Kind: strictyaml.Object, Sub: limitsSchema},
	}}
)

// Parse reads a policy document (YAML or JSON) strictly: unknown keys, duplicate keys, anchors,
// aliases, explicit tags and multiple documents are all errors, each with line and column. It
// only checks structure; call Validate/Compile for semantics. file is used in error messages.
func Parse(file string, data []byte) (*Policy, error) {
	top, err := strictyaml.Parse(file, data, policySchema)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := strictyaml.Decode(file, top, &p); err != nil {
		return nil, err
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
