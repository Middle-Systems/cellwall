// Package strictyaml parses YAML (or JSON) configuration files strictly and reports problems the
// way a compiler would: file:line:col and a plain-language message.
//
// "Strict" means the things that let a document say one thing and mean another are errors:
// unknown keys (a typo must not silently drop a restriction), duplicate keys, YAML anchors,
// aliases and explicit tags, more than one document, and wrongly shaped values. Validation of
// meaning (ranges, hostnames) is left to the caller; this package only checks structure.
package strictyaml

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// MaxBytes bounds how much of a file is parsed.
const MaxBytes = 1 << 20

// Error is a problem with a position, formatted like a compiler error.
type Error struct {
	File string
	Line int
	Col  int
	Msg  string
}

func (e *Error) Error() string {
	file := e.File
	if file == "" {
		file = "config"
	}
	if e.Line == 0 {
		return fmt.Sprintf("%s: %s", file, e.Msg)
	}
	return fmt.Sprintf("%s:%d:%d: %s", file, e.Line, e.Col, e.Msg)
}

// Kind is the shape a value must have.
type Kind int

const (
	// Scalar is a single value (string, number, bool).
	Scalar Kind = iota
	// ScalarList is a list of single values.
	ScalarList
	// ScalarOrList is either a single value or a list of single values.
	ScalarOrList
	// ScalarMap is a mapping with arbitrary keys whose values are single values (e.g. env vars).
	ScalarMap
	// Object is a mapping with a known set of keys (Field.Sub).
	Object
	// ObjectList is a list of such mappings.
	ObjectList
)

// Field describes one allowed key.
type Field struct {
	Kind Kind
	Sub  *Schema // for Object and ObjectList
}

// Schema is the set of allowed keys of a mapping.
type Schema struct {
	Keys map[string]Field
}

// Parse reads one YAML or JSON document and checks it against root. It returns the document's top
// mapping node so callers can decode it and read positions from it.
func Parse(file string, data []byte, root *Schema) (*yaml.Node, error) {
	if len(data) > MaxBytes {
		return nil, &Error{File: file, Msg: fmt.Sprintf("file is %d bytes; the limit is %d", len(data), MaxBytes)}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &Error{File: file, Msg: "file is empty"}
		}
		return nil, WrapYAML(file, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, &Error{File: file, Line: extra.Line, Col: extra.Column, Msg: "multiple YAML documents are not allowed"}
	} else if !errors.Is(err, io.EOF) {
		return nil, WrapYAML(file, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, &Error{File: file, Msg: "not a YAML document"}
	}
	top := doc.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, &Error{File: file, Line: top.Line, Col: top.Column, Msg: "must be a mapping of keys to values"}
	}
	if err := checkMapping(file, top, root, ""); err != nil {
		return nil, err
	}
	return top, nil
}

// Decode decodes a node returned by Parse into v, converting decoder errors to positioned ones.
func Decode(file string, n *yaml.Node, v any) error {
	if err := n.Decode(v); err != nil {
		return WrapYAML(file, err)
	}
	return nil
}

// WrapYAML turns a decoder error into an Error, keeping a line number when the decoder gave one.
func WrapYAML(file string, err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) && len(te.Errors) > 0 {
		return &Error{File: file, Msg: strings.TrimPrefix(te.Errors[0], "yaml: ")}
	}
	msg := strings.TrimPrefix(err.Error(), "yaml: ")
	if rest, ok := strings.CutPrefix(msg, "line "); ok {
		var line int
		if n, _ := fmt.Sscanf(rest, "%d:", &line); n == 1 {
			if _, after, found := strings.Cut(rest, ": "); found {
				return &Error{File: file, Line: line, Col: 1, Msg: after}
			}
		}
	}
	return &Error{File: file, Msg: msg}
}

func checkMapping(file string, n *yaml.Node, s *Schema, path string) error {
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
			return &Error{File: file, Line: k.Line, Col: k.Column, Msg: "keys must be plain strings"}
		}
		field, ok := s.Keys[k.Value]
		if !ok {
			msg := fmt.Sprintf("unknown key %q", path+k.Value)
			if guess := nearest(k.Value, s.Keys); guess != "" {
				msg += fmt.Sprintf(" (did you mean %q?)", guess)
			}
			return &Error{File: file, Line: k.Line, Col: k.Column, Msg: msg}
		}
		if seen[k.Value] {
			return &Error{File: file, Line: k.Line, Col: k.Column, Msg: fmt.Sprintf("duplicate key %q", path+k.Value)}
		}
		seen[k.Value] = true
		if err := checkValue(file, v, field, path+k.Value); err != nil {
			return err
		}
	}
	return nil
}

func checkValue(file string, v *yaml.Node, f Field, path string) error {
	if err := checkPlain(file, v); err != nil {
		return err
	}
	bad := func(expect string) error {
		return &Error{File: file, Line: v.Line, Col: v.Column, Msg: fmt.Sprintf("%q must be %s", path, expect)}
	}
	scalars := func(list *yaml.Node) error {
		for _, item := range list.Content {
			if err := checkPlain(file, item); err != nil {
				return err
			}
			if item.Kind != yaml.ScalarNode {
				return &Error{File: file, Line: item.Line, Col: item.Column, Msg: fmt.Sprintf("items of %q must be single values", path)}
			}
		}
		return nil
	}
	switch f.Kind {
	case Scalar:
		if v.Kind != yaml.ScalarNode {
			return bad("a single value")
		}
	case ScalarList:
		if v.Kind != yaml.SequenceNode {
			return bad("a list")
		}
		return scalars(v)
	case ScalarOrList:
		switch v.Kind {
		case yaml.ScalarNode:
		case yaml.SequenceNode:
			return scalars(v)
		default:
			return bad("a single value or a list")
		}
	case ScalarMap:
		if v.Kind != yaml.MappingNode {
			return bad("a mapping of names to single values")
		}
		seen := map[string]bool{}
		for i := 0; i+1 < len(v.Content); i += 2 {
			k, val := v.Content[i], v.Content[i+1]
			if err := checkPlain(file, k); err != nil {
				return err
			}
			if err := checkPlain(file, val); err != nil {
				return err
			}
			if k.Kind != yaml.ScalarNode || val.Kind != yaml.ScalarNode {
				return &Error{File: file, Line: val.Line, Col: val.Column, Msg: fmt.Sprintf("entries of %q must be name: value", path)}
			}
			if seen[k.Value] {
				return &Error{File: file, Line: k.Line, Col: k.Column, Msg: fmt.Sprintf("duplicate key %q", path+"."+k.Value)}
			}
			seen[k.Value] = true
		}
	case Object:
		if v.Kind != yaml.MappingNode {
			return bad("a mapping")
		}
		return checkMapping(file, v, f.Sub, path+".")
	case ObjectList:
		if v.Kind != yaml.SequenceNode {
			return bad("a list")
		}
		for i, item := range v.Content {
			if item.Kind != yaml.MappingNode {
				return &Error{File: file, Line: item.Line, Col: item.Column, Msg: fmt.Sprintf("%s[%d] must be a mapping", path, i)}
			}
			if err := checkMapping(file, item, f.Sub, fmt.Sprintf("%s[%d].", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkPlain rejects YAML features that let a document say one thing and mean another.
func checkPlain(file string, n *yaml.Node) error {
	switch {
	case n.Kind == yaml.AliasNode:
		return &Error{File: file, Line: n.Line, Col: n.Column, Msg: "YAML aliases are not allowed"}
	case n.Anchor != "":
		return &Error{File: file, Line: n.Line, Col: n.Column, Msg: "YAML anchors are not allowed"}
	case n.Style&yaml.TaggedStyle != 0:
		return &Error{File: file, Line: n.Line, Col: n.Column, Msg: "explicit YAML tags are not allowed"}
	}
	return nil
}

// nearest returns the allowed key within edit distance 2 of s, if any.
func nearest(s string, keys map[string]Field) string {
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
