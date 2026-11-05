package strictyaml

import (
	"errors"
	"strings"
	"testing"
)

var testSchema = &Schema{Keys: map[string]Field{
	"name":  {},
	"tags":  {Kind: ScalarList},
	"mode":  {Kind: ScalarOrList},
	"env":   {Kind: ScalarMap},
	"inner": {Kind: Object, Sub: &Schema{Keys: map[string]Field{"a": {}, "b": {}}}},
	"items": {Kind: ObjectList, Sub: &Schema{Keys: map[string]Field{"x": {}}}},
}}

func TestParseAccepts(t *testing.T) {
	for name, src := range map[string]string{
		"minimal":        "name: a\n",
		"scalar or list": "mode: auto\n",
		"list form":      "mode: [a, b]\n",
		"env map":        "env: {A: '1', B: two}\n",
		"nested":         "inner: {a: 1}\nitems:\n  - x: 1\n  - x: 2\n",
		"json":           `{"name": "a", "tags": ["x"]}`,
	} {
		if _, err := Parse("t.yaml", []byte(src), testSchema); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseRejectsWithPositions(t *testing.T) {
	tests := []struct {
		name, src, want string
		line, col       int
	}{
		{"unknown key", "name: a\nnmae: b\n", `unknown key "nmae" (did you mean "name"?)`, 2, 1}, //nolint:misspell // deliberate typo
		{"nested unknown", "inner:\n  c: 1\n", `unknown key "inner.c"`, 2, 3},
		{"duplicate", "name: a\nname: b\n", `duplicate key "name"`, 2, 1},
		{"env duplicate", "env:\n  A: 1\n  A: 2\n", "duplicate key", 3, 3},
		{"alias", "name: &x a\n", "anchors are not allowed", 1, 7},
		{"tag", "name: !!str a\n", "tags are not allowed", 1, 7},
		{"scalar given list", "name: [a]\n", `"name" must be a single value`, 1, 7},
		{"list given scalar", "tags: a\n", `"tags" must be a list`, 1, 7},
		{"scalar or list given map", "mode: {a: b}\n", "single value or a list", 1, 7},
		{"env given list", "env: [a]\n", "mapping of names", 1, 6},
		{"env value not scalar", "env:\n  A: [1]\n", "name: value", 2, 6},
		{"list item not scalar", "tags:\n  - [a]\n", "must be single values", 2, 5},
		{"object given scalar", "inner: x\n", `"inner" must be a mapping`, 1, 8},
		{"object list item", "items:\n  - x\n", "must be a mapping", 2, 5},
		{"top not mapping", "- a\n", "must be a mapping", 1, 1},
		{"multi doc", "name: a\n---\nname: b\n", "multiple YAML documents", 2, 1},
	}
	for _, tt := range tests {
		_, err := Parse("t.yaml", []byte(tt.src), testSchema)
		var e *Error
		if !errors.As(err, &e) {
			t.Errorf("%s: got %v", tt.name, err)
			continue
		}
		if !strings.Contains(e.Msg, tt.want) || e.Line != tt.line || e.Col != tt.col {
			t.Errorf("%s: %d:%d %q; want %d:%d containing %q", tt.name, e.Line, e.Col, e.Msg, tt.line, tt.col, tt.want)
		}
	}
	if _, err := Parse("t", nil, testSchema); err == nil {
		t.Error("empty must fail")
	}
	if _, err := Parse("t", []byte(strings.Repeat("#", MaxBytes+1)), testSchema); err == nil {
		t.Error("oversize must fail")
	}
}

func TestErrorFormat(t *testing.T) {
	if got := (&Error{File: "a.yaml", Line: 3, Col: 5, Msg: "m"}).Error(); got != "a.yaml:3:5: m" {
		t.Error(got)
	}
	if got := (&Error{Msg: "m"}).Error(); got != "config: m" {
		t.Error(got)
	}
}
