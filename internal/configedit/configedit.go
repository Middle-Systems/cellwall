// Package configedit makes small, comment-preserving changes to .cellwall/config.yaml on behalf of
// commands such as `cellwall ports add`. Anything larger is the user's to edit by hand.
package configedit

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"go.yaml.in/yaml/v3"

	"github.com/middle-systems/cellwall/internal/config"
	"github.com/middle-systems/cellwall/internal/safefs"
	"github.com/middle-systems/cellwall/internal/yamlkeep"
)

// Change records an edit so it can be undone if what depends on it is refused.
type Change struct {
	Changed bool
	path    string
	prev    []byte
}

// Rollback restores the file to what it was before the edit.
func (c Change) Rollback() error {
	if !c.Changed {
		return nil
	}
	return safefs.WriteAtomic(c.path, c.prev, 0o644)
}

// SetPorts replaces the `ports` list, keeping the file's comments and every other setting. The
// ports are written sorted, as a flow list (`[3000, 5173]`), matching how `init` writes them.
func SetPorts(root string, ports []int) (Change, error) {
	if why := safefs.SymlinkOnPath(root, config.ProjectFile); why != "" {
		return Change{}, errors.New(why)
	}
	path := filepath.Join(root, filepath.FromSlash(config.ProjectFile))
	src, err := os.ReadFile(path) //nolint:gosec // fixed location in the project
	if errors.Is(err, fs.ErrNotExist) {
		return Change{}, config.ErrNoProjectConfig
	}
	if err != nil {
		return Change{}, err
	}
	ports = slices.Clone(ports)
	slices.Sort(ports)
	ports = slices.Compact(ports)

	// Nothing to do when the list already says this: a YAML round trip is not byte-identical, and
	// an unneeded rewrite would churn the user's file.
	var cur struct {
		Ports []int `yaml:"ports"`
	}
	if err := yaml.Unmarshal(src, &cur); err == nil {
		have := slices.Clone(cur.Ports)
		slices.Sort(have)
		if slices.Equal(slices.Compact(have), ports) {
			return Change{}, nil
		}
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return Change{}, fmt.Errorf("%s: %w", config.ProjectFile, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return Change{}, fmt.Errorf("%s: expected a mapping at the top level", config.ProjectFile)
	}
	top := doc.Content[0]
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, p := range ports {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(p)})
	}
	found := false
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "ports" {
			old := top.Content[i+1]
			seq.HeadComment, seq.LineComment, seq.FootComment = old.HeadComment, old.LineComment, old.FootComment
			top.Content[i+1] = seq
			found = true
			break
		}
	}
	if !found {
		top.Content = append(top.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ports"}, seq)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return Change{}, err
	}
	if err := enc.Close(); err != nil {
		return Change{}, err
	}
	out := yamlkeep.BlankLines(src, buf.Bytes())
	if bytes.Equal(out, src) {
		return Change{}, nil
	}
	if err := safefs.WriteAtomic(path, out, 0o644); err != nil {
		return Change{}, err
	}
	return Change{Changed: true, path: path, prev: src}, nil
}
