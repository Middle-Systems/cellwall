package gen

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/middle-systems/kennel/internal/config"
	"github.com/middle-systems/kennel/internal/pins"
)

//go:embed templates/*
var templatesFS embed.FS

// Kind says how a file may be written.
type Kind int

const (
	// Generated files are stamped; they are regenerated when pristine and kept (with a report) if a
	// human edited them. This is the default for everything under .devcontainer/.
	Generated Kind = iota
	// Seed files are starting points owned by the user afterwards: written only if absent, never
	// overwritten (not even by --force).
	Seed
	// Verbatim files cannot carry a marker (JSON lockfiles); they count as ours only if they are
	// byte-identical to what would be written.
	Verbatim
)

// File is one file to write, with a path relative to the project root.
type File struct {
	Path    string
	Content []byte
	Mode    fs.FileMode
	Kind    Kind
}

var funcs = template.FuncMap{
	// q renders a string as a double-quoted scalar. JSON strings are valid YAML double-quoted
	// scalars, so one function is safe for compose.yaml, devcontainer.json and config files.
	"q": func(s string) string {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(s)
		return strings.TrimRight(buf.String(), "\n")
	},
	"inc": func(i int) int { return i + 1 },
}

func render(name string, data any) (string, error) {
	t, err := template.New(name).Funcs(funcs).Option("missingkey=error").ParseFS(templatesFS, "templates/"+name)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		return "", fmt.Errorf("render %s: %w", name, err)
	}
	return buf.String(), nil
}

// ---- view helpers used by the templates ----

// ToRoot is the path from the container-files directory back to the project root.
func (d *Data) ToRoot() string { return d.Layout.ToRoot }

// StateRel is the gateway state directory relative to the project root.
func (d *Data) StateRel() string { return StateDirRel }

// StateEnv is the state directory as a compose expression with a relative default.
func (d *Data) StateEnv() string {
	return "${KENNEL_STATE:-" + d.Layout.ToRoot + "/" + StateDirRel + "}"
}

// WorkspaceEnv is the workspace directory as a compose expression with a relative default.
func (d *Data) WorkspaceEnv() string { return "${KENNEL_WORKSPACE:-" + d.Layout.ToRoot + "}" }

// PinnedVersion is the agent version kennel holds an integrity lockfile for.
func (d *Data) PinnedVersion() string { return pins.ClaudeCodeVersion }

func flow(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func quoted(items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = funcs["q"].(func(string) string)(s)
	}
	return out
}

// StacksYAML renders stacks: auto, or the explicit list.
func (d *Data) StacksYAML() string {
	if d.Cfg.Stacks.Auto {
		return "auto"
	}
	return flow(d.Cfg.Stacks.Items)
}

// CacheYAML renders cache_volumes.
func (d *Data) CacheYAML() string {
	switch {
	case d.Cfg.Workspace.CacheVolumes.Auto:
		return "auto"
	case d.Cfg.Workspace.CacheVolumes.IsNone():
		return "none"
	}
	return flow(quoted(d.Cfg.Workspace.CacheVolumes.Items))
}

// CommandYAML renders agent.command as a flow list.
func (d *Data) CommandYAML() string { return flow(quoted(d.Cfg.Agent.Command)) }

// PortsYAML renders ports as a flow list of integers.
func (d *Data) PortsYAML() string {
	s := make([]string, len(d.Ports))
	for i, p := range d.Ports {
		s[i] = strconv.Itoa(p)
	}
	return flow(s)
}

// DefaultProtected lists the built-in protected paths for the config comment.
func (d *Data) DefaultProtected() string { return strings.Join(config.DefaultProtected, ", ") }

// PresetsYAML renders the stack presets for the policy seed.
func (d *Data) PresetsYAML() string { return flow(d.SeedPresets) }

// ---- committed files ----

// Committed returns the files `init` writes into the project, in a stable order.
func Committed(in Inputs, seedPresets []string) ([]File, error) {
	d, err := NewData(in)
	if err != nil {
		return nil, err
	}
	d.SeedPresets = seedPresets
	dir := d.Layout.Dir

	var files []File
	add := func(path string, kind Kind, mode fs.FileMode, comment, body string) {
		content := body
		if kind == Generated {
			content = Stamp(comment, body)
		}
		files = append(files, File{Path: path, Content: []byte(content), Mode: mode, Kind: kind})
	}

	for _, spec := range []struct {
		out, tmpl, comment string
		kind               Kind
		mode               fs.FileMode
		dir                string
	}{
		{"config.yaml", "config.yaml.tmpl", "", Seed, 0o644, ".kennel"},
		{"policy.yaml", "policy.yaml.tmpl", "", Seed, 0o644, ".kennel"},
		{".gitignore", "kennel.gitignore.tmpl", "#", Generated, 0o644, ".kennel"},
		{"Dockerfile", "Dockerfile.tmpl", "#", Generated, 0o644, dir},
		{"compose.yaml", "compose.yaml.tmpl", "#", Generated, 0o644, dir},
		{"devcontainer.json", "devcontainer.json.tmpl", "//", Generated, 0o644, dir},
		{".gitattributes", "gitattributes.tmpl", "#", Generated, 0o644, dir},
	} {
		body, err := render(spec.tmpl, d)
		if err != nil {
			return nil, err
		}
		add(spec.dir+"/"+spec.out, spec.kind, spec.mode, spec.comment, body)
	}
	ep, err := templatesFS.ReadFile("templates/entrypoint.sh")
	if err != nil {
		return nil, err
	}
	add(dir+"/entrypoint.sh", Generated, 0o755, "#", string(ep))

	if d.Claude {
		if pkg, lock, ok := pins.ClaudeLock(d.ClaudeVersion); ok {
			add(dir+"/agent/claude/package.json", Verbatim, 0o644, "", string(pkg))
			add(dir+"/agent/claude/package-lock.json", Verbatim, 0o644, "", string(lock))
		} else {
			pkg := fmt.Sprintf("{\n  \"name\": \"kennel-agent-claude\",\n  \"version\": \"0.0.0\",\n  \"private\": true,\n  \"dependencies\": {\n    \"@anthropic-ai/claude-code\": %q\n  }\n}\n", d.ClaudeVersion)
			add(dir+"/agent/claude/package.json", Verbatim, 0o644, "", pkg)
		}
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}
