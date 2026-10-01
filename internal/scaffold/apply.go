package scaffold

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/middle-systems/cellwall/internal/safefs"
)

// Report summarises what Apply did.
type Report struct {
	Written   []string
	Unchanged []string
	Kept      []string
}

// Apply performs the plan. It refuses to write anything if the plan has conflicts. Files are
// written atomically (temp file in the same directory, then rename).
func (p *Plan) Apply() (*Report, error) {
	if c := p.Conflicts(); len(c) > 0 {
		return nil, &ConflictError{Conflicts: c}
	}
	rep := &Report{}
	for _, a := range p.Actions {
		switch a.Kind {
		case Unchanged:
			rep.Unchanged = append(rep.Unchanged, a.File.Path)
		case Keep:
			rep.Kept = append(rep.Kept, a.File.Path)
		case Create, Update, Overwrite:
			// Re-check at write time: a symlink could have appeared since Build.
			if why := safefs.SymlinkOnPath(p.Root, a.File.Path); why != "" {
				return rep, fmt.Errorf("refusing to write %s: %s", a.File.Path, why)
			}
			if err := safefs.WriteAtomic(filepath.Join(p.Root, filepath.FromSlash(a.File.Path)), a.File.Content, a.File.Mode); err != nil {
				return rep, fmt.Errorf("write %s: %w", a.File.Path, err)
			}
			rep.Written = append(rep.Written, a.File.Path)
		}
	}
	return rep, nil
}

// ConflictError carries the conflicting files so the CLI can explain each and what to do next.
type ConflictError struct{ Conflicts []Action }

func (e *ConflictError) Error() string {
	var paths []string
	for _, c := range e.Conflicts {
		paths = append(paths, c.File.Path)
	}
	return "refusing to overwrite existing files: " + strings.Join(paths, ", ")
}
