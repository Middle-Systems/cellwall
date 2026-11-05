package volume

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/middle-systems/kennel/internal/safefs"
)

// StateFile is where the seeding record lives, relative to the project root.
const StateFile = ".kennel/state/volume.json"

// State records how the workspace volume was seeded. Base is the host commit the agent's copy
// started from (later: the commit last brought back with `fetch --apply`); bundles carry only
// what is newer than it.
type State struct {
	Version int    `json:"version"`
	Base    string `json:"base"`
	Branch  string `json:"branch"`
}

// ErrNotSeeded means the workspace volume has not been seeded from this repository yet.
var ErrNotSeeded = errors.New("the workspace volume has not been seeded from this repository\n  next: run `kennel up`, which seeds it")

// LoadState reads the seeding record.
func LoadState(root string) (State, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(StateFile))) //nolint:gosec // fixed location in the project's state dir
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, ErrNotSeeded
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil || s.Base == "" {
		return State{}, fmt.Errorf("%s is unreadable; delete it and run `kennel up` to seed again (the volume keeps the agent's work)", StateFile)
	}
	return s, nil
}

// SaveState writes the seeding record atomically.
func SaveState(root string, s State) error {
	if why := safefs.SymlinkOnPath(root, StateFile); why != "" {
		return errors.New(why)
	}
	s.Version = 1
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(root, filepath.FromSlash(StateFile))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // state dir
		return err
	}
	return safefs.WriteAtomic(p, append(b, '\n'), 0o644)
}
