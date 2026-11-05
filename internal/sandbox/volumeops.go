package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/middle-systems/kennel/internal/compose"
	"github.com/middle-systems/kennel/internal/config"
	"github.com/middle-systems/kennel/internal/volume"
)

// agentRunner runs commands in the agent container for the volume package.
type agentRunner struct {
	p *compose.Project
}

func (a agentRunner) Run(ctx context.Context, stdin io.Reader, stdout io.Writer, argv ...string) (string, int, error) {
	var eb bytes.Buffer
	if stdout == nil {
		stdout = io.Discard
	}
	code, err := a.p.Exec(ctx, compose.Streams{In: stdin, Out: stdout, Err: &eb}, compose.AgentService, false, argv...)
	return eb.String(), code, err
}

// ErrNotVolumeMode is returned by commands that only make sense when the repository lives in a
// volume.
var ErrNotVolumeMode = errors.New("workspace.mode is bind: the agent works directly in your working tree, so there is nothing to fetch\n  next: use `git diff` / `git status`, or switch with workspace.mode: volume in .kennel/config.yaml and `kennel init`")

func volumeProject(ctx context.Context, e Env, root string) (*compose.Project, volume.Repo, agentRunner, error) {
	p, err := compose.Open(root, e.GlobalDir)
	if err != nil {
		return nil, volume.Repo{}, agentRunner{}, err
	}
	if p.Cfg.Workspace.Mode != "volume" {
		return nil, volume.Repo{}, agentRunner{}, ErrNotVolumeMode
	}
	up, err := Running(ctx, e, p, compose.AgentService)
	if err != nil {
		return nil, volume.Repo{}, agentRunner{}, fmt.Errorf("could not query the sandbox: %s\n  next: run `kennel doctor`", Brief(err))
	}
	if !up {
		return nil, volume.Repo{}, agentRunner{}, errors.New("the agent container is not running, so its repository cannot be read\n  next: run `kennel up`, then retry")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, volume.Repo{}, agentRunner{}, err
	}
	return p, volume.Repo{Dir: abs}, agentRunner{p}, nil
}

// SeedVolume copies the host repository into the workspace volume if it is empty. Up calls it.
func SeedVolume(ctx context.Context, e Env, root string) (*volume.SeedResult, error) {
	p, repo, ag, err := volumeProject(ctx, e, root)
	if err != nil {
		return nil, err
	}
	_ = p
	return volume.Seed(ctx, ag, repo, repo.Dir, volume.DefaultLayout)
}

// Fetch brings the agent's commits into refs/kennel/* on the host.
func Fetch(ctx context.Context, e Env, root string) (*volume.FetchResult, *config.Config, error) {
	p, repo, ag, err := volumeProject(ctx, e, root)
	if err != nil {
		return nil, nil, err
	}
	res, err := volume.Fetch(ctx, ag, repo, repo.Dir, volume.FetchOptions{Protected: p.Cfg.ProtectedSet()})
	return res, p.Cfg, err
}

// ApplyFetched fast-forwards the host's current branch to a fetched branch.
func ApplyFetched(ctx context.Context, e Env, root, branch string, protected []string, allowProtected bool) (*volume.BranchReport, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return volume.Apply(ctx, volume.Repo{Dir: abs}, abs, branch, protected, allowProtected)
}

// FetchedDiff shows what a fetched branch changes in the given paths.
func FetchedDiff(ctx context.Context, root, branch string, paths []string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return volume.Diff(ctx, volume.Repo{Dir: abs}, branch, paths)
}

// AtRisk reports what deleting the workspace volume would lose. known is false when the agent is
// not running so the volume could not be inspected.
func AtRisk(ctx context.Context, e Env, root string) (commits, dirty int, known bool, err error) {
	p, err := compose.Open(root, e.GlobalDir)
	if err != nil || p.Cfg.Workspace.Mode != "volume" {
		return 0, 0, true, err
	}
	_, repo, ag, err := volumeProject(ctx, e, root)
	if err != nil {
		return 0, 0, false, nil //nolint:nilerr // not running: report "unknown", not a failure
	}
	commits, dirty, err = volume.Pending(ctx, ag, repo, volume.DefaultLayout)
	return commits, dirty, err == nil, err
}
