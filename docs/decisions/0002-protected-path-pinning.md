# 0002: Protected paths are enforced by mount pinning, not just read-only mounts

Status: accepted for Linux; macOS/Windows pending (S4). Point 3 (detect, not auto-create, missing protected paths) confirmed by the maintainer.

## Context
Spike S4: a read-only nested mount does not prevent renaming its parent directory, so
`.git` can be moved aside and replaced by an attacker-controlled copy whose hooks the host
later runs. Also, `-v` creates missing sources as host directories, and a ro mount over a
non-existent target creates an empty placeholder in the host workspace.

## Decision
1. For every protected path, also bind-mount each existing intermediate parent (below the workspace
   root) rw onto itself so it becomes a mount point and cannot be renamed or removed.
2. The generator uses long-form `type: bind` mounts only (a missing source is an error, never
   silently created).
3. Protected paths that do not exist at `up` time are **not** auto-created by default. Instead
   `up` records a manifest of the protected set, and `down`/`status`/`verify` report any protected
   path that appeared in the workspace during the session. Config option
   `protected_paths_create_placeholders: true` opts in to placeholders for users who prefer
   prevention over detection (it dirties the git tree).
4. `.git` as a file (worktrees/submodules) is a known gap until tested.

## Consequences
Prevention for paths that exist, detection for those that don't. This is weaker than the original
spec implied and the README must say so.
