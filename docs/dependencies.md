# Dependencies

Standard library first. Every third-party module needs a one-line justification here before it is
added. `go mod verify` and `govulncheck` gate merges.

| Module | Why |
|---|---|
| `go.yaml.in/yaml/v3` | Policy files are YAML (spec section 7) and Go has no YAML parser. This is the maintained fork of `gopkg.in/yaml.v3` under the YAML organisation. The Node API gives line/column for errors and lets the loader reject anchors, aliases, tags and duplicate keys before decoding. |
| `github.com/spf13/cobra` | Subcommands, flag parsing and shell completions; reimplementing these is more code and more bugs than the dependency (spec section 6). Pulls in `spf13/pflag` and, for Windows, `inconshreveable/mousetrap` (both indirect). |

## CI actions

The organization enforces "all actions must be pinned to a full-length commit SHA", which is also
the right policy for this project. Each action is pinned to a commit SHA with its version in a
comment; Dependabot (`github-actions` ecosystem) keeps them current.

When pinning, resolve the tag with `git ls-remote <repo> refs/tags/<tag> 'refs/tags/<tag>^{}'` and
use the **peeled `^{}` commit** when it exists: for annotated tags the first line is the tag
object, not a commit, and pinning it fails (golangci-lint-action v8.0.0 is annotated).

| Action | Version | Why |
|---|---|---|
| `actions/checkout` | v4.4.0 | Fetch the repo; `persist-credentials: false` so later steps cannot reuse the token. |
| `actions/setup-go` | v5.6.0 | Install the Go version from `go.mod`. |
| `golangci/golangci-lint-action` | v8.0.0 | Run golangci-lint v2 with caching. |
