# Dependencies

Standard library first. Every third-party module needs a one-line justification here before it is
added. `go mod verify` and `govulncheck` gate merges.

| Module | Why |
|---|---|
| `github.com/spf13/cobra` | Subcommands, flag parsing and shell completions; reimplementing these is more code and more bugs than the dependency (spec section 6). Pulls in `spf13/pflag` and, for Windows, `inconshreveable/mousetrap` (both indirect). |

## CI actions

Currently referenced by major-version tag. **TODO before M5:** pin each to a full commit SHA
(Dependabot will keep the SHAs current). Not done in M0 because resolving SHAs needs access to
the actions' repositories, which this session's tooling is scoped away from.
