# 0010: Project name "Kennel" and MIT licence (M5)

Status: accepted.

## Why

`cellwall` was a working name (spec Section 14). The product name had to be easy to type and
spell, suggest safety, describe a CLI that puts coding agents in sandboxed containers, and avoid
"Claude", "Anthropic" and any employer tool name (spec Section 2). The licence was also open.

## Decisions

- **Name: Kennel.** Binary `kennel`; project directory `.kennel/`; environment variables
  `KENNEL_*`; compose projects and local images `kennel-<project>`; module path
  `github.com/middle-systems/kennel`. The agent is housed in an enclosed place with one
  controlled entrance (the gateway).
- **No compatibility with the working name.** Nothing was released under `cellwall`, so there are
  no aliases: a repository initialised by a development build needs `.cellwall/` renamed to
  `.kennel/` and `kennel init` re-run (generated files carry `kennel:generated` markers now).
- **Licence: MIT.**

Alternatives considered for the name: Cordon (does not describe the tool, easier to misspell),
Hatch (clashes with the Python project manager), Corral ("coral"), Burrow, Hatchery, Fort, Latch,
Bulkhead, Membrane, Drawbridge, Cellwall.

## Availability (checked 2026-10-08)

- GitHub: a personal account `kennel` exists with no public repositories; use `Middle-Systems/kennel`.
- Homebrew core/cask, Scoop Main/Extras/Versions, crates.io: no `kennel` found.
- PyPI: an empty placeholder package (2021). npm: taken by an apparently inactive CLI; use a scope
  such as `@middle-systems/kennel` if a wrapper is ever wanted.
- Domains: `kennel.dev`, `.sh`, `.com`, `.ai` are in use or parked; `getkennel.com`,
  `usekennel.com`, `kennelhq.com` and `kennel.tools` had no DNS records (not confirmed unregistered).

## Before the first public release

- [ ] Rename the GitHub repository to `Middle-Systems/kennel` (GitHub redirects the old URL) and
      confirm `go install github.com/middle-systems/kennel/cmd/kennel@latest` resolves.
- [ ] Trademark search (USPTO, software/AI classes) for "Kennel".
- [ ] Register a project domain.
- [ ] Re-check Homebrew, Scoop and crates.io immediately before publishing.
