# Platforms and the manual test matrix

kennel's isolation claims are verified in CI on Linux with Docker Engine. macOS and Windows run
containers inside a VM, so the same claims need to be checked there by a person. Record results with
`kennel verify --strict` plus the steps below, and add a row per run.

## What differs

| | Linux | macOS (Docker Desktop / OrbStack) | Windows 11 (Docker Desktop, WSL2) |
|---|---|---|---|
| Default workspace | `bind` | `volume` (git repos with a commit) | `volume` |
| Gateway image | built from the running binary | built from the Linux binary inside the release binary | same |
| Protected paths | read-only overlay mounts | not applicable in volume mode (host files are not shared) | same |
| Bind mode | fast | slow file sharing; works | very slow from the Windows filesystem (measured 65-300x slower than a volume for 20,000 small files, S8); keep the project in the WSL filesystem if you need bind |

Volume mode copies the repository into the sandbox. Work comes back with `kennel fetch` and is
applied with `kennel fetch --apply` (see ADR 0009). Ignored files (for example `.env`) are not
copied in.

## Checklist for a run

On a clean checkout of a small git repository:

1. `kennel init` — the printed workspace mode matches the table above.
2. `kennel up` — completes without hand-built images; `kennel status` shows an isolated network.
3. `kennel verify --strict` — all checks pass (workspace isolation runs instead of protected paths
   in volume mode).
4. In `kennel shell`: `curl -sS https://example.org` is refused; `kennel allow example.org` makes
   it work without a restart.
5. Commit in the agent, then `kennel fetch` lists the commit; `kennel fetch --apply` fast-forwards.
6. A preview port (`kennel ports add 5173`) opens in the host browser.
7. `kennel down --volumes` warns about unfetched work.

## Results

| Date | Platform | Engine | kennel | Result | Notes |
|---|---|---|---|---|---|
| — | Ubuntu 24.04 (CI) | Docker Engine | each commit | e2e + `verify --strict` pass | automated |
| _pending_ | macOS (Apple silicon) | | | | needs a Mac |
| 2026-10-08 | Windows 10 22H2 (build 19045.6466), WSL2 backend | Docker Desktop 4.92.0 (Engine 29.8.0, Compose 5.5.1) | dev build from branch, `go build -tags embedgw` (version string `dev`, commit none) | checklist passed after the console fix below (reported by the maintainer) | Windows 11 is still untested. First run in a JetBrains terminal (pipes, not a console) sent CRLF to the shell; fixed by detecting real consoles with GetConsoleMode and normalising CRLF when there is no TTY. |
