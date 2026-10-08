# Troubleshooting

Start with `cellwall doctor`; it checks the engine, its version and the network features cellwall
relies on, and prints the next command for anything it finds.

| Symptom | Cause | Fix |
|---|---|---|
| `the gateway image ... does not exist, and this ... build of cellwall cannot make one` | A development build on macOS/Windows has no embedded gateway. | Install a release build, or pass `--gateway-image <ref>`. |
| `docker engine too old` / isolated network unsupported | `gateway_mode_ipv4: isolated` needs Docker 28+. | Upgrade Docker (`cellwall doctor`). |
| A host is refused with 403 | Not in the policy. | `cellwall logs --denied`, then `cellwall allow <host>` (add `--save` to keep it). |
| `fetch` says nothing to fetch | The agent has not committed. | Commit inside the sandbox (`cellwall shell`), then fetch again. |
| `fetch --apply` stops at protected files | The agent changed files that can run code on your machine (hooks, `.gitattributes`, CI). | Review with `cellwall fetch`, then `--allow-protected` if you accept them. |
| Files missing in the sandbox | Volume mode copies tracked and untracked-but-not-ignored files only. | Commit or `git add` them, or use `--workspace bind`. |
| Slow file access on macOS/Windows | Bind mount across the VM. | Use volume mode (the default there). |
