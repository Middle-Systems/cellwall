# Policy reference

The policy decides which destinations the agent's traffic may reach. It is an allowlist: anything
not matched is denied, and there is no way to switch that around.

## File

> **Status (M1):** the policy engine and gateway exist; the host CLI that merges layers and writes
> the gateway's `policy.json` (`init`, `up`, `allow`) does not yet. Today you write a `policy.json`
> by hand and mount its directory into the gateway (see `test/e2e/lab_test.go` for a working
> example). The layering below is the design the CLI will implement.

`.cellwall/policy.yaml` (project) is merged over built-in defaults and your user-global policy; the
host CLI writes the merged, preset-expanded result as `policy.json` for the gateway. YAML or JSON
are both accepted. Unknown keys, duplicate keys, anchors, aliases and explicit tags are errors, and
errors carry `file:line:col` and a "did you mean" hint.

```yaml
version: 1
presets: [claude, node, github]      # reviewed, exact-host allowlists (see below)
rules:
  - host: registry.example.com       # exact hostname
  - host: "*.cdn.example.com"        # exactly one label below cdn.example.com
  - host: api.example.com
    ports: [443, 8443]
    note: "partner API"              # free text, shown in lint output
  - host: telemetry.example.com
    action: deny                     # deny beats allow, whatever the order
limits:
  max_conns: 256
  idle_timeout: 60s
```

## Rules

| Field | Meaning |
|---|---|
| `host` | `example.com`, `*.example.com` (one label), or `**.example.com` (one or more labels). Wildcards never match the apex. ASCII/punycode only; IP addresses are rejected. |
| `action` | `allow` (default) or `deny`. Deny always wins. |
| `ports` | Allow rules default to `[443]` (`[80, 443]` with `unsafe_allow_http`); deny rules default to every port. |
| `note` | Free text, up to 200 characters. |

Among allow rules, the first in order wins (presets come first, then your rules), and its options
apply. Hostnames are lowercased and one trailing dot is ignored.

### Relaxations (`unsafe_*`)

Each widens what the agent can do. They are printed in the gateway's startup log and `/status`, and
reported by `policy lint`. Presets can never contain them.

| Option | Effect |
|---|---|
| `unsafe_allow_http` | Allow plain HTTP to this host (off by default). |
| `unsafe_allow_private` | Allow this host to resolve to RFC 1918, CGNAT, ULA or link-local addresses. Exact hosts only. Loopback, metadata, unspecified and multicast stay blocked regardless. |
| `unsafe_allow_ech` | Do not refuse a ClientHello carrying an Encrypted Client Hello extension. |
| `unsafe_skip_tls_check` | Do not inspect the ClientHello (for non-TLS protocols such as SSH). The tunnel can then carry anything. |
| `unsafe_allow_dangerous_wildcard` | Waive a lint **error** on this wildcard rule. |

## What the gateway checks, in order

1. The CONNECT target is well formed; IP literals are refused.
2. The **name** is matched against the policy (nothing is resolved yet).
3. Rate and connection limits.
4. The name is resolved once and every address is classified; a non-public address refuses the
   connection.
5. The allow decision is written to the audit log (if that fails the connection is refused).
6. The connection is made to the vetted IP, `200 Connection Established` is sent, and the client's
   TLS ClientHello must carry an SNI equal to the CONNECT host, with no ECH.
7. Bytes flow under idle, total-time and byte-count limits.

A refusal returns a plain-text body naming the host and the next command to run.

## Limits

Zero or unset uses the default; `-1` (or `unlimited` for durations) disables the limit and counts as
a relaxation.

| Key | Default | |
|---|---|---|
| `max_conns` | 256 | concurrent tunnels |
| `idle_timeout` | 60s | no bytes either way |
| `total_timeout` | 1h | per connection |
| `dial_timeout` | 10s | resolve + connect |
| `handshake_timeout` | 10s | time to send a ClientHello |
| `max_bytes_per_conn` | 8 GiB | both directions combined |
| `max_new_conns_per_host_per_min` | 300 | token bucket per destination host |
| `max_label_len` / `max_host_len` | 63 / 253 | can only be lowered; DNS-exfil hygiene |
| `deny_suspicious` | false | refuse hostnames with a high-entropy label (otherwise just logged) |

## Layers and changing policy while the sandbox runs

Rules accumulate from four layers, lowest precedence first: the agent's own hosts (from `agent:`
in `config.yaml`), your user-global `~/.config/cellwall/policy.yaml`, the committed
`.cellwall/policy.yaml`, and the **session layer** `.cellwall/state/session-policy.yaml`. Deny
beats allow whatever the layer, so a higher layer can add rules but never override a deny.

`cellwall allow|deny <host>...` edits the session layer (or the committed file with `--save`),
re-runs `prepare`, and waits for the running gateway to report the new policy hash, normally
within a second. The command is refused, and undone, if the host would still be denied, if plain
HTTP is requested (`unsafe_allow_http` can only be set by hand in the project policy), or if the
result fails lint. Session rules are shown with the relaxations everywhere, because they are not
in version control. `cellwall logs --denied` lists what was refused and the command that would
allow each destination, or why no rule can (IP literals, private addresses, SNI mismatches).

## Presets

Exact hostnames on port 443 only, no wildcards, no relaxations. The `claude` list comes from the
Claude Code network requirements page (read 2026-10-01); every other preset is drawn from public
registry documentation. **None has been verified empirically yet (spike S6).**

`claude` (API, sign-in) · `claude-updates` · `claude-mcp-connectors` · `claude-telemetry` ·
`node` · `python` · `go` · `rust` · `java` · `github` · `github-raw` · `github-codeload` ·
`docker-hub`

`storage.googleapis.com` is deliberately absent from `claude-updates`: it is path-style
multi-tenant storage, so allowing the host would let an agent upload to any attacker-owned bucket.

## Lint

`policy lint` (M4) will print these; `allow` and `deny` already enforce the errors. Errors block loading unless waived on the rule.

| Level | Codes |
|---|---|
| error | `wildcard-tld`, `wildcard-public-suffix`, `wildcard-user-content` |
| warn | `unsafe-private`, `unsafe-http`, `unsafe-ech`, `unsafe-skip-tls`, `wildcard-multi-label`, `*-waived`, `unlimited-*` |
| info | `wildcard`, `nonstandard-port`, `tls-on-nonstandard-port`, `duplicate-rule`, `shadowed-by-deny` |
