# Threat model

Status: covers everything through M4 (gateway, generated topology, lifecycle, previews, `verify`).
Topology claims rest on spikes S1-S4, S9, S10 and are **verified on Linux with Docker Engine
only**; macOS, Windows and other engines are untested. Every claim below is a check you can run:
`cellwall verify` attacks the live sandbox and reports each property as PASS, FAIL or SKIP.

## What cellwall protects against

A prompt-injected or misbehaving agent, or a malicious dependency script it runs, trying to:

1. contact arbitrary internet hosts,
2. reach the host network, private networks or cloud metadata endpoints,
3. reconfigure its own egress rules,
4. plant config that the host later executes (protected paths: read-only mounts, parents pinned),
5. read host files or credentials that were not explicitly mounted.

## How the gateway enforces (1) and (2), and the tests that back each claim

| Claim | Mechanism | Test |
|---|---|---|
| The agent has no direct route out | `internal` + `gateway_mode_ipv4=isolated` network, agent attached only to it | spikes S1/S1b; e2e check 00 |
| The agent cannot reach the gateway's control surface | admin listener bound to loopback, enforced | `TestValidateAdminAddr`; e2e check 00 |
| A denied name is never resolved | policy is evaluated on the name before any lookup | `TestPolicyIsCheckedBeforeResolution` |
| IP-literal destinations are refused | `LooksLikeIP` covers legacy notations | policy fuzz/table tests; e2e check 04 |
| Names resolving to internal addresses are refused | every resolved address classified; hard blocks never relaxed | `guard_test.go`; e2e check 05 |
| No DNS-rebinding window | resolve once, dial the vetted IP literal, `Control` re-check | `dial_test.go` |
| The ClientHello's SNI must equal the CONNECT host | first TLS flight parsed with strict rules and forwarded verbatim | `hello_test.go`, fuzzing; e2e check 06 |
| Plain HTTP is off unless a rule opts in | `unsafe_allow_http` | e2e check 07 |
| Policy changes apply without dropping connections | content-hash polling, atomic swap | e2e check 12 |
| No unaudited egress | decision written before the tunnel opens | `TestAuditFailureFailsClosed` |

## The escape suite: `cellwall verify`

The same twelve checks run in CI (`TestVerifyCommand`, strict) and against your own sandbox. A
check never reports PASS when it could not run; a sandbox that cannot be told apart from a broken
one is a SKIP or a FAIL, and `--strict` makes skips fail. The suite is itself tested against
deliberately weakened sandboxes, and `TestVerifyCommand` attaches the agent to the egress network
and requires `verify` to notice.

| # | Check | What it tries |
|---|---|---|
| 1 | `direct-egress` | TCP to public IPv4/IPv6 addresses without the proxy |
| 2 | `dns-leak` | resolving a public name; raw UDP queries to public resolvers (positive control: the gateway resolves) |
| 3 | `proxy-policy` | an unlisted host (expects 403 + an audit deny record) and an allowed one |
| 4 | `ip-literal` | CONNECT to IP literals: metadata, IPv6, decimal and hex forms |
| 5 | `internal-addresses` | a name that resolves to loopback, allowed for the check so only the address guard can refuse it |
| 6 | `tls-sni-ech` | a correct handshake (control), then SNI mismatch, ECH and non-TLS bytes through a tunnel |
| 7 | `plain-http` | `http://` requests, to unlisted and to https-allowed hosts |
| 8 | `protected-paths` | writes, renames of the path and of every parent, visibility of gateway state and policy |
| 9 | `hardening` | `CapEff`, `NoNewPrivs`, uid, Docker socket, host memory devices |
| 10 | `host-isolation` | `host.docker.internal`, host-service ports on likely host addresses, the gateway's admin port |
| 11 | `preview-inbound` | host to agent through the forwarder; and that the forwarder answers from the agent, not the outside |
| 12 | `hot-reload` | a new rule enforced in under 2s while an open tunnel survives |

Checks 5 and 12 briefly add a session rule (always removed); `--read-only` skips them.

## Previews

A preview is published by the **gateway** on the host's `127.0.0.1` and relayed to the same port in
the agent. The relay (`internal/forward`) is a byte copier: its upstream is the agent's service
name, fixed when the gateway starts, and nothing a client sends can change it. Every address the
name resolves to must be private, so even a poisoned lookup cannot turn it into an outbound path.
Publishing on all interfaces needs `unsafe.publish_all_interfaces`.

## What it does NOT protect against

- **Data sent to allowlisted hosts.** Anything allowed can receive anything (a push to a malicious
  repository on `github.com`, a package registry upload). Use narrowly scoped tokens and specific
  hostnames.
- **Domain fronting.** Without TLS interception the HTTP `Host` header is invisible. The SNI check
  stops trivial mismatches only. Allowlist specific hostnames, not wildcards over shared CDNs.
- **Traffic after the handshake.** The gateway inspects the first TLS flight, then splices bytes.
  A tunnel to an allowed host can carry any protocol the endpoint accepts.
- **DNS exfiltration through wildcard rules.** The gateway resolves names itself, so a wildcard
  over a domain where an attacker controls subdomain DNS leaks data in the lookup. The linter
  refuses known user-content domains, but its list is curated and incomplete: every wildcard is a
  judgement call, and `policy lint` warns on each.
- **Encrypted Client Hello and future extensions.** ECH is detected by a list of known extension
  code points; one assigned later would not be seen. Any hello without a matching SNI is refused,
  which blocks real ECH use, but this is partial mitigation, not a guarantee.
- **Kernel or container-runtime vulnerabilities.** Optional stronger runtimes are a later
  milestone; nothing is claimed here.
- **A malicious or compromised host**, and anything the user deliberately mounts or allows.

## Known gaps

- `verify` proves the guards for loopback only against the live sandbox; the other internal
  ranges, IPv4-mapped IPv6 and rebinding are covered by unit tests and the M1 lab, not by `verify`.
- A policy-allowed host is the only thing `verify` can use to test SNI/ECH and hot reload, so
  those two need outbound network from the gateway (they SKIP without it).
- macOS (VirtioFS), Windows and Podman behaviour is untested (spikes S5, S8). File-change events
  from host edits reaching a dev server in the container are only exercised on Linux.
- Presets are drawn from public documentation and have not been checked empirically (spike S6).
- IPv6 on the sandbox network is untested.
