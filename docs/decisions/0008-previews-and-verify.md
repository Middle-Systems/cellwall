# 0008: Previews, `verify` and `policy lint` (M4)

Status: accepted.

## Previews

- **Published by the gateway, never the agent** (spike S3). The generated compose file publishes
  each configured port on the gateway at `127.0.0.1` (all interfaces only with
  `unsafe.publish_all_interfaces`, which is listed with the active relaxations) and starts it with
  `--forward-port N` per port and `--forward-target agent`.
- **The forwarder cannot become an outbound path** (`internal/forward`). It parses nothing: a
  connection on port N is copied to port N of the *agent*. The upstream host is a start-up flag,
  not something a client can influence; the name is resolved per connection and every address must
  be private (RFC 1918, ULA, CGNAT), otherwise the connection is dropped and nothing is dialled.
  Loopback is refused too: that would point the relay at the gateway itself. A connection limit
  (128) bounds it.
- **Not through the proxy.** Previews use their own listeners, not the policy engine: the traffic
  is inbound and the destination is fixed, so a policy would add nothing. They are not audited per
  connection; `status` and `ports ls` show what is published.
- **`ports add|rm`** edits `.cellwall/config.yaml` through the YAML node tree (comments survive),
  regenerates the compose file, and recreates only the gateway (in-flight proxy connections are
  dropped; the agent is untouched). It refuses, and undoes the config edit, when the compose file
  was edited by hand or the port is invalid: a silently unpublished preview is worse than an error.
  `up` also checks the host ports are free first, since Docker's "address already in use" does not
  say which preview it was.
- **The classic failure** is a dev server bound to `localhost` inside the container, which the
  gateway cannot reach. `ports ls` reads `/proc/net/tcp{,6}` in the agent and prints the
  framework-specific fix (`vite --host 0.0.0.0`, `flask run --host=0.0.0.0`, ...).

## `verify`

- The twelve checks of spec section 10 live in `internal/verify` behind an `Env` interface, so the
  CLI, CI and the unit tests share them. CI runs `cellwall verify --strict` on the real topology.
- **PASS / FAIL / SKIP.** A check that cannot run is never a pass. Checks that need outbound
  network from the gateway (SNI/ECH, hot reload) SKIP without it; `--strict` fails on skips.
- **Positive controls.** "Blocked" is only meaningful if the same path works when it should: the
  gateway must resolve, the proxy port must connect, a correct TLS handshake must complete. A
  failed control yields SKIP/FAIL, never PASS.
- **The suite is tested against broken sandboxes.** 32 scripted weaknesses each have to be caught by
  the check they belong to and by no other, and `TestVerifyCommand` attaches the agent to the egress
  network of a real sandbox and requires `verify` to fail.
- **Two checks write.** Proving the address guard needs a policy that *allows* a name resolving to
  loopback, and proving hot reload needs a rule change. Both add a session rule and remove it again
  (also on failure); `--read-only` skips them. The hot-reload time is taken from the gateway's own
  audit record against the policy file's mtime, with the wall-clock wait as the fallback when the
  host and container clocks visibly disagree.
- The probes are Python run in the agent (every generated image has `python3`); an image without it
  fails with a message naming `agent.apt_packages`, rather than passing.

## `policy lint`

Lints the merged *uncompiled* policy (agent presets, user-global, project, session), because
compilation refuses dangerous rules and lint must be able to show them. Also lints files given as
arguments. Exit 1 on errors, and on warnings with `--strict`. Relaxations from `config.yaml` and
session rules are listed with the findings.

## Not done

Benchmarks (proxy p50/p99, throughput) from spec section 10; the compose "topology finalisation
per spikes" rests on ADR 0001, with S5, S6 and S8 still outstanding.
