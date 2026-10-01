# 0003: Configurable, but every relaxation is explicit, visible and checkable

Status: accepted (guides M1/M2 schema design)

## Context
Requirement: cellwall is security-first *and* very configurable. Those conflict if any knob can
silently weaken isolation.

## Decision
1. **Secure by default.** An empty config yields the strictest topology the spec describes.
2. **Two classes of option.**
   - *Tuning* (limits, timeouts, ports, resources, agent command, presets, workspace mode): free to
     change, validated, no ceremony.
   - *Relaxations* (anything that widens what the agent can reach or modify: `allow_private`,
     `allow_ech`, plain-HTTP rules, `protected_paths` removals, host-network access, extra
     capabilities, `0.0.0.0` port publishing, disabling the engine-version gate): live under an
     `unsafe:` key or carry an `unsafe_` prefix, and are never produced by `init` defaults or presets.
3. **Visible.** `status`, `verify`, `policy lint` and the gateway's startup log print every active
   relaxation in one block. The audit log records the effective-policy hash.
4. **Unknown keys are errors** (typos must not silently drop a restriction).
5. **Layering can only tighten implicitly.** Merge order stays defaults < user-global < project <
   session, but a *relaxation* is only honoured from project config or above, never from session
   overrides or environment variables, so a stray env var cannot weaken a committed policy.
6. **Not configurable at all:** Docker socket mounts, privileged mode, `NET_ADMIN`/`NET_RAW`, and
   the agent holding the policy files. If a user needs these, cellwall is the wrong tool.

## Consequences
Config schema work in M2 starts from this split. Every relaxation needs a `verify`/lint
treatment and a test before it ships.
