# 0004: Gateway and policy design decisions (M1)

Status: accepted. Several items deliberately differ from the literal text of `PROJECT_SPEC.md`;
each says why.

## Deviations from the spec text

1. **Relaxation options are `unsafe_*`, not `allow_*`.** The spec shows `allow_private` and
   `allow_ech`. ADR 0003 says every relaxation carries an `unsafe_` prefix so it cannot be enabled
   by accident or mistaken for ordinary tuning. The rule options are therefore
   `unsafe_allow_private`, `unsafe_allow_ech`, `unsafe_allow_http`, `unsafe_skip_tls_check` and
   `unsafe_allow_dangerous_wildcard`. The spec's `methods_note` becomes the free-form `note`.
2. **The gateway reads the policy from a mounted DIRECTORY, not a single file.** Appendix A mounts
   `policy.effective.yaml` as a file. Spike S9 showed a single-file bind mount keeps pointing at the
   old inode after an atomic replace (which is how the CLI and editors write), so hot reload would
   silently never fire. The gateway watches `<dir>/policy.json` by content hash. The effective
   policy is canonical JSON (YAML is a superset, so one loader reads both).
3. **Decision and close are separate audit records** (ADR 0005), not one record per connection.

## Policy semantics

- `default` can only be `deny`. There is no allow-by-default.
- Hostnames: ASCII/punycode letters, digits and hyphens only. Non-ASCII input is rejected, never
  IDNA-converted, because silent normalization is how allowlists get bypassed. Underscores are
  rejected. IP literals are rejected in every notation (`LooksLikeIP`), including `2130706433`,
  `0x7f.1`, `127.1` and any name whose last label is all digits.
- `*.example.com` matches exactly one label below the base; `**.example.com` one or more. Neither
  matches the apex. `**.` raises a lint warning.
- Deny rules beat allow rules regardless of order. Among allow rules the first in policy order wins
  (presets first, then the project's own). A host that is allowed only over HTTPS and requested over
  plain HTTP is `http-not-allowed` ("use https"), not `port-not-allowed`.
- Lint errors block loading: wildcard over a TLD, over a multi-label public suffix, or over a
  user-content domain (`github.io`, `s3.amazonaws.com`, `vercel.app`, ...). A rule may waive one
  with `unsafe_allow_dangerous_wildcard: true`; the waiver is reported as a relaxation.

## Address guard

- Policy is consulted using only the name. A denied name is never resolved: even a lookup can
  carry data out.
- A name is resolved once and every address is checked; one bad address refuses the connection.
  The vetted IP literal is dialed, and `net.Dialer.Control` re-checks the final socket address.
- Hard blocks (never relaxed): loopback (the gateway's own admin listener), unspecified,
  multicast, reserved/documentation/benchmark ranges, and cloud metadata endpoints (including
  Azure's public wireserver address). `unsafe_allow_private` relaxes only RFC 1918, CGNAT, ULA and
  non-metadata link-local, and only on exact hosts, never wildcards.
- Addresses embedding IPv4 (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4, ISATAP) are judged by the
  stricter of the outer and embedded address.
- Dotted names are looked up fully qualified (trailing dot): no DNS search domains and no
  `/etc/hosts`. Go's resolver does not use `/etc/hosts` for rooted names. Single-label names are
  looked up as written so Docker service aliases and search domains still work.

## Operational choices

- The admin listener (`/healthz`, `/status`) must bind a loopback IP literal. The agent shares the
  gateway's network but not its loopback interface. This is not configurable.
- An invalid, empty, deleted or dangerous new policy never replaces the active one; the failure is
  logged loudly, audited once, and shown in `/status`. The gateway refuses to start without a
  valid policy.
- ECH detection is a list of known code points (`internal/proxy/hello.go`). It was wrong once:
  an early version included `0xff01` (renegotiation_info), which would have blocked ordinary
  OpenSSL clients. It is now covered by tests against real OpenSSL, curl, Python and Node hellos.
