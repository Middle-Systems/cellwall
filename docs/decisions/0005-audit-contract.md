# 0005: Audit log contract

Status: accepted.

## Records

JSON Lines in `audit.jsonl` (rotated to `audit.jsonl.1` ... `.N`). Every record has `ts` (UTC) and
`event`:

| event | when | notable fields |
|---|---|---|
| `decision` | the policy was consulted | `action` = `allow` / `deny` / `error`, `host`, `port`, `proto`, `src`, `rule`, `reason`, `suspicious`, `policy`, `id` |
| `close` | an allowed connection ended, or was cut by an integrity check | the same identity fields plus `bytes_up`, `bytes_down`, `duration_ms`, `sni`; `action` is `allow`, or `deny` when the gateway cut the tunnel (`sni-mismatch`, `ech`, `no-sni`, `tls-*`) |
| `policy` | a policy was loaded or reloaded | `action` = `load` / `reload` / `reload-failed`, `policy` (hash prefix), `reason` |

`id` correlates a connection's records. `error` means policy allowed the connection but it could
not be completed (`resolve-failed`, `dial-failed`, `handshake-timeout`).

`logs --denied` (M3) should treat `action=deny` on either `decision` or `close` records as a
blocked attempt.

## Fail closed

For allowed connections the `decision` record is written BEFORE the tunnel opens. If the write
fails the connection is refused with `503 audit-unavailable`. There is no unaudited allow unless
the operator starts the gateway with `--audit-fail-open`, which is logged as a relaxation. Denials
are still enforced when the log is broken. The logger reopens the file after a failure, so the
gateway recovers on its own.

## Known limits

- Writes are handed to the OS, not fsynced per record; a host crash can lose the tail.
- A `close` record is written when a tunnel ends, so a gateway killed with SIGKILL leaves `decision`
  records without a matching `close`. Graceful shutdown writes `close` with `reason=shutdown`.
- Bytes for plain HTTP count payload only.
