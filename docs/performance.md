# Performance

The spec asks for a proxy that adds negligible latency, with benchmarks that fail CI on large
regressions. The benchmarks live in `internal/proxy/bench_test.go`; run them with `make bench`.

## What is measured

The real proxy server, policy engine, dial guard and audit logger (writing to disk), on loopback.
Only the DNS answer and the final socket connect are substituted, as in the functional tests.
Loopback has no network latency, so the figures are the gateway's own cost; on a real network its
share of the total is smaller.

- **CONNECT setup**: from sending `CONNECT` to receiving `200`, which includes the policy decision,
  name resolution, the SSRF checks, the upstream dial and the audit write (the decision is
  written before the tunnel opens).
- **First byte**: CONNECT, ClientHello inspection, and the first echoed byte, next to the same
  exchange with no proxy.
- **Throughput**: 256 MiB each way through a tunnel.

## Reference results

4 vCPU Linux container, Go 1.26, one run (`make bench`):

| | p50 | p99 |
|---|---|---|
| CONNECT setup | 0.23 ms | 0.61 ms |
| First byte through the proxy | 0.51 ms | 1.0 ms |
| First byte, no proxy | 0.17 ms | 0.29 ms |

The gateway adds roughly 0.3 ms at p50 and 0.7 ms at p99 to a new connection. Throughput through
the proxy was about 1.2 GB/s upload and 1.2 GB/s download, within about 15% of a direct connection
(the TLS payload is copied, not parsed, after the ClientHello).

These are single-machine figures; treat them as an order of magnitude, not a specification.

## CLI startup

The spec asks for under 50 ms for commands that do not need Docker. `kennel version` measured a
median of 6 ms (maximum 9 ms over 30 runs) on the same machine.

## Regression gate

`make bench-check` (`TestProxyOverheadBudget`) runs in CI on Linux and fails if, on loopback:

- the proxy adds more than 20 ms at p50 or its p99 first byte exceeds 150 ms;
- throughput through the proxy falls below 100 MB/s or below 15% of a direct connection.

The budgets are about an order of magnitude looser than the figures above, because shared CI
runners are noisy; they catch a real regression (a lock held across a dial, tiny copy buffers,
per-connection work that grows with history), not run-to-run variation. The test is skipped under
the race detector, which slows everything several-fold.

## Not measured

Filesystem throughput for `bind` versus `volume` on macOS and Windows (spike S8) needs those
machines and is still open, as is startup time of non-Docker commands.
