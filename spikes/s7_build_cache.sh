#!/usr/bin/env bash
# S7: keep `up` fast after first build. Measure BuildKit layer-cache behavior for a
# Dockerfile ordered toolchain -> manifests -> deps -> source, plus a cache-mount demo.
source "$(dirname "$0")/lib.sh"
D="$(mktemp -d)"; defer "rm -rf $D"
cat >"$D/Dockerfile" <<'DF'
# syntax=docker/dockerfile:1
FROM busybox:1.36
# Layer 1: toolchain (changes rarely, keyed on pinned version args)
ARG TOOL_VERSION=1
RUN echo "toolchain $TOOL_VERSION" >/toolchain
# Layer 2: user + agent CLI (keyed on agent.version)
ARG AGENT_VERSION=1
RUN echo "agent $AGENT_VERSION" >/agent
# Layer 3: expensive step using a cache mount (stand-in for apt/npm/pip caches)
RUN --mount=type=cache,target=/var/cache/spike sleep 2 && echo done >/var/cache/spike/marker && cat /var/cache/spike/marker >/deps
DF
t() { local s e; s=$(date +%s.%N); "$@" >/dev/null 2>&1; e=$(date +%s.%N); awk "BEGIN{printf \"%.2f\", $e-$s}"; }
TAG="cwspike-$RUN_ID"
defer "docker rmi -f $TAG"
cold=$(t docker build -t "$TAG" "$D")
warm=$(t docker build -t "$TAG" "$D")
agentbump=$(t docker build --build-arg AGENT_VERSION=2 -t "$TAG" "$D")
echo "cold=${cold}s warm=${warm}s agent-version-bump=${agentbump}s"
awk "BEGIN{exit !($warm < 1.5)}" && result PASS "warm rebuild with no changes is fast (${warm}s)" || result FAIL "warm rebuild slow (${warm}s)"
awk "BEGIN{exit !($agentbump >= 1.5)}" && result INFO "bumping AGENT_VERSION re-runs the downstream deps layer (${agentbump}s); order layers so slow steps come BEFORE agent install" || result INFO "agent bump reused cache (${agentbump}s)"
summary
