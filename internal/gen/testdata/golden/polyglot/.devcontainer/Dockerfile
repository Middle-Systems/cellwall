# kennel:generated sha256=c252343ab0d364b6fd961517b303003734306cece78336248649e3cb7c92a205
# Agent image for polyglot.
# Built on the HOST network (not sandboxed). At run time the container is attached only to the
# internal `sandbox` network, so it reaches the internet only through the gateway.
# Every base and toolchain image is pinned by digest (they move only when you upgrade kennel and re-run `kennel init`).
# Edit .kennel/config.yaml and re-run `kennel init`; hand edits to this file are detected and kept.

ARG UID=1000
ARG GID=1000

FROM node:lts-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS tool-node

FROM golang:bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS tool-go

FROM tool-node AS agent-claude
WORKDIR /opt/claude
COPY agent/claude/package.json agent/claude/package-lock.json* ./
# Claude Code 2.1.286 is installed from an npm lockfile, so every package is checked against
# a recorded sha512 integrity hash: `npm ci` fails if the registry serves different bytes.
RUN npm ci --omit=dev --no-audit --no-fund

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS agent
ARG UID
ARG GID
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      gcc \
      git \
      jq \
      less \
      libc6-dev \
      make \
      pkg-config \
      procps \
      python3 \
      python3-dev \
      python3-pip \
      python3-venv \
      ripgrep \
      unzip

COPY --from=tool-node /usr/local/ /usr/local/
RUN rm -f /usr/local/bin/yarn /usr/local/bin/yarnpkg && corepack enable
COPY --from=tool-go /usr/local/go /usr/local/go
ENV GOPATH=/home/dev/go \
    PATH=/usr/local/go/bin:/home/dev/go/bin:${PATH}
COPY --from=agent-claude /opt/claude /opt/claude
RUN ln -s /opt/claude/node_modules/.bin/claude /usr/local/bin/claude \
 && DISABLE_AUTOUPDATER=1 claude --version

# Non-root user matching the host UID/GID so bind-mounted files keep sane ownership.
RUN set -eux; \
    existing="$(getent passwd "${UID}" | cut -d: -f1 || true)"; \
    if [ -n "${existing}" ] && [ "${existing}" != dev ]; then userdel -r "${existing}" || true; fi; \
    getent group "${GID}" >/dev/null || groupadd --gid "${GID}" dev; \
    useradd --uid "${UID}" --gid "${GID}" --create-home --shell /bin/bash dev; \
    git config --system --add safe.directory /workspace

# The workspace and every cache directory must exist in the image and be owned by the user: Docker
# copies that ownership into a fresh named volume, which is otherwise root-owned and unwritable.
RUN install -d -o "${UID}" -g "${GID}" /workspace '/workspace/api/.mypy_cache' '/workspace/api/.pytest_cache' '/workspace/api/.ruff_cache' '/workspace/api/.venv' '/workspace/web/node_modules' \
 && install -d -o "${UID}" -g "${GID}" /home/dev/.cache

COPY --chmod=0755 entrypoint.sh /usr/local/bin/kennel-entrypoint

USER dev
WORKDIR /workspace
ENV HOME=/home/dev
ENTRYPOINT ["/usr/local/bin/kennel-entrypoint"]
CMD ["sleep", "infinity"]
