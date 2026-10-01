# The cellwall gateway: one static binary, nothing else. No shell, no package manager, no CA
# bundle (the gateway never terminates or originates TLS), so there is nothing to exec into or
# exploit beyond the binary itself.
#
# The CI/release build copies a pre-built, reproducible linux binary for the target architecture:
#   docker build -f build/gateway/Dockerfile --build-arg BINARY=cellwall-linux-amd64 dist  (BINARY is relative to the context)
FROM scratch
ARG BINARY=cellwall
COPY ${BINARY} /cellwall
# Numeric IDs: scratch has no /etc/passwd.
USER 65532:65532
EXPOSE 3128
# `cellwall gateway healthcheck` talks to the loopback-only admin endpoint inside the container.
HEALTHCHECK --interval=2s --timeout=3s --start-period=3s --retries=3 CMD ["/cellwall", "gateway", "healthcheck"]
ENTRYPOINT ["/cellwall", "gateway"]
