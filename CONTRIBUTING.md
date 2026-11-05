# Contributing

## Clean-room statement

kennel is an independent design derived from `PROJECT_SPEC.md` and public documentation only.
Contributors must not read, copy, paste or imitate any proprietary implementation of similar
tooling, and must not reference employer source code, configuration, images or internal
documents in issues, pull requests or commits. If a design choice looks like it mirrors something
proprietary, say so in an ADR under `docs/decisions/` instead of silently keeping it.

## Ground rules

- Standard library first; justify any new dependency in `docs/dependencies.md`.
- Security-relevant behaviour needs a test. If a claim cannot be tested, do not make it in the docs.
- Ambiguous? Choose the safer default and record it as a short ADR (`docs/decisions/NNNN-title.md`).
- Spike before building on an assumption about Docker/Podman behaviour (`spikes/`, `docs/spikes.md`).

## Before you push

    make lint test build
    make spikes      # needs Docker; run with sudo for the DNS meter in s2
