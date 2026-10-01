# Security policy

cellwall is a security tool, so reports about its isolation claims are the most valuable kind.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's "Report a vulnerability"
(Security advisories) on this repository. Include the engine and version, OS, your `cellwall
version`, and the smallest reproduction you can, ideally a failing `cellwall verify` check.

We aim to acknowledge reports within 3 working days. Coordinated disclosure: we will agree a
timeline with you and credit you unless you prefer otherwise.

> The disclosure contact must be confirmed by the maintainers before the first release (spec M5).

## Scope

In scope: anything that lets an agent inside the sandbox reach the network, the host, or the
gateway's control surface in a way the documentation says it cannot; anything that lets it
modify protected paths or its own policy; flaws in the proxy, policy matcher or generator.

Out of scope (documented non-goals, see `docs/threat-model.md` once written): kernel or container
runtime escapes, data sent to hosts you allowlisted, domain fronting through shared CDNs, and a
compromised host.

## Supported versions

Pre-release: only the latest commit on `main`.
