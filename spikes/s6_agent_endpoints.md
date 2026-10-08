# S6: which endpoints the agent needs

Needs a real, authenticated agent session, so it cannot run in CI. Goal: the minimal host list for
the `claude` preset, and how the agent behaves when optional hosts are blocked.

1. In a scratch project: `cellwall init`, then `cellwall up`.
2. Observe with the **default** policy first (do not loosen it): `cellwall run`, sign in, ask the
   agent to do a small task that reads a file, edits it, runs a command and uses a web search or
   fetch if you use them. Then:

   ```sh
   cellwall logs --denied            # what the policy blocked, with the allow command for each
   cellwall logs --json > run1.jsonl # everything, one decision per line
   ```

3. For each denied host, decide: needed (the agent failed or degraded), optional (telemetry,
   update checks, error reporting), or unexpected. Allow one at a time with
   `cellwall allow <host>` and repeat the task, so each addition is tied to a visible effect.
4. To see the full list at once, temporarily allow `**` with `unsafe_allow_wildcard_all` in a
   throwaway project only, run the same task, and read the hosts from `cellwall logs --json`
   (`"action":"allow"` records, the `host` field). Delete the project afterwards.
5. Record in `docs/spikes.md` (S6): the agent and version, the hosts that were needed, the optional
   ones and what changed when they were blocked (error text, slower start, lost feature), and compare
   with `presets/claude.yaml`. Differences become preset changes.

Do not paste tokens, prompts or file contents into the record; hostnames and counts only.
