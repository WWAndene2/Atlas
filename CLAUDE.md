@AGENTS.md

## Claude Code specifics

- `AGENTS.md` above is the single source of rules for every agent; this file adds only what is specific to
  Claude Code. Never duplicate a rule here.
- Before merging into `main`, run `/code-review` on the diff. For changes to the tools layer, secrets
  handling or anything that executes target code, also run `/security-review`.
