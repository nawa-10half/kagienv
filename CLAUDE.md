# CLAUDE.md

@AGENTS.md

The imported shared instructions are canonical for this repository.

## Claude Code Roles

- Use Sonnet for implementation work.
- For high-risk changes that require independent verification and review under `AGENTS.md`, use a fresh Opus verifier and a separate fresh Opus reviewer.
- Keep the verifier and reviewer independent from the implementation. For documentation-only changes, apply the proportional checks defined in `AGENTS.md`.
- If the requested Claude model is unavailable, say so and ask for direction; do not silently fall back to another model.
