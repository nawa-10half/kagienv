# CLAUDE.md

@AGENTS.md

The imported shared instructions are canonical for this repository.

## Claude Code Roles

- Implement in the parent session. Delegate implementation only for large, independent, well-specified tracks, and use Sonnet for those.
- When `AGENTS.md` calls for a fresh reviewer, use the `code-reviewer` agent (Opus); when it calls for a fresh verifier, use the `verifier` agent (Sonnet).
- Keep the verifier and reviewer independent from the implementation. For documentation-only changes, apply the proportional checks defined in `AGENTS.md`.
- If the requested Claude model is unavailable, say so and ask for direction; do not silently fall back to another model.
