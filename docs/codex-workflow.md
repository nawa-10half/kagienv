# Codex Workflow

This file applies only to Codex agents. Follow the shared repository rules in [AGENTS.md](../AGENTS.md) first.

## Routing

- Use `gpt-5.6-sol` with medium reasoning effort for normal orchestration. The project default is in `.codex/config.toml`.
- Use `gpt-5.6-luna` with max reasoning effort for ordinary implementation through `.codex/agents/implementer.toml`.
- For high-risk changes identified by `AGENTS.md`, use a fresh `gpt-5.6-sol` agent with high reasoning effort through `.codex/agents/verifier.toml` for independent verification and a separate fresh `gpt-5.6-sol` agent through `.codex/agents/code-reviewer.toml` for review.
- Escalate only the hardest design, integration, or audit work to a general `gpt-6-astra` agent with high reasoning effort.

The role configuration pins the ordinary implementer to Luna. When escalating, explicitly select the general Astra model rather than invoking that Luna-pinned role. Custom role model overrides take precedence when the runtime honors them.

## Handoffs and Scope

Implement and verify in the parent session by default; trivial, documentation-only, and configuration-only work needs only proportional checks. Before committing a behavior-changing code change that spans multiple files, use the code-reviewer role from the Routing section; high-risk changes also use the verifier role.

When delegating, the parent assigns each worker a narrow file or behavior scope, explicit acceptance criteria, and the minimum context needed to work independently. Spawn specialist agents with `fork_turns: "none"` and a self-contained task packet; never omit `fork_turns`, because omission may copy the full parent history. Use a positive bounded turn count only when a small amount of recent conversational context is strictly necessary. Avoid full-history forks except for an exact continuation where their cost is justified.

Implementers return changed files, checks run, and unresolved issues. Verifiers return observed evidence against the criteria and any coverage gaps. Reviewers return findings with severity and file locations. Implementers, verifiers, and reviewers do not launch further workflow agents; they return to the parent for the next handoff.

Wait for delegated work in minute-scale intervals and return as soon as completion is reported. Do not busy-poll agent status or repeatedly list agents, and do not interrupt a worker without evidence that it is stalled.

## Runtime Compatibility

Some Codex runtimes do not consume CLI custom-agent configuration files. Use explicit model selection when it is available. If the needed model or independent-agent capability is unavailable, report that limitation and do not silently substitute another routing plan.

## Loading the Setup

Open kagienv itself as the project and start a new Codex session after changing these files. Project configuration requires the repository to be trusted in Codex; this repository does not change your global trust or permission settings. Explicit session model/reasoning overrides can supersede project defaults, so confirm the parent uses Sol/medium and each delegated task uses its assigned model.

The CLI role files configure runtimes that support project custom agents. In other runtimes, the parent must select these models explicitly from the available delegation tools. For independent verification and review, pass the requirements, changed files and acceptance criteria in a new context rather than copying the implementer's full conversation.
