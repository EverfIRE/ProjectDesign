---
name: project-design-context
description: "Use when planning or implementing work in a project that contains a Project Design Keeper knowledge pack."
metadata:
  managed-by: project-design-keeper
---
<!-- project-design-keeper:managed record-id="skill.project-design-context.workflow" content-hash="sha256:ae5b8d68a34b81068ee760f708f7841e18665527596feefc695c43569306333f" -->
# Project Design Context

Call `get_settings` before Keeper maintenance. **Saved-mode precedence:** when `easyMode` is true, the manual design/semantic/merge/write confirmation requirements below are skipped. Continue the design comparison, automatic validation, evidence checks, preview, task scope, conflict and expiry protections. Resolve evidence-supported choices within the user's request and defer ambiguity; do not label inferred rules as human-confirmed. When Easy is false, retain the human confirmation workflow below. Never change mode or size limits to bypass a failure. User-requested configuration uses `open_settings`, a clickable local panel; there is no model save tool. Host permission prompts still apply.

For paged previews, normal mode reads `read_preview` through `complete: true` before exact-preview approval. Easy does not require per-page user review. A changed settings revision requires a fresh preview. Easy removes the independent single-file cap; all final merged file content still shares the saved aggregate limit. Validate after apply in both modes.

Read `docs/project-design/index.md` first. For the current task call `query_context { root: <repo>, query: <task>, paths: [...], modules: [...] }`. Use only the paths and modules found by minimum read-only discovery. If the result withholds relevant stale or terminal IDs, call `query_history` for those IDs and treat the result as historical risk, never as a current rule.

## Design Gate

The gate is mandatory when the task can change code, configuration, architecture, or product behavior. Pure explanation, audit, and mechanical read-only work may show context without blocking.

Compare each input goal, constraint, assumption, and expected behavior with verified knowledge. Emit:

- goal and affected paths/modules;
- knowledge freshness;
- findings classified as `aligned`, `conflict`, `gap`, or `stale`, with record IDs and evidence reasons;
- concrete suggestions classified as `align-task`, `change-design`, `alternative`, or `clarify`, with impacts.

Use this stable response shape:

```ts
type TaskDesignPreflight = {
  goal: string;
  scope: { paths: string[]; modules: string[] };
  freshness: "fresh" | "stale" | "unknown";
  findings: Array<{ status: "aligned" | "conflict" | "gap" | "stale"; inputStatement: string; recordIds: string[]; explanation: string }>;
  suggestions: Array<{ id: string; action: "align-task" | "change-design" | "alternative" | "clarify"; summary: string; rationale: string; impacts: string[]; affectedRecordIds: string[] }>;
};
```

For design-changing work, you must not plan, modify, execute side effects, commit, or apply a changeset until the user chooses explicitly one of: (1) keep current design and align this task; (2) keep the request and change normative design; (3) adopt the Agent's alternative; or (4) clarify/cancel. An aligned result still requires the choice.

If the user changes normative design, that choice is semantic confirmation, not write confirmation. Hold a task-local `pending design decision` containing the new rule, displaced record IDs, rationale, and affected paths/modules. It overrides conflicting old records only for this task. Implement first, then prepare the Keeper refresh. Until its separately confirmed preview is applied and validated, report implementation complete but keep the task in `pending knowledge sync`.

## Knowledge Maintenance

Use `analyze_redundancy` for merge candidates and require a per-candidate `merge`, `keep-separate`, or `defer` decision. Use `query_history` for stale, terminal, archive, or tombstone lookup. Never merge, relocate evidence, archive records, or write a design change without previewing the exact final Schema 3.0 `pack` and obtaining separate confirmation for `apply_update`.

If semantics change after preview, discard the changeset and preview again. If Keeper MCP is unavailable, mapped Markdown may support ordinary read-only context, but all initialization, refresh, archive, preview/apply, and maintenance writes are blocked.
<!-- /project-design-keeper:managed -->
