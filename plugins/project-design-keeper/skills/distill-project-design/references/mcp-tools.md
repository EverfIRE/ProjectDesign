# MCP Tool Contract

Use exactly these nine tools. Pass a repository root/path and repository-relative evidence paths; never invent absolute paths for pack records.

| Tool | Role | Essential result |
| --- | --- | --- |
| `scan_scope` | Read a bounded scope | Bounded summary or cursor-paged files/evidence for one immutable snapshot |
| `search_evidence` | Search the scanned repository | Matching repository-relative paths, one-based lines, text; optional domain/status filters |
| `detect_drift` | Compare source with a prior snapshot/manifest | Summary counts and invalidated IDs; optional cursor-paged details |
| `query_context` | Load current task/path/module context | Active verified records plus withheld stale/unverified/terminal IDs and reasons |
| `query_history` | Inspect non-current knowledge | Stale active, terminal, two retained archive generations, and opt-in tombstones |
| `analyze_redundancy` | Recall possible semantic overlap | Snapshot-bound 30-minute candidates and recommended survivors for explicit decisions |
| `preview_update` | Validate and stage proposed managed changes in Keeper cache | Diff, conflicts, `changesetId`, creation/expiry time; no project write |
| `apply_update` | Commit one confirmed changeset | Applied paths and recovery snapshot metadata, or a stale/conflict error |
| `validate_pack` | Check schema and repository-backed integrity | Valid flag, errors, and warnings for links, IDs, records, evidence, ownership |

## Read sequence

Call `scan_scope` with `view: "summary"` first. Use bounded pages and never reuse a cursor across snapshot, scope, view, or filters. Use `detect_drift` before refresh. Call `query_context { root: <repo>, query: <task>, paths: [...], modules: [...] }` with only relevant paths/modules. It never returns stale content; retrieve specifically withheld IDs through `query_history`. Use `analyze_redundancy` only for candidate recall and obtain a user decision for every candidate before preview.

`validate_pack` receives the candidate canonical pack plus repository root. Resolve every diagnostic before presenting a pack as valid; report warnings that represent genuine uncertainty.

## Preview and apply

`preview_update` accepts only writes under `docs/project-design/` and `.agents/skills/project-design-context/`. Any project-design change includes the exact final Schema 3.0 `pack`. Managed-block deletion supports physical archive moves. Archive JSONL is restricted to the archive directory and validated with its manifest metadata. Redundancy decisions must reference the unexpired snapshot-bound analysis. Preview validates the complete overlay before storing an external changeset.

A changeset expires exactly 30 minutes after creation. Present its diff and conflicts, then obtain explicit confirmation. Invoke `apply_update` by `changesetId` only after confirmation. Apply rejects expired, missing, tampered, or stale changesets and target/source/manifest drift. Create a new preview after any rejection; do not retry an old changeset as though it were current.

The host approval form shows a compact summary of file and record counts, the changeset ID, digest, and expiry. Review the full file list and diff from `preview_update` before opening it; long lists are not repeated in the form. Select `approve` and type the eight-character code shown at the top and in the confirmation field's title. A long project path is explicitly shortened for display only. Authorization remains bound to the complete changeset.

Apply writes atomically and retains bounded recovery snapshots, but recovery does not replace confirmation or concurrency checks.

## Degraded mode

If the MCP server is unavailable:

- ordinary downstream context may read `docs/project-design/index.md` first and follow its mapped Markdown links;
- initialization, refresh, validation-for-write, preview, apply, and maintenance stop explicitly;
- do not recreate transaction behavior with direct file writes.
