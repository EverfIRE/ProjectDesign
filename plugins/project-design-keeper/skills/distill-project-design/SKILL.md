---
name: distill-project-design
description: Use when a project needs its product, gameplay, technical architecture, module contracts, design decisions, or engineering conventions initialized, refreshed, audited for drift, or distilled into reusable agent context.
---

# Distill Project Design

## Overview

Maintain an evidence-backed Project Design Keeper memory layer. Initialize, refresh, audit, or distill task context; never substitute stored knowledge for a user decision.

## Start the Run

Call `get_settings` to read the saved mode before maintenance. If the user asks to configure Keeper, call `open_settings`; the clickable local panel provides the Easy switch and aggregate limit (1–64 MiB, default 8). Never change settings yourself to make a failed operation pass.

**Mode rule (takes precedence over confirmation steps below and in references):** Normal mode requires the existing semantic and exact-preview human confirmations. When saved `easyMode` is true, skip Keeper chat/design/merge/write confirmation prompts and the digest form. Continue all automatic validation, evidence checks, scope constraints, preview, expiry, conflict protection and post-write validation. Choose evidence-supported maintenance actions within the user's request; keep ambiguity descriptive or deferred. Do not claim inferred norms were human-confirmed: code-derived statements remain `observed` / `informational` unless the user has actually established the rule. Host tool permissions remain in force.

Preview reports its frozen policy and revision. If settings change, generate a new preview. Large diffs expose `nextCursor`: in normal mode read `read_preview` pages through `complete: true` and provide the complete review path before approval; in Easy mode pages remain available without requiring the user to review each one. Never call a partial diff complete. Easy has no independent single-file write limit; final merged files together must fit the configured aggregate limit. Normal mode also limits each new file to 2 MiB. Deletes add zero write bytes.

State four choices before calling a tool:

- operation: `initialize`, `refresh`, `audit`, or `distill`;
- exactly one scope mode: `files`, `feature`, or `project`;
- document language, following the user's current language while preserving code identifiers, filenames, and domain terms;
- write intent: read-only or a proposed pack update.

Apply scope literally:

- `files`: for every explicit file, call `scan_scope { root, path: <each-explicit-file>, view: "files" }` separately, then page `view: "evidence"`; never scan their common parent;
- `feature`: if its path is known, scan that path; otherwise start with bounded `search_evidence { root, path?, query: <feature-name> }`, then follow only matched paths and their evidence-bearing references;
- `project`: call `scan_scope { root, view: "summary" }`, then page `view: "files"` for fingerprints and `view: "evidence"` only as needed.

Read [workflow.md](references/workflow.md) when choosing an operation/scope, refreshing, auditing, handling a failure, or deciding whether confirmation is required.

## Run the Evidence Workflow

1. Execute the exact scope mapping above. Search only for unanswered questions; keep repository-relative paths and line numbers.
2. Classify each statement from its actual source. Code, tests, and configuration remain `observed` and `informational` unless the user confirms them as normative. Record intent-versus-implementation disagreement as `conflicted` plus an open question.
3. If the evidence suggests a new normative rule, supersession, or chosen conflict resolution, ask for **semantic confirmation now**, before rendering a normative candidate.
4. After semantic confirmation, synthesize an atomic schema 3.0 record with `kind`, one `ownerDocument`, typed evidence, `assertedConfidence`, and lifecycle. Render confirmed rules as `required|preferred` with `approval: confirmed`; for supersession, include the new decision and reciprocal history. Use `assets/knowledge-pack/` for initialization.
5. Audit with `validate_pack`. For writes, call `preview_update` with the final `pack` and every change.
6. Show the validated diff, ownership/merge/validation conflicts, and 30-minute expiry. Obtain a separate explicit **write confirmation** for this exact preview.
7. Apply only that confirmed, unexpired changeset; then validate and query representative context.

If semantics change after preview, discard the changeset, rebuild the candidate, and preview again before asking for write confirmation.

End audit/read-only operations before `preview_update` or `apply_update` unless the user separately asks to refresh. If an existing output lacks Keeper ownership, stop at the conflict preview.

Read [knowledge-model.md](references/knowledge-model.md) before creating records, IDs, strengths, managed blocks, conflicts, or supersession links. Read [document-contract.md](references/document-contract.md) before generating or reorganizing the pack. Read [mcp-tools.md](references/mcp-tools.md) for tool boundaries and inputs/outputs.

## Preserve History and Human Work

Preserve human spans and stable IDs. Never overwrite a hash conflict, restate derived navigation as canonical knowledge, or silently delete history. Use `query_history` for non-current knowledge and `analyze_redundancy` for user-decided merge candidates. Archive only after two confirmed terminal refreshes; keep two full generations and permanent tombstones. Follow the knowledge-model and document-contract references for exact fields and ownership.

## Activate a Packaged Runtime

For a marketplace installation, upgrade through Codex with `codex plugin marketplace upgrade project-design-keeper`, then open a new task or restart the app. The installable runtime intentionally omits repository development scripts.

Manual package verification and cache activation are developer-only operations. Run them from the repository's `source/` checkout after reading the release activation section in [workflow.md](references/workflow.md). There, run `npm run package:verify`, then invoke `scripts/activate-installed-plugin.ps1` in one `powershell.exe -NoProfile` process with absolute `-PackageRoot`, `-InstallRoot`, and disposable `-SmokeProject` directories. Package construction and verification are bounded, exact-topology operations whose reads bind identity, size, content, and high-resolution version metadata. The activation script applies a global work deadline, denies concurrent writers while authenticating package files, refuses a matching live Codex `node.exe` MCP child, reports its PID, and never kills it.

Replacing files cannot reconnect an existing stdio client. Close the active Codex task or restart the app before activation, then use a new task or another app restart to verify the new runtime. The installed smoke requires two absolute positional roots and an empty disposable smoke-project directory; its environment variables are a deprecated zero-positional compatibility fallback. It creates a complete canonical Schema 3 fixture under an isolated child, validates it, and waits for bounded confirmation that the MCP stdio child has fully closed before cleanup. Activation starts that smoke suspended inside a private Windows Job Object, limits aggregate stdout/stderr to 1 MiB, and on timeout or overflow terminates the complete owned tree and confirms zero active processes before rollback. Fixture and cache roots are moved into random same-parent quarantines and identity-checked after the move; only the confirmed self-created roots are removed from fixed, bounded inventories. Activation staging holds the random root and every expected subdirectory against replacement, while activation cleanup deletes only through authenticated Windows handles after a final exact-inventory commit point. A post-commit cleanup error fails nonzero and preserves the quarantine and all remaining objects, although already-disposed authenticated objects may be gone. A nonempty project is rejected without modification, and any close, identity, hash, deadline, inventory, handle, or cleanup ambiguity fails nonzero while preserving the remaining paths as evidence. Pure Node smoke cleanup still has a final pathname check/use window inside the random quarantine; it does not claim handle-bound conditional deletion. Smoke preview is non-writing and deliberately verifies that a client without host elicitation cannot apply. Normal writes still require host elicitation for the exact confirmed preview, and an expired changeset must be rebuilt and reconfirmed.

## MCP Unavailable

For ordinary downstream task context, read `docs/project-design/index.md` and its mapped Markdown directly. For initialize, refresh, preview/apply, or any maintenance write, stop and explain that transaction protection is unavailable. Do not emulate Keeper writes with direct filesystem edits.

The generated project-local Skill template is `assets/project-design-context/SKILL.md`; install it only through the preview/apply transaction.
