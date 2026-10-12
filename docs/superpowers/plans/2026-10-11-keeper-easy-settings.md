# Keeper 1.1.0 implementation plan

Goal: Implement the approved clickable settings, Easy authorization policy, configurable aggregate update budget, and authenticated paginated previews; release 1.1.0.

Architecture: A durable global settings store supplies immutable operation snapshots. Existing one-use authorization and transaction validation remain authoritative. Settings editing uses an explicit local UI session, never an apply argument. UI resources are bundled locally. Large diffs are authenticated with their changeset and exposed through bounded pages.

Tech Stack: TypeScript, Node.js, MCP SDK, Zod, Vitest, local HTML/JavaScript.

Spec: ../specs/2026-10-11-keeper-easy-settings-design.md

Global Constraints: Default normal mode / 8 MiB; integer 1–64 MiB; Easy removes only human confirmation and independent single-file limit. Retain automatic validation, expiry, path, signature, conflicts and rollback. Do not alter source scan budgets. No model-callable save permission based solely on hidden tool metadata. Never enable the user's global Easy setting during implementation. Preserve source/generated distribution consistency. Do not change tracked files while full/activation tests run.

Review Focus: Settings authorization and atomicity; frozen revision binding; final merged UTF-8 byte totals; large original-file reads after disabling Easy; full authenticated diff pagination; real clickable UI; packaging and downgrade/cache compatibility.

## Task 1: Settings store and clickable local UI

Files: new src/settings/store.ts, src/settings/ui.ts, src/settings/panel.ts and test/settings.test.ts (under sources/project-design-keeper).

Interfaces: KeeperSettings = {version:1, revision:string, easyMode:boolean, maxUpdateMiB:number}; createSettingsStore({cacheDirectory,...}) exposes read() and save(values, expectedRevision). openSettingsPanel(store) returns clickable loopback URL. A session capability is available only in the opened browser fragment; never expose mutation through a model save tool. Validate loopback Host/Origin, JSON, session token, bounded body, revision, and limited lifetime. Bundle a Chinese keyboard-accessible form with switch, numeric input, read-only single-file explanation, save/reset and durable status/errors.

- [x] Write failing tests for defaults, strict values, corruption, revision conflicts, persistence, concurrent save and HTTP authorization.
- [x] Run targeted Vitest; expected RED due missing implementation.
- [x] Implement secure atomic store and UI; run tests to GREEN.
- [x] Verify panel interactions using actual browser controls. First release uses the local browser panel under the documented design amendment.

## Task 2: Runtime policy, transaction budgets and paged diff

Files: src/transactions.ts, src/types/schema.ts, src/security/limits.ts, src/security/approval.ts, src/changesets/store.ts; new src/settings/policy.ts; targeted transaction tests.

Interfaces: runtime policy contains easyMode, maxUpdateMiB, revision. createTransactionService accepts an internal frozen policy snapshot; shared approval authority persists between snapshots. Preview/binding returns policy; changeset stores authenticated policy plus full diff. readPreview(input:{root,changesetId,cursor?}) returns bounded text page, nextCursor, complete and digest. Settings revision mismatch rejects before writes. Existing legacy previews require regeneration. Read budgets are independent of new write budgets.

- [x] Write RED tests for >2 MiB Easy roundtrip, normal rejection, exact aggregate / one-byte overflow, merged managed block, deletes/shrink, pagination and settings revision mismatch.
- [x] Implement trusted policy limits without elevating arbitrary test overrides or source scan limits.
- [x] Persist/authenticate policy and diff; keep cache GC/recovery bounded and compatible.
- [x] Run targeted transaction/security regressions to GREEN.

## Task 3: Service/MCP integration and documentation

Files: src/index.ts, src/mcp.ts, new integration tests, source skills and workflow documentation.

Interfaces: index loads settings once at each operation boundary and shares one approval authority. Normal uses existing elicitation. Easy uses authenticated binding policy to issue the same one-use capability and records easy-policy authorization source. get_settings is read-only; open_settings opens the explicit clickable session; read_preview pages authenticated diff. Tool schema supports bounded maximum input; final configured content budget enforced in transaction. No apply-time mode override.

- [x] Write RED MCP/direct tests for Easy without elicitation, normal confirmation retention, revision changes, get/open settings and page tools.
- [x] Integrate settings service and transaction snapshots; update skills to avoid redundant chat confirmations only when returned policy enables Easy.
- [x] Run typecheck plus targeted tests and exercise actual panel save/reload/reset/errors without modifying real user settings.

## Task 4: Review, release contracts and publish

Files: source package/lock/plugin metadata, installation/release scripts, release and root distribution tests, generated plugins/project-design-keeper.

- [x] Fresh independent review against approved spec, fix material findings with regression tests.
- [x] Set 1.1.0 metadata and update tool catalog/install contracts; build and regenerate package.
- [x] Freeze tracked changes; run complete tests, typecheck, package verification, relocated smoke and root distribution tests. Final affected-suite reruns resolve every failure; 1,113 passing cases and 15 platform/privilege skips are accounted for.
- [ ] Commit versioned feature, annotate tag, push and publish 1.1.0 release with ZIP and SHA256SUMS. Verify downloaded public artifact checksum.
- [ ] Report actual tested UI path, version/release URL and any material limitations.
