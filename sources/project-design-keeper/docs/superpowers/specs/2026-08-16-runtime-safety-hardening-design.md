# Project Design Keeper Runtime Safety Hardening Design

**Date:** 2026-08-16

**Status:** Approved design, pending implementation
**Target:** Project Design Keeper `1.0.0` on branch `codex/project-design-keeper`

## Purpose

This change hardens the current plugin runtime against the defects confirmed by the latest security and plugin-eval review:

1. `apply_update` does not currently prove that the user approved the exact changeset.
2. Preview and knowledge inputs can consume unbounded memory, CPU, and durable cache before the response-size guard runs.
3. Repository scans and semantic redundancy analysis can perform unbounded work, and immutable scope snapshots are never evicted.
4. `query_history` returns structurally unvalidated manifest, archive, and tombstone content.
5. Scope and drift cursors are unsigned and can be modified by callers.
6. Scope-index storage lacks the secure cache boundary used by transactions and has no read/reuse path.
7. Recovery snapshot naming and retention are unsafe across multiple MCP processes.
8. Final project mutations retain a pathname time-of-check/time-of-use window.
9. Hot installation can leave existing Codex tasks connected to a terminated or obsolete MCP process.
10. The installed-root smoke test is not part of package scripts or CI.

The implementation retains all nine MCP tool names, Schema 3.0 knowledge semantics, preview-before-apply, changeset expiry, tamper detection, optimistic concurrency, manifest-last commit order, atomic rollback, and the private-plugin exemption for public website/privacy/terms URLs.

## Trust Boundaries

The trusted components are the Project Design Keeper process, its owner-only external cache, and a conforming MCP host. Project repository contents and MCP tool arguments are untrusted. Other processes running as the same operating-system user are outside the plugin's control and may contend with project or cache paths.

MCP tool annotations remain advisory. The server therefore does not treat `destructiveHint`, a changeset ID, caller-provided `approval: "confirmed"`, or caller-provided redundancy decisions as proof of a user gesture.

The MCP protocol's form elicitation response is the available host-mediated approval boundary. A malicious MCP host can forge that response; a plugin cannot distinguish such a host from its user. The runtime will trust a conforming host but fail closed when the client does not advertise form elicitation, the user declines or cancels, the response is malformed, or the changeset changes between inspection and application.

## Architecture

The hardening is divided into focused modules rather than adding more responsibilities to `transactions.ts` or `scope/index.ts`:

- `src/security/limits.ts`: shared byte, count, and duration budgets plus bounded input measurement.
- `src/security/cache.ts`: owner-only cache creation, path-component/reparse validation, project/cache disjointness, atomic file publication, and safe cleanup primitives.
- `src/security/cursor.ts`: persistent HMAC-key management and versioned signed cursors.
- `src/security/approval.ts`: exact changeset inspection, elicitation request construction, one-call approval capability, and capability consumption.
- `src/security/process-lock.ts`: cross-process project lock with bounded stale-lock recovery.
- `src/scope/store.ts`: validated immutable snapshot persistence, loading, access tracking, and eviction.
- `src/knowledge/history-integrity.ts`: structural manifest/archive/tombstone validation for historical queries.

Existing public service functions continue to own business behavior. The new modules provide narrow security mechanisms that can be tested independently.

## Host-Mediated Apply Approval

### Apply flow

`apply_update` keeps its existing MCP input contract: project root plus changeset ID. The handler performs the following sequence:

1. Load the changeset through the transaction service's authenticated inspection API.
2. Verify its HMAC, schema, ID, canonical root, expiry, and current diff digest.
3. Build a bounded approval summary containing the canonical project root, changeset ID, expiry, exact diff digest, affected paths, operation counts, archive/tombstone actions, and confirmed semantic-decision IDs.
4. Call `server.server.elicitInput` in form mode. The user must select `approve` and type the final eight hexadecimal characters of the diff digest.
5. Bind the accepted result to the in-memory request object, MCP request ID/session ID when supplied, canonical root, changeset ID, diff digest, and an immediate expiry no later than the changeset expiry.
6. Re-load and re-authenticate the changeset inside `applyUpdate`, consume the one-call capability, and compare every binding before any project mutation.
7. Apply the transaction. The capability cannot be retried or reused; another attempt requires a new elicitation.

The capability is an in-memory object tracked by a private `WeakSet`; it is never accepted from JSON and never persisted. The production MCP path always requires it. Direct library application is disabled by default and is available only when the embedding application injects an explicit trusted approval provider at service construction. Tests use a dedicated test-only provider rather than a public input flag.

If form elicitation is unsupported, `apply_update` returns a bounded error explaining that the client must support user confirmation. It does not fall back to annotations, a typed tool argument, environment variables, or an automatically runnable command.

### Semantic confirmation

The elicitation summary calls out newly confirmed required/preferred records and redundancy merge decisions separately from filesystem writes. This does not make candidate fields self-authenticating: the exact candidate diff is authenticated first, displayed by identity and digest, and confirmed through the host before it can reach disk. Existing preview output continues to show the complete diff and conflicts before this independent write confirmation.

### 1.0.3 amendment: compact host form

The authenticated approval binding in step 3 still includes all affected paths and record IDs. The host form displays operation and record counts instead of those lists, with at most eight logical lines and 1,536 UTF-8 bytes. It retains the full changeset ID, digest, and expiry; a long project root is visibly shortened for display only. Full details must be reviewed in `preview_update` before opening the form. The digest confirmation code appears first and in the explicitly labelled input field. This presentation change does not alter the full binding, one-use authorization, or exact typed confirmation checks.

## Input and Durable Cache Budgets

All MCP handlers measure the parsed argument object before invoking business logic. The SDK necessarily parses JSON first, so the plugin cannot prevent the host/SDK parse allocation; it can and will prevent expensive validation, diff construction, repository reads, and persistence for oversized arguments.

Hard limits are centralized and tested:

- Serialized MCP arguments: 8 MiB maximum.
- Root/path/ID strings: 4 KiB each.
- Query text: 32 KiB.
- Preview changes: 200 maximum.
- One proposed file body: 2 MiB.
- Aggregate proposed file bodies: 8 MiB.
- Generated diff returned or persisted: 768 KiB.
- Pack documents: 256; pack records: 10,000.
- Evidence references per record: 128; impact items per record: 128.
- Redundancy decisions: 1,000.
- Redundancy input records: 10,000; emitted candidate pairs: 20,000.

The changeset cache is cleaned before preview persistence and after apply:

- Applied changeset and signature pairs are removed after a successful commit.
- Expired changeset/signature pairs and orphan halves are removed opportunistically.
- At most 64 live changesets per canonical project, 256 globally, and 128 MiB total are retained.
- Cleanup uses authenticated metadata and owner-only safe-cache paths. If sufficient space cannot be reclaimed, preview fails before persistence.
- A response-budget failure cannot leave a newly persisted changeset: the complete bounded response is constructed and measured before the authenticated pair is published.

## Bounded Scanning and Snapshot Reuse

### Scan work budget

Discovery rejects or records omission instead of reading arbitrary inputs without limit:

- 100,000 discovered files maximum.
- 8 MiB indexable text per file.
- 256 MiB aggregate bytes opened per cold scan.
- 250,000 evidence chunks maximum.
- Eight concurrent file readers.
- 60-second cold-scan deadline checked during discovery and extraction.

Files are `lstat`/`realpath` checked and sized before opening. Hashing and line extraction use streams with bounded buffers. Oversized or budget-exhausted files are represented by deterministic omission metadata; they are not silently treated as deleted. Explicitly scoped files remain discoverable, including untracked files, but the same safety budgets apply.

Preview target reads, output inventory, manifest/history dependencies, and exact candidate-source reads use bounded handle evidence rather than unbounded convenience reads. Apply creates one shared dependency budget and one shared source-scan budget before its first optimistic-concurrency check. Every pre-mutation revalidation consumes those same counters, aggregate bytes, and monotonic deadline; an `N`-output apply cannot reset a full cold-scan allowance `N+2` times.

Redundancy analysis uses deterministic blocking keys before pair comparison and stops at the configured record and candidate ceilings. It never constructs all `n*(n-1)/2` pairs for an unbounded manifest.

### Immutable snapshot reuse

The first cursorless scan builds a snapshot. Subsequent pages decode and authenticate the cursor first, then load the exact immutable snapshot by `(projectHash, scopeHash, snapshotId)` without rescanning the repository. The loader verifies:

- secure cache ancestry and absence of reparse points;
- metadata schema and project/scope/snapshot bindings;
- every shard is a regular file;
- declared byte length and SHA-256 for every shard;
- JSONL line count and per-entry schema;
- stable file/evidence ordering and evidence lookup consistency.

A missing, expired, or corrupt snapshot fails explicitly and asks the caller to restart pagination. It never silently mixes a new scan with an old cursor.

Snapshot, access, and prune ownership records publish through a two-name hard-link state before settling to one deterministic name. Windows may expose the unlink as mixed `nlink`/`ctime` observations across pathname and handle metadata. Only the same file identity, owner, mode, size, and `mtime`, with link counts restricted to one or two, is classified as that transition; it triggers a bounded full recapture and is never accepted as a stable version. Every retry remains bound to the first observed claim identity, parent, and parsed owner epoch. Scope inventory likewise restarts the complete access-and-snapshot pass under one shared work budget and monotonic deadline, and counts bytes only after an exact stable claim version; a third link, owner rewrite, inode replacement, or exhausted retry fails closed.

Cursorless scans may create a new immutable snapshot. Snapshot retention is bounded to eight snapshots per project/scope, 256 MiB per project, and 1 GiB globally, with a seven-day TTL. Access times live in a separate authenticated registry so snapshot contents remain immutable. Eviction never removes the snapshot being loaded or built and uses the same secure cleanup primitives.

## Signed Scope and Drift Cursors

Scope and drift pagination use a version-2 payload containing snapshot ID, scope key, view, offset, issued time, and snapshot expiry. The body is authenticated with HMAC-SHA-256 using a persistent owner-only key under the external cache. Keys are created atomically and validated with the same protection as the changeset key.

Malformed, modified, cross-snapshot, cross-scope, cross-view, expired, and out-of-range cursors are rejected before item access. The persistent key permits pagination across MCP process restarts while retained snapshots remain valid. History cursor behavior remains signed; it is migrated to the shared implementation and keeps filter binding.

## History Integrity

`query_history` validates historical material before returning any record:

1. Parse the manifest with the canonical knowledge-pack structural schema and require Schema 3.0 for archive access.
2. Validate unique record/document IDs, owner references, lifecycle shape, typed evidence shape, source-revision path/hash syntax, and archive metadata.
3. Require canonical generation IDs and paths, at most two generations, strict generation order, exact declared entry counts, and unique record IDs across active/archive/tombstone sets.
4. Validate every archive line with the complete archive-entry schema, including terminal eligibility, owner consistency, managed-body hash, evidence hash, reason, revision, and timestamp.
5. Validate every tombstone with an exact schema and exact declared count; unknown fields are rejected rather than canonicalized away.
6. Reject unsafe paths, malformed JSONL, duplicate IDs, broken successor relationships, invalid generation chains, or any partial validation result.

Freshness comparison remains separate from structural integrity so stale evidence can still be queried as history. A stale but structurally sound record is returned with its historical source classification; invalid or forged structure produces no knowledge result.

## Secure Index Cache

All scope-cache paths use the shared secure-cache boundary:

- Cache and project roots must be disjoint.
- Every existing component is checked with `lstat` and canonical containment; symbolic links, junctions, and other reparse-point paths are rejected.
- Directories and files use owner-only permissions where supported.
- Shards are written with exclusive creation into a random build directory.
- Publication validates the parent identity immediately before rename.
- A concurrent winner is adopted only after full byte, hash, schema, and binding validation.
- Recursive cleanup is allowed only for a build directory whose recorded identity still matches and whose canonical path remains inside the validated cache root.

## Transaction Concurrency and Filesystem Mutation

### Cross-process coordination

Apply obtains an exclusive lock keyed by canonical project root in the external cache. Lock creation is atomic. The lock records process ID, creation time, random nonce, and project digest. Contenders wait for a bounded interval. A stale lock is reclaimed only when its age exceeds the configured lease and the recorded process is no longer alive; ambiguous state fails closed.

The lock spans final changeset verification, recovery capture, project mutation, rollback, changeset consumption, and recovery retention. Recovery filenames contain a monotonic timestamp, changeset ID, and UUID and are published with exclusive creation, so correctness does not depend on read-max-plus-one. Retention cannot delete the snapshot for an active transaction.

### Path mutation strategy

Pure Node.js does not expose the handle-relative `openat`/`renameat`/`unlinkat` or equivalent Windows handle APIs needed to prove race-free path mutation against a hostile same-user process. This release does not add a native extension. It therefore makes the strongest truthful pure-Node improvement:

- Acquire the cross-process Keeper lock.
- Capture canonical managed-root and parent identities (`dev`, `ino`, type, canonical path, and Windows reparse status where available).
- Stage replacement files with exclusive random names in the verified destination parent.
- Recheck every parent identity and target CAS immediately before each rename.
- Use rename-first quarantine for deletes and overwritten originals; never call recursive removal on a project path.
- Commit the manifest last.
- On success, clean only random quarantine files whose identity and parent still match.
- On any identity change or ambiguous cleanup, stop, roll back verified entries, retain recovery material, and report the exact manual-cleanup path without following it.

This closes races between Keeper MCP processes and removes unsafe direct project-path deletion. A malicious same-user process that swaps a parent in the final interval around one pathname syscall remains a documented platform residual. The plugin must not claim that repeated pathname checks eliminate it. Deployments requiring protection from such a process must use OS permissions/workspace isolation or a future audited native helper.

## Installation, Reconnection, and Release Verification

The plugin cannot force the Codex host to reconnect an already-open stdio transport. The supported activation flow therefore becomes explicit and safe:

1. Build the allowlisted `.package` artifact from a bounded identity/version-bound source snapshot, then re-capture the source before and after publication.
2. Verify the exact 25-file manifest, regular-file/no-reparse/single-link status, bounded JSON and file sizes, and source/package hashes. Windows activation reads deny concurrent write/delete sharing.
3. Refuse to replace an installed directory while matching MCP child processes are alive; report their process IDs and require the user to close affected tasks or restart Codex.
4. Hold the random staging root and every expected child directory against replacement while copying exclusively; rename active installation to a timestamped backup, rename verified staging into place, and preserve the backup until installed-root smoke passes.
5. Run the installed-root SDK handshake, exact nine-tool listing, read-only scan, cursor-tamper rejection, and an `apply_update` no-elicitation fail-closed probe against a temporary project.
6. On failure, restore the backup atomically. Once the first rename has moved the active install, every failure switches to a separate bounded recovery deadline so a forward deadline reached at the failure boundary cannot suppress an authenticated restore; identity ambiguity still prohibits rollback mutation. Cleanup first quarantines an exact package tree, acquires authenticated Windows delete handles for every fixed file and directory, and performs a final bounded topology check. That check is the cleanup commit point: later failures are reported nonzero, only already-held authenticated objects may have been deleted, and the quarantine plus every remaining object is preserved and reported. A stable historical `backup-*` directory whose content does not match the bounded current-package shape is rechecked against its captured root and parent identities, preserved unchanged, reported, and excluded from cleanup rather than blocking a verified current-package swap. Timeout, I/O, and identity-authentication failures remain blocking. On success, report that existing tasks still need a new MCP connection; a new task or app restart is the verification boundary.

`package.json` adds a checked-in `smoke:installed` command that accepts explicit absolute roots, and CI runs it against `.package/project-design-keeper` after package verification. Packaging remains allowlist-only and excludes `src`, tests, `.plugin-eval`, `.superpowers`, coverage, caches, lockfiles, and development artifacts. Packaging is limited to 256 entries, depth 16, 16 MiB per file, and 64 MiB aggregate; package JSON consumed by verification, smoke, or activation is limited to 256 KiB. Activation uses an overall monotonic deadline, a separate 30-second recovery deadline, bounded directory enumeration, and a WMI operation timeout. Installed smoke is created suspended, assigned to a private Windows Job Object before it can spawn descendants, and resumed only after assignment; timeout or a 1 MiB aggregate stdout/stderr limit terminates the complete owned tree, and rollback starts only after the root handle, Job `ActiveProcesses=0`, and both pipe EOFs are confirmed within five seconds. Test-only barriers require `NODE_ENV=test`, a verified direct-child temporary test root, a previously absent UUID control path acquired by exclusive creation, an open no-delete lease held through release validation, and exclusive marker publication.

No placeholder public website, privacy policy, or terms URL is added. Final plugin-eval reporting explicitly distinguishes those three private-plugin false positives from actionable runtime findings.

## Error Handling

All new failures are bounded, deterministic, and fail closed. Public MCP errors expose no absolute filesystem paths or sensitive cache data. Internal errors retain causes for tests and logs. A budget failure reports the exceeded category and configured limit. Integrity failures identify the relative managed file and line when safe. Cursor failures do not reveal signing details. Approval failures distinguish unsupported, declined, cancelled, malformed, changed, expired, and already-consumed states without applying any project mutation.

Cleanup is best-effort only after the durable operation's result is known. A cleanup failure never converts an uncommitted transaction into a reported success. Recovery evidence is preserved whenever rollback or quarantine cleanup is uncertain.

## Testing Strategy

Every production change begins with a focused failing test and is committed only after its focused suite passes. Required coverage includes:

- MCP apply accepted, declined, cancelled, unsupported, malformed, reused, expired, and diff-changed elicitation paths.
- Direct MCP bypass attempts and caller-supplied confirmation fields.
- Oversized arguments, change counts, bodies, aggregate content, pack arrays, diff output, and cache exhaustion before persistence.
- Expired/applied/orphan changeset cleanup and quota refusal.
- Oversized files, aggregate scan budget, file/evidence limits, timeout, binary input, untracked explicit files, and deterministic omissions.
- Cursor HMAC modification, cross-binding, expiry, process restart, offset bounds, and same-snapshot page completeness.
- Snapshot load/reuse without repository content reads, corruption rejection, concurrent publication, TTL/LRU/quota eviction, and protected active snapshots.
- Strict manifest, generation, archive-entry, tombstone, count, hash, duplicate, owner, lifecycle, and relationship rejection while stale valid history remains queryable.
- Scope-cache path escape, junction/symlink ancestry, swapped cleanup directory, unsafe winner, and cache/project overlap.
- Cross-process apply serialization, collision-free recovery names, stale-lock handling, retention safety, parent identity change, rename-first delete, rollback, and manifest-last invariants.
- Installed-root smoke success, no-elicitation fail-closed behavior, occupied-install refusal, backup restore, and restart guidance.

Coverage gates remain at least 85% lines/statements and 80% branches globally. Modified security, history-integrity, cursor, scope-store, and process-lock modules require at least 90% lines/statements and 85% branches.

## Acceptance Gates

Completion requires current evidence for every command and artifact:

```text
npm run typecheck
npm test -- --maxWorkers=1
npm run test:coverage
npm run build
npm run smoke
npm run test:perf
npm run package:verify
npm run smoke:installed -- <verified package root> <temporary project root>
plugin-eval start <plugin-root> --request "Evaluate this plugin." --format markdown
plugin-eval analyze <plugin-root> --format json
plugin-eval benchmark <plugin-root> --dry-run
plugin-eval benchmark <plugin-root>
```

The final completion audit also proves:

- source and packaged `dist/index.js` SHA-256 match;
- installed and packaged file manifests match exactly;
- the source worktree and tracked Demo project are unchanged except for intentional commits;
- pre-existing untracked `.plugin-eval/**` artifacts were not staged or overwritten;
- the active installed plugin passes installed-root smoke from its actual path;
- a fresh Codex task connects to the new process, while old tasks are explicitly identified as requiring reconnection;
- no Critical or Important actionable plugin-eval/security finding remains, except the documented pure-Node final-syscall TOCTOU residual.

## Non-Goals

- Adding SQLite, native Node extensions, a network service, or a vector database.
- Changing the nine public MCP tool names.
- Automatically migrating or applying the Demo project's knowledge pack.
- Signing arbitrary repository content with a globally trusted identity.
- Claiming protection from a malicious operating-system user or kernel.
- Adding fake public policy URLs to improve a private-plugin score.
