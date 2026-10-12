# Project Design Keeper 1.1.0

Keeper adds a clickable settings panel, saved Easy mode, configurable aggregate write limits, and complete paginated previews for large knowledge updates.

## Settings

Ask “打开 Keeper 设置” after activating the updated plugin. Keeper opens a temporary local browser page with the Easy switch, aggregate limit, save button, and restore-defaults button. The panel is served only on loopback and expires after 15 minutes. Its save capability is handed directly to the browser; model-visible tool results contain only a tokenless link. There is no model-callable settings-save tool.

Settings apply to this machine's current-user Keeper installation across projects and tasks. They persist across upgrades. Saving affects the next operation without restarting; an operation already in progress keeps its policy snapshot. Concurrent edits produce a visible revision conflict instead of silently overwriting one another.

## Update behavior

- Normal mode remains the default and requires Keeper human confirmation.
- Easy skips Keeper human confirmation, including the digest form, while retaining automatic validation, evidence, ownership, path, signature, expiry, concurrency, and recovery checks. Host permissions remain unchanged.
- The aggregate limit is configurable from 1 to 64 MiB, default 8. It counts the final UTF-8 content of every file written, once per path, including surrounding text after managed-block merges. Deletes count zero.
- Easy has no independent single-file write cap. Normal retains a 2 MiB cap. Old larger files remain readable for shrinking or deletion after Easy is disabled.
- Large diffs are available through authenticated `read_preview` pages. Continue `nextCursor` until `complete` is true for normal-mode review.
- Previews bind the settings revision. A settings change or a pre-1.1.0 preview requires a fresh preview before apply.

## New tools

`get_settings`, `open_settings`, and `read_preview` supplement the original nine tools.

## Upgrade

Upgrade the `project-design` marketplace and install/update Keeper. Start a new task or restart Codex to connect the new plugin runtime. Existing stdio sessions do not hot-reload. No global Easy setting is enabled by this release.

The settings UI is a local browser page, not a native panel injected into Codex's plugin-management screen. Source and generated installable trees are published together; release assets contain the ZIP and SHA-256 checksum.

## Validation

Windows full-suite coverage and final affected-suite reruns account for 1,113 passing tests and 15 platform/privilege skips, with no remaining failures. Typechecking, the exact 25-file package contract, installed-package smoke, and 20 repository distribution checks passed. Isolated browser checks covered saving, reloading, resetting, keyboard submission, and concurrent-edit conflicts without changing the user's real settings.

Large-file regressions include a 64 MiB actual write, 63 MiB Unicode knowledge reads and validation, byte-preserving compressed storage, and a subsequent update after deleting four 56 MiB files.
