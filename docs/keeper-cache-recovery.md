# Keeper historical cache recovery

Older Keeper releases could leave a changeset backlog larger than the current
1,024-entry publication inventory. The inventory reader rejected that backlog
before authenticated garbage collection could run, so even expired previews
prevented a new preview from being created.

Recovery now enumerates at most 4,096 entries before collecting expired pairs.
New publications still reserve their temporary-file headroom within the original
1,024-entry ceiling and enforce the existing live-pair and byte quotas. Enumeration
stops at the recovery ceiling instead of performing an unbounded scan. Young orphan
halves are retained, and unauthenticated or malformed pairs still stop recovery.

Some historical V2 writers also predate `historyFiles`, and earlier V2 writers
predate `archiveActions`. Garbage collection can validate these signed, expired
records with empty values for the absent fields. It still checks the complete
remaining schema, filename ID, diff digest, and exact file identities. This
compatibility path is unavailable to normal load/apply and to unexpired records.

`preview_update` invokes this recovery before admitting a new changeset. No
knowledge-pack files need to be edited to repair the cache. The regression tests
are in `sources/project-design-keeper/test/changeset-store.test.ts`; source and
release bundles are rebuilt from `sources/project-design-keeper/`.
