# Project Design Keeper 1.0.2

- Tag: `project-design-keeper-v1.0.2`
- Plugin: `project-design-keeper` version `1.0.2`
- Assets: `project-design-keeper-1.0.2.zip` and `SHA256SUMS.txt`

This patch restores preview creation when historical changeset caches exceed
the normal publication inventory. Recovery scans at most 4,096 entries before
collecting expired, authenticated pairs; the existing 1,024-entry publication
ceiling, live-pair quotas, and signature checks remain in force.

It also permits garbage collection of expired, authenticated early V2 records
that predate history bindings or archive actions. Normal load/apply still
requires the complete current format.

Plugin metadata, package metadata, the MCP server version, and installation
validation now identify the package as 1.0.2. The earlier unversioned fix commit
`f8fc909` is explicitly reverted before this versioned release commit.

The underlying fix passed all 38 test files in batches (1,063 passed and 15
platform skips), plus 20 repository distribution checks. The versioned release
also checks type safety, packaging parity, MCP/release contracts, and installation
of the newly versioned package. A real 2,025-entry expired cache was backed up and
recovered, followed by a successful preview using the published runtime.

Refresh the `project-design` marketplace and update ProjectDesignKeeper to
1.0.2. Existing preview drafts whose source evidence changed must be refreshed
before they can be applied.
