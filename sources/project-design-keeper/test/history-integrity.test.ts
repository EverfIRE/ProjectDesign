import { createHash } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import type { ServiceOptions } from "../src/types/schema.js";
import { writeCanonicalPackFixture, writeV3PackFixture } from "./canonical-pack-fixture.js";
import { createProjectFixture, removeProjectFixture, type ProjectFixture } from "./fixtures.js";

type JsonObject = Record<string, unknown>;

interface HistoryState {
  sourcePath: string;
  manifestPath: string;
  generationPath: string;
  tombstonePath: string;
  manifest: JsonObject;
  generationEntries: Map<string, JsonObject[]>;
  generationBytes: Map<string, Buffer>;
  tombstones: JsonObject[];
  tombstoneBytes?: Buffer;
}

let fixture: ProjectFixture | undefined;

beforeEach(async () => {
  fixture = await createProjectFixture();
});

afterEach(async () => {
  await removeProjectFixture(fixture);
  fixture = undefined;
});

function project(): ProjectFixture {
  if (!fixture) throw new Error("fixture was not created");
  return fixture;
}

function hash(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function asObject(value: unknown): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected an object");
  return value as JsonObject;
}

function asObjects(value: unknown): JsonObject[] {
  if (!Array.isArray(value)) throw new Error("expected an object array");
  for (const item of value) asObject(item);
  return value as JsonObject[];
}

function historyRecord(
  sourcePath: string,
  id: string,
  lifecycle: JsonObject,
  overrides: JsonObject = {}
): JsonObject {
  return {
    id,
    kind: "decision",
    ownerDocument: "document.decisions",
    domain: "project-design",
    scope: "history",
    statement: `${id} historical statement`,
    evidence: [{ path: sourcePath, startLine: 1, role: "design", excerptHash: hash("old source") }],
    impact: ["history"],
    status: lifecycle.state === "terminal" ? "superseded" : "observed",
    strength: "informational",
    approval: "not-required",
    assertedConfidence: "high",
    lifecycle,
    ...overrides
  };
}

function archiveEntry(
  sourcePath: string,
  id: string,
  maintenanceRevision: number,
  archivedAt: string,
  successorIds: string[] = ["record.stale"]
): JsonObject {
  const record = historyRecord(sourcePath, id, {
    state: "terminal",
    reason: "merged",
    sinceRevision: Math.max(0, maintenanceRevision - 1),
    confirmedRefreshes: 2,
    successorIds
  });
  const managedBody = `Archived body for ${id}`;
  return {
    record,
    originalOwnerDocument: "document.decisions",
    managedBody,
    contentHash: hash(managedBody),
    evidenceHash: hash(JSON.stringify(record.evidence)),
    terminalReason: "merged",
    maintenanceRevision,
    archivedAt
  };
}

function archiveMetadata(state: HistoryState): JsonObject {
  return asObject(state.manifest.archive);
}

function generations(state: HistoryState): JsonObject[] {
  return asObjects(archiveMetadata(state).generations);
}

function generationEntry(state: HistoryState): JsonObject {
  const entry = state.generationEntries.get(state.generationPath)?.[0];
  if (!entry) throw new Error("default archive entry is missing");
  return entry;
}

function archivedRecord(state: HistoryState): JsonObject {
  return asObject(generationEntry(state).record);
}

function tombstoneMetadata(state: HistoryState): JsonObject {
  return asObject(archiveMetadata(state).tombstones);
}

function createHistoryState(): HistoryState {
  const sourcePath = relative(project().repository, project().trackedText).replaceAll("\\", "/");
  const manifestPath = "docs/project-design/manifest.json";
  const generationPath = "docs/project-design/archive/generation-000001.records.jsonl";
  const tombstonePath = "docs/project-design/archive/tombstones.jsonl";
  const archivedAt = "2026-08-15T00:00:00.000Z";
  return {
    sourcePath,
    manifestPath,
    generationPath,
    tombstonePath,
    manifest: {
      managedBy: "project-design-keeper",
      schemaVersion: "3.0",
      maintenanceRevision: 2,
      scope: { root: ".", paths: [sourcePath] },
      sourceRevision: { kind: "git", files: { [sourcePath]: hash("old source\n") } },
      documents: [{ id: "document.decisions", path: "docs/project-design/decisions.md" }],
      records: [
        historyRecord(sourcePath, "record.stale", { state: "active" }),
        historyRecord(sourcePath, "record.terminal", {
          state: "terminal",
          reason: "resolved",
          sinceRevision: 1,
          confirmedRefreshes: 2,
          successorIds: []
        })
      ],
      archive: {
        generations: [{
          id: "generation-000001",
          path: generationPath,
          recordCount: 1,
          createdAt: archivedAt
        }],
        tombstones: { path: tombstonePath, count: 1 }
      },
      dedupeExceptions: []
    },
    generationEntries: new Map([[generationPath, [archiveEntry(sourcePath, "record.archived", 1, archivedAt)]]]),
    generationBytes: new Map(),
    tombstones: [{
      id: "record.tombstone",
      reason: "resolved",
      successorIds: [],
      contentHash: hash("old tombstone"),
      archivedAt: "2026-08-14T00:00:00.000Z"
    }]
  };
}

async function writeRepositoryFile(path: string, bytes: string | Buffer): Promise<void> {
  const target = join(project().repository, ...path.split("/"));
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, bytes);
}

async function persistHistoryState(state: HistoryState): Promise<void> {
  await writeFile(project().trackedText, "changed source\n", "utf8");
  for (const [path, entries] of state.generationEntries) {
    const bytes = state.generationBytes.get(path) ?? Buffer.from(`${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, "utf8");
    await writeRepositoryFile(path, bytes);
  }
  for (const [path, bytes] of state.generationBytes) {
    if (!state.generationEntries.has(path)) await writeRepositoryFile(path, bytes);
  }
  const tombstonePath = String(tombstoneMetadata(state).path);
  const tombstoneBytes = state.tombstoneBytes ?? Buffer.from(`${state.tombstones.map((item) => JSON.stringify(item)).join("\n")}\n`, "utf8");
  await writeRepositoryFile(tombstonePath, tombstoneBytes);
  await writeRepositoryFile(state.manifestPath, `${JSON.stringify(state.manifest, null, 2)}\n`);
}

async function writeHistoryPack(): Promise<HistoryState> {
  const state = createHistoryState();
  await persistHistoryState(state);
  return state;
}

async function queryHistory(
  input: JsonObject = {},
  options: ServiceOptions = {}
): Promise<JsonObject> {
  const { createProjectDesignKeeper } = await import("../src/index.js");
  const api = createProjectDesignKeeper({
    ...options,
    cacheDirectory: options.cacheDirectory ?? join(project().root, "keeper-cache")
  });
  return api.queryHistory({ root: project().repository, recordIds: ["record.never"], ...input });
}

async function parseHistoryOverlay(state: HistoryState) {
  const integrity = await import("../src/knowledge/history-integrity.js");
  const pack = integrity.parseCanonicalPackStructure(state.manifest);
  const parsedGenerations = pack.archive.generations.map((metadata) => {
    const entries = state.generationEntries.get(metadata.path) ?? [];
    const bytes = state.generationBytes.get(metadata.path) ??
      Buffer.from(`${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, "utf8");
    return integrity.parseArchiveGeneration(bytes, metadata);
  });
  const tombstoneBytes = state.tombstoneBytes ??
    Buffer.from(`${state.tombstones.map((item) => JSON.stringify(item)).join("\n")}\n`, "utf8");
  const parsedTombstones = integrity.parseTombstones(tombstoneBytes, pack.archive.tombstones.count);
  return { integrity, pack, parsedGenerations, parsedTombstones };
}

describe("historical integrity interfaces", () => {
  test("exports the exact strict history parsers and schemas", async () => {
    const integrity = await import("../src/knowledge/history-integrity.js");
    const schemas = await import("../src/types/schema.js") as unknown as JsonObject;

    expect(integrity).toMatchObject({
      parseCanonicalPackStructure: expect.any(Function),
      parseArchiveGeneration: expect.any(Function),
      parseTombstones: expect.any(Function),
      validateHistoryRelationships: expect.any(Function)
    });
    expect(schemas).toMatchObject({
      archiveEntrySchema: expect.objectContaining({ safeParse: expect.any(Function) }),
      tombstoneSchema: expect.objectContaining({ safeParse: expect.any(Function) }),
      strictHistoryKnowledgeRecordSchema: expect.objectContaining({ safeParse: expect.any(Function) })
    });
  });

  test("keeps ordinary Schema 1.0 record extensions readable", async () => {
    const pack = await writeCanonicalPackFixture(project());
    const record = asObjects(pack.records)[0];
    record.compatibilityExtension = { retained: true };
    const { projectDesignKeeper } = await import("../src/index.js");

    await expect(projectDesignKeeper.validatePack({ root: project().repository, pack }))
      .resolves.toMatchObject({ valid: true, errors: [] });
  });

  test("preserves canonical Schema 3 scope and source-revision extensions in history reads", async () => {
    const pack = await writeV3PackFixture(project());
    asObject(pack.scope).selectionMetadata = { mode: "explicit", retained: true };
    asObject(pack.sourceRevision).providerMetadata = { provider: "git", commit: "0123456789abcdef" };
    await writeRepositoryFile("docs/project-design/manifest.json", `${JSON.stringify(pack, null, 2)}\n`);
    const { parseCanonicalPackStructure } = await import("../src/knowledge/history-integrity.js");
    const { projectDesignKeeper } = await import("../src/index.js");

    await expect(projectDesignKeeper.validatePack({ root: project().repository, pack }))
      .resolves.toMatchObject({ valid: true, errors: [] });
    expect(parseCanonicalPackStructure(pack)).toMatchObject({
      scope: { selectionMetadata: { retained: true } },
      sourceRevision: { providerMetadata: { commit: "0123456789abcdef" } }
    });
    await expect(queryHistory({ recordIds: ["record.architecture"] }))
      .resolves.toMatchObject({ schemaVersion: 3, items: [] });
  });
});

describe("canonical manifest trust boundaries", () => {
  test("accepts a dedupe exception only when both active-record digests are exact", async () => {
    const state = createHistoryState();
    const records = asObjects(state.manifest.records);
    state.manifest.dedupeExceptions = [{
      leftId: records[0].id,
      rightId: records[1].id,
      leftDigest: hash(JSON.stringify(records[0])),
      rightDigest: hash(JSON.stringify(records[1]))
    }];
    const { parseCanonicalPackStructure } = await import("../src/knowledge/history-integrity.js");

    expect(parseCanonicalPackStructure(state.manifest).dedupeExceptions).toEqual(state.manifest.dedupeExceptions);
  });

  const manifestMutations: Array<{
    name: string;
    expected: RegExp;
    mutate(state: HistoryState): void;
  }> = [
    {
      name: "empty source revision",
      expected: /sourceRevision\.files.*source files|must contain source files/i,
      mutate: (state) => { asObject(state.manifest.sourceRevision).files = {}; }
    },
    {
      name: "document and active-record ID collision",
      expected: /duplicate document or active record IDs/i,
      mutate: (state) => { asObjects(state.manifest.records)[0].id = "document.decisions"; }
    },
    {
      name: "case-aliased managed document path",
      expected: /document paths.*duplicate or aliased/i,
      mutate: (state) => {
        asObjects(state.manifest.documents).push({
          id: "document.alias",
          path: "docs/project-design/DECISIONS.md"
        });
      }
    },
    {
      name: "active-record owner incompatible with its kind",
      expected: /record owner is missing or incompatible/i,
      mutate: (state) => { asObjects(state.manifest.records)[0].kind = "architecture"; }
    },
    {
      name: "active-record evidence outside source revision",
      expected: /evidence is not bound to sourceRevision\.files/i,
      mutate: (state) => { asObjects(asObjects(state.manifest.records)[0].evidence)[0].path = "Source/Unbound.txt"; }
    },
    {
      name: "nonconsecutive generation ID",
      expected: /generations must be consecutive and ordered/i,
      mutate: (state) => {
        generations(state).push({
          id: "generation-000003",
          path: "docs/project-design/archive/generation-000003.records.jsonl",
          recordCount: 0,
          createdAt: "2026-08-16T00:00:00.000Z"
        });
      }
    },
    {
      name: "nonincreasing generation timestamp",
      expected: /generations must be consecutive and ordered/i,
      mutate: (state) => {
        generations(state).push({
          id: "generation-000002",
          path: "docs/project-design/archive/generation-000002.records.jsonl",
          recordCount: 0,
          createdAt: "2026-08-14T00:00:00.000Z"
        });
      }
    },
    {
      name: "noncanonical tombstone path",
      expected: /tombstone path must be docs\/project-design\/archive\/tombstones\.jsonl/i,
      mutate: (state) => { tombstoneMetadata(state).path = "docs/project-design/archive/renamed-tombstones.jsonl"; }
    },
    {
      name: "dedupe exception with identical IDs",
      expected: /dedupe exception references invalid active record IDs/i,
      mutate: (state) => {
        const record = asObjects(state.manifest.records)[0];
        state.manifest.dedupeExceptions = [{
          leftId: record.id,
          rightId: record.id,
          leftDigest: hash(JSON.stringify(record)),
          rightDigest: hash(JSON.stringify(record))
        }];
      }
    },
    {
      name: "dedupe exception with a stale digest",
      expected: /dedupe exception digests do not match active records/i,
      mutate: (state) => {
        const records = asObjects(state.manifest.records);
        state.manifest.dedupeExceptions = [{
          leftId: records[0].id,
          rightId: records[1].id,
          leftDigest: hash("stale record bytes"),
          rightDigest: hash(JSON.stringify(records[1]))
        }];
      }
    }
  ];

  test.each(manifestMutations)("rejects a $name", async ({ expected, mutate }) => {
    const state = createHistoryState();
    mutate(state);
    const { parseCanonicalPackStructure } = await import("../src/knowledge/history-integrity.js");

    expect(() => parseCanonicalPackStructure(state.manifest)).toThrow(expected);
  });

  test.each([
    { name: "archive generation", path: (state: HistoryState) => state.generationPath, expected: /archive generation is missing/i },
    { name: "nonempty tombstone", path: (state: HistoryState) => state.tombstonePath, expected: /tombstone file is missing/i }
  ])("rejects a missing $name file before returning history", async ({ path, expected }) => {
    const state = await writeHistoryPack();
    await rm(join(project().repository, ...path(state).split("/")));

    await expect(queryHistory()).rejects.toThrow(expected);
  });
});

describe("cross-tier relationship trust boundaries", () => {
  test("rejects an incomplete generation set supplied to relationship validation", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      [],
      overlay.parsedTombstones
    )).toThrow(/archive generations are incomplete/i);
  });

  test("rejects generation metadata changed after its archive bytes were parsed", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());
    overlay.parsedGenerations[0].metadata.createdAt = "2026-08-15T01:00:00.000Z";

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      overlay.parsedGenerations,
      overlay.parsedTombstones
    )).toThrow(/generation metadata changed during validation/i);
  });

  test("rejects a nonempty generation whose parsed revision is missing", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());
    overlay.parsedGenerations[0].maintenanceRevision = undefined;

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      overlay.parsedGenerations,
      overlay.parsedTombstones
    )).toThrow(/generation revision is missing/i);
  });

  test("rejects an archived record whose owner is absent from managed documents", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());
    overlay.parsedGenerations[0].entries[0].record.ownerDocument = "document.missing";

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      overlay.parsedGenerations,
      overlay.parsedTombstones
    )).toThrow(/record owner is missing or incompatible/i);
  });

  test("rejects a terminal active-tier record whose revision is in the future", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());
    const lifecycle = overlay.pack.records[1].lifecycle;
    if (lifecycle.state !== "terminal") throw new Error("expected a terminal fixture record");
    lifecycle.sinceRevision = overlay.pack.maintenanceRevision + 1;

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      overlay.parsedGenerations,
      overlay.parsedTombstones
    )).toThrow(/terminal record revision is in the future/i);
  });

  test("rejects an archive entry whose record is no longer terminal", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());
    asObject(overlay.parsedGenerations[0].entries[0].record).lifecycle = { state: "active" };

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      overlay.parsedGenerations,
      overlay.parsedTombstones
    )).toThrow(/archive record owner, lifecycle, or revision is invalid/i);
  });

  test("rejects a supersedes reference to an unknown predecessor", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());
    asObject(overlay.pack.records[0]).supersedes = "record.missing";

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      overlay.parsedGenerations,
      overlay.parsedTombstones
    )).toThrow(/supersedes relationship is broken/i);
  });

  test("rejects superseding an active predecessor", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());
    asObject(overlay.pack.records[0]).supersedes = "record.terminal";
    asObject(overlay.pack.records[1]).lifecycle = { state: "active" };

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      overlay.parsedGenerations,
      overlay.parsedTombstones
    )).toThrow(/cannot supersede an active predecessor/i);
  });

  test("rejects supersededBy on an active record", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());
    asObject(overlay.pack.records[0]).supersededBy = "record.terminal";

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      overlay.parsedGenerations,
      overlay.parsedTombstones
    )).toThrow(/active record cannot declare supersededBy/i);
  });

  test("rejects contradictory successor and supersedes encodings across tiers", async () => {
    const overlay = await parseHistoryOverlay(createHistoryState());
    asObject(overlay.pack.records[0]).supersedes = "record.terminal";
    const terminalLifecycle = overlay.pack.records[1].lifecycle;
    if (terminalLifecycle.state !== "terminal") throw new Error("expected a terminal fixture record");
    terminalLifecycle.successorIds = ["record.stale"];

    expect(() => overlay.integrity.validateHistoryRelationships(
      overlay.pack,
      overlay.parsedGenerations,
      overlay.parsedTombstones
    )).toThrow(/successor encodings contradict each other/i);
  });
});

describe("safe historical integer parsing", () => {
  const unsafe = Number.MAX_SAFE_INTEGER + 1;
  const cases: Array<{
    name: string;
    parser: "pack" | "record" | "entry" | "generation" | "tombstone-count";
    mutate(state: HistoryState): void;
  }> = [
    {
      name: "pack maintenanceRevision",
      parser: "pack",
      mutate: (state) => { state.manifest.maintenanceRevision = unsafe; }
    },
    {
      name: "terminal sinceRevision",
      parser: "record",
      mutate: (state) => { asObject(archivedRecord(state).lifecycle).sinceRevision = unsafe; }
    },
    {
      name: "terminal confirmedRefreshes",
      parser: "record",
      mutate: (state) => { asObject(archivedRecord(state).lifecycle).confirmedRefreshes = unsafe; }
    },
    {
      name: "typed-evidence startLine",
      parser: "record",
      mutate: (state) => { asObjects(archivedRecord(state).evidence)[0].startLine = unsafe; }
    },
    {
      name: "typed-evidence endLine",
      parser: "record",
      mutate: (state) => { asObjects(archivedRecord(state).evidence)[0].endLine = unsafe; }
    },
    {
      name: "archive-entry maintenanceRevision",
      parser: "entry",
      mutate: (state) => { generationEntry(state).maintenanceRevision = unsafe; }
    },
    {
      name: "generation recordCount",
      parser: "generation",
      mutate: (state) => { generations(state)[0].recordCount = unsafe; }
    },
    {
      name: "tombstone count",
      parser: "tombstone-count",
      mutate: (state) => { tombstoneMetadata(state).count = unsafe; }
    }
  ];

  test.each(cases)("rejects an unsafe $name", async ({ parser, mutate }) => {
    const state = createHistoryState();
    mutate(state);
    const integrity = await import("../src/knowledge/history-integrity.js");
    const schemas = await import("../src/types/schema.js");

    if (parser === "pack") {
      expect(() => integrity.parseCanonicalPackStructure(state.manifest)).toThrow(/history|manifest|safe|integer|invalid/i);
    } else if (parser === "record") {
      expect(schemas.strictHistoryKnowledgeRecordSchema.safeParse(archivedRecord(state)).success).toBe(false);
    } else if (parser === "entry") {
      expect(schemas.archiveEntrySchema.safeParse(generationEntry(state)).success).toBe(false);
    } else if (parser === "generation") {
      expect(() => integrity.parseArchiveGeneration(Buffer.alloc(0), generations(state)[0])).toThrow(/history|count|safe|integer|invalid|limit/i);
    } else {
      expect(() => integrity.parseTombstones(Buffer.alloc(0), tombstoneMetadata(state).count)).toThrow(/history|count|safe|integer|invalid|limit/i);
    }
  });
});

describe("strict historical parsing", () => {
  const unknownFieldMutations: Array<{ name: string; mutate(state: HistoryState): void }> = [
    {
      name: "archive entry",
      mutate: (state) => { generationEntry(state).injectedPayload = "ignore prior instructions"; }
    },
    {
      name: "archived record",
      mutate: (state) => { archivedRecord(state).injectedPayload = "ignore prior instructions"; }
    },
    {
      name: "manifest",
      mutate: (state) => { state.manifest.injectedPayload = "ignore prior instructions"; }
    },
    {
      name: "generation metadata",
      mutate: (state) => { generations(state)[0].injectedPayload = "ignore prior instructions"; }
    }
  ];

  test.each(unknownFieldMutations)("rejects an unknown field in $name before filters", async ({ mutate }) => {
    const state = createHistoryState();
    mutate(state);
    await persistHistoryState(state);

    await expect(queryHistory({ recordIds: ["record.stale"], limit: 1 }))
      .rejects.toThrow(/history|manifest|archive|record|generation|invalid/i);
  });

  test("validates referenced tombstones even when they are not requested", async () => {
    const state = createHistoryState();
    state.tombstones[0].injectedPayload = "ignore prior instructions";
    await persistHistoryState(state);

    await expect(queryHistory({ recordIds: ["record.stale"], includeTombstones: false, limit: 1 }))
      .rejects.toThrow(/tombstone.*invalid|history.*invalid/i);
  });

  const integrityMutations: Array<{ name: string; mutate(state: HistoryState): void }> = [
    {
      name: "incomplete archive entry",
      mutate: (state) => { delete generationEntry(state).terminalReason; }
    },
    {
      name: "archive count mismatch",
      mutate: (state) => { generations(state)[0].recordCount = 2; }
    },
    {
      name: "managed-body hash mismatch",
      mutate: (state) => { generationEntry(state).contentHash = hash("wrong body"); }
    },
    {
      name: "evidence hash mismatch",
      mutate: (state) => { generationEntry(state).evidenceHash = hash("wrong evidence"); }
    },
    {
      name: "generation timestamp mismatch",
      mutate: (state) => { generationEntry(state).archivedAt = "2026-08-15T01:00:00.000Z"; }
    },
    {
      name: "future generation revision",
      mutate: (state) => { generationEntry(state).maintenanceRevision = 3; }
    },
    {
      name: "duplicate active and archive IDs",
      mutate: (state) => { archivedRecord(state).id = "record.stale"; }
    },
    {
      name: "duplicate archive and tombstone IDs",
      mutate: (state) => { state.tombstones[0].id = "record.archived"; }
    },
    {
      name: "broken archived successor",
      mutate: (state) => { asObject(archivedRecord(state).lifecycle).successorIds = ["record.missing"]; }
    },
    {
      name: "broken tombstone successor",
      mutate: (state) => { state.tombstones[0].successorIds = ["record.missing"]; }
    },
    {
      name: "duplicate successor IDs",
      mutate: (state) => { asObject(archivedRecord(state).lifecycle).successorIds = ["record.stale", "record.stale"]; }
    },
    {
      name: "self successor",
      mutate: (state) => { asObject(archivedRecord(state).lifecycle).successorIds = ["record.archived"]; }
    },
    {
      name: "cross-tier successor cycle",
      mutate: (state) => {
        asObjects(state.manifest.records)[0].lifecycle = {
          state: "terminal",
          reason: "merged",
          sinceRevision: 1,
          confirmedRefreshes: 2,
          successorIds: ["record.archived"]
        };
      }
    },
    {
      name: "nonreciprocal supersedes encoding",
      mutate: (state) => {
        asObject(archivedRecord(state).lifecycle).successorIds = [];
        asObjects(state.manifest.records)[0].supersedes = "record.terminal";
      }
    },
    {
      name: "nonreciprocal supersededBy encoding",
      mutate: (state) => { asObjects(state.manifest.records)[1].supersededBy = "record.stale"; }
    },
    {
      name: "archive owner mismatch",
      mutate: (state) => { generationEntry(state).originalOwnerDocument = "document.other"; }
    },
    {
      name: "attacker-controlled archive count",
      mutate: (state) => { generations(state)[0].recordCount = Number.MAX_SAFE_INTEGER; }
    }
  ];

  test.each(integrityMutations)("rejects $name", async ({ mutate }) => {
    const state = createHistoryState();
    mutate(state);
    await persistHistoryState(state);

    await expect(queryHistory())
      .rejects.toThrow(/history|archive|record|count|hash|owner|successor|revision|timestamp|invalid|limit/i);
  });

  const malformedJsonl: Array<{
    name: string;
    contents(state: HistoryState, second: JsonObject): Buffer;
  }> = [
    {
      name: "interior blank line",
      contents: (state, second) => Buffer.from(`${JSON.stringify(generationEntry(state))}\n\n${JSON.stringify(second)}\n`, "utf8")
    },
    {
      name: "malformed line",
      contents: (state) => Buffer.from(`${JSON.stringify(generationEntry(state))}\n{\n`, "utf8")
    },
    {
      name: "trailing non-whitespace garbage",
      contents: (state) => Buffer.from(`${JSON.stringify(generationEntry(state))}\nnot-json`, "utf8")
    },
    {
      name: "duplicate terminating newline",
      contents: (state, second) => Buffer.from(`${JSON.stringify(generationEntry(state))}\n${JSON.stringify(second)}\n\n`, "utf8")
    },
    {
      name: "CRLF terminator",
      contents: (state, second) => Buffer.from(`${JSON.stringify(generationEntry(state))}\r\n${JSON.stringify(second)}\r\n`, "utf8")
    },
    {
      name: "missing terminating newline",
      contents: (state, second) => Buffer.from(`${JSON.stringify(generationEntry(state))}\n${JSON.stringify(second)}`, "utf8")
    },
    {
      name: "trailing whitespace before LF",
      contents: (state, second) => Buffer.from(`${JSON.stringify(generationEntry(state))}\n${JSON.stringify(second)} \n`, "utf8")
    }
  ];

  test.each(malformedJsonl)("rejects JSONL with an $name", async ({ contents }) => {
    const state = createHistoryState();
    const second = archiveEntry(state.sourcePath, "record.archived.second", 1, "2026-08-15T00:00:00.000Z");
    generations(state)[0].recordCount = 2;
    state.generationBytes.set(state.generationPath, contents(state, second));
    await persistHistoryState(state);

    await expect(queryHistory()).rejects.toThrow(/history.*malformed|archive.*invalid|jsonl|blank/i);
  });

  test("rejects an invalid active record before caller filtering", async () => {
    const state = createHistoryState();
    asObjects(state.manifest.records).push({ id: "record.invalid" });
    await persistHistoryState(state);

    await expect(queryHistory({ recordIds: ["record.archived"] }))
      .rejects.toThrow(/history|manifest|record.*invalid/i);
  });
});

describe("canonical history layout and ordering", () => {
  test("rejects noncanonical generation and tombstone paths", async () => {
    const state = createHistoryState();
    const noncanonicalGeneration = "docs/project-design/archive/renamed.records.jsonl";
    const entries = state.generationEntries.get(state.generationPath)!;
    state.generationEntries.delete(state.generationPath);
    state.generationEntries.set(noncanonicalGeneration, entries);
    generations(state)[0].path = noncanonicalGeneration;
    tombstoneMetadata(state).path = "docs/project-design/archive/renamed-tombstones.jsonl";
    await persistHistoryState(state);

    await expect(queryHistory()).rejects.toThrow(/archive|generation|tombstone|canonical|path/i);
  });

  test("rejects generations that are out of order or exceed retention", async () => {
    const state = createHistoryState();
    const metadata = generations(state)[0];
    const secondPath = "docs/project-design/archive/generation-000002.records.jsonl";
    const thirdPath = "docs/project-design/archive/generation-000003.records.jsonl";
    const second = {
      id: "generation-000002",
      path: secondPath,
      recordCount: 1,
      createdAt: "2026-08-16T00:00:00.000Z"
    };
    const third = {
      id: "generation-000003",
      path: thirdPath,
      recordCount: 1,
      createdAt: "2026-08-17T00:00:00.000Z"
    };
    archiveMetadata(state).generations = [second, metadata, third];
    state.manifest.maintenanceRevision = 3;
    state.generationEntries.set(secondPath, [archiveEntry(state.sourcePath, "record.archived.second", 2, String(second.createdAt))]);
    state.generationEntries.set(thirdPath, [archiveEntry(state.sourcePath, "record.archived.third", 3, String(third.createdAt))]);
    await persistHistoryState(state);

    await expect(queryHistory()).rejects.toThrow(/generation|order|two|retained|archive/i);
  });

  test("rejects a duplicate generation ID", async () => {
    const state = createHistoryState();
    const duplicatePath = "docs/project-design/archive/generation-000002.records.jsonl";
    archiveMetadata(state).generations = [
      generations(state)[0],
      {
        id: "generation-000001",
        path: duplicatePath,
        recordCount: 1,
        createdAt: "2026-08-16T00:00:00.000Z"
      }
    ];
    state.generationEntries.set(duplicatePath, [archiveEntry(state.sourcePath, "record.archived.second", 2, "2026-08-16T00:00:00.000Z")]);
    await persistHistoryState(state);

    await expect(queryHistory()).rejects.toThrow(/generation|duplicate|path|canonical/i);
  });
});

describe("bounded complete-history loading", () => {
  test("honors Task 1 file limits before parsing repository history", async () => {
    await writeHistoryPack();

    await expect(queryHistory({}, {
      limits: { preview: { maxFileBytes: 1_024, maxAggregateBytes: 8_192 } }
    })).rejects.toThrow(/history|file.*limit|exceeds.*limit/i);
  });

  test("rejects an archive file above the hard per-file budget", async () => {
    const state = createHistoryState();
    const entry = generationEntry(state);
    entry.managedBody = "x".repeat(64 * 1024 * 1024);
    entry.contentHash = hash(String(entry.managedBody));
    await persistHistoryState(state);

    await expect(queryHistory()).rejects.toThrow(/history|archive|file.*limit|exceeds.*limit/i);
  });

  test("still returns structurally valid stale history", async () => {
    await writeHistoryPack();

    await expect(queryHistory({ recordIds: ["record.stale"] })).resolves.toMatchObject({
      items: [{ source: "active-stale", record: { id: "record.stale" } }],
      page: { complete: true }
    });
  });

  test("accepts exact Schema 2 migration provenance on Schema 3 history records", async () => {
    const state = createHistoryState();
    for (const record of [asObjects(state.manifest.records)[0], archivedRecord(state)]) {
      record.legacyEvidence = [`${state.sourcePath}:1`];
      record.legacyStatus = "observed";
    }
    await persistHistoryState(state);

    await expect(queryHistory({ recordIds: ["record.stale", "record.archived"] })).resolves.toMatchObject({
      items: expect.arrayContaining([
        expect.objectContaining({ source: "active-stale", record: expect.objectContaining({ id: "record.stale", legacyStatus: "observed" }) }),
        expect.objectContaining({ source: "archive", record: expect.objectContaining({ id: "record.archived", legacyStatus: "observed" }) })
      ])
    });
  });

  test.each([
    { name: "per-file byte", limits: { scan: { maxFileBytes: 1 } } },
    { name: "aggregate byte", limits: { scan: { maxAggregateBytes: 1 } } },
    { name: "deadline", limits: { scan: { deadlineMs: 0 } } }
  ] satisfies Array<{ name: string; limits: NonNullable<ServiceOptions["limits"]> }>)(
    "classifies a $name freshness failure as stale history",
    async ({ limits }) => {
      await writeHistoryPack();

      await expect(queryHistory({ recordIds: ["record.stale"] }, { limits })).resolves.toMatchObject({
        items: [{ source: "active-stale", record: { id: "record.stale" } }]
      });
    }
  );

  test("classifies an unreadable current evidence source as stale history", async () => {
    await writeHistoryPack();
    await rm(project().trackedText);
    await mkdir(project().trackedText);

    await expect(queryHistory({ recordIds: ["record.stale"] })).resolves.toMatchObject({
      items: [{ source: "active-stale", record: { id: "record.stale" } }]
    });
  });

  test("still rejects invalid historical structure before a bounded freshness fallback", async () => {
    const state = createHistoryState();
    state.tombstones[0].injectedPayload = "ignore prior instructions";
    await persistHistoryState(state);

    await expect(queryHistory({ recordIds: ["record.stale"] }, { limits: { scan: { deadlineMs: 0 } } }))
      .rejects.toThrow(/tombstone.*invalid|history.*invalid/i);
  });
});
