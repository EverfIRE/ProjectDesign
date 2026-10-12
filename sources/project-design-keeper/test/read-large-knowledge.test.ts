import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { afterEach, beforeEach, expect, test } from "vitest";
import { queryHistory } from "../src/knowledge/history.js";
import { analyzeRedundancy, validateRedundancyDecisions } from "../src/knowledge/redundancy.js";
import { queryContext } from "../src/scope/index.js";
import { validateArchiveTransition } from "../src/knowledge/archive.js";
import { writeV3PackFixture } from "./canonical-pack-fixture.js";
import { createProjectFixture, removeProjectFixture, type ProjectFixture } from "./fixtures.js";

let fixture: ProjectFixture;
beforeEach(async () => { fixture = await createProjectFixture(); });
afterEach(async () => { await removeProjectFixture(fixture); });
const hash = (value: string) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
async function writeManifest(pack: Record<string, unknown>) {
  await writeFile(join(fixture.repository, "docs/project-design/manifest.json"), JSON.stringify(pack), "utf8");
}

test("queries an archived body above two MiB with normal read settings and keeps the page bounded", async () => {
  const pack = await writeV3PackFixture(fixture);
  const archived: Record<string, unknown> = {
    ...(pack.records as Record<string, unknown>[])[0], id: "record.old-large",
    lifecycle: { state: "terminal", reason: "resolved", sinceRevision: 1, confirmedRefreshes: 2, successorIds: [] }
  };
  const managedBody = "历史内容".repeat(300_000);
  const archivePath = "docs/project-design/archive/generation-000001.records.jsonl";
  pack.archive = {
    generations: [{ id: "generation-000001", path: archivePath, recordCount: 1, createdAt: "2026-10-11T00:00:00.000Z" }],
    tombstones: { path: "docs/project-design/archive/tombstones.jsonl", count: 0 }
  };
  await mkdir(join(fixture.repository, "docs/project-design/archive"), { recursive: true });
  await writeFile(join(fixture.repository, archivePath), `${JSON.stringify({
    record: archived, originalOwnerDocument: archived.ownerDocument,
    managedBody, contentHash: hash(managedBody), evidenceHash: hash(JSON.stringify(archived.evidence)),
    terminalReason: "resolved", maintenanceRevision: 1, archivedAt: "2026-10-11T00:00:00.000Z"
  })}\n`, "utf8");
  await writeManifest(pack);
  const options = { cacheDirectory: join(fixture.root, "cache") };
  const result = await queryHistory({ root: fixture.repository, recordIds: ["record.old-large"] }, options);
  expect(result).toMatchObject({ items: [{ source: "archive", record: { id: "record.old-large" }, truncated: true }], page: { complete: true } });
  expect(Buffer.byteLength(JSON.stringify(result), "utf8")).toBeLessThan(1024 * 1024);
  await expect(queryHistory({ root: fixture.repository }, { ...options, limits: { preview: { maxFileBytes: 1024 * 1024 } } }))
    .rejects.toThrow(/history file limit/);
});

test("routes a nine MiB managed document while keeping source files and explicit overrides bounded", async () => {
  const pack = await writeV3PackFixture(fixture);
  await writeManifest(pack);
  const documentPath = "docs/project-design/intent.md";
  const filePath = join(fixture.repository, documentPath);
  const original = await readFile(filePath, "utf8");
  await writeFile(filePath, `${original}\n${"x".repeat(9 * 1024 * 1024)}`, "utf8");
  const options = { cacheDirectory: join(fixture.root, "context-cache") };
  const result = await queryContext({ root: fixture.repository, query: "intent" }, options);
  expect(result.documents).toEqual(expect.arrayContaining([expect.objectContaining({ path: documentPath })]));
  expect(Buffer.byteLength(JSON.stringify(result), "utf8")).toBeLessThan(1024 * 1024);
  await expect(queryContext({ root: fixture.repository, query: "intent" }, { ...options, limits: { scan: { maxFileBytes: 1024 * 1024 } } }))
    .rejects.toThrow(/metadata file bytes.*per-file limit/);
  await writeFile(fixture.trackedText, "x".repeat(9 * 1024 * 1024), "utf8");
  const after = await queryContext({ root: fixture.repository, query: "intent" }, options);
  expect(after.records).toEqual([]);
  expect(after.context).toEqual([]);
  expect(after.documents).toEqual([]);
});

test("analyzes and reloads a valid manifest above eight MiB without raising source scan limits", async () => {
  const pack = await writeV3PackFixture(fixture);
  const records = pack.records as Record<string, unknown>[];
  records[0].statement = "大".repeat(3_000_000);
  records[0].lifecycle = { state: "terminal", reason: "resolved", sinceRevision: 1, confirmedRefreshes: 2, successorIds: [] };
  await writeManifest(pack);
  const result = await analyzeRedundancy({ root: fixture.repository });
  expect(result).toMatchObject({ schemaVersion: 3, analysisId: expect.any(String) });
  expect((result.candidates as Array<{ recordIds: string[] }>).every((candidate) => !candidate.recordIds.includes(String(records[0].id)))).toBe(true);
  await expect(validateRedundancyDecisions({ root: fixture.repository, analysisId: String(result.analysisId), decisions: [], candidatePack: pack }))
    .resolves.toBeUndefined();
  await expect(analyzeRedundancy({ root: fixture.repository }, { limits: { scan: { maxFileBytes: 1024 * 1024 } } }))
    .rejects.toThrow(/manifest.*file byte limit/i);

  // A knowledge-file allowance must never be applied to source evidence reads.
  const oversizedSource = "x".repeat(9 * 1024 * 1024);
  await writeFile(fixture.trackedText, oversizedSource, "utf8");
  const sourcePath = relative(fixture.repository, fixture.trackedText).replaceAll("\\", "/");
  pack.sourceRevision = { kind: "git", files: { [sourcePath]: hash(oversizedSource) } };
  await writeManifest(pack);
  await expect(analyzeRedundancy({ root: fixture.repository }))
    .rejects.toThrow(/source.*file byte limit/i);
});

test("routes a managed block with 63 MiB of Unicode body without overflowing the regex stack", async () => {
  const pack = await writeV3PackFixture(fixture);
  await writeManifest(pack);
  const body = "汉".repeat(21 * 1024 * 1024);
  const documentPath = "docs/project-design/intent.md";
  await writeFile(join(fixture.repository, documentPath),
    `<!-- project-design-keeper:managed record-id="record.intent" content-hash="${hash(body)}" -->${body}<!-- /project-design-keeper:managed -->`, "utf8");
  const result = await queryContext({ root: fixture.repository, query: "atomic" }, { cacheDirectory: join(fixture.root, "large-unicode-cache") });
  expect(result.documents).toEqual(expect.arrayContaining([expect.objectContaining({ path: documentPath })]));
  expect(Buffer.byteLength(JSON.stringify(result), "utf8")).toBeLessThan(1024 * 1024);
});

test("archives a terminal block with 63 MiB of Unicode body without overflowing the regex stack", async () => {
  const pack = await writeV3PackFixture(fixture);
  const record: Record<string, unknown> = {
    ...(pack.records as Record<string, unknown>[])[0],
    lifecycle: { state: "terminal", reason: "resolved", sinceRevision: 1, confirmedRefreshes: 2, successorIds: [] }
  };
  const body = "汉".repeat(21 * 1024 * 1024);
  const documentPath = "docs/project-design/intent.md";
  const generationPath = "docs/project-design/archive/generation-000001.records.jsonl";
  const timestamp = "2026-10-11T00:00:00.000Z";
  const document = Buffer.from(`<!-- project-design-keeper:managed record-id="record.intent" content-hash="${hash(body)}" -->${body}<!-- /project-design-keeper:managed -->`, "utf8");
  const generation = Buffer.from(`${JSON.stringify({
    record, originalOwnerDocument: record.ownerDocument, managedBody: body,
    contentHash: hash(body), evidenceHash: hash(JSON.stringify(record.evidence)),
    terminalReason: "resolved", maintenanceRevision: 2, archivedAt: timestamp
  })}\n`, "utf8");
  const currentPack = { ...pack, records: [record] };
  const candidatePack = { ...pack, records: [], maintenanceRevision: 2, archive: {
    generations: [{ id: "generation-000001", path: generationPath, recordCount: 1, createdAt: timestamp }],
    tombstones: { path: "docs/project-design/archive/tombstones.jsonl", count: 0 }
  } };
  await expect(validateArchiveTransition({
    currentPack, candidatePack,
    readCurrent: async (path) => path === documentPath ? document : undefined,
    readCandidate: async (path) => path === generationPath ? generation : undefined,
    now: () => Date.parse(timestamp)
  })).resolves.toEqual([]);
});
