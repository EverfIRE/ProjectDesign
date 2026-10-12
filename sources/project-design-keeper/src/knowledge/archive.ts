import { isCompleteArchiveEntry } from "../types/schema.js";
import { CanonicalJsonLinesError, decodeCanonicalJsonLines } from "./jsonl.js";

type JsonObject = Record<string, unknown>;

export interface ArchiveTransitionIssue {
  code: string;
  path: string;
  message: string;
}

interface ArchiveEntry {
  record?: JsonObject;
  contentHash?: unknown;
  archivedAt?: unknown;
  terminalReason?: unknown;
}

const archiveTimestampWindowMs = 5 * 60 * 1000;

function objects(value: unknown): JsonObject[] {
  return Array.isArray(value)
    ? value.filter((item): item is JsonObject => Boolean(item) && typeof item === "object" && !Array.isArray(item))
    : [];
}

function archive(pack: JsonObject): JsonObject {
  return pack.archive && typeof pack.archive === "object" && !Array.isArray(pack.archive) ? pack.archive as JsonObject : {};
}

function generations(pack: JsonObject): JsonObject[] {
  return objects(archive(pack).generations);
}

function tombstonePath(pack: JsonObject): string | undefined {
  const tombstones = archive(pack).tombstones;
  return tombstones && typeof tombstones === "object" && !Array.isArray(tombstones) && typeof (tombstones as JsonObject).path === "string"
    ? (tombstones as JsonObject).path as string
    : undefined;
}

function tombstoneCount(pack: JsonObject): unknown {
  const tombstones = archive(pack).tombstones;
  return tombstones && typeof tombstones === "object" && !Array.isArray(tombstones)
    ? (tombstones as JsonObject).count
    : undefined;
}

async function jsonLines(
  path: string | undefined,
  expectedCount: unknown,
  read: (path: string) => Promise<Buffer | undefined>
): Promise<JsonObject[]> {
  if (!path) {
    if (expectedCount === undefined || expectedCount === 0) return [];
    throw new Error("Archive JSONL path is missing");
  }
  const bytes = await read(path);
  if (!bytes) {
    if (expectedCount === 0) return [];
    throw new Error(`Archive JSONL source is missing: ${path}`);
  }
  return decodeCanonicalJsonLines(bytes, `Archive history ${path}`, { expectedCount }).map(({ value, line }) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`Archive history ${path}:${line} is not an object`);
    }
    return value as JsonObject;
  });
}

async function strictArchiveEntries(
  path: string | undefined,
  expectedCount: number,
  read: (path: string) => Promise<Buffer | undefined>
): Promise<{ entries: ArchiveEntry[]; issues: ArchiveTransitionIssue[] }> {
  if (!path) {
    return { entries: [], issues: [{ code: "archive_generation_source_missing", path: "archive.generations", message: "Dropped archive generation has no readable source path" }] };
  }
  const bytes = await read(path);
  if (!bytes) {
    return { entries: [], issues: [{ code: "archive_generation_source_missing", path, message: "Dropped archive generation source is missing" }] };
  }
  const issues: ArchiveTransitionIssue[] = [];
  let lines: ReturnType<typeof decodeCanonicalJsonLines>;
  try {
    lines = decodeCanonicalJsonLines(bytes, `Dropped archive generation ${path}`, { expectedCount });
  } catch (error) {
    return {
      entries: [],
      issues: [{
        code: error instanceof CanonicalJsonLinesError && error.kind === "count"
          ? "archive_generation_record_count_mismatch"
          : "archive_generation_source_invalid",
        path,
        message: error instanceof Error ? error.message : "Dropped archive generation JSONL is invalid"
      }]
    };
  }
  const entries: ArchiveEntry[] = [];
  for (const { value, line } of lines) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      issues.push({ code: "archive_generation_source_invalid", path: `${path}:${line}`, message: "Dropped archive generation contains non-object JSONL history" });
      continue;
    }
    if (!isCompleteArchiveEntry(value)) {
      issues.push({ code: "archive_generation_entry_invalid", path: `${path}:${line}`, message: "Dropped archive generation must contain complete and internally consistent Schema 3.0 archive entries" });
      continue;
    }
    entries.push(value as ArchiveEntry);
  }
  return { entries, issues };
}

function terminalEligible(record: JsonObject | undefined): boolean {
  const lifecycle = record?.lifecycle;
  return Boolean(lifecycle && typeof lifecycle === "object" && !Array.isArray(lifecycle) &&
    (lifecycle as JsonObject).state === "terminal" && Number((lifecycle as JsonObject).confirmedRefreshes) >= 2);
}

function tombstoneFor(entry: ArchiveEntry): JsonObject | undefined {
  const record = entry.record;
  const lifecycle = record?.lifecycle;
  if (!record || typeof record.id !== "string" || !lifecycle || typeof lifecycle !== "object" || Array.isArray(lifecycle) ||
    typeof entry.contentHash !== "string" || typeof entry.archivedAt !== "string") return undefined;
  return {
    id: record.id,
    reason: (lifecycle as JsonObject).reason ?? entry.terminalReason,
    successorIds: Array.isArray((lifecycle as JsonObject).successorIds) ? (lifecycle as JsonObject).successorIds : [],
    contentHash: entry.contentHash,
    archivedAt: entry.archivedAt
  };
}

function equalJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function managedBody(contents: Buffer | undefined, recordId: string): string | undefined {
  if (!contents) return undefined;
  const escaped = recordId.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const text = contents.toString("utf8");
  const match = new RegExp(`<!-- project-design-keeper:managed record-id="${escaped}" content-hash="sha256:[a-f0-9]{64}" -->`, "u").exec(text);
  if (!match) return undefined;
  const start = match.index + match[0].length;
  const end = text.indexOf("<!-- /project-design-keeper:managed -->", start);
  return end < 0 ? undefined : text.slice(start, end);
}

/**
 * Enforces historical continuity across one Schema 3.0 changeset. Validation of
 * the individual files remains the canonical pack validator's responsibility.
 */
export async function validateArchiveTransition(input: {
  currentPack: JsonObject;
  candidatePack: JsonObject;
  readCurrent(path: string): Promise<Buffer | undefined>;
  readCandidate(path: string): Promise<Buffer | undefined>;
  now?: () => number;
}): Promise<ArchiveTransitionIssue[]> {
  const { currentPack, candidatePack } = input;
  if (currentPack.schemaVersion !== "3.0" || candidatePack.schemaVersion !== "3.0") return [];
  const issues: ArchiveTransitionIssue[] = [];
  if (Number(candidatePack.maintenanceRevision) !== Number(currentPack.maintenanceRevision) + 1) {
    issues.push({ code: "maintenance_revision_transition_invalid", path: "maintenanceRevision", message: "Schema 3.0 updates must increment maintenanceRevision by exactly one" });
  }

  const currentGenerations = generations(currentPack);
  const candidateGenerations = generations(candidatePack);
  const currentById = new Map(currentGenerations.map((generation) => [String(generation.id), generation]));
  const candidateById = new Map(candidateGenerations.map((generation) => [String(generation.id), generation]));
  const dropped = currentGenerations.filter((generation) => !candidateById.has(String(generation.id)));
  const added = candidateGenerations.filter((generation) => !currentById.has(String(generation.id)));
  const numericIds = candidateGenerations.map((generation) => Number(String(generation.id).slice("generation-".length)));
  if (numericIds.some((id, index) => index > 0 && id <= numericIds[index - 1])) {
    issues.push({ code: "archive_generation_order_invalid", path: "archive.generations", message: "Archive generations must be unique and ordered from oldest to newest" });
  }
  if (added.length > 1) {
    issues.push({ code: "archive_generation_sequence_invalid", path: "archive.generations", message: "One maintenance revision may create at most one archive generation" });
  } else if (added.length === 1) {
    const latestCurrent = currentGenerations.at(-1);
    const expectedNumber = latestCurrent
      ? Number(String(latestCurrent.id).slice("generation-".length)) + 1
      : 1;
    const addedNumber = Number(String(added[0].id).slice("generation-".length));
    if (addedNumber !== expectedNumber || String(candidateGenerations.at(-1)?.id) !== String(added[0].id)) {
      issues.push({ code: "archive_generation_sequence_invalid", path: "archive.generations", message: "A new archive generation must be the consecutive newest generation" });
    }
    const createdAt = Date.parse(String(added[0].createdAt));
    const transactionTime = (input.now ?? Date.now)();
    const latestCreatedAt = latestCurrent ? Date.parse(String(latestCurrent.createdAt)) : Number.NEGATIVE_INFINITY;
    if (Number.isNaN(createdAt) || createdAt > transactionTime || createdAt < transactionTime - archiveTimestampWindowMs ||
      (latestCurrent !== undefined && createdAt <= latestCreatedAt)) {
      issues.push({ code: "archive_generation_timestamp_invalid", path: "archive.generations", message: "A new archive generation timestamp must be recent, non-future, and strictly later than retained history" });
    }
  }
  for (const [id, generation] of currentById) {
    const retained = candidateById.get(id);
    if (retained && !equalJson(retained, generation)) {
      issues.push({ code: "archive_generation_metadata_changed", path: "archive.generations", message: `Existing archive generation metadata is immutable: ${id}` });
    }
    if (retained && typeof generation.path === "string" && typeof retained.path === "string") {
      const [currentBytes, candidateBytes] = await Promise.all([
        input.readCurrent(generation.path),
        input.readCandidate(retained.path)
      ]);
      if (!currentBytes || !candidateBytes || !currentBytes.equals(candidateBytes)) {
        issues.push({ code: "archive_generation_content_changed", path: generation.path, message: `Existing archive generation content is immutable: ${id}` });
      }
    }
  }

  const readTombstones = async (
    pack: JsonObject,
    read: (path: string) => Promise<Buffer | undefined>,
    label: string
  ): Promise<JsonObject[]> => {
    try {
      return await jsonLines(tombstonePath(pack), tombstoneCount(pack), read);
    } catch (error) {
      issues.push({
        code: "tombstone_history_invalid",
        path: "archive.tombstones",
        message: `${label}: ${error instanceof Error ? error.message : "invalid tombstone JSONL"}`
      });
      return [];
    }
  };
  const currentTombstones = await readTombstones(currentPack, input.readCurrent, "Current tombstones are invalid");
  const candidateTombstones = await readTombstones(candidatePack, input.readCandidate, "Candidate tombstones are invalid");
  const candidateTombstonesById = new Map(candidateTombstones.map((item) => [String(item.id), item]));
  for (const prior of currentTombstones) {
    const retained = candidateTombstonesById.get(String(prior.id));
    if (!retained || !equalJson(prior, retained)) {
      issues.push({ code: "tombstone_history_removed", path: "archive.tombstones", message: `Existing tombstone is immutable and cannot be removed: ${String(prior.id)}` });
    }
  }

  if (dropped.length > 0) {
    const validRotation = currentGenerations.length === 2 && candidateGenerations.length === 2 && dropped.length === 1 && added.length === 1 &&
      String(dropped[0].id) === String(currentGenerations[0].id) &&
      String(candidateGenerations[0].id) === String(currentGenerations[1].id) &&
      String(candidateGenerations[1].id) === String(added[0].id);
    if (!validRotation) {
      issues.push({ code: "archive_rotation_invalid", path: "archive.generations", message: "A full generation may be dropped only when a third generation rotates the oldest of two retained generations into tombstones" });
    }
  }
  const expectedNewTombstones = new Map<string, JsonObject>();
  for (const generation of dropped) {
    const source = await strictArchiveEntries(
      typeof generation.path === "string" ? generation.path : undefined,
      Number(generation.recordCount),
      input.readCurrent
    );
    issues.push(...source.issues);
    const entries = source.entries;
    for (const entry of entries) {
      const expected = tombstoneFor(entry);
      if (expected) expectedNewTombstones.set(String(expected.id), expected);
      const actual = expected ? candidateTombstonesById.get(String(expected.id)) : undefined;
      if (!expected || !actual || !equalJson(expected, actual)) {
        issues.push({ code: "archive_generation_not_tombstoned", path: String(generation.path), message: `Dropped archive record must be preserved as an exact tombstone: ${String(entry.record?.id ?? "unknown")}` });
      }
    }
  }
  const currentTombstonesById = new Map(currentTombstones.map((item) => [String(item.id), item]));
  for (const actual of candidateTombstones) {
    const id = String(actual.id);
    const expected = currentTombstonesById.get(id) ?? expectedNewTombstones.get(id);
    if (!expected || !equalJson(expected, actual)) {
      issues.push({ code: "tombstone_unexpected", path: "archive.tombstones", message: `Tombstone must be immutable prior history or derive exactly from the generation rotated now: ${id}` });
    }
  }

  const currentRecords = new Map(objects(currentPack.records).map((record) => [String(record.id), record]));
  const candidateRecords = new Map(objects(candidatePack.records).map((record) => [String(record.id), record]));
  const candidateRecordIds = new Set(candidateRecords.keys());
  for (const [id, currentRecord] of currentRecords) {
    const candidateRecord = candidateRecords.get(id);
    if (!candidateRecord) continue;
    const before = currentRecord.lifecycle as JsonObject | undefined;
    const after = candidateRecord.lifecycle as JsonObject | undefined;
    if (before?.state === "active" && after?.state === "terminal" && Number(after.confirmedRefreshes) !== 1) {
      issues.push({ code: "terminal_refresh_transition_invalid", path: `records.${id}.lifecycle`, message: `A newly terminal record must begin with one confirmed refresh: ${id}` });
    }
    if (before?.state === "terminal") {
      if (after?.state !== "terminal") {
        issues.push({ code: "terminal_record_reactivated", path: `records.${id}.lifecycle`, message: `A terminal record cannot return to active state: ${id}` });
        continue;
      }
      const beforeCount = Number(before.confirmedRefreshes);
      const afterCount = Number(after.confirmedRefreshes);
      if (afterCount < beforeCount || afterCount > beforeCount + 1) {
        issues.push({ code: "terminal_refresh_transition_invalid", path: `records.${id}.lifecycle.confirmedRefreshes`, message: `A terminal refresh count may increase by at most one per confirmed refresh: ${id}` });
      }
      for (const field of ["reason", "sinceRevision", "successorIds"] as const) {
        if (!equalJson(before[field], after[field])) {
          issues.push({ code: "terminal_history_changed", path: `records.${id}.lifecycle.${field}`, message: `Terminal history is immutable after confirmation: ${id}` });
        }
      }
    }
  }
  const newArchiveIds = new Set<string>();
  for (const generation of candidateGenerations.filter((item) => !currentById.has(String(item.id)))) {
    let entries: ArchiveEntry[] = [];
    try {
      entries = await jsonLines(
        typeof generation.path === "string" ? generation.path : undefined,
        generation.recordCount,
        input.readCandidate
      ) as ArchiveEntry[];
    } catch (error) {
      issues.push({
        code: "archive_generation_source_invalid",
        path: String(generation.path ?? "archive.generations"),
        message: error instanceof Error ? error.message : "Candidate archive generation JSONL is invalid"
      });
    }
    for (const entry of entries) {
      const id = typeof entry.record?.id === "string" ? entry.record.id : undefined;
      if (!id) continue;
      newArchiveIds.add(id);
      const currentRecord = currentRecords.get(id);
      if (!terminalEligible(currentRecord)) {
        issues.push({ code: "archive_record_transition_ineligible", path: String(generation.path), message: `Only an already-terminal record with two confirmed refreshes may be archived: ${id}` });
      }
      if (currentRecord && !equalJson(entry.record, currentRecord)) {
        issues.push({ code: "archive_record_content_changed", path: String(generation.path), message: `Archived record must exactly preserve the terminal active-pack record: ${id}` });
      }
      const owner = typeof currentRecord?.ownerDocument === "string" ? currentRecord.ownerDocument : undefined;
      const document = owner ? objects(currentPack.documents).find((item) => item.id === owner) : undefined;
      const currentBody = document && typeof document.path === "string"
        ? managedBody(await input.readCurrent(document.path), id)
        : undefined;
      if (typeof (entry as JsonObject).managedBody === "string" && currentBody !== (entry as JsonObject).managedBody) {
        issues.push({ code: "archive_record_managed_body_changed", path: String(generation.path), message: `Archived managed body must match the current owning block: ${id}` });
      }
      if (Number((entry as JsonObject).maintenanceRevision) !== Number(candidatePack.maintenanceRevision)) {
        issues.push({ code: "archive_record_revision_invalid", path: String(generation.path), message: `Archived record revision must equal the candidate maintenance revision: ${id}` });
      }
      if ((entry as JsonObject).archivedAt !== generation.createdAt) {
        issues.push({ code: "archive_record_timestamp_invalid", path: String(generation.path), message: `Archived record timestamp must equal its generation timestamp: ${id}` });
      }
    }
  }
  for (const id of currentRecords.keys()) {
    if (!candidateRecordIds.has(id) && !newArchiveIds.has(id)) {
      issues.push({ code: "active_record_history_removed", path: "records", message: `Removed active-pack record is not preserved in a new archive generation: ${id}` });
    }
  }
  return issues;
}
