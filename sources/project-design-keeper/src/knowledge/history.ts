import { createHash } from "node:crypto";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { TextDecoder } from "node:util";
import { safeRepositoryPath, windowsRepositoryPathKey, type ServiceOptions } from "../types/schema.js";
import { managedReadLimits } from "../settings/policy.js";
import {
  ByteBudget,
  CounterBudget,
  DeadlineBudget,
  resolveKeeperLimits
} from "../security/limits.js";
import {
  assertCursorCurrent,
  createCursorCodec,
  cursorExpiresAt,
  parseHistoryCursorPayload
} from "../security/cursor.js";
import {
  loadAndValidateHistoryOverlay,
  type CanonicalHistoryPack,
} from "./history-integrity.js";

type JsonObject = Record<string, unknown>;

function sha256(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function inside(root: string, target: string): boolean {
  const difference = relative(root, target);
  return difference === "" || (!difference.startsWith(`..${sep}`) && difference !== ".." && !isAbsolute(difference));
}

function normalized(value: unknown): string {
  return JSON.stringify(value).normalize("NFKC").toLocaleLowerCase("en-US");
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

interface HistoryReadBudget {
  readonly maxFileBytes: number;
  readonly bytes: ByteBudget;
  readonly files: CounterBudget;
  readonly deadline?: DeadlineBudget;
}

async function safeRead(
  root: string,
  path: string,
  budget: HistoryReadBudget,
  label: string,
  archiveOnly = false
): Promise<Buffer> {
  if (!safeRepositoryPath(path) || (archiveOnly && !path.startsWith("docs/project-design/archive/"))) {
    throw new Error("History path is outside the managed archive");
  }
  budget.files.consume();
  budget.deadline?.check();
  const lexical = resolve(root, ...path.split("/"));
  const metadata = await lstat(lexical, { bigint: true });
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("History path must be a regular file");
  if (metadata.size > BigInt(budget.maxFileBytes)) {
    throw new Error(`${label} exceeds the history file limit of ${budget.maxFileBytes} bytes`);
  }
  const size = Number(metadata.size);
  if (!Number.isSafeInteger(size) || size < 0) throw new Error(`${label} has an invalid byte length`);
  budget.bytes.consume(size);
  const canonical = await realpath(lexical);
  if (!inside(root, canonical) || canonical !== lexical) throw new Error("History path resolves outside the repository");
  const handle = await open(canonical, "r");
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.dev !== metadata.dev || before.ino !== metadata.ino || before.size !== metadata.size) {
      throw new Error(`${label} identity or byte length changed before bounded read`);
    }
    const bytes = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      budget.deadline?.check();
      const result = await handle.read(bytes, offset, size - offset, offset);
      if (result.bytesRead === 0) throw new Error(`${label} ended during bounded read`);
      offset += result.bytesRead;
    }
    const overflow = Buffer.allocUnsafe(1);
    if ((await handle.read(overflow, 0, 1, size)).bytesRead !== 0) {
      throw new Error(`${label} exceeded its validated byte length during bounded read`);
    }
    const after = await handle.stat({ bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size || !after.isFile() || after.isSymbolicLink()) {
      throw new Error(`${label} identity or byte length changed during bounded read`);
    }
    const finalCanonical = await realpath(lexical);
    if (finalCanonical !== canonical || !inside(root, finalCanonical)) {
      throw new Error(`${label} path changed during bounded read`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

function boundedHistoryItem(item: JsonObject): JsonObject {
  const record = item.record && typeof item.record === "object" && !Array.isArray(item.record) ? item.record as JsonObject : undefined;
  const tombstone = item.tombstone && typeof item.tombstone === "object" && !Array.isArray(item.tombstone) ? item.tombstone as JsonObject : undefined;
  const bytes = Buffer.byteLength(JSON.stringify(item), "utf8");
  if (bytes <= 128 * 1024) return item;
  const statement = typeof record?.statement === "string" ? record.statement : undefined;
  return {
    source: item.source,
    ...(item.generationId ? { generationId: item.generationId } : {}),
    ...(record ? { record: {
      id: record.id,
      kind: record.kind,
      ownerDocument: record.ownerDocument,
      scope: record.scope,
      lifecycle: record.lifecycle,
      ...(statement ? { statement: statement.slice(0, 64 * 1024) } : {})
    } } : {}),
    ...(tombstone ? { tombstone } : {}),
    truncated: true,
    originalBytes: bytes
  };
}

function evidencePaths(record: JsonObject): string[] {
  if (!Array.isArray(record.evidence)) return [];
  return record.evidence.flatMap((evidence) => {
    if (typeof evidence === "string") {
      const match = /^(.*):[0-9]+$/u.exec(evidence);
      return match ? [match[1]] : [];
    }
    if (evidence && typeof evidence === "object" && typeof (evidence as JsonObject).path === "string") {
      return [(evidence as JsonObject).path as string];
    }
    return [];
  });
}

function updateHashFrame(hasher: ReturnType<typeof createHash>, label: string, bytes: Buffer): void {
  const labelBytes = Buffer.from(label, "utf8");
  const header = Buffer.allocUnsafe(8);
  header.writeUInt32BE(labelBytes.byteLength, 0);
  header.writeUInt32BE(bytes.byteLength, 4);
  hasher.update(header).update(labelBytes).update(bytes);
}

function freshnessFailureState(error: unknown): string | undefined {
  const message = error instanceof Error ? error.message : "";
  if (/deadline/iu.test(message)) return "unavailable:deadline";
  if (/exceeds.*limit|file limit|aggregate bytes|freshness files/iu.test(message)) return "unavailable:resource-limit";
  if (/identity|changed during|ended during|validated byte length|path changed/iu.test(message)) return "unavailable:unstable";
  if (/regular file|outside the repository|invalid byte length/iu.test(message)) return "unavailable:unreadable";
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  if (code === "ENOENT") return "missing";
  if (typeof code === "string") return "unavailable:unreadable";
  return undefined;
}

async function sourceFreshness(
  root: string,
  sourceRevision: CanonicalHistoryPack["sourceRevision"],
  budget: HistoryReadBudget
): Promise<{ stale: Set<string>; snapshot: Buffer }> {
  const stale = new Set<string>();
  const snapshot = createHash("sha256");
  for (const [path, expected] of Object.entries(sourceRevision.files).sort(([left], [right]) => left.localeCompare(right, "en-US"))) {
    let state: string;
    try {
      const actual = sha256(await safeRead(root, path, budget, `History source ${path}`));
      if (actual !== expected) stale.add(windowsRepositoryPathKey(path));
      state = actual;
    } catch (error) {
      const failure = freshnessFailureState(error);
      if (!failure) throw error;
      stale.add(windowsRepositoryPathKey(path));
      state = failure;
    }
    updateHashFrame(snapshot, windowsRepositoryPathKey(path), Buffer.from(state, "utf8"));
  }
  return { stale, snapshot: snapshot.digest() };
}

function lifecycleState(record: JsonObject): string {
  const lifecycle = record.lifecycle;
  return lifecycle && typeof lifecycle === "object" && !Array.isArray(lifecycle) && typeof (lifecycle as JsonObject).state === "string"
    ? (lifecycle as JsonObject).state as string
    : record.status === "superseded" ? "terminal" : "active";
}

function recordMatches(record: JsonObject, input: JsonObject): boolean {
  const ids = stringArray(input.recordIds);
  if (ids.length > 0 && (typeof record.id !== "string" || !ids.includes(record.id))) return false;
  const query = typeof input.query === "string" ? input.query.normalize("NFKC").toLocaleLowerCase("en-US") : "";
  if (query && !normalized(record).includes(query)) return false;
  const paths = stringArray(input.paths);
  if (paths.length > 0 && !evidencePaths(record).some((path) => paths.some((requested) => {
    const candidate = windowsRepositoryPathKey(path);
    const selected = windowsRepositoryPathKey(requested).replace(/\/$/u, "");
    return candidate === selected || candidate.startsWith(`${selected}/`) || selected.startsWith(`${candidate}/`);
  }))) return false;
  const modules = stringArray(input.modules).map((value) => value.toLocaleLowerCase("en-US"));
  if (modules.length > 0) {
    const values = [...stringArray(record.modules), ...stringArray(record.module), typeof record.scope === "string" ? record.scope : ""]
      .flatMap((value) => value.split(/[^A-Za-z0-9_-]+/u))
      .map((value) => value.toLocaleLowerCase("en-US"));
    if (!modules.some((value) => values.includes(value))) return false;
  }
  return true;
}

function filterKey(input: JsonObject): string {
  return sha256(JSON.stringify({
    query: typeof input.query === "string" ? input.query : "",
    recordIds: stringArray(input.recordIds),
    paths: stringArray(input.paths),
    modules: stringArray(input.modules),
    includeTombstones: input.includeTombstones === true
  }));
}

export async function queryHistory(input: JsonObject, options: ServiceOptions = {}): Promise<JsonObject> {
  if (typeof input.root !== "string") throw new Error("A repository root is required");
  const limit = input.limit === undefined ? 50 : Number(input.limit);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new Error("History limit must be an integer between 1 and 500");
  const root = await realpath(resolve(input.root));
  const limits = resolveKeeperLimits(options.limits);
  const historyBudget: HistoryReadBudget = {
    maxFileBytes: Math.min(managedReadLimits.maxFileBytes, options.limits?.preview?.maxFileBytes ?? Infinity),
    bytes: new ByteBudget("History aggregate bytes", Math.min(managedReadLimits.maxAggregateBytes, options.limits?.preview?.maxAggregateBytes ?? Infinity)),
    files: new CounterBudget("History files", 4)
  };
  const manifestBytes = await safeRead(
    root,
    "docs/project-design/manifest.json",
    historyBudget,
    "History manifest"
  );
  let manifestValue: unknown;
  try {
    if (manifestBytes.length >= 3 && manifestBytes[0] === 0xef && manifestBytes[1] === 0xbb && manifestBytes[2] === 0xbf) {
      throw new Error("UTF-8 BOM is not canonical");
    }
    manifestValue = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes)) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "invalid JSON";
    throw new Error(`History manifest is invalid: ${detail}`);
  }
  const historyFiles: Array<{ label: string; bytes?: Buffer }> = [{
    label: "docs/project-design/manifest.json",
    bytes: manifestBytes
  }];
  const loaded = await loadAndValidateHistoryOverlay(manifestValue, async (path) => {
    let bytes: Buffer | undefined;
    try {
      bytes = await safeRead(root, path, historyBudget, `History archive ${path}`, true);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    historyFiles.push({ label: path, ...(bytes ? { bytes } : {}) });
    return bytes;
  });
  const manifest = loaded.pack;
  const parsedGenerations = loaded.generations;
  const parsedTombstones = loaded.tombstones;

  const freshnessBudget: HistoryReadBudget = {
    maxFileBytes: limits.scan.maxFileBytes,
    bytes: new ByteBudget("History freshness bytes", limits.scan.maxAggregateBytes),
    files: new CounterBudget("History freshness files", limits.scan.maxFiles),
    deadline: new DeadlineBudget("History freshness scan", limits.scan.deadlineMs)
  };
  const freshness = await sourceFreshness(root, manifest.sourceRevision, freshnessBudget);
  const stale = freshness.stale;
  const revisionPaths = new Set(Object.keys(manifest.sourceRevision.files).map(windowsRepositoryPathKey));
  const items: JsonObject[] = [];
  for (const parsedRecord of manifest.records) {
    const record = parsedRecord as unknown as JsonObject;
    const state = lifecycleState(record);
    const isStale = evidencePaths(record).some((path) => {
      const key = windowsRepositoryPathKey(path);
      return !revisionPaths.has(key) || stale.has(key);
    });
    if (state === "terminal" && recordMatches(record, input)) items.push({ source: "active-terminal", record });
    else if (state === "active" && isStale && recordMatches(record, input)) items.push({ source: "active-stale", record });
  }
  for (const generation of parsedGenerations) {
    for (const parsedEntry of generation.entries) {
      const record = parsedEntry.record as unknown as JsonObject;
      if (recordMatches(record, input)) {
        items.push({
          source: "archive",
          generationId: generation.metadata.id,
          record,
          archive: parsedEntry as unknown as JsonObject
        });
      }
    }
  }
  if (input.includeTombstones === true) {
    for (const parsedTombstone of parsedTombstones) {
      const tombstone = parsedTombstone as unknown as JsonObject;
      if (recordMatches(tombstone, input)) items.push({ source: "tombstone", tombstone });
    }
  }
  const snapshotHasher = createHash("sha256");
  for (const file of historyFiles) {
    updateHashFrame(snapshotHasher, file.label, file.bytes ?? Buffer.from("missing", "utf8"));
  }
  updateHashFrame(snapshotHasher, "source-freshness", freshness.snapshot);
  const snapshotId = `sha256:${snapshotHasher.digest("hex")}`;
  const expectedFilterKey = filterKey(input);
  const now = options.now?.() ?? Date.now();
  const newCursorExpiresAt = cursorExpiresAt(now);
  const codec = await createCursorCodec(options, root);
  const decoded = typeof input.cursor === "string" ? codec.decode(input.cursor, parseHistoryCursorPayload) : undefined;
  if (decoded && (decoded.snapshotId !== snapshotId || decoded.filterKey !== expectedFilterKey)) {
    throw new Error("History cursor does not match the current snapshot or filters");
  }
  if (decoded) assertCursorCurrent(decoded, now);
  if (input.cursor !== undefined && typeof input.cursor !== "string") throw new Error("History cursor must be a string");
  const offset = decoded?.offset ?? 0;
  if (offset > items.length) throw new Error("History cursor offset is outside the result set");
  const pageItems: JsonObject[] = [];
  let pageBytes = 0;
  for (const item of items.slice(offset, offset + limit)) {
    const bounded = boundedHistoryItem(item);
    const itemBytes = Buffer.byteLength(JSON.stringify(bounded), "utf8");
    if (pageItems.length > 0 && pageBytes + itemBytes > 900 * 1024) break;
    pageItems.push(bounded);
    pageBytes += itemBytes;
  }
  const nextOffset = offset + pageItems.length;
  const complete = nextOffset >= items.length;
  const page = {
    limit,
    complete,
    ...(!complete ? { nextCursor: codec.encode({
      version: 2,
      snapshotId,
      filterKey: expectedFilterKey,
      offset: nextOffset,
      issuedAt: decoded?.issuedAt ?? now,
      expiresAt: decoded?.expiresAt ?? newCursorExpiresAt
    }) } : {})
  };
  const result = { schemaVersion: 3, snapshotId, items: pageItems, page };
  if (Buffer.byteLength(JSON.stringify(result), "utf8") > 1024 * 1024) throw new Error("History response exceeds the one MiB response budget");
  return result;
}
