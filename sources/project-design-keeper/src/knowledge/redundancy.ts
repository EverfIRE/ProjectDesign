import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { BigIntStats } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { performance } from "node:perf_hooks";
import { TextDecoder } from "node:util";
import { safeRepositoryPath, type ServiceOptions } from "../types/schema.js";
import { managedReadLimits } from "../settings/policy.js";
import {
  ByteBudget,
  CounterBudget,
  DeadlineBudget,
  resolveKeeperLimits,
  type KeeperLimits
} from "../security/limits.js";
import { assessRecord, type EvidenceRef } from "./model.js";

type JsonObject = Record<string, unknown>;
const analysisSigningKey = randomBytes(32);

interface AnalysisCandidateToken {
  candidateId: string;
  recordIds: [string, string];
  recordDigests: [string, string];
  recommendedSurvivorId: string;
}

interface AnalysisPayload {
  version: 1;
  root: string;
  snapshotId: string;
  createdAt: number;
  expiresAt: number;
  candidates: AnalysisCandidateToken[];
}

export interface RedundancyDecision {
  candidateId: string;
  decision: "merge" | "keep-separate" | "defer";
  survivorId?: string;
}

function hash(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function inside(root: string, target: string): boolean {
  const difference = relative(root, target);
  return difference === "" || (!difference.startsWith(`..${sep}`) && difference !== ".." && !isAbsolute(difference));
}

interface RedundancyReadBudget {
  readonly bytes: ByteBudget;
  readonly files: CounterBudget;
  readonly deadline: DeadlineBudget;
  readonly deadlineAt: number;
  readonly maxFiles: number;
  readonly maxFileBytes: number;
  readonly beforeRepositoryContentRead?: (path: string) => Promise<void>;
}

class RedundancyReadLimitError extends Error {}

function readBudget(limits: KeeperLimits, io: ServiceOptions["redundancyIo"] = {}): RedundancyReadBudget {
  const startedAt = performance.now();
  return {
    bytes: new ByteBudget("Redundancy aggregate bytes", limits.scan.maxAggregateBytes),
    files: new CounterBudget("Redundancy source files", limits.scan.maxFiles),
    deadline: new DeadlineBudget("Redundancy source read", limits.scan.deadlineMs),
    deadlineAt: startedAt + limits.scan.deadlineMs,
    maxFiles: limits.scan.maxFiles,
    maxFileBytes: limits.scan.maxFileBytes,
    ...(io?.beforeRepositoryContentRead ? { beforeRepositoryContentRead: io.beforeRepositoryContentRead } : {})
  };
}

function consumeReadBudget(budget: RedundancyReadBudget, size?: number): void {
  try {
    budget.deadline.check();
    if (size === undefined) budget.files.consume();
    else budget.bytes.consume(size);
  } catch (error) {
    throw new RedundancyReadLimitError(error instanceof Error ? error.message : "Redundancy read limit exceeded");
  }
}

function checkReadDeadline(budget: RedundancyReadBudget): void {
  try {
    budget.deadline.check();
  } catch (error) {
    throw new RedundancyReadLimitError(error instanceof Error ? error.message : "Redundancy read deadline exceeded");
  }
}

function remainingReadDeadlineMs(budget: RedundancyReadBudget): number {
  checkReadDeadline(budget);
  const remaining = Math.ceil(budget.deadlineAt - performance.now());
  if (remaining <= 0) checkReadDeadline(budget);
  return Math.max(1, remaining);
}

async function runBeforeRepositoryContentReadHook(
  budget: RedundancyReadBudget,
  path: string
): Promise<void> {
  const hook = budget.beforeRepositoryContentRead;
  if (!hook) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      hook(path),
      new Promise<never>((_accept, reject) => {
        timer = setTimeout(
          () => reject(new RedundancyReadLimitError("Redundancy repository content hook deadline exceeded")),
          remainingReadDeadlineMs(budget)
        );
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
  checkReadDeadline(budget);
}

function sameFileIdentity(
  left: BigIntStats,
  right: BigIntStats
): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.gid === right.gid &&
    left.mode === right.mode && left.nlink === right.nlink && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs &&
    left.isFile() && right.isFile() && !left.isSymbolicLink() && !right.isSymbolicLink();
}

async function readBoundedRepositoryFile(
  root: string,
  repositoryPath: string,
  budget: RedundancyReadBudget,
  label: string,
  collectBytes: boolean
): Promise<{ bytes?: Buffer; digest: string }> {
  consumeReadBudget(budget);
  const lexical = resolve(root, ...repositoryPath.split("/"));
  const metadata = await lstat(lexical, { bigint: true });
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`${label} must be a regular file`);
  if (metadata.size > BigInt(budget.maxFileBytes)) {
    throw new RedundancyReadLimitError(`${label} exceeds the file byte limit of ${budget.maxFileBytes} bytes`);
  }
  const size = Number(metadata.size);
  if (!Number.isSafeInteger(size) || size < 0) throw new Error(`${label} has an invalid byte length`);
  consumeReadBudget(budget, size);
  const canonical = await realpath(lexical);
  if (!inside(root, canonical) || canonical !== lexical) throw new Error(`${label} resolves outside the repository`);
  checkReadDeadline(budget);
  await runBeforeRepositoryContentReadHook(budget, lexical);
  const handle = await open(canonical, "r");
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameFileIdentity(metadata, opened) || opened.size !== metadata.size) {
      throw new Error(`${label} identity or byte length changed before bounded read`);
    }
    checkReadDeadline(budget);
    const digest = createHash("sha256");
    let bytes: Buffer | undefined;
    let offset = 0;
    if (collectBytes) {
      bytes = Buffer.allocUnsafe(size);
      while (offset < size) {
        checkReadDeadline(budget);
        const length = Math.min(64 * 1024, size - offset);
        const result = await handle.read(bytes, offset, length, offset);
        if (result.bytesRead === 0) throw new Error(`${label} ended during bounded read`);
        digest.update(bytes.subarray(offset, offset + result.bytesRead));
        offset += result.bytesRead;
      }
    } else if (size > 0) {
      const stream = handle.createReadStream({ autoClose: false, highWaterMark: 64 * 1024, start: 0, end: size - 1 });
      for await (const value of stream) {
        checkReadDeadline(budget);
        const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
        offset += chunk.byteLength;
        if (offset > size) {
          stream.destroy();
          throw new Error(`${label} exceeded its validated byte length during bounded read`);
        }
        digest.update(chunk);
      }
    }
    if (offset !== size) throw new Error(`${label} ended during bounded read`);
    const overflow = Buffer.allocUnsafe(1);
    if ((await handle.read(overflow, 0, 1, size)).bytesRead !== 0) {
      throw new Error(`${label} exceeded its validated byte length during bounded read`);
    }
    const [finalPath, finalCanonical, finalHandle] = await Promise.all([
      lstat(lexical, { bigint: true }),
      realpath(lexical),
      handle.stat({ bigint: true })
    ]);
    if (!sameFileIdentity(metadata, finalPath) || !sameFileIdentity(metadata, finalHandle) ||
        finalPath.size !== metadata.size || finalHandle.size !== metadata.size || finalCanonical !== canonical) {
      throw new Error(`${label} identity or byte length changed during bounded read`);
    }
    checkReadDeadline(budget);
    return { ...(bytes ? { bytes } : {}), digest: `sha256:${digest.digest("hex")}` };
  } finally {
    await handle.close();
  }
}

async function manifest(rootInput: string, budget: RedundancyReadBudget, maxFileBytes = managedReadLimits.maxFileBytes): Promise<{ root: string; bytes: Buffer; value: JsonObject }> {
  checkReadDeadline(budget);
  const root = await realpath(resolve(rootInput));
  checkReadDeadline(budget);
  const result = await readBoundedRepositoryFile(
    root,
    "docs/project-design/manifest.json",
    // Manifest knowledge can be larger than source evidence. Only its per-file
    // allowance changes; count, aggregate and deadline remain shared and bounded.
    { ...budget, maxFileBytes },
    "The Keeper manifest",
    true
  );
  const bytes = result.bytes!;
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as JsonObject;
  checkReadDeadline(budget);
  if (value.managedBy !== "project-design-keeper") throw new Error("The manifest is not Keeper-owned");
  return { root, bytes, value };
}

function normalized(value: string): string {
  return value.normalize("NFKC").toLocaleLowerCase("en-US").replace(/[\p{P}\p{S}\s]+/gu, "");
}

const maximumTrigramBandsPerRecord = 4096;

function trigrams(value: string): Set<string> {
  const text = normalized(value);
  if (text.length < 3) return new Set(text ? [text] : []);
  const values = new Set<string>();
  for (let index = 0; index <= text.length - 3; index += 1) {
    values.add(text.slice(index, index + 3));
    if (values.size > maximumTrigramBandsPerRecord) {
      throw new RedundancyReadLimitError(
        `Redundancy trigram bands exceed the limit of ${maximumTrigramBandsPerRecord} per record`
      );
    }
  }
  return values;
}

function jaccard(left: Set<string>, right: Set<string>): number {
  const intersection = [...left].filter((value) => right.has(value)).length;
  const union = new Set([...left, ...right]).size;
  return union === 0 ? 0 : intersection / union;
}

function strings(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  return typeof value === "string" ? [value] : [];
}

function evidenceKeys(record: JsonObject): Set<string> {
  if (!Array.isArray(record.evidence)) return new Set();
  return new Set(record.evidence.map((evidence) => {
    if (typeof evidence === "string") return evidence.toLocaleLowerCase("en-US");
    if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return "";
    const typed = evidence as JsonObject;
    return `${String(typed.path).toLocaleLowerCase("en-US")}:${String(typed.startLine)}:${String(typed.endLine ?? typed.startLine)}`;
  }).filter(Boolean));
}

function evidencePaths(record: JsonObject): string[] {
  if (!Array.isArray(record.evidence)) return [];
  return record.evidence.flatMap((evidence) => {
    if (typeof evidence === "string") return [/^(.*):[0-9]+$/u.exec(evidence)?.[1]].filter((value): value is string => Boolean(value));
    if (evidence && typeof evidence === "object" && !Array.isArray(evidence) && typeof (evidence as JsonObject).path === "string") {
      return [(evidence as JsonObject).path as string];
    }
    return [];
  });
}

async function sourceState(
  root: string,
  revisions: JsonObject,
  budget: RedundancyReadBudget
): Promise<{ freshPaths: Set<string>; digest: string }> {
  const states: Array<{ path: string; state: string; fresh: boolean }> = [];
  const paths = Object.keys(revisions);
  if (paths.length > budget.maxFiles) {
    throw new RedundancyReadLimitError(`Redundancy source revisions exceed the limit of ${budget.maxFiles} items`);
  }
  checkReadDeadline(budget);
  paths.sort((left, right) => left.localeCompare(right, "en-US"));
  checkReadDeadline(budget);
  for (const path of paths) {
    checkReadDeadline(budget);
    const expected = revisions[path];
    if (typeof expected !== "string" || !safeRepositoryPath(path)) {
      states.push({ path, state: "invalid", fresh: false });
      continue;
    }
    try {
      const actual = (await readBoundedRepositoryFile(root, path, budget, `Redundancy source ${path}`, false)).digest;
      states.push({ path, state: actual, fresh: actual === expected });
    } catch (error) {
      if (error instanceof RedundancyReadLimitError) throw error;
      states.push({ path, state: "missing", fresh: false });
    }
  }
  return {
    freshPaths: new Set(states.filter((state) => state.fresh).map((state) => state.path.toLocaleLowerCase("en-US"))),
    digest: hash(states.map((state) => `${state.path}\0${state.state}`).join("\n"))
  };
}

function effectiveAssessment(record: JsonObject, freshPaths: Set<string>) {
  const evidence = Array.isArray(record.evidence)
    ? record.evidence.filter((value): value is string | EvidenceRef => {
      if (typeof value === "string") return freshPaths.has((/^(.*):[0-9]+$/u.exec(value)?.[1] ?? "").toLocaleLowerCase("en-US"));
      return Boolean(value) && typeof value === "object" && !Array.isArray(value) &&
        freshPaths.has(String((value as JsonObject).path).toLocaleLowerCase("en-US"));
    })
    : [];
  return assessRecord({
    id: String(record.id),
    kind: typeof record.kind === "string" ? record.kind : undefined,
    approval: typeof record.approval === "string" ? record.approval : undefined,
    assertedConfidence: record.assertedConfidence === "high" || record.assertedConfidence === "medium" || record.assertedConfidence === "low" ? record.assertedConfidence : "low",
    evidence
  });
}

function overlaps(left: Set<string>, right: Set<string>): boolean {
  return [...left].some((value) => right.has(value));
}

function contentDigest(record: JsonObject): string {
  return hash(JSON.stringify(record));
}

function signature(payload: string): Buffer {
  return createHmac("sha256", analysisSigningKey).update(payload, "utf8").digest();
}

function encodeAnalysis(payload: AnalysisPayload): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${signature(body).toString("base64url")}`;
}

function decodeAnalysis(analysisId: string): AnalysisPayload {
  const [body, encodedSignature, ...extra] = analysisId.split(".");
  if (!body || !encodedSignature || extra.length > 0) throw new Error("Redundancy analysis ID is malformed or tampered");
  let supplied: Buffer;
  try {
    supplied = Buffer.from(encodedSignature, "base64url");
  } catch {
    throw new Error("Redundancy analysis ID is malformed or tampered");
  }
  const expected = signature(body);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new Error("Redundancy analysis ID is malformed or tampered");
  }
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as AnalysisPayload;
    if (payload.version !== 1 || typeof payload.root !== "string" || typeof payload.snapshotId !== "string" ||
      !Number.isSafeInteger(payload.createdAt) || !Number.isSafeInteger(payload.expiresAt) || !Array.isArray(payload.candidates)) {
      throw new Error("invalid payload");
    }
    return payload;
  } catch {
    throw new Error("Redundancy analysis ID is malformed or tampered");
  }
}

function activeRecords(pack: JsonObject): JsonObject[] {
  return Array.isArray(pack.records)
    ? pack.records.filter((record): record is JsonObject => Boolean(record) && typeof record === "object" && !Array.isArray(record))
    : [];
}

/** Validate the user-confirmed semantic decisions before a changeset can be previewed. */
export async function validateRedundancyDecisions(input: {
  root: string;
  analysisId: string;
  decisions: RedundancyDecision[];
  candidatePack: JsonObject;
  candidateRecordAssessments?: Array<{ id: string; effectiveConfidence: "high" | "medium" | "low" }>;
  now?: () => number;
}): Promise<void> {
  const budget = readBudget(resolveKeeperLimits());
  const loaded = await manifest(input.root, budget);
  const payload = decodeAnalysis(input.analysisId);
  if (payload.root !== loaded.root) throw new Error("Redundancy analysis belongs to a different project");
  if ((input.now ?? Date.now)() > payload.expiresAt) throw new Error("Redundancy analysis has expired");
  const loadedRevision = loaded.value.sourceRevision && typeof loaded.value.sourceRevision === "object" && !Array.isArray(loaded.value.sourceRevision)
    ? (loaded.value.sourceRevision as JsonObject).files
    : undefined;
  const loadedRevisions = loadedRevision && typeof loadedRevision === "object" && !Array.isArray(loadedRevision) ? loadedRevision as JsonObject : {};
  const loadedSources = await sourceState(loaded.root, loadedRevisions, budget);
  if (payload.snapshotId !== hash(`${hash(loaded.bytes)}\0${loadedSources.digest}`)) throw new Error("Redundancy analysis is stale for the current knowledge snapshot");
  let candidateFreshPaths: Set<string> | undefined;
  if (!input.candidateRecordAssessments) {
    const candidateRevision = input.candidatePack.sourceRevision && typeof input.candidatePack.sourceRevision === "object" &&
      !Array.isArray(input.candidatePack.sourceRevision)
      ? (input.candidatePack.sourceRevision as JsonObject).files
      : undefined;
    const candidateRevisions = candidateRevision && typeof candidateRevision === "object" && !Array.isArray(candidateRevision)
      ? candidateRevision as JsonObject
      : {};
    candidateFreshPaths = (await sourceState(loaded.root, candidateRevisions, budget)).freshPaths;
  }
  const candidates = new Map(payload.candidates.map((candidate) => [candidate.candidateId, candidate]));
  const seen = new Set<string>();
  const records = new Map(activeRecords(input.candidatePack).map((record) => [String(record.id), record]));
  const currentRecords = new Map(activeRecords(loaded.value).map((record) => [String(record.id), record]));
  const exceptions = Array.isArray(input.candidatePack.dedupeExceptions)
    ? input.candidatePack.dedupeExceptions.filter((value): value is JsonObject => Boolean(value) && typeof value === "object" && !Array.isArray(value))
    : [];
  for (const decision of input.decisions) {
    if (seen.has(decision.candidateId)) throw new Error(`Redundancy candidate decision is duplicated: ${decision.candidateId}`);
    seen.add(decision.candidateId);
    const candidate = candidates.get(decision.candidateId);
    if (!candidate) throw new Error(`Redundancy candidate does not belong to this analysis: ${decision.candidateId}`);
    candidate.recordIds.forEach((id, index) => {
      const current = currentRecords.get(id);
      if (!current || contentDigest(current) !== candidate.recordDigests[index]) {
        throw new Error(`Redundancy candidate record digest is stale or tampered: ${id}`);
      }
    });
    if (decision.decision === "defer") continue;
    if (decision.decision === "keep-separate") {
      const [leftId, rightId] = candidate.recordIds;
      const [leftDigest, rightDigest] = candidate.recordDigests;
      const kept = exceptions.some((exception) =>
        (exception.leftId === leftId && exception.rightId === rightId && exception.leftDigest === leftDigest && exception.rightDigest === rightDigest) ||
        (exception.leftId === rightId && exception.rightId === leftId && exception.leftDigest === rightDigest && exception.rightDigest === leftDigest)
      );
      if (!kept) throw new Error(`Candidate pack is missing the confirmed keep-separate exception: ${decision.candidateId}`);
      continue;
    }
    const survivorId = decision.survivorId ?? candidate.recommendedSurvivorId;
    if (!candidate.recordIds.includes(survivorId)) throw new Error(`Merge survivor is not part of candidate: ${decision.candidateId}`);
    const loserId = candidate.recordIds.find((id) => id !== survivorId)!;
    const survivor = records.get(survivorId);
    const loser = records.get(loserId);
    const originalSurvivor = currentRecords.get(survivorId)!;
    const lifecycle = loser?.lifecycle as JsonObject | undefined;
    if (!survivor || !loser || lifecycle?.state !== "terminal" || lifecycle.reason !== "merged" ||
      !strings(lifecycle.successorIds).includes(survivorId)) {
      throw new Error(`Candidate pack does not encode the confirmed merge relationship: ${decision.candidateId}`);
    }
    const ranks: Record<string, Record<string, number>> = {
      strength: { pending: 0, informational: 1, preferred: 2, required: 3 },
      approval: { pending: 0, "not-required": 1, confirmed: 2 },
      assertedConfidence: { low: 0, medium: 1, high: 2 }
    };
    for (const field of ["strength", "approval", "assertedConfidence"] as const) {
      const before = ranks[field][String(originalSurvivor[field])] ?? -1;
      const after = ranks[field][String(survivor[field])] ?? -1;
      if (after > before) throw new Error(`Redundancy merge cannot promote survivor ${field}: ${survivorId}`);
    }
    const confidenceRank = { low: 0, medium: 1, high: 2 } as const;
    const beforeEffective = effectiveAssessment(originalSurvivor, loadedSources.freshPaths).effectiveConfidence;
    const validatedAssessment = input.candidateRecordAssessments?.find((assessment) => assessment.id === survivorId);
    if (input.candidateRecordAssessments && !validatedAssessment) {
      throw new Error(`Validated candidate assessment is missing for merge survivor: ${survivorId}`);
    }
    const afterEffective = validatedAssessment?.effectiveConfidence ?? effectiveAssessment(survivor, candidateFreshPaths!).effectiveConfidence;
    if (confidenceRank[afterEffective] > confidenceRank[beforeEffective]) {
      throw new Error(`Redundancy merge cannot promote survivor effective confidence: ${survivorId}`);
    }
  }
}

function survivorScore(record: JsonObject, index: number, freshPaths: Set<string>): [number, number, number, number, number, string] {
  const normative = record.approval === "confirmed" && (record.strength === "required" || record.strength === "preferred") ? 1 : 0;
  const assessed = effectiveAssessment(record, freshPaths);
  const confidence = assessed.effectiveConfidence === "high" ? 2 : assessed.effectiveConfidence === "medium" ? 1 : 0;
  const evidence = Array.isArray(record.evidence) ? record.evidence.length : 0;
  const freshEvidence = evidencePaths(record).filter((path) => freshPaths.has(path.toLocaleLowerCase("en-US"))).length;
  return [normative, confidence, freshEvidence, evidence, -index, String(record.id)];
}

function compareScores(left: [number, number, number, number, number, string], right: [number, number, number, number, number, string]): number {
  for (let index = 0; index < 5; index += 1) {
    if (left[index] !== right[index]) return Number(right[index]) - Number(left[index]);
  }
  return String(left[5]).localeCompare(String(right[5]), "en-US");
}

function selected(record: JsonObject, input: JsonObject): boolean {
  const query = typeof input.query === "string" ? input.query.normalize("NFKC").toLocaleLowerCase("en-US") : "";
  if (query && !JSON.stringify(record).normalize("NFKC").toLocaleLowerCase("en-US").includes(query)) return false;
  const paths = strings(input.paths);
  const evidenceText = JSON.stringify(record.evidence ?? []).toLocaleLowerCase("en-US");
  if (paths.length > 0 && !paths.some((path) => evidenceText.includes(path.toLocaleLowerCase("en-US")))) return false;
  const modules = strings(input.modules);
  if (modules.length > 0 && !modules.some((module) => `${String(record.scope)} ${strings(record.modules).join(" ")}`.toLocaleLowerCase("en-US").includes(module.toLocaleLowerCase("en-US")))) return false;
  return true;
}

interface IndexedRedundancyRecord {
  record: JsonObject;
  index: number;
  digest: string;
  trigrams: Set<string>;
  evidence: Set<string>;
  impacts: Set<string>;
}

function redundancyBucketKeys(indexed: IndexedRedundancyRecord): string[] {
  const record = indexed.record;
  const kind = normalized(String(record.kind ?? ""));
  const owner = normalized(String(record.ownerDocument ?? ""));
  const scope = normalized(String(record.scope ?? ""));
  const structuralKey = [kind || "<missing>", owner || "<missing>", scope || "<missing>"].join("\0");
  const keys = [
    ...[...indexed.trigrams].map((trigram) => `trigram-band:${trigram}`),
    ...[...indexed.evidence].map((evidence) => `evidence:${evidence}`),
    ...[...indexed.impacts].map((impact) => `kind-owner-scope-impact:${structuralKey}\0${impact}`)
  ];
  return [...new Set(keys)].sort((left, right) => left.localeCompare(right, "en-US"));
}

function boundedCandidatePairs(
  records: IndexedRedundancyRecord[],
  maximumPairs: number,
  budget: RedundancyReadBudget
): Array<[number, number]> {
  const buckets = new Map<string, number[]>();
  const membershipWork = new CounterBudget(
    "Redundancy bucket membership work",
    Math.max(1024, maximumPairs * 64)
  );
  for (const indexed of records) {
    checkReadDeadline(budget);
    for (const key of redundancyBucketKeys(indexed)) {
      membershipWork.consume();
      const members = buckets.get(key) ?? [];
      members.push(indexed.index);
      buckets.set(key, members);
    }
  }
  const pairs = new Map<string, [number, number]>();
  const pairWork = new CounterBudget("Redundancy candidate pair work", Math.max(1024, maximumPairs * 64));
  for (const key of [...buckets.keys()].sort((left, right) => left.localeCompare(right, "en-US"))) {
    checkReadDeadline(budget);
    const members = buckets.get(key)!.sort((left, right) => left - right);
    for (let left = 0; left < members.length; left += 1) {
      for (let right = left + 1; right < members.length; right += 1) {
        pairWork.consume();
        checkReadDeadline(budget);
        const leftIndex = members[left]!;
        const rightIndex = members[right]!;
        const pairKey = `${leftIndex}:${rightIndex}`;
        if (pairs.has(pairKey)) continue;
        pairs.set(pairKey, [leftIndex, rightIndex]);
        if (pairs.size > maximumPairs) {
          throw new Error(`Redundancy candidate pairs exceed the limit of ${maximumPairs}; narrow the analysis scope`);
        }
      }
    }
  }
  return [...pairs.values()].sort(([leftA, rightA], [leftB, rightB]) => leftA - leftB || rightA - rightB);
}

function recordPairKey(leftId: string, rightId: string): string {
  return JSON.stringify(leftId <= rightId ? [leftId, rightId] : [rightId, leftId]);
}

function exceptionBindingKey(leftId: string, rightId: string, leftDigest: string, rightDigest: string): string {
  return leftId <= rightId
    ? JSON.stringify([leftId, rightId, leftDigest, rightDigest])
    : JSON.stringify([rightId, leftId, rightDigest, leftDigest]);
}

export async function analyzeRedundancy(input: JsonObject, options: ServiceOptions = {}): Promise<JsonObject> {
  if (typeof input.root !== "string") throw new Error("A repository root is required");
  const resolvedLimits = resolveKeeperLimits(options.limits);
  const budget = readBudget(resolvedLimits, options.redundancyIo);
  const loaded = await manifest(input.root, budget, Math.min(managedReadLimits.maxFileBytes, options.limits?.scan?.maxFileBytes ?? Infinity));
  const limits = resolvedLimits.redundancy;
  const rawRecords = Array.isArray(loaded.value.records) ? loaded.value.records : [];
  if (rawRecords.length > limits.maxRecords) {
    throw new Error(`Redundancy records exceed the limit of ${limits.maxRecords}; narrow the analysis scope`);
  }
  const records: JsonObject[] = [];
  const recordIds = new Set<string>();
  for (const value of rawRecords) {
    checkReadDeadline(budget);
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    const record = value as JsonObject;
    if (typeof record.id !== "string" || record.id.length === 0) {
      throw new Error("Redundancy record ID must be a non-empty string");
    }
    if (recordIds.has(record.id)) throw new Error(`Redundancy record ID is duplicated: ${record.id}`);
    recordIds.add(record.id);
    if (selected(record, input)) records.push(record);
  }
  const rawExceptions = Array.isArray(loaded.value.dedupeExceptions) ? loaded.value.dedupeExceptions : [];
  if (rawExceptions.length > limits.maxPairs) {
    throw new Error(`Redundancy exceptions exceed the limit of ${limits.maxPairs}; narrow the analysis scope`);
  }
  const exceptionPairs = new Set<string>();
  const exactExceptions = new Set<string>();
  for (const value of rawExceptions) {
    checkReadDeadline(budget);
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    const exception = value as JsonObject;
    if (typeof exception.leftId !== "string" || typeof exception.rightId !== "string") continue;
    exceptionPairs.add(recordPairKey(exception.leftId, exception.rightId));
    if (typeof exception.leftDigest === "string" && typeof exception.rightDigest === "string") {
      exactExceptions.add(exceptionBindingKey(
        exception.leftId,
        exception.rightId,
        exception.leftDigest,
        exception.rightDigest
      ));
    }
  }
  const revision = loaded.value.sourceRevision && typeof loaded.value.sourceRevision === "object" && !Array.isArray(loaded.value.sourceRevision)
    ? (loaded.value.sourceRevision as JsonObject).files
    : undefined;
  const revisions = revision && typeof revision === "object" && !Array.isArray(revision) ? revision as JsonObject : {};
  const sources = await sourceState(loaded.root, revisions, budget);
  const candidates: JsonObject[] = [];
  let invalidatedExceptionCount = 0;
  const indexedRecords: IndexedRedundancyRecord[] = [];
  for (const [index, record] of records.entries()) {
    checkReadDeadline(budget);
    if ((record.lifecycle as JsonObject | undefined)?.state === "terminal") continue;
    if (Array.isArray(record.evidence) && record.evidence.length > resolvedLimits.pack.maxEvidencePerRecord) {
      throw new RedundancyReadLimitError(
        `Redundancy record evidence exceeds the limit of ${resolvedLimits.pack.maxEvidencePerRecord} items`
      );
    }
    if (Array.isArray(record.impact) && record.impact.length > resolvedLimits.pack.maxImpactPerRecord) {
      throw new RedundancyReadLimitError(
        `Redundancy record impact exceeds the limit of ${resolvedLimits.pack.maxImpactPerRecord} items`
      );
    }
    const digest = contentDigest(record);
    options.redundancyIo?.onRecordDigest?.(String(record.id));
    indexedRecords.push({
      record,
      index,
      digest,
      trigrams: trigrams(String(record.statement ?? "")),
      evidence: evidenceKeys(record),
      impacts: new Set(strings(record.impact).map(normalized))
    });
    checkReadDeadline(budget);
  }
  const byIndex = new Map(indexedRecords.map((indexed) => [indexed.index, indexed]));
  for (const [leftIndex, rightIndex] of boundedCandidatePairs(indexedRecords, limits.maxPairs, budget)) {
      checkReadDeadline(budget);
      const leftIndexed = byIndex.get(leftIndex)!;
      const rightIndexed = byIndex.get(rightIndex)!;
      const left = leftIndexed.record;
      const right = rightIndexed.record;
      const similarity = jaccard(leftIndexed.trigrams, rightIndexed.trigrams);
      checkReadDeadline(budget);
      const evidenceOverlap = overlaps(leftIndexed.evidence, rightIndexed.evidence);
      const impactOverlap = overlaps(leftIndexed.impacts, rightIndexed.impacts);
      const sameKind = left.kind === right.kind;
      const sameScope = left.scope === right.scope;
      const sameOwner = left.ownerDocument === right.ownerDocument;
      const related = similarity >= 0.32 || evidenceOverlap || (impactOverlap && sameKind && sameScope && sameOwner);
      if (!related) continue;
      const pairKey = recordPairKey(String(left.id), String(right.id));
      if (exactExceptions.has(exceptionBindingKey(
        String(left.id),
        String(right.id),
        leftIndexed.digest,
        rightIndexed.digest
      ))) continue;
      if (exceptionPairs.has(pairKey)) invalidatedExceptionCount += 1;
      const ranked = [
        { record: left, index: leftIndex, score: survivorScore(left, leftIndex, sources.freshPaths) },
        { record: right, index: rightIndex, score: survivorScore(right, rightIndex, sources.freshPaths) }
      ].sort((a, b) => compareScores(a.score, b.score));
      const reasons = [
        ...(similarity >= 0.32 ? [`character-trigram:${similarity.toFixed(3)}`] : []),
        ...(evidenceOverlap ? ["evidence-overlap"] : []),
        ...(impactOverlap ? ["impact-overlap"] : []),
        ...(sameKind ? ["same-kind"] : []),
        ...(sameScope ? ["same-scope"] : []),
        ...(sameOwner ? ["same-owner"] : [])
      ];
      candidates.push({
        candidateId: hash(recordPairKey(String(left.id), String(right.id))),
        recordIds: [String(left.id), String(right.id)],
        recommendedSurvivorId: String(ranked[0].record.id),
        reasons,
        decision: null
      });
  }
  const createdAt = (options.now ?? Date.now)();
  const expiresAt = createdAt + 30 * 60 * 1000;
  const snapshotId = hash(`${hash(loaded.bytes)}\0${sources.digest}`);
  const recordsById = new Map(indexedRecords.map((indexed) => [String(indexed.record.id), indexed]));
  const tokenCandidates = candidates.map((candidate) => {
    const recordIds = candidate.recordIds as [string, string];
    const left = recordsById.get(recordIds[0])!;
    const right = recordsById.get(recordIds[1])!;
    return {
      candidateId: String(candidate.candidateId),
      recordIds,
      recordDigests: [left.digest, right.digest] as [string, string],
      recommendedSurvivorId: String(candidate.recommendedSurvivorId)
    };
  });
  const analysisPayload: AnalysisPayload = { version: 1, root: loaded.root, snapshotId, createdAt, expiresAt, candidates: tokenCandidates };
  const analysisId = encodeAnalysis(analysisPayload);
  const result = {
    schemaVersion: 3,
    snapshotId,
    analysisId,
    createdAt: new Date(createdAt).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    candidates,
    invalidatedExceptionCount
  };
  if (Buffer.byteLength(JSON.stringify(result), "utf8") > 1024 * 1024) throw new Error("Redundancy analysis exceeds the one MiB response budget");
  return result;
}
