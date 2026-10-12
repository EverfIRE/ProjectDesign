import { createHash } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { lstat, open, opendir, realpath, stat } from "node:fs/promises";
import type { BigIntStats } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { performance } from "node:perf_hooks";
import { promisify, TextDecoder } from "node:util";
import { safeRepositoryPath } from "../types/schema.js";
import { assessRecord, type EvidenceRef } from "../knowledge/model.js";
import {
  assertCursorCurrent,
  createCursorCodec,
  cursorMaximumLifetimeMs,
  parseScopeCursorPayload,
  type ScopeCursorPayload
} from "../security/cursor.js";
import { ByteBudget, CounterBudget, DeadlineBudget, resolveKeeperLimits } from "../security/limits.js";
import { managedReadLimits } from "../settings/policy.js";
import { pageItems, scanLimit, scanView } from "./pagination.js";
import { readIndexedFile } from "./reader.js";
import {
  loadScopeIndex,
  persistScopeIndex,
  scopeCandidateModulesForFiles,
  scopeCursorKey,
  scopePathsKey,
  scopeSnapshotIdForContent,
  ScopeSnapshotRestartError
} from "./store.js";
import type {
  Evidence,
  CandidateModule,
  ResolvedScope,
  ScanResult,
  ScopeFileEntry,
  ScopeInput,
  ScopeOmission,
  ScopeRelocationCandidate,
  Snapshot,
  ServiceOptions
} from "../types/schema.js";

const execFile = promisify(execFileCallback);
const generatedDirectories = new Set([".git", ".cache", ".next", "build", "coverage", "dist", "generated", "node_modules"]);

export interface ScopeOperationBudget {
  readonly deadline: DeadlineBudget;
  readonly deadlineAt: number;
  readonly maxFileBytes: number;
  readonly maxFiles: number;
  readonly maxEvidence: number;
  /** Shared by scanned source, manifests, and routed pack documents. */
  readonly repositoryBytes: ByteBudget;
  readonly repositoryFiles: CounterBudget;
  readonly selectorWork: CounterBudget;
}

export function createScopeOperationBudget(options: ServiceOptions): ScopeOperationBudget {
  const resolvedLimits = resolveKeeperLimits(options.limits);
  const limits = resolvedLimits.scan;
  const startedAt = performance.now();
  return {
    deadline: new DeadlineBudget("cold scan", limits.deadlineMs, () => performance.now()),
    deadlineAt: startedAt + limits.deadlineMs,
    maxFileBytes: limits.maxFileBytes,
    maxFiles: limits.maxFiles,
    maxEvidence: limits.maxEvidence,
    repositoryBytes: new ByteBudget("scope repository aggregate bytes", limits.maxAggregateBytes),
    repositoryFiles: new CounterBudget("scope repository files", limits.maxFiles),
    selectorWork: new CounterBudget(
      "scope post-scan selector work",
      resolvedLimits.pack.maxRecords * (resolvedLimits.pack.maxEvidencePerRecord * 4 + 64) +
        limits.maxEvidence * 4 + limits.maxFiles * 4
    )
  };
}

type SelectorWorkKind = "record-filter" | "reference-index" | "chunk-filter";

function consumeSelectorWork(
  budget: ScopeOperationBudget,
  options: ServiceOptions,
  kind: SelectorWorkKind,
  items = 1
): void {
  budget.selectorWork.consume(items);
  budget.deadline.check();
  options.scopeIo?.onSelectorWork?.(kind);
}

function remainingOperationMs(budget: ScopeOperationBudget): number {
  budget.deadline.check();
  const remaining = Math.ceil(budget.deadlineAt - performance.now());
  if (remaining <= 0) budget.deadline.check();
  return Math.max(1, remaining);
}

async function runBeforeGitHook(
  options: ServiceOptions,
  args: readonly string[],
  budget: ScopeOperationBudget
): Promise<void> {
  const hook = options.scopeIo?.beforeGitCommand;
  if (!hook) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      hook(args),
      new Promise<never>((_accept, reject) => {
        timer = setTimeout(() => reject(new Error("cold scan deadline exceeded before Git command")), remainingOperationMs(budget));
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
  budget.deadline.check();
}

async function runBeforeRepositoryContentHook(
  options: ServiceOptions,
  path: string,
  budget: ScopeOperationBudget
): Promise<void> {
  const hook = options.scopeIo?.beforeRepositoryContentRead;
  if (!hook) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      hook(path),
      new Promise<never>((_accept, reject) => {
        timer = setTimeout(
          () => reject(new Error("cold scan deadline exceeded before repository content read")),
          remainingOperationMs(budget)
        );
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
  budget.deadline.check();
}

async function runBeforeRepositoryStatHook(
  options: ServiceOptions,
  path: string,
  budget: ScopeOperationBudget
): Promise<void> {
  const hook = options.scopeIo?.beforeRepositoryFileStat;
  if (!hook) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      hook(path),
      new Promise<never>((_accept, reject) => {
        timer = setTimeout(
          () => reject(new Error("cold scan deadline exceeded before repository file stat")),
          remainingOperationMs(budget)
        );
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
  budget.deadline.check();
}

async function runBeforeRepositoryDiscoveryHook(
  options: ServiceOptions,
  path: string,
  budget: ScopeOperationBudget
): Promise<void> {
  const hook = options.scopeIo?.beforeRepositoryDiscovery;
  if (!hook) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      hook(path),
      new Promise<never>((_accept, reject) => {
        timer = setTimeout(
          () => reject(new Error("cold scan deadline exceeded before repository discovery")),
          remainingOperationMs(budget)
        );
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
  budget.deadline.check();
}

async function gitText(
  args: string[],
  options: ServiceOptions,
  budget: ScopeOperationBudget
): Promise<string> {
  await runBeforeGitHook(options, args, budget);
  const result = await execFile("git", args, {
    encoding: "utf8",
    timeout: remainingOperationMs(budget),
    maxBuffer: 1024 * 1024
  });
  budget.deadline.check();
  return result.stdout;
}

async function gitBytes(
  args: string[],
  maximumBytes: number,
  options: ServiceOptions,
  budget: ScopeOperationBudget
): Promise<Buffer> {
  await runBeforeGitHook(options, args, budget);
  const result = await execFile("git", args, {
    encoding: "buffer",
    timeout: remainingOperationMs(budget),
    maxBuffer: maximumBytes
  });
  budget.deadline.check();
  return Buffer.from(result.stdout);
}

type ManifestRecord = Record<string, unknown>;

interface Manifest {
  records: ManifestRecord[];
  documents: ManifestRecord[];
  sourceRevision?: unknown;
  scope?: unknown;
  schemaVersion?: unknown;
}

type ManifestFile =
  | { kind: "missing" }
  | { kind: "unsafe" }
  | { kind: "regular"; path: string };

interface ValidatedPackRoot {
  lexical: string;
  canonical: string;
}

interface InternalScanResult extends ResolvedScope {
  repository?: { root: string; head: string; branch?: string };
  indexedFiles: ScopeFileEntry[];
  files: string[];
  fingerprints: Record<string, string>;
  chunks: Evidence[];
  snapshot: Snapshot;
  changed: string[];
  new: string[];
  deleted: string[];
  candidateModules: CandidateModule[];
  omissions: ScopeOmission[];
  omitted: number;
  snapshotId: string;
  snapshotExpiresAt: number;
  scopePaths: string[];
  scopeKey: string;
  cursorScopeKey: string;
}

export function sha256(contents: Buffer): string {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

export function isInside(root: string, target: string): boolean {
  const difference = relative(root, target);
  return difference === "" || (!difference.startsWith(`..${sep}`) && difference !== ".." && !isAbsolute(difference));
}

async function gitRoot(path: string, options: ServiceOptions, budget: ScopeOperationBudget): Promise<string | undefined> {
  try {
    budget.deadline.check();
    const location = (await stat(path)).isDirectory() ? path : dirname(path);
    const stdout = await gitText(["-C", location, "rev-parse", "--show-toplevel"], options, budget);
    return await realpath(stdout.trim());
  } catch {
    // Repository detection is optional. The shared budget is checked again by
    // discovery, which records a deadline omission without opening content.
    return undefined;
  }
}

async function gitMetadata(
  repositoryRoot: string | undefined,
  options: ServiceOptions,
  budget: ScopeOperationBudget
): Promise<{ root: string; head: string; branch?: string } | undefined> {
  if (!repositoryRoot) return undefined;
  try {
    const [head, branch] = await Promise.all([
      gitText(["-C", repositoryRoot, "rev-parse", "HEAD"], options, budget),
      gitText(["-C", repositoryRoot, "branch", "--show-current"], options, budget)
    ]);
    const currentBranch = branch.trim();
    return { root: repositoryRoot, head: head.trim(), ...(currentBranch ? { branch: currentBranch } : {}) };
  } catch {
    // Git metadata is descriptive; a timeout must not discard the bounded scan.
    return undefined;
  }
}

async function canonical(path: string): Promise<string> {
  try {
    return await realpath(resolve(path));
  } catch (error) {
    throw new Error(`Cannot resolve scope path: ${path}`, { cause: error });
  }
}

export async function resolveScope(
  input: ScopeInput,
  options: ServiceOptions = {},
  budget: ScopeOperationBudget = createScopeOperationBudget(options)
): Promise<ResolvedScope> {
  if (!input.path && !input.root) throw new Error("A scope path or root is required");

  if (input.root) {
    const root = await canonical(input.root);
    const requested = input.path ?? ".";
    if (isAbsolute(requested)) throw new Error("An absolute path is not allowed when root is supplied");
    const lexicalTarget = resolve(root, requested);
    if (!isInside(root, lexicalTarget)) throw new Error("Scope path escapes the supplied root");
    const target = await canonical(lexicalTarget);
    if (!isInside(root, target)) throw new Error("Scope path resolves outside the supplied root");
    const repositoryRoot = await gitRoot(target, options, budget);
    return { root, target, isGitRepository: Boolean(repositoryRoot), repositoryRoot };
  }

  const target = await canonical(input.path!);
  const repositoryRoot = await gitRoot(target, options, budget);
  return { root: target, target, isGitRepository: Boolean(repositoryRoot), repositoryRoot };
}

function generatedPath(path: string): boolean {
  const normalized = path.replaceAll("\\", "/").replace(/^\.\//u, "");
  if (normalized === "docs/project-design" || normalized.startsWith("docs/project-design/") ||
      normalized === ".agents/skills/project-design-context" || normalized.startsWith(".agents/skills/project-design-context/")) {
    return true;
  }
  const parts = normalized.split("/");
  return parts.some((part) => generatedDirectories.has(part)) || /\.(?:map|min\.js)$/iu.test(path);
}

function outputPath(scope: ResolvedScope, file: string): string {
  if (file === scope.root) return basename(file);
  return repositoryPath(relative(scope.root, file));
}

interface DiscoveryState {
  readonly base: ResolvedScope;
  readonly deadline: DeadlineBudget;
  readonly budget: ScopeOperationBudget;
  readonly options: ServiceOptions;
  readonly maxFiles: number;
  readonly maxWork: number;
  readonly files: string[];
  readonly seen: Set<string>;
  readonly omissions: ScopeOmission[];
  work: number;
  stopped: boolean;
}

function pathIdentityKey(path: string): string {
  const absolute = resolve(path);
  return process.platform === "win32" ? absolute.toLocaleLowerCase("en-US") : absolute;
}

function recordDiscoveryOmission(state: DiscoveryState, path: string, reason: ScopeOmission["reason"]): void {
  if (state.omissions.some((omission) => omission.reason === reason && omission.path === path)) return;
  state.omissions.push({ path, reason });
}

function checkDiscoveryBudget(state: DiscoveryState, path: string): boolean {
  try {
    state.deadline.check();
  } catch {
    recordDiscoveryOmission(state, path, "deadline");
    state.stopped = true;
    return false;
  }
  state.work += 1;
  if (state.work > state.maxWork) {
    recordDiscoveryOmission(state, path, "file-limit");
    state.stopped = true;
    return false;
  }
  return true;
}

function addDiscoveredFile(state: DiscoveryState, candidate: string): boolean {
  const key = pathIdentityKey(candidate);
  if (state.seen.has(key)) return true;
  if (state.files.length >= state.maxFiles) {
    recordDiscoveryOmission(state, outputPath(state.base, candidate), "file-limit");
    state.stopped = true;
    return false;
  }
  state.seen.add(key);
  state.files.push(resolve(candidate));
  return true;
}

async function discoverRecursive(scope: ResolvedScope, state: DiscoveryState): Promise<void> {
  let rootMetadata;
  try {
    rootMetadata = await lstat(scope.target);
  } catch {
    recordDiscoveryOmission(state, outputPath(state.base, scope.target), "unreadable");
    return;
  }
  if (!rootMetadata.isDirectory()) {
    addDiscoveredFile(state, scope.target);
    return;
  }
  const pending = [scope.target];
  while (pending.length > 0 && !state.stopped) {
    const directory = pending.pop()!;
    if (!checkDiscoveryBudget(state, outputPath(state.base, directory))) break;
    const directories: string[] = [];
    const files: string[] = [];
    try {
      const handle = await opendir(directory, { bufferSize: 32 });
      for await (const entry of handle) {
        const fullPath = join(directory, entry.name);
        if (!checkDiscoveryBudget(state, outputPath(state.base, fullPath))) break;
        if (generatedPath(relative(scope.target, fullPath))) continue;
        if (entry.isDirectory()) directories.push(fullPath);
        else if (entry.isFile() || entry.isSymbolicLink()) files.push(fullPath);
      }
    } catch {
      recordDiscoveryOmission(state, outputPath(state.base, directory), "unreadable");
      continue;
    }
    files.sort((left, right) => left.localeCompare(right, "en-US"));
    for (const file of files) {
      if (!addDiscoveredFile(state, file)) break;
    }
    directories.sort((left, right) => right.localeCompare(left, "en-US"));
    pending.push(...directories);
  }
}

async function discoverTracked(scope: ResolvedScope, state: DiscoveryState): Promise<void> {
  if (!checkDiscoveryBudget(state, outputPath(state.base, scope.target))) return;
  let stdout: Buffer;
  try {
    const maximumOutputBytes = Math.min(
      20 * 1024 * 1024,
      Math.max(64 * 1024, (state.maxWork + 1) * 64 * 1024)
    );
    stdout = await gitBytes(
      ["-C", scope.repositoryRoot!, "ls-files", "-z"],
      maximumOutputBytes,
      state.options,
      state.budget
    );
  } catch (error) {
    const reason = /deadline|timed out|timeout/i.test(String((error as Error).message)) ? "deadline" : "unreadable";
    recordDiscoveryOmission(state, outputPath(state.base, scope.target), reason);
    if (reason === "deadline") state.stopped = true;
    return;
  }
  let names: string[];
  try {
    names = new TextDecoder("utf-8", { fatal: true }).decode(stdout).split("\0").filter(Boolean);
  } catch {
    recordDiscoveryOmission(state, outputPath(state.base, scope.target), "unreadable");
    return;
  }
  if (names.length > state.maxWork) {
    recordDiscoveryOmission(state, outputPath(state.base, scope.target), "file-limit");
    state.stopped = true;
    return;
  }
  names.sort((left, right) => left.localeCompare(right, "en-US"));
  for (const name of names) {
    if (!checkDiscoveryBudget(state, name)) break;
    if (generatedPath(name)) continue;
    if (!safeRepositoryPath(name)) {
      recordDiscoveryOmission(state, name.slice(0, 4096), "unsafe");
      continue;
    }
    const candidate = resolve(scope.repositoryRoot!, ...name.split("/"));
    if (!isInside(scope.repositoryRoot!, candidate) || !isInside(scope.target, candidate)) continue;
    if (!addDiscoveredFile(state, candidate)) break;
  }
}

async function discoverScope(scope: ResolvedScope, state: DiscoveryState): Promise<void> {
  if (state.stopped) return;
  let metadata;
  try {
    metadata = await lstat(scope.target);
  } catch {
    recordDiscoveryOmission(state, outputPath(state.base, scope.target), "unreadable");
    return;
  }
  if (!metadata.isDirectory()) {
    addDiscoveredFile(state, scope.target);
    return;
  }
  if (sameCanonicalAbsolutePath(scope.target, scope.root) && scope.repositoryRoot) {
    await discoverTracked(scope, state);
    return;
  }
  await discoverRecursive(scope, state);
}

interface IndexedScopeFiles {
  files: ScopeFileEntry[];
  evidence: Evidence[];
  omissions: ScopeOmission[];
}

async function indexScopes(
  base: ResolvedScope,
  scopes: ResolvedScope[],
  options: ServiceOptions,
  budget: ScopeOperationBudget = createScopeOperationBudget(options)
): Promise<IndexedScopeFiles> {
  const limits = resolveKeeperLimits(options.limits).scan;
  const deadline = budget.deadline;
  const state: DiscoveryState = {
    base,
    deadline,
    budget,
    options,
    maxFiles: limits.maxFiles,
    maxWork: Math.max(limits.maxFiles, Math.min(400_000, limits.maxFiles * 4)),
    files: [],
    seen: new Set(),
    omissions: [],
    work: 0,
    stopped: false
  };
  const orderedScopes = [...scopes].sort((left, right) => left.target.localeCompare(right.target, "en-US"));
  for (const scope of orderedScopes) {
    await runBeforeRepositoryDiscoveryHook(options, scope.target, budget);
    await discoverScope(scope, state);
  }
  const candidates = state.files.sort((left, right) => outputPath(base, left).localeCompare(outputPath(base, right), "en-US"));
  const aggregate = budget.repositoryBytes;
  const prepared: Array<{ path: string; size: number }> = [];
  for (const candidate of candidates) {
    let metadata;
    try {
      deadline.check();
      budget.repositoryFiles.consume();
      metadata = await lstat(candidate, { bigint: true });
    } catch (error) {
      const message = String((error as Error).message);
      const reason: ScopeOmission["reason"] = /deadline/iu.test(message)
        ? "deadline"
        : /files?.*exceed|exceed.*files?/iu.test(message) ? "file-limit" : "unreadable";
      state.omissions.push({ path: outputPath(base, candidate), reason });
      if (reason === "deadline" || reason === "file-limit") break;
      continue;
    }
    const size = Number(metadata.size);
    if (!Number.isSafeInteger(size) || size < 0 || size > limits.maxFileBytes) {
      state.omissions.push({ path: outputPath(base, candidate), reason: "file-bytes", ...(Number.isSafeInteger(size) ? { size } : {}) });
      continue;
    }
    try {
      aggregate.consume(size);
    } catch {
      state.omissions.push({ path: outputPath(base, candidate), reason: "aggregate-bytes", size });
      continue;
    }
    prepared.push({ path: candidate, size });
  }

  const files: ScopeFileEntry[] = [];
  const evidence: Evidence[] = [];
  let start = 0;
  while (start < prepared.length) {
    try {
      deadline.check();
    } catch {
      recordDiscoveryOmission(state, outputPath(base, prepared[start]!.path), "deadline");
      break;
    }
    const remainingEvidence = Math.max(0, limits.maxEvidence - evidence.length);
    if (remainingEvidence === 0) {
      for (const candidate of prepared.slice(start)) {
        state.omissions.push({ path: outputPath(base, candidate.path), reason: "evidence-limit", size: candidate.size });
      }
      break;
    }
    let reservableEvidence = remainingEvidence;
    const batch: Array<{ path: string; size: number; evidenceCapacity: number }> = [];
    while (start < prepared.length && batch.length < 8) {
      const candidate = prepared[start]!;
      const evidenceCapacity = candidate.size === 0 ? 0 : Math.min(candidate.size, reservableEvidence);
      if (candidate.size > 0 && evidenceCapacity === 0) break;
      batch.push({ ...candidate, evidenceCapacity });
      start += 1;
      reservableEvidence -= evidenceCapacity;
      if (evidenceCapacity < candidate.size) break;
    }
    const results = await Promise.all(batch.map((candidate) => readIndexedFile({
      absolutePath: candidate.path,
      outputPath: outputPath(base, candidate.path),
      bytes: new ByteBudget("scan file bytes", candidate.size),
      evidence: new CounterBudget("scan file evidence", candidate.evidenceCapacity),
      deadline,
      maxFileBytes: limits.maxFileBytes
    }, {
      beforeStat: async (path) => runBeforeRepositoryStatHook(options, path, budget),
      beforeOpen: async (path) => runBeforeRepositoryContentHook(options, path, budget)
    })));
    let deadlineReached = false;
    for (const result of results) {
      if (!result.file) {
        if (result.omission) {
          state.omissions.push(result.omission);
          if (result.omission.reason === "deadline") deadlineReached = true;
        }
        continue;
      }
      files.push(result.file);
      evidence.push(...result.evidence);
    }
    if (deadlineReached) {
      if (start < prepared.length) recordDiscoveryOmission(state, outputPath(base, prepared[start]!.path), "deadline");
      break;
    }
  }
  return {
    files: files.sort((left, right) => left.path.localeCompare(right.path, "en-US")),
    evidence: evidence.sort((left, right) => left.path.localeCompare(right.path, "en-US") || left.line - right.line),
    omissions: state.omissions.sort((left, right) => left.path.localeCompare(right.path, "en-US") || left.reason.localeCompare(right.reason, "en-US"))
  };
}

async function index(scope: ResolvedScope, options: ServiceOptions, budget: ScopeOperationBudget): Promise<IndexedScopeFiles> {
  return indexScopes(scope, [scope], options, budget);
}

function repositoryPath(path: string): string {
  return path.replaceAll("\\", "/");
}

function pathKey(path: string): string {
  return repositoryPath(path).toLocaleLowerCase("en-US");
}

function differences(
  current: Record<string, string>,
  previous: unknown,
  budget?: ScopeOperationBudget
): Pick<Snapshot, "changed" | "new" | "deleted"> {
  const previousFiles = typeof previous === "object" && previous !== null && "files" in previous
    ? (previous as { files?: unknown }).files
    : previous;
  const prior = typeof previousFiles === "object" && previousFiles !== null && !Array.isArray(previousFiles)
    ? previousFiles as Record<string, unknown>
    : {};
  if (Object.keys(prior).length > (budget?.maxFiles ?? resolveKeeperLimits().scan.maxFiles)) {
    throw new Error(`Previous snapshot files exceed the file limit of ${budget?.maxFiles ?? resolveKeeperLimits().scan.maxFiles}`);
  }
  const currentByKey = new Map(Object.entries(current).map(([path, fingerprint]) => [pathKey(path), { path, fingerprint }]));
  const priorByKey = new Map(Object.entries(prior).map(([path, fingerprint]) => [pathKey(path), { path, fingerprint }]));
  const changed = [...currentByKey.entries()].flatMap(([key, value]) => {
    const earlier = priorByKey.get(key);
    return earlier && earlier.fingerprint !== value.fingerprint ? [value.path] : [];
  }).sort();
  const fresh = [...currentByKey.entries()].flatMap(([key, value]) => priorByKey.has(key) ? [] : [value.path]).sort();
  const deleted = [...priorByKey.entries()].flatMap(([key, value]) => currentByKey.has(key) ? [] : [value.path]).sort();
  return { changed, new: fresh, deleted };
}

async function finalizeScan(
  scope: ResolvedScope,
  indexed: ScopeFileEntry[],
  chunks: Evidence[],
  omissions: ScopeOmission[],
  scopePaths: string[],
  previousSnapshot: unknown,
  options: ServiceOptions,
  persistIndex = true,
  budget: ScopeOperationBudget = createScopeOperationBudget(options)
): Promise<InternalScanResult> {
  const fingerprints = Object.fromEntries(indexed.map((file) => [file.path, file.fingerprint]));
  const changeSet = differences(fingerprints, previousSnapshot, budget);
  const snapshot: Snapshot = { ...scope, files: fingerprints, ...changeSet };
  const repository = await gitMetadata(scope.repositoryRoot, options, budget);
  const scopeKey = scopePathsKey(scopePaths);
  const cursorScopeKey = scopeCursorKey(scope.root, scopeKey);
  const modules = scopeCandidateModulesForFiles(indexed);
  const snapshotId = scopeSnapshotIdForContent({
    scopePaths,
    files: indexed,
    evidence: chunks,
    candidateModules: modules,
    omissions
  });
  const now = options.now?.() ?? Date.now();
  let snapshotExpiresAt = now + cursorMaximumLifetimeMs;
  if (persistIndex) {
    const persisted = await persistScopeIndex({
      options,
      projectRoot: scope.root,
      scopePaths,
      snapshotId,
      files: indexed,
      evidence: chunks,
      candidateModules: modules,
      omissions
    });
    snapshotExpiresAt = persisted.expiresAt;
  }
  return {
    ...scope,
    ...(repository ? { repository } : {}),
    indexedFiles: indexed,
    files: indexed.map((file) => file.path),
    fingerprints,
    chunks,
    candidateModules: modules,
    omissions,
    snapshot,
    ...changeSet,
    omitted: omissions.length,
    snapshotId,
    snapshotExpiresAt,
    scopePaths,
    scopeKey,
    cursorScopeKey
  };
}

async function scan(
  input: ScopeInput & { previousSnapshot?: unknown },
  options: ServiceOptions = {},
  persistIndex = true,
  budget: ScopeOperationBudget = createScopeOperationBudget(options)
): Promise<InternalScanResult> {
  const scope = await resolveScope(input, options, budget);
  const indexedResult = await index(scope, options, budget);
  return finalizeScan(
    scope,
    indexedResult.files,
    indexedResult.evidence,
    indexedResult.omissions,
    [input.root ? repositoryPath(input.path ?? ".") : "."],
    input.previousSnapshot,
    options,
    persistIndex,
    budget
  );
}

export async function snapshotForFingerprint(
  input: ScopeInput,
  options: ServiceOptions = {},
  budget: ScopeOperationBudget = createScopeOperationBudget(options)
): Promise<Snapshot> {
  const scope = await resolveScope(input, options, budget);
  const indexedResult = await index(scope, options, budget);
  return (await finalizeScan(
    scope,
    indexedResult.files,
    indexedResult.evidence,
    indexedResult.omissions,
    [input.path ?? "."],
    undefined,
    options,
    false,
    budget
  )).snapshot;
}

async function resolveSelectedScope(
  base: ResolvedScope,
  path: string,
  budget: ScopeOperationBudget
): Promise<ResolvedScope | undefined> {
  budget.deadline.check();
  const lexicalTarget = resolve(base.root, path);
  if (!isInside(base.root, lexicalTarget)) throw new Error(`Selected scope path escapes the supplied root: ${path}`);
  try {
    await lstat(lexicalTarget);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  const target = await canonical(lexicalTarget);
  budget.deadline.check();
  if (!isInside(base.root, target)) throw new Error(`Selected scope path resolves outside the supplied root: ${path}`);
  return { ...base, target };
}

async function scanSelectedPaths(
  root: string,
  requestedPaths: string[],
  previousSnapshot: unknown,
  options: ServiceOptions,
  persistIndex = true,
  budget: ScopeOperationBudget = createScopeOperationBudget(options)
): Promise<InternalScanResult> {
  budget.deadline.check();
  if (requestedPaths.length > budget.maxFiles) {
    throw new Error(`Selected scope paths exceed the file limit of ${budget.maxFiles}`);
  }
  const paths = [...new Set(requestedPaths.map(repositoryPath))].sort((left, right) => left.localeCompare(right));
  if (paths.length === 0 || paths.includes(".")) return scan({ root, previousSnapshot }, options, persistIndex, budget);
  for (const path of paths) {
    if (!safeRepositoryPath(path)) throw new Error(`Selected scope path is not a safe repository path: ${path}`);
  }
  const base = await resolveScope({ root }, options, budget);
  const selectedScopes: ResolvedScope[] = [];
  for (let start = 0; start < paths.length; start += 8) {
    budget.deadline.check();
    const batch = await Promise.all(paths.slice(start, start + 8).map((path) => resolveSelectedScope(base, path, budget)));
    selectedScopes.push(...batch.filter((scope): scope is ResolvedScope => Boolean(scope)));
  }
  const indexed = await indexScopes(base, selectedScopes, options, budget);
  return finalizeScan(
    base,
    indexed.files,
    indexed.evidence,
    indexed.omissions,
    paths,
    previousSnapshot,
    options,
    persistIndex,
    budget
  );
}

function scopeInput(input: Record<string, unknown>): ScopeInput {
  return {
    path: typeof input.path === "string" ? input.path : undefined,
    root: typeof input.root === "string" ? input.root : undefined
  };
}

function asArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : typeof value === "string" ? [value] : [];
}

function boundedInteger(value: unknown, fallback: number, maximum: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return Number(value);
}

async function manifestFor(
  scope: ResolvedScope,
  options: ServiceOptions,
  budget: ScopeOperationBudget
): Promise<Manifest | undefined> {
  const packRoot = await safePackRoot(scope);
  if (!packRoot) return undefined;
  for (const name of ["manifest.json", "project-design-manifest.json"]) {
    const candidate = await safeManifestFile(packRoot, name);
    if (candidate.kind === "missing") continue;
    if (candidate.kind === "unsafe") return undefined;
    const bytes = await readBoundedRepositoryMetadata(candidate.path, packRoot.canonical, options, budget);
    if (!bytes) return undefined;
    try {
      const parsed = JSON.parse(decodeFatalUtf8(bytes)) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
      const raw = parsed as Record<string, unknown>;
      const limits = resolveKeeperLimits(options.limits).pack;
      if (Array.isArray(raw.documents) && raw.documents.length > limits.maxDocuments) {
        throw new Error(`Pack documents exceed the limit of ${limits.maxDocuments}`);
      }
      const records = boundedPackRecords(raw.records, options, budget);
      return {
        records,
        documents: Array.isArray(raw.documents) ? raw.documents.filter((item): item is ManifestRecord => typeof item === "object" && item !== null) : [],
        sourceRevision: raw.sourceRevision,
        scope: raw.scope,
        schemaVersion: raw.schemaVersion
      };
    } catch (error) {
      if (/^Pack /u.test(String((error as Error).message))) throw error;
      return undefined;
    }
  }
  return undefined;
}

function boundedPackRecords(value: unknown, options: ServiceOptions, budget: ScopeOperationBudget): ManifestRecord[] {
  if (!Array.isArray(value)) return [];
  const limits = resolveKeeperLimits(options.limits).pack;
  if (value.length > limits.maxRecords) throw new Error(`Pack records exceed the limit of ${limits.maxRecords}`);
  const records: ManifestRecord[] = [];
  for (const item of value) {
    budget.deadline.check();
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const record = item as ManifestRecord;
    if (Array.isArray(record.evidence) && record.evidence.length > limits.maxEvidencePerRecord) {
      throw new Error(`Pack record evidence exceeds the limit of ${limits.maxEvidencePerRecord}`);
    }
    for (const evidence of Array.isArray(record.evidence) ? record.evidence : []) {
      if (!evidence || typeof evidence !== "object" || Array.isArray(evidence) ||
          !("endLine" in (evidence as Record<string, unknown>))) continue;
      const typed = evidence as Record<string, unknown>;
      const startLine = Number(typed.startLine);
      const endLine = Number(typed.endLine);
      if (!Number.isSafeInteger(startLine) || startLine < 1 || !Number.isSafeInteger(endLine) || endLine < startLine) {
        throw new Error("Pack record evidence range has an invalid endLine");
      }
    }
    if (Array.isArray(record.impact) && record.impact.length > limits.maxImpactPerRecord) {
      throw new Error(`Pack record impact exceeds the limit of ${limits.maxImpactPerRecord}`);
    }
    for (const field of ["paths", "modules"] as const) {
      if (Array.isArray(record[field]) && record[field].length > limits.maxEvidencePerRecord) {
        throw new Error(`Pack record ${field} exceed the limit of ${limits.maxEvidencePerRecord}`);
      }
    }
    records.push(record);
  }
  return records;
}

function textOf(record: ManifestRecord): string {
  const fields = [
    "id", "domain", "scope", "statement", "evidence", "impact", "status", "strength", "approval", "confidence", "assertedConfidence",
    "supersedes", "supersededBy", "module", "modules", "path", "paths", "summary"
  ];
  return fields.flatMap((field) => {
    const value = record[field];
    return asArray(value).length > 0 ? asArray(value) : value && typeof value === "object" ? [JSON.stringify(value)] : [];
  }).join(" ").toLocaleLowerCase();
}

function evidenceReference(value: string): { path: string; line: number } | undefined {
  const match = /^(.*):([0-9]+)$/u.exec(value);
  if (!match) return undefined;
  const line = Number(match[2]);
  return Number.isSafeInteger(line) && line > 0 ? { path: match[1], line } : undefined;
}

function recordEvidence(record: ManifestRecord): Array<{ path: string; line: number; endLine?: number; reference: string }> {
  if (!Array.isArray(record.evidence)) return [];
  return record.evidence.flatMap((value) => {
    if (typeof value === "string") {
      const parsed = evidenceReference(value);
      return parsed ? [{ ...parsed, reference: value }] : [];
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) return [];
    const evidence = value as Record<string, unknown>;
    const line = Number(evidence.startLine);
    const endLine = Number(evidence.endLine ?? evidence.startLine);
    if (evidence.endLine !== undefined && (!Number.isSafeInteger(endLine) || endLine < line)) return [];
    return typeof evidence.path === "string" && Number.isSafeInteger(line) && line > 0
      ? [{
        path: evidence.path,
        line,
        ...(Number.isSafeInteger(endLine) && endLine >= line ? { endLine } : {}),
        reference: `${evidence.path}:${String(evidence.startLine)}`
      }]
      : [];
  });
}

function manifestEvidencePaths(manifest: Manifest, budget: ScopeOperationBudget): string[] {
  const paths = new Set(Object.keys(revisionFiles(manifest.sourceRevision, budget.maxFiles, budget.deadline)));
  if (paths.size > budget.maxFiles) throw new Error(`Manifest evidence paths exceed the file limit of ${budget.maxFiles}`);
  for (const record of manifest.records) {
    budget.deadline.check();
    for (const evidence of recordEvidence(record)) {
      paths.add(evidence.path);
      if (paths.size > budget.maxFiles) {
        throw new Error(`Manifest evidence paths exceed the file limit of ${budget.maxFiles}`);
      }
    }
  }
  return [...paths];
}

function typedRecordEvidence(record: ManifestRecord): Array<{
  evidenceIndex: number;
  path: string;
  startLine: number;
  endLine: number;
  excerptHash: string;
}> {
  if (!Array.isArray(record.evidence)) return [];
  return record.evidence.flatMap((value, evidenceIndex) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return [];
    const evidence = value as Record<string, unknown>;
    const startLine = Number(evidence.startLine);
    const endLine = Number(evidence.endLine ?? evidence.startLine);
    return typeof evidence.path === "string" && Number.isSafeInteger(startLine) && startLine > 0 &&
      Number.isSafeInteger(endLine) && endLine >= startLine && typeof evidence.excerptHash === "string"
      ? [{ evidenceIndex, path: evidence.path, startLine, endLine, excerptHash: evidence.excerptHash }]
      : [];
  });
}

function revisionFiles(
  value: unknown,
  maximumEntries = resolveKeeperLimits().scan.maxFiles,
  deadline?: DeadlineBudget
): Record<string, string> {
  const candidate = typeof value === "object" && value !== null && "files" in value
    ? (value as { files?: unknown }).files
    : value;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return {};
  const entries = Object.entries(candidate);
  if (entries.length > maximumEntries) throw new Error(`Source revision files exceed the file limit of ${maximumEntries}`);
  const result: Record<string, string> = {};
  for (const [path, fingerprint] of entries) {
    deadline?.check();
    if (typeof fingerprint === "string" && safeRepositoryPath(path)) result[path] = fingerprint;
  }
  return result;
}

function declaredScopePaths(
  pack: Record<string, unknown> | Manifest | undefined,
  previous: unknown,
  budget: ScopeOperationBudget
): string[] {
  const scope = pack && typeof pack.scope === "object" && pack.scope !== null ? pack.scope as Record<string, unknown> : undefined;
  if (Array.isArray(scope?.paths) && scope.paths.length > budget.maxFiles) {
    throw new Error(`Selected scope paths exceed the file limit of ${budget.maxFiles}`);
  }
  const paths = asArray(scope?.paths).filter((path) => safeRepositoryPath(path));
  const revisionPaths = Object.keys(revisionFiles(previous, budget.maxFiles, budget.deadline));
  if (paths.length + revisionPaths.length > budget.maxFiles * 2) {
    throw new Error(`Selected scope path work exceeds the file limit of ${budget.maxFiles}`);
  }
  const selected = [...new Set([...paths, ...revisionPaths])];
  if (selected.length > budget.maxFiles) throw new Error(`Selected scope paths exceed the file limit of ${budget.maxFiles}`);
  return selected;
}

interface ContextFreshness {
  status: "fresh" | "stale" | "unknown";
  checkedAt: string;
  comparedFiles: number;
  changedFiles: string[];
  deletedFiles: string[];
  invalidatedRecordIds: string[];
}

function freshnessFor(
  result: InternalScanResult,
  previous: unknown,
  records: ManifestRecord[],
  now: () => number,
  schemaVersion?: unknown
): {
  freshness: ContextFreshness;
  records: Array<{
    record: ManifestRecord;
    verification: "verified" | "historical" | "unverified";
    effectiveConfidence: string;
    reasons: string[];
  }>;
} {
  const prior = revisionFiles(previous);
  const hasRevision = Object.keys(prior).length > 0;
  const changed = new Set(result.changed.map(pathKey));
  const deleted = new Set(result.deleted.map(pathKey));
  const current = new Set(Object.keys(result.fingerprints).map(pathKey));
  const revisionPaths = new Set(Object.keys(prior).map(pathKey));
  const evidenceIndex = new Map(result.chunks.map((chunk) => [`${pathKey(chunk.path)}:${chunk.line}`, chunk]));
  const recordState = records.map((record) => {
    const reasons = new Set<string>();
    let hasUnrevisionedEvidence = false;
    const parsedEvidence = recordEvidence(record);
    const declaredEvidenceCount = Array.isArray(record.evidence) ? record.evidence.length : 0;
    if (parsedEvidence.length !== declaredEvidenceCount) reasons.add("evidence-reference-invalid");
    for (const parsed of parsedEvidence) {
      if (!parsed) {
        reasons.add("evidence-reference-invalid");
        continue;
      }
      const key = pathKey(parsed.path);
      if (hasRevision && !revisionPaths.has(key)) {
        reasons.add("evidence-source-unrevisioned");
        hasUnrevisionedEvidence = true;
      } else if (deleted.has(key) || !current.has(key)) reasons.add("evidence-source-deleted");
      else if (changed.has(key)) reasons.add("evidence-source-modified");
      else if (!evidenceIndex.has(`${key}:${parsed.line}`)) reasons.add("evidence-line-invalid");
    }
    const verification: "verified" | "historical" | "unverified" = !hasRevision || hasUnrevisionedEvidence
      ? "unverified"
      : reasons.size > 0 ? "historical" : "verified";
    const declaredConfidence = record.assertedConfidence ?? record.confidence;
    let confidence = typeof declaredConfidence === "string" && ["high", "medium", "low"].includes(declaredConfidence)
      ? declaredConfidence
      : "unknown";
    if (schemaVersion === "3.0" && verification === "verified" && typeof record.id === "string" &&
      typeof record.assertedConfidence === "string" && Array.isArray(record.evidence)) {
      const assessment = assessRecord({
        id: record.id,
        kind: typeof record.kind === "string" ? record.kind : undefined,
        approval: typeof record.approval === "string" ? record.approval : undefined,
        assertedConfidence: record.assertedConfidence as "high" | "medium" | "low",
        evidence: record.evidence as Array<string | EvidenceRef>
      });
      confidence = assessment.effectiveConfidence;
      for (const reason of assessment.reasons) reasons.add(reason);
    }
    return {
      record,
      verification,
      effectiveConfidence: verification === "historical" ? "low" : verification === "unverified" ? "unknown" : confidence,
      reasons: [...reasons]
    };
  });
  const invalidatedRecordIds = recordState.flatMap((state) => state.verification === "historical" && typeof state.record.id === "string"
    ? [state.record.id]
    : []);
  const stale = result.changed.length > 0 || result.new.length > 0 || result.deleted.length > 0 || invalidatedRecordIds.length > 0;
  return {
    freshness: {
      status: !hasRevision ? "unknown" : stale ? "stale" : "fresh",
      checkedAt: new Date(now()).toISOString(),
      comparedFiles: Object.keys(prior).length,
      changedFiles: result.changed,
      deletedFiles: result.deleted,
      invalidatedRecordIds
    },
    records: recordState
  };
}

function pathApplies(candidate: string, requested: string): boolean {
  const candidateKey = pathKey(candidate);
  const requestedKey = pathKey(requested).replace(/\/$/u, "");
  return candidateKey === requestedKey || candidateKey.startsWith(`${requestedKey}/`) || requestedKey.startsWith(`${candidateKey}/`);
}

interface PathSelectorNode {
  terminal: boolean;
  readonly children: Map<string, PathSelectorNode>;
}

function pathSelector(paths: readonly string[], budget: ScopeOperationBudget, options: ServiceOptions): PathSelectorNode {
  const root: PathSelectorNode = { terminal: false, children: new Map() };
  for (const path of paths) {
    consumeSelectorWork(budget, options, "record-filter");
    let node = root;
    for (const segment of pathKey(path).replace(/\/$/u, "").split("/")) {
      consumeSelectorWork(budget, options, "record-filter");
      let child = node.children.get(segment);
      if (!child) {
        child = { terminal: false, children: new Map() };
        node.children.set(segment, child);
      }
      node = child;
    }
    node.terminal = true;
  }
  return root;
}

function pathSelectorMatches(
  selector: PathSelectorNode,
  candidate: string,
  budget: ScopeOperationBudget,
  options: ServiceOptions
): boolean {
  let node = selector;
  for (const segment of pathKey(candidate).split("/")) {
    consumeSelectorWork(budget, options, "record-filter");
    if (node.terminal) return true;
    const child = node.children.get(segment);
    if (!child) return false;
    node = child;
  }
  return node.terminal || node.children.size > 0;
}

function recordPaths(record: ManifestRecord): string[] {
  return [
    ...recordEvidence(record).map((evidence) => evidence.path),
    ...asArray(record.paths ?? record.path)
  ];
}

function recordModules(record: ManifestRecord): string[] {
  const explicit = asArray(record.modules ?? record.module);
  const scope = typeof record.scope === "string" ? record.scope : "";
  return [...explicit, ...scope.split(/[^A-Za-z0-9_-]+/u).filter(Boolean)];
}

function chunkKey(path: string, line: number): string {
  return `${pathKey(path)}:${line}`;
}

function chunkLookup(chunks: Evidence[]): Map<string, Evidence> {
  return new Map(chunks.map((chunk) => [chunkKey(chunk.path, chunk.line), chunk]));
}

function referencedChunk(chunks: Map<string, Evidence>, reference: { path: string; line: number }): Evidence | undefined {
  return chunks.get(chunkKey(reference.path, reference.line));
}

function queryMatchesRecord(
  record: ManifestRecord,
  queryTerm: string,
  chunks: Map<string, Evidence>,
  budget: ScopeOperationBudget,
  options: ServiceOptions
): boolean {
  if (!queryTerm) return true;
  consumeSelectorWork(budget, options, "record-filter");
  if (textOf(record).includes(queryTerm)) return true;
  budget.deadline.check();
  for (const evidence of recordEvidence(record)) {
    consumeSelectorWork(budget, options, "record-filter");
    if (referencedChunk(chunks, evidence)?.text.toLocaleLowerCase().includes(queryTerm)) return true;
  }
  return false;
}

function matchingRecords(
  manifest: Manifest | undefined,
  query: string,
  paths: string[],
  modules: string[],
  chunks: Evidence[],
  options: ServiceOptions,
  budget: ScopeOperationBudget
): ManifestRecord[] {
  if (!manifest) return [];
  const queryTerm = query.toLocaleLowerCase();
  const pathTerms = paths.filter(Boolean);
  const selectedPaths = pathTerms.length > 0 ? pathSelector(pathTerms, budget, options) : undefined;
  const moduleTerms = new Set<string>();
  for (const term of modules.filter(Boolean)) {
    consumeSelectorWork(budget, options, "record-filter");
    moduleTerms.add(term.toLocaleLowerCase("en-US"));
  }
  const indexedChunks = chunkLookup(chunks);
  if (!queryTerm && !selectedPaths && moduleTerms.size === 0) return [];
  const matches: ManifestRecord[] = [];
  for (const record of manifest.records) {
    consumeSelectorWork(budget, options, "record-filter");
    let pathsMatch = !selectedPaths;
    if (selectedPaths) {
      for (const path of recordPaths(record)) {
        if (pathSelectorMatches(selectedPaths, path, budget, options)) {
          pathsMatch = true;
          break;
        }
      }
    }
    if (!pathsMatch) continue;
    let modulesMatch = moduleTerms.size === 0;
    if (!modulesMatch) {
      for (const module of recordModules(record)) {
        consumeSelectorWork(budget, options, "record-filter");
        if (moduleTerms.has(module.toLocaleLowerCase("en-US"))) {
          modulesMatch = true;
          break;
        }
      }
    }
    if (modulesMatch && queryMatchesRecord(record, queryTerm, indexedChunks, budget, options)) matches.push(record);
  }
  return matches;
}

function filteredRecords(
  records: ManifestRecord[],
  domain: unknown,
  status: unknown,
  options: ServiceOptions,
  budget: ScopeOperationBudget
): ManifestRecord[] {
  const domains = new Set(asArray(domain).map((value) => value.toLocaleLowerCase("en-US")));
  const statuses = new Set(asArray(status).map((value) => value.toLocaleLowerCase("en-US")));
  const matches: ManifestRecord[] = [];
  for (const record of records) {
    consumeSelectorWork(budget, options, "record-filter");
    const recordDomains = asArray(record.domain ?? record.domains);
    const recordStatuses = asArray(record.status ?? record.statuses);
    const domainMatches = domains.size === 0 || recordDomains.some((value) => domains.has(value.toLocaleLowerCase("en-US")));
    const statusMatches = statuses.size === 0 || recordStatuses.some((value) => statuses.has(value.toLocaleLowerCase("en-US")));
    if (domainMatches && statusMatches) matches.push(record);
  }
  return matches;
}

function recordSummary(record: ManifestRecord): Record<string, unknown> {
  const fields = [
    "id", "domain", "scope", "statement", "evidence", "impact", "status", "strength", "approval", "confidence",
    "assertedConfidence", "kind", "ownerDocument", "lifecycle", "supersedes", "supersededBy"
  ] as const;
  return Object.fromEntries(fields.flatMap((field) => field in record ? [[field, record[field]]] : []));
}

function documentSummary(document: ManifestRecord): Record<string, unknown> {
  return Object.fromEntries(["id", "path"].flatMap((field) => field in document ? [[field, document[field]]] : []));
}

function sameCanonicalAbsolutePath(left: string, right: string): boolean {
  const leftPath = resolve(left);
  const rightPath = resolve(right);
  return process.platform === "win32"
    ? leftPath.toLocaleLowerCase("en-US") === rightPath.toLocaleLowerCase("en-US")
    : leftPath === rightPath;
}

function sameRepositoryFileIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.gid === right.gid &&
    left.mode === right.mode && left.nlink === right.nlink && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs &&
    left.isFile() && right.isFile() && !left.isSymbolicLink() && !right.isSymbolicLink();
}

/**
 * Read an already-routed repository metadata file at exactly its pre-stat
 * length. This intentionally returns undefined for path/identity failures but
 * propagates resource-limit, deadline, and instrumentation failures.
 */
async function readBoundedRepositoryMetadata(
  lexicalPath: string,
  allowedRoot: string,
  options: ServiceOptions,
  budget: ScopeOperationBudget
): Promise<Buffer | undefined> {
  budget.deadline.check();
  let initial: BigIntStats;
  let canonicalPath: string;
  try {
    [initial, canonicalPath] = await Promise.all([
      lstat(lexicalPath, { bigint: true }),
      realpath(lexicalPath)
    ]);
  } catch {
    budget.deadline.check();
    return undefined;
  }
  if (initial.isSymbolicLink() || !initial.isFile() || !sameCanonicalAbsolutePath(canonicalPath, lexicalPath) ||
      !isInside(allowedRoot, canonicalPath)) return undefined;
  const size = Number(initial.size);
  if (!Number.isSafeInteger(size) || size < 0) throw new Error("Scope metadata file has an invalid byte length");
  budget.repositoryFiles.consume();
  // This reader is only used after routing a manifest or managed pack document.
  // Source scans retain budget.maxFileBytes; explicit lower test budgets still apply.
  const maxFileBytes = Math.min(managedReadLimits.maxFileBytes, options.limits?.scan?.maxFileBytes ?? Infinity);
  if (size > maxFileBytes) {
    throw new Error(`Scope metadata file bytes exceed the per-file limit of ${maxFileBytes}`);
  }
  budget.repositoryBytes.consume(size);
  await runBeforeRepositoryContentHook(options, lexicalPath, budget);

  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(lexicalPath, "r");
  } catch {
    budget.deadline.check();
    return undefined;
  }
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameRepositoryFileIdentity(initial, opened) || Number(opened.size) !== size) return undefined;
    const bytes = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      budget.deadline.check();
      const chunkSize = Math.min(64 * 1024, size - offset);
      const read = await handle.read(bytes, offset, chunkSize, offset);
      if (read.bytesRead <= 0) return undefined;
      offset += read.bytesRead;
    }
    budget.deadline.check();
    let finalPath: BigIntStats;
    let finalHandle: BigIntStats;
    let finalCanonical: string;
    try {
      [finalPath, finalHandle, finalCanonical] = await Promise.all([
        lstat(lexicalPath, { bigint: true }),
        handle.stat({ bigint: true }),
        realpath(lexicalPath)
      ]);
    } catch {
      return undefined;
    }
    if (!sameRepositoryFileIdentity(initial, finalPath) || !sameRepositoryFileIdentity(initial, finalHandle) ||
        Number(finalPath.size) !== size || Number(finalHandle.size) !== size ||
        !sameCanonicalAbsolutePath(finalCanonical, lexicalPath) || !isInside(allowedRoot, finalCanonical)) return undefined;
    budget.deadline.check();
    return bytes;
  } finally {
    await handle.close();
  }
}

function decodeFatalUtf8(bytes: Buffer): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

async function safePackRoot(scope: ResolvedScope): Promise<ValidatedPackRoot | undefined> {
  const lexicalPackRoot = resolve(scope.root, "docs", "project-design");
  try {
    const [actualRepositoryRoot, actualPackRoot] = await Promise.all([
      realpath(scope.repositoryRoot ?? scope.root),
      realpath(lexicalPackRoot)
    ]);
    if (!sameCanonicalAbsolutePath(actualPackRoot, lexicalPackRoot) || !isInside(actualRepositoryRoot, actualPackRoot) ||
        !(await stat(actualPackRoot)).isDirectory()) return undefined;
    return { lexical: lexicalPackRoot, canonical: actualPackRoot };
  } catch {
    return undefined;
  }
}

async function safeManifestFile(packRoot: ValidatedPackRoot, name: string): Promise<ManifestFile> {
  const lexicalPath = resolve(packRoot.lexical, name);
  if (!isInside(packRoot.lexical, lexicalPath)) return { kind: "unsafe" };
  let metadata;
  try {
    metadata = await lstat(lexicalPath);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? { kind: "missing" } : { kind: "unsafe" };
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) return { kind: "unsafe" };
  try {
    const [currentPackRoot, actualPath] = await Promise.all([realpath(packRoot.lexical), realpath(lexicalPath)]);
    if (!sameCanonicalAbsolutePath(currentPackRoot, packRoot.canonical) ||
        !isInside(packRoot.canonical, actualPath) || !sameCanonicalAbsolutePath(actualPath, lexicalPath)) return { kind: "unsafe" };
    return { kind: "regular", path: actualPath };
  } catch {
    return { kind: "unsafe" };
  }
}

async function safeDocumentRoute(
  root: string,
  packRoot: ValidatedPackRoot,
  document: ManifestRecord,
  options: ServiceOptions,
  budget: ScopeOperationBudget
): Promise<{ document: ManifestRecord; recordIds: Set<string> } | undefined> {
  if (typeof document.path !== "string" || !safeRepositoryPath(document.path) ||
      !document.path.startsWith("docs/project-design/") ||
      !document.path.endsWith(".md")) return undefined;
  const lexicalPath = resolve(root, document.path);
  if (!isInside(packRoot.lexical, lexicalPath)) return undefined;
  const bytes = await readBoundedRepositoryMetadata(lexicalPath, packRoot.canonical, options, budget);
  if (!bytes) return undefined;
  try {
    const markdown = decodeFatalUtf8(bytes);
    const expression = /<!-- project-design-keeper:managed record-id="([A-Za-z0-9][A-Za-z0-9._:-]*)" content-hash="(sha256:[a-f0-9]{64})" -->/gu;
    const close = "<!-- /project-design-keeper:managed -->";
    const recordIds = new Set<string>();
    for (let match = expression.exec(markdown); match; match = expression.exec(markdown)) {
      const start = expression.lastIndex;
      const end = markdown.indexOf(close, start);
      if (end < 0) break;
      budget.deadline.check();
      if (sha256(Buffer.from(markdown.slice(start, end), "utf8")) === match[2]) recordIds.add(match[1]);
      expression.lastIndex = end + close.length;
    }
    return { document, recordIds };
  } catch {
    return undefined;
  }
}

async function documentsForContext(
  scope: ResolvedScope,
  manifest: Manifest | undefined,
  related: ManifestRecord[],
  query: string,
  paths: string[],
  options: ServiceOptions,
  budget: ScopeOperationBudget
): Promise<Record<string, unknown>[]> {
  if (!manifest) return [];
  if (manifest.documents.length > budget.maxFiles) {
    throw new Error(`Pack documents exceed the file limit of ${budget.maxFiles}`);
  }
  const packRoot = await safePackRoot(scope);
  if (!packRoot) return [];
  const relatedIds = new Set(related.flatMap((record) => typeof record.id === "string" ? [record.id] : []));
  const routed: Array<{ document: ManifestRecord; recordIds: Set<string> }> = [];
  for (let start = 0; start < manifest.documents.length; start += 8) {
    budget.deadline.check();
    const batch = await Promise.all(manifest.documents.slice(start, start + 8)
      .map((document) => safeDocumentRoute(scope.root, packRoot, document, options, budget)));
    routed.push(...batch.filter((route): route is { document: ManifestRecord; recordIds: Set<string> } => Boolean(route)));
  }
  const queryTerm = query.toLocaleLowerCase();
  return routed.filter(({ document, recordIds }) =>
    [...recordIds].some((id) => relatedIds.has(id)) ||
    (queryTerm.length > 0 && textOf(document).includes(queryTerm)) ||
    paths.some((path) => typeof document.path === "string" && pathApplies(document.path, path))
  ).map(({ document }) => documentSummary(document));
}

function assertContinuationCursorCurrent(cursor: ScopeCursorPayload, now: number): void {
  if (Number.isSafeInteger(now) && now >= cursor.expiresAt) {
    throw new ScopeSnapshotRestartError("expired");
  }
  assertCursorCurrent(cursor, now);
}

function evidenceForContext(
  chunks: Evidence[],
  query: string,
  requestedPaths: string[],
  requestedModules: string[],
  related: ManifestRecord[],
  modules: CandidateModule[],
  limit: number,
  options: ServiceOptions,
  budget: ScopeOperationBudget
): Evidence[] {
  const indexedChunks = chunkLookup(chunks);
  const seen = new Set<string>();
  const selected: Evidence[] = [];
  let sawReference = false;
  for (const record of related) {
    for (const reference of recordEvidence(record)) {
      sawReference = true;
      consumeSelectorWork(budget, options, "reference-index");
      const key = chunkKey(reference.path, reference.line);
      if (seen.has(key)) continue;
      seen.add(key);
      const chunk = referencedChunk(indexedChunks, reference);
      if (chunk) selected.push(chunk);
      if (selected.length >= limit) return selected;
    }
  }
  if (sawReference) return selected;
  const requestedModuleSet = new Set(requestedModules.map((requested) => requested.toLocaleLowerCase("en-US")));
  const modulePaths: string[] = [];
  for (const module of modules) {
    consumeSelectorWork(budget, options, "record-filter");
    const id = module.id.toLocaleLowerCase("en-US");
    let applies = requestedModuleSet.has(id);
    for (let separator = id.indexOf("."); !applies && separator >= 0; separator = id.indexOf(".", separator + 1)) {
      consumeSelectorWork(budget, options, "record-filter");
      applies = requestedModuleSet.has(id.slice(separator + 1));
    }
    if (applies) modulePaths.push(...module.paths);
  }
  const allowed = [...requestedPaths, ...modulePaths];
  const selectedPaths = allowed.length > 0 ? pathSelector(allowed, budget, options) : undefined;
  const queryTerm = query.toLocaleLowerCase();
  const filtered: Evidence[] = [];
  for (const chunk of chunks) {
    consumeSelectorWork(budget, options, "chunk-filter");
    if (queryTerm && !chunk.text.toLocaleLowerCase().includes(queryTerm)) continue;
    if (!selectedPaths && !queryTerm) continue;
    if (selectedPaths && !pathSelectorMatches(selectedPaths, chunk.path, budget, options)) continue;
    filtered.push(chunk);
  }
  return filtered.sort((left, right) => {
    const score = (value: string) => queryTerm ? value.toLocaleLowerCase().split(queryTerm).length - 1 : 0;
    return score(right.text) - score(left.text) || left.path.localeCompare(right.path) || left.line - right.line;
  }).slice(0, limit);
}

async function continuationScopeBinding(input: ScopeInput): Promise<{ root: string; scopePaths: string[]; cursorScopeKey: string }> {
  if (input.root) {
    const root = await canonical(input.root);
    const requested = repositoryPath(input.path ?? ".");
    if (isAbsolute(requested)) throw new Error("An absolute path is not allowed when root is supplied");
    const lexicalTarget = resolve(root, requested);
    if (!isInside(root, lexicalTarget)) throw new Error("Scope path escapes the supplied root");
    const scopePaths = [requested];
    return { root, scopePaths, cursorScopeKey: scopeCursorKey(root, scopePathsKey(scopePaths)) };
  }
  if (!input.path) throw new Error("A scope path or root is required");
  const root = await canonical(input.path);
  const scopePaths = ["."];
  return { root, scopePaths, cursorScopeKey: scopeCursorKey(root, scopePathsKey(scopePaths)) };
}

function explicitDriftScopePaths(input: Record<string, unknown>, budget: ScopeOperationBudget): string[] | undefined {
  const pack = typeof input.pack === "object" && input.pack !== null ? input.pack as Record<string, unknown> : undefined;
  const hasExplicitSelection = input.sourceRevision !== undefined || pack?.sourceRevision !== undefined || pack?.scope !== undefined;
  if (!hasExplicitSelection) return undefined;
  const previous = input.previousSnapshot ?? input.sourceRevision ?? pack?.sourceRevision;
  const selected = declaredScopePaths(pack, previous, budget);
  if (selected.length === 0) return undefined;
  const normalized = [...new Set(selected.map(repositoryPath))].sort((left, right) => left.localeCompare(right));
  return normalized.includes(".") ? ["."] : normalized;
}

interface DriftRequestScopeSelection {
  mode: "declared" | "explicit-path" | "implicit-root" | "path-root";
  scopePaths: string[];
}

function driftRequestScopeSelection(input: Record<string, unknown>, budget: ScopeOperationBudget): DriftRequestScopeSelection {
  const explicit = explicitDriftScopePaths(input, budget);
  if (explicit) return { mode: "declared", scopePaths: explicit };
  const source = scopeInput(input);
  if (source.root) {
    return {
      mode: source.path === undefined ? "implicit-root" : "explicit-path",
      scopePaths: [repositoryPath(source.path ?? ".")]
    };
  }
  return { mode: "path-root", scopePaths: ["."] };
}

function driftRequestCursorScopeKey(root: string, selection: DriftRequestScopeSelection): string {
  return scopeCursorKey(root, scopePathsKey([`@drift-request:${selection.mode}`, ...selection.scopePaths]));
}

async function driftContinuationScopeBinding(
  input: Record<string, unknown>,
  options: ServiceOptions
): Promise<{ root: string; scopePaths: string[]; cursorScopeKey: string }> {
  const binding = await continuationScopeBinding(scopeInput(input));
  const selection = driftRequestScopeSelection(input, createScopeOperationBudget(options));
  return {
    ...binding,
    scopePaths: selection.scopePaths,
    cursorScopeKey: driftRequestCursorScopeKey(binding.root, selection)
  };
}

const driftCursorSnapshotPattern = /^(sha256:[a-f0-9]{64})@([a-f0-9]{64})$/u;

function driftCursorSnapshotBinding(snapshotId: string, storageScopePaths: readonly string[]): string {
  return `${snapshotId}@${scopePathsKey([...storageScopePaths])}`;
}

function driftCursorStorageBinding(
  root: string,
  cursorSnapshotId: string,
  legacyCursorScopeKey: string
): { snapshotId: string; cursorScopeKey: string } {
  const match = driftCursorSnapshotPattern.exec(cursorSnapshotId);
  return match
    ? { snapshotId: match[1]!, cursorScopeKey: scopeCursorKey(root, match[2]!) }
    : { snapshotId: cursorSnapshotId, cursorScopeKey: legacyCursorScopeKey };
}

function publicScopePaths(input: ScopeInput, root: string, internalScopePaths: readonly string[]): string[] {
  // Preserve the original scan_scope contract for path-only calls while the
  // immutable v3 snapshot and cursor binding use repository-relative paths.
  return input.root === undefined && input.path !== undefined ? [root] : [...internalScopePaths];
}

export async function scanScope(
  input: ScopeInput & { previousSnapshot?: unknown; view?: unknown; cursor?: unknown; limit?: unknown },
  options: ServiceOptions = {}
): Promise<ScanResult> {
  const view = scanView(input.view);
  const cursor = typeof input.cursor === "string" ? input.cursor : input.cursor === undefined ? undefined : (() => {
    throw new Error("Scan cursor must be a string");
  })();
  if (cursor !== undefined) {
    if (view === "summary") throw new Error("A scan cursor requires files or evidence view");
    const binding = await continuationScopeBinding(input);
    const now = options.now?.() ?? Date.now();
    const codec = await createCursorCodec(options, binding.root);
    const decoded = codec.decode(cursor, parseScopeCursorPayload);
    assertContinuationCursorCurrent(decoded, now);
    if (decoded.scopeKey !== binding.cursorScopeKey || decoded.view !== view) {
      throw new Error("Scan cursor does not belong to this root, scope, or view");
    }
    const loaded = await loadScopeIndex({
      options,
      projectRoot: binding.root,
      scopeKey: decoded.scopeKey,
      snapshotId: decoded.snapshotId,
      now
    });
    if (decoded.expiresAt !== loaded.expiresAt) {
      throw new ScopeSnapshotRestartError("corrupt");
    }
    const base: ScanResult = {
      schemaVersion: 2,
      snapshotId: loaded.snapshotId,
      scope: { root: binding.root, paths: publicScopePaths(input, binding.root, loaded.scopePaths) },
      totals: {
        files: loaded.totals.files,
        evidence: loaded.totals.evidence,
        omitted: loaded.totals.omitted
      },
      candidateModules: loaded.candidateModules.slice(0, 200)
    };
    const limit = scanLimit(input.limit);
    const byteBudget = Math.max(16 * 1024, 1024 * 1024 - Buffer.byteLength(JSON.stringify(base), "utf8") - 4096);
    if (view === "files") {
      const page = await pageItems({
        items: loaded.files,
        limit,
        codec,
        now,
        expiresAt: loaded.expiresAt,
        cursor,
        snapshotId: loaded.snapshotId,
        scopeKey: loaded.cursorScopeKey,
        view,
        byteBudget
      });
      return { ...base, ...page };
    }
    const page = await pageItems({
      items: loaded.evidence,
      limit,
      codec,
      now,
      expiresAt: loaded.expiresAt,
      cursor,
      snapshotId: loaded.snapshotId,
      scopeKey: loaded.cursorScopeKey,
      view,
      byteBudget
    });
    return { ...base, ...page };
  }

  const result = await scan(input, options);
  const base: ScanResult = {
    schemaVersion: 2,
    snapshotId: result.snapshotId,
    scope: { root: result.root, paths: publicScopePaths(input, result.root, result.scopePaths) },
    ...(result.repository ? { repository: result.repository } : {}),
    totals: { files: result.indexedFiles.length, evidence: result.chunks.length, omitted: result.omitted },
    candidateModules: result.candidateModules.slice(0, 200)
  };
  if (view === "summary") {
    return base;
  }
  const limit = scanLimit(input.limit);
  const now = options.now?.() ?? Date.now();
  const codec = await createCursorCodec(options, result.root);
  const expiresAt = result.snapshotExpiresAt;
  if (view === "files") {
    const files: ScopeFileEntry[] = result.indexedFiles;
    const byteBudget = Math.max(16 * 1024, 1024 * 1024 - Buffer.byteLength(JSON.stringify(base), "utf8") - 4096);
    const page = await pageItems({
      items: files, limit, codec, now, expiresAt, cursor,
      snapshotId: result.snapshotId, scopeKey: result.cursorScopeKey, view, byteBudget
    });
    return { ...base, ...page };
  }
  const byteBudget = Math.max(16 * 1024, 1024 * 1024 - Buffer.byteLength(JSON.stringify(base), "utf8") - 4096);
  const page = await pageItems({
    items: result.chunks, limit, codec, now, expiresAt, cursor,
    snapshotId: result.snapshotId, scopeKey: result.cursorScopeKey, view, byteBudget
  });
  return { ...base, ...page };
}

export async function snapshot(input: ScopeInput & { previousSnapshot?: unknown }, options: ServiceOptions = {}): Promise<Snapshot> {
  return (await scan(input, options)).snapshot;
}

function filterEvidenceChunks(
  chunks: readonly Evidence[],
  query: string,
  referenceRecords: readonly ManifestRecord[] | undefined,
  limit: number,
  options: ServiceOptions,
  budget: ScopeOperationBudget
): Evidence[] {
  let referenced: Set<string> | undefined;
  if (referenceRecords) {
    referenced = new Set<string>();
    for (const record of referenceRecords) {
      for (const reference of recordEvidence(record)) {
        consumeSelectorWork(budget, options, "reference-index");
        referenced.add(chunkKey(reference.path, reference.line));
      }
    }
  }
  const matches: Evidence[] = [];
  for (const chunk of chunks) {
    consumeSelectorWork(budget, options, "chunk-filter");
    if (chunk.text.includes(query) && (!referenced || referenced.has(chunkKey(chunk.path, chunk.line)))) {
      matches.push(chunk);
      if (matches.length >= limit) break;
    }
  }
  return matches;
}

export async function searchEvidence(input: Record<string, unknown>, options: ServiceOptions = {}): Promise<{ matches: Evidence[] }> {
  const query = typeof input.query === "string" ? input.query : "";
  if (!query) return { matches: [] };
  const budget = createScopeOperationBudget(options);
  const result = await scan(scopeInput(input), options, true, budget);
  const manifest = await manifestFor(result, options, budget);
  const domains = input.domain ?? input.domains;
  const statuses = input.status ?? input.statuses;
  if (asArray(domains).length === 0 && asArray(statuses).length === 0) {
    return { matches: filterEvidenceChunks(result.chunks, query, undefined, 100, options, budget) };
  }
  const records = filteredRecords(
    matchingRecords(manifest, query, [], [], result.chunks, options, budget),
    domains,
    statuses,
    options,
    budget
  );
  return {
    matches: filterEvidenceChunks(result.chunks, query, records, 100, options, budget)
  };
}

export async function queryContext(input: Record<string, unknown>, options: ServiceOptions = {}): Promise<Record<string, unknown>> {
  const query = typeof input.query === "string" ? input.query : "";
  const paths = asArray(input.paths);
  const modules = asArray(input.modules ?? input.module);
  const maxRecords = boundedInteger(input.maxRecords, 20, 100, "maxRecords");
  const maxEvidence = boundedInteger(input.maxEvidence, 100, 500, "maxEvidence");
  const budget = createScopeOperationBudget(options);
  const scope = await resolveScope(scopeInput(input), options, budget);
  const manifest = await manifestFor(scope, options, budget);
  const evidencePaths = manifest ? manifestEvidencePaths(manifest, budget) : [];
  const result = manifest && evidencePaths.length > 0
    ? await scanSelectedPaths(scope.root, evidencePaths, manifest.sourceRevision, options, false, budget)
    : await scan(scopeInput(input), options, false, budget);
  const related = matchingRecords(manifest, query, paths, modules, result.chunks, options, budget).slice(0, maxRecords);
  const verified = freshnessFor(result, manifest?.sourceRevision, related, options.now ?? Date.now, manifest?.schemaVersion);
  const currentStates = verified.records.filter((state) => {
    const lifecycle = state.record.lifecycle;
    const terminal = state.record.status === "superseded" ||
      (lifecycle && typeof lifecycle === "object" && !Array.isArray(lifecycle) && (lifecycle as ManifestRecord).state === "terminal");
    return state.verification === "verified" && !terminal;
  });
  const currentRecords = currentStates.map((state) => state.record as ManifestRecord);
  const withheldRecords = verified.records.flatMap((state) => {
    const lifecycle = state.record.lifecycle;
    const terminal = state.record.status === "superseded" ||
      (lifecycle && typeof lifecycle === "object" && !Array.isArray(lifecycle) && (lifecycle as ManifestRecord).state === "terminal");
    const id = typeof state.record.id === "string" ? state.record.id : "unknown-record";
    if (terminal) return [{ id, reason: "terminal", reasons: state.reasons }];
    if (state.verification === "historical") return [{ id, reason: "stale", reasons: state.reasons }];
    if (state.verification === "unverified") return [{ id, reason: "unverified", reasons: state.reasons }];
    return [];
  });
  // A manifest match that is entirely withheld must not fall back to raw repository
  // evidence or document-name matching: doing so would leak stale/unverified design
  // content into the current-context channel.
  const hasOnlyWithheldMatches = related.length > 0 && currentRecords.length === 0;
  const context = hasOnlyWithheldMatches
    ? []
    : evidenceForContext(result.chunks, query, paths, modules, currentRecords, result.candidateModules, maxEvidence, options, budget);
  const documents = hasOnlyWithheldMatches
    ? []
    : await documentsForContext(result, manifest, currentRecords, query, paths, options, budget);
  return {
    context,
    records: currentStates.map((state) => ({ ...state, record: recordSummary(state.record as ManifestRecord) })),
    withheld: {
      counts: {
        stale: withheldRecords.filter((record) => record.reason === "stale").length,
        unverified: withheldRecords.filter((record) => record.reason === "unverified").length,
        terminal: withheldRecords.filter((record) => record.reason === "terminal").length
      },
      records: withheldRecords
    },
    documents,
    conflicts: currentRecords.flatMap((record) => asArray(record.conflicts)),
    openQuestions: currentRecords.flatMap((record) => asArray(record.openQuestions)),
    freshness: verified.freshness
  };
}

export async function detectDrift(input: Record<string, unknown>, options: ServiceOptions = {}): Promise<Record<string, unknown>> {
  const view = input.view ?? "summary";
  if (view !== "summary" && view !== "details") throw new Error("Drift view must be summary or details");
  const cursor = typeof input.cursor === "string" ? input.cursor : input.cursor === undefined ? undefined : (() => {
    throw new Error("Drift cursor must be a string");
  })();
  if (cursor !== undefined) {
    if (view !== "details") throw new Error("A drift cursor requires details view");
    const binding = await driftContinuationScopeBinding(input, options);
    const now = options.now?.() ?? Date.now();
    const codec = await createCursorCodec(options, binding.root);
    const decoded = codec.decode(cursor, parseScopeCursorPayload);
    assertContinuationCursorCurrent(decoded, now);
    if (decoded.scopeKey !== binding.cursorScopeKey || decoded.view !== "details") {
      throw new Error("Drift cursor does not belong to this root, scope, or view");
    }
    const storage = driftCursorStorageBinding(binding.root, decoded.snapshotId, decoded.scopeKey);
    const loaded = await loadScopeIndex({
      options,
      projectRoot: binding.root,
      scopeKey: storage.cursorScopeKey,
      snapshotId: storage.snapshotId,
      now
    });
    if (decoded.expiresAt !== loaded.expiresAt) {
      throw new ScopeSnapshotRestartError("corrupt");
    }
    if (!loaded.details || !loaded.driftSummary) throw new ScopeSnapshotRestartError("corrupt");
    const byteBudget = 1024 * 1024 - Buffer.byteLength(JSON.stringify(loaded.driftSummary), "utf8") - 4096;
    const page = await pageItems({
      items: loaded.details,
      limit: scanLimit(input.limit),
      codec,
      now,
      expiresAt: loaded.expiresAt,
      cursor,
      snapshotId: decoded.snapshotId,
      scopeKey: binding.cursorScopeKey,
      view: "details",
      byteBudget
    });
    return { ...loaded.driftSummary, ...page };
  }

  const source = scopeInput(input);
  const budget = createScopeOperationBudget(options);
  const scope = await resolveScope(source, options, budget);
  const manifest = await manifestFor(scope, options, budget);
  const pack = typeof input.pack === "object" && input.pack !== null ? input.pack as Record<string, unknown> : undefined;
  const directPackRecords = pack ? boundedPackRecords(pack.records, options, budget) : undefined;
  const packLimits = resolveKeeperLimits(options.limits).pack;
  const rawRequiredEvidence = pack?.requiredEvidence ?? input.requiredEvidence;
  if (Array.isArray(rawRequiredEvidence) && rawRequiredEvidence.length > packLimits.maxEvidencePerRecord) {
    throw new Error(`Pack required evidence exceeds the limit of ${packLimits.maxEvidencePerRecord}`);
  }
  const previousSnapshot = input.previousSnapshot ?? input.sourceRevision ?? pack?.sourceRevision ?? manifest?.sourceRevision;
  const hasDeclaredPackRevision = input.sourceRevision !== undefined || pack?.sourceRevision !== undefined || manifest?.sourceRevision !== undefined ||
    (pack?.scope !== undefined) || (manifest?.scope !== undefined);
  const scopePaths = hasDeclaredPackRevision ? declaredScopePaths(pack ?? manifest, previousSnapshot, budget) : [];
  const result = scopePaths.length > 0
    ? await scanSelectedPaths(scope.root, scopePaths, previousSnapshot, options, false, budget)
    : await scan({ ...source, previousSnapshot }, options, false, budget);
  const requiredEvidence = asArray(rawRequiredEvidence);
  const compatibilityWork = new CounterBudget("Drift compatibility evidence work", Math.max(1024, budget.maxEvidence * 8));
  const compatibilityDrift: Array<{ kind: "missing-evidence"; evidence: string }> = [];
  for (const required of requiredEvidence) {
    budget.deadline.check();
    let found = false;
    for (const chunk of result.chunks) {
      compatibilityWork.consume();
      budget.deadline.check();
      if (chunk.text.includes(required)) {
        found = true;
        break;
      }
    }
    if (!found) compatibilityDrift.push({ kind: "missing-evidence", evidence: required });
  }
  const records = directPackRecords ?? manifest?.records ?? [];
  const changed = new Set(result.changed.map(pathKey));
  const deleted = new Set(result.deleted.map(pathKey));
  const currentFiles = new Set(Object.keys(result.fingerprints).map(pathKey));
  const indexedChunks = chunkLookup(result.chunks);
  const filesByPath = new Map(result.indexedFiles.map((file) => [pathKey(file.path), file]));
  const evidenceByPath = new Map<string, Map<number, Evidence>>();
  for (const chunk of result.chunks) {
    budget.deadline.check();
    const key = pathKey(chunk.path);
    const lines = evidenceByPath.get(key) ?? new Map<number, Evidence>();
    lines.set(chunk.line, chunk);
    evidenceByPath.set(key, lines);
  }
  const recordEvidenceWork = new CounterBudget(
    "Drift record evidence work",
    Math.max(1, packLimits.maxRecords * packLimits.maxEvidencePerRecord)
  );
  const recordDrift: Array<Record<string, unknown>> = [];
  for (const record of records) {
    budget.deadline.check();
    for (const parsed of recordEvidence(record)) {
      recordEvidenceWork.consume();
      budget.deadline.check();
      const evidence = parsed.reference;
      const recordId = typeof record.id === "string" ? record.id : "unknown-record";
      const key = pathKey(parsed.path);
      const file = filesByPath.get(key);
      if (deleted.has(key)) recordDrift.push({ kind: "deleted-evidence", recordId, evidence });
      else if (!currentFiles.has(key) || !file) recordDrift.push({ kind: "missing-evidence", recordId, evidence });
      else if ((parsed.endLine !== undefined && parsed.endLine > file.lineCount) || !referencedChunk(indexedChunks, parsed)) {
        recordDrift.push({ kind: "invalid-evidence", recordId, evidence, reason: "line-invalid" });
      } else if (changed.has(key)) recordDrift.push({ kind: "modified-evidence", recordId, evidence });
    }
  }
  const relocationWork = new CounterBudget("Drift relocation work", Math.max(1024, budget.maxEvidence * 8));
  const relocationCandidates: ScopeRelocationCandidate[] = [];
  for (const record of records) {
    budget.deadline.check();
    for (const evidence of typedRecordEvidence(record)) {
      budget.deadline.check();
      const key = pathKey(evidence.path);
      const file = filesByPath.get(key);
      if (!file || evidence.startLine > file.lineCount || evidence.endLine > file.lineCount) continue;
      const fileEvidence = evidenceByPath.get(key) ?? new Map<number, Evidence>();
      const span = evidence.endLine - evidence.startLine + 1;
      const excerptAt = (startLine: number): string | undefined => {
        const parts: string[] = [];
        for (let offset = 0; offset < span; offset += 1) {
          relocationWork.consume();
          budget.deadline.check();
          const chunk = fileEvidence.get(startLine + offset);
          if (!chunk || chunk.truncated) return undefined;
          parts.push(chunk.text);
        }
        return parts.join("\n");
      };
      const current = excerptAt(evidence.startLine);
      if (current !== undefined && sha256(Buffer.from(current, "utf8")) === evidence.excerptHash) continue;
      const matches: number[] = [];
      for (let line = 1; line + span - 1 <= file.lineCount; line += 1) {
        budget.deadline.check();
        const excerpt = excerptAt(line);
        if (excerpt !== undefined && sha256(Buffer.from(excerpt, "utf8")) === evidence.excerptHash) {
          matches.push(line);
          if (matches.length > 1) break;
        }
      }
      if (matches.length !== 1 || matches[0] === evidence.startLine) continue;
      const relocatedEnd = matches[0] + span - 1;
      relocationCandidates.push({
        recordId: typeof record.id === "string" ? record.id : "unknown-record",
        evidenceIndex: evidence.evidenceIndex,
        path: evidence.path,
        from: { startLine: evidence.startLine, ...(evidence.endLine !== evidence.startLine ? { endLine: evidence.endLine } : {}) },
        to: { startLine: matches[0], ...(relocatedEnd !== matches[0] ? { endLine: relocatedEnd } : {}) }
      });
    }
  }
  const archiveEligibleRecordIds = records.flatMap((record) => {
    const lifecycle = record.lifecycle;
    if (!lifecycle || typeof lifecycle !== "object" || Array.isArray(lifecycle)) return [];
    const terminal = lifecycle as Record<string, unknown>;
    return terminal.state === "terminal" && Number.isSafeInteger(terminal.confirmedRefreshes) && Number(terminal.confirmedRefreshes) >= 2 && typeof record.id === "string"
      ? [record.id]
      : [];
  });
  const drift = [...recordDrift, ...compatibilityDrift];
  const invalidatedRecordIds = [...new Set(recordDrift.flatMap((item) => "recordId" in item && typeof item.recordId === "string" ? [item.recordId] : []))];
  const hasRevision = Object.keys(revisionFiles(previousSnapshot)).length > 0;
  const stale = result.changed.length > 0 || result.new.length > 0 || result.deleted.length > 0 || drift.length > 0;
  const freshness: "unknown" | "stale" | "fresh" = !hasRevision ? "unknown" : stale ? "stale" : "fresh";
  const summary = {
    freshness,
    counts: {
      new: result.new.length,
      modified: result.changed.length,
      deleted: result.deleted.length,
      invalidated: invalidatedRecordIds.length
    },
    invalidatedRecordIds,
    relocationCandidates,
    archiveEligibleRecordIds
  };
  if (view === "summary") {
    return summary;
  }
  const details = [
    ...result.new.map((path) => ({ kind: "new", path })),
    ...result.changed.map((path) => ({ kind: "modified", path })),
    ...result.deleted.map((path) => ({ kind: "deleted", path })),
    ...drift
  ];
  const limit = scanLimit(input.limit);
  result.snapshotId = scopeSnapshotIdForContent({
    scopePaths: result.scopePaths,
    files: result.indexedFiles,
    evidence: result.chunks,
    candidateModules: result.candidateModules,
    omissions: result.omissions,
    details,
    driftSummary: summary
  });
  const persisted = await persistScopeIndex({
    options,
    projectRoot: result.root,
    scopePaths: result.scopePaths,
    snapshotId: result.snapshotId,
    files: result.indexedFiles,
    evidence: result.chunks,
    candidateModules: result.candidateModules,
    omissions: result.omissions,
    details,
    driftSummary: summary
  });
  result.snapshotExpiresAt = persisted.expiresAt;
  const now = options.now?.() ?? Date.now();
  const requestScopeSelection = driftRequestScopeSelection(input, budget);
  const page = await pageItems({
    items: details,
    limit,
    codec: await createCursorCodec(options, result.root),
    now,
    expiresAt: result.snapshotExpiresAt,
    cursor,
    snapshotId: driftCursorSnapshotBinding(result.snapshotId, result.scopePaths),
    scopeKey: driftRequestCursorScopeKey(result.root, requestScopeSelection),
    view: "details",
    byteBudget: 1024 * 1024 - Buffer.byteLength(JSON.stringify(summary), "utf8") - 4096
  });
  return { ...summary, ...page };
}

export function createScopeService(options: ServiceOptions = {}) {
  return {
    resolveScope,
    scanScope: (input: Parameters<typeof scanScope>[0]) => scanScope(input, options),
    searchEvidence: (input: Record<string, unknown>) => searchEvidence(input, options),
    detectDrift: (input: Record<string, unknown>) => detectDrift(input, options),
    queryContext: (input: Record<string, unknown>) => queryContext(input, options),
    snapshot: (input: ScopeInput & { previousSnapshot?: unknown }) => snapshot(input, options)
  };
}
