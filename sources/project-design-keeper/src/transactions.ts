import { createHash, randomUUID } from "node:crypto";
import type { BigIntStats } from "node:fs";
import { lstat, mkdir, open, opendir, readdir, realpath, rename, rmdir, unlink, type FileHandle } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, win32 } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  createScopeOperationBudget,
  isInside,
  resolveScope,
  sha256,
  snapshotForFingerprint,
  type ScopeOperationBudget
} from "./scope/index.js";
import {
  assertSecureOwnerFileMetadata,
  captureSecurePathIdentity,
  createSecureCacheDirectory,
  prepareSecureCache,
  publishExclusiveFile,
  reconcileExactRemovalIntents,
  resolveCacheDirectory,
  safeRemoveExactCacheFile,
  sameFilesystemPath,
  validateCacheFile,
  validateCacheFiles,
  validateSecurePathIdentity,
  type SecureCacheLayout,
  type SecurePathIdentity
} from "./security/cache.js";
import { withProcessLease } from "./security/process-lock.js";
import { validateRedundancyDecisions, type RedundancyDecision } from "./knowledge/redundancy.js";
import { validateArchiveTransition } from "./knowledge/archive.js";
import { loadAndValidateHistoryOverlay } from "./knowledge/history-integrity.js";
import { decodeCanonicalJsonLines } from "./knowledge/jsonl.js";
import {
  createApplyApprovalAuthority,
  type ApplyApprovalAuthority,
  type ApplyAuthorization,
  type ChangesetApprovalBinding
} from "./security/approval.js";
import {
  assertSerializedWithin,
  assertToolResultBudget,
  ByteBudget,
  CounterBudget,
  DeadlineBudget,
  keeperLimits,
  resolveKeeperLimits,
  type KeeperLimits
} from "./security/limits.js";
import {
  createChangesetStore,
  persistedDiffDigest,
  type LoadedAuthenticatedChangeset
} from "./changesets/store.js";
import {
  stableId,
  assertPackValidationInputBounds,
  changesetLifetimeMs,
  safeRepositoryPath,
  validatePack,
  windowsRepositoryPathKey,
  type ManagedBlockInput,
  type PersistedChange,
  type PersistedChangeset,
  type RequestedChange,
  type ScopeInput,
  type ServiceOptions
} from "./types/schema.js";
import { freezeRuntimePolicy, managedReadLimits, sameRuntimePolicy } from "./settings/policy.js";
import { decodeStoredText, encodeStoredText } from "./security/text-storage.js";

const managedRoots = ["docs/project-design", ".agents/skills/project-design-context"] as const;
const managedClose = "<!-- /project-design-keeper:managed -->";

export { resolveCacheDirectory } from "./security/cache.js";

function pathHash(contents: Buffer | undefined): string | null {
  return contents === undefined ? null : sha256(contents);
}

function equalOptionalBytes(left: Buffer | undefined, right: Buffer | undefined): boolean {
  return left === undefined ? right === undefined : right !== undefined && left.equals(right);
}

interface ProjectFileReadBudget {
  readonly label: string;
  readonly maxFileBytes: number;
  readonly files: CounterBudget;
  readonly accountedFiles: Set<string>;
  readonly aggregate: ByteBudget;
  readonly deadline: DeadlineBudget;
}

function projectFileReadBudget(
  label: string,
  maxFileBytes: number,
  maxAggregateBytes: number,
  maxFiles: number,
  deadlineMs: number
): ProjectFileReadBudget {
  return {
    label,
    maxFileBytes,
    files: new CounterBudget(`${label} files`, maxFiles),
    accountedFiles: new Set<string>(),
    aggregate: new ByteBudget(label, maxAggregateBytes),
    deadline: new DeadlineBudget(label, deadlineMs)
  };
}

function canonicalRelativePath(requestedPath: string): { path: string; key: string; managedRoot: string } {
  if (!requestedPath || isAbsolute(requestedPath) || win32.isAbsolute(requestedPath)) {
    throw new Error("Output path must be repository-relative");
  }
  const rawParts = requestedPath.replaceAll("\\", "/").split("/");
  const parts: string[] = [];
  for (const rawPart of rawParts) {
    if (rawPart === ".") continue;
    if (!rawPart) throw new Error("Output path contains an invalid Windows path component");
    if (rawPart === "..") throw new Error("Output path traversal is not allowed");
    parts.push(rawPart);
  }
  const requestedCanonical = parts.join("/");
  if (!safeRepositoryPath(requestedCanonical)) throw new Error("Output path contains an invalid Windows path component");
  const lower = parts.map((part) => part.toLocaleLowerCase("en-US"));
  const managedRoot = managedRoots.find((candidate) => {
    const rootParts = candidate.split("/");
    return rootParts.every((part, index) => lower[index] === part.toLocaleLowerCase("en-US")) && parts.length > rootParts.length;
  });
  if (!managedRoot) throw new Error("Output path is outside managed project-design locations");
  const rootParts = managedRoot.split("/");
  const canonicalParts = [...rootParts, ...parts.slice(rootParts.length)];
  const path = canonicalParts.join("/");
  return { path, key: windowsRepositoryPathKey(path), managedRoot };
}

async function optionalLstat(path: string) {
  try {
    return await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

async function validateManagedRoots(root: string): Promise<void> {
  const repositoryRoot = await realpath(root);
  for (const managedRoot of managedRoots) {
    let current = repositoryRoot;
    for (const part of managedRoot.split("/")) {
      current = join(current, part);
      const metadata = await optionalLstat(current);
      if (!metadata) break;
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw new Error(`Managed root contains a symbolic-link, junction, reparse, or non-directory component: ${managedRoot}`);
      }
      const canonical = await realpath(current);
      if (!isInside(repositoryRoot, canonical) || !sameFilesystemPath(canonical, current)) {
        throw new Error(`Managed root resolves outside its repository or lexical root: ${managedRoot}`);
      }
    }
  }
  const manifestPath = join(repositoryRoot, "docs", "project-design", "manifest.json");
  const manifestMetadata = await optionalLstat(manifestPath);
  if (manifestMetadata) {
    if (manifestMetadata.isSymbolicLink() || !manifestMetadata.isFile()) {
      throw new Error("Project design manifest must be an ordinary file, not a symbolic link, junction, reparse point, or directory");
    }
    const canonicalManifest = await realpath(manifestPath);
    if (!isInside(repositoryRoot, canonicalManifest) || !sameFilesystemPath(canonicalManifest, manifestPath)) {
      throw new Error("Project design manifest resolves outside its repository path");
    }
  }
}

async function rejectSymlinkComponents(root: string, relativePath: string): Promise<void> {
  let current = root;
  for (const part of relativePath.split("/")) {
    current = join(current, part);
    const metadata = await optionalLstat(current);
    if (metadata?.isSymbolicLink()) throw new Error(`Output path contains a symbolic-link component: ${relativePath}`);
  }
}

async function canonicalOutput(root: string, requestedPath: string): Promise<{ path: string; key: string; target: string }> {
  await validateManagedRoots(root);
  const canonical = canonicalRelativePath(requestedPath);
  const target = resolve(root, ...canonical.path.split("/"));
  const managedRootPath = resolve(root, ...canonical.managedRoot.split("/"));
  if (!isInside(root, target)) throw new Error("Output path escapes the repository root");
  await rejectSymlinkComponents(root, canonical.path);

  const managedRootMetadata = await optionalLstat(managedRootPath);
  if (managedRootMetadata) {
    const realManagedRoot = await realpath(managedRootPath);
    let existing = target;
    for (;;) {
      const metadata = await optionalLstat(existing);
      if (metadata) {
        const realExisting = await realpath(existing);
        if (!isInside(realManagedRoot, realExisting)) throw new Error("Output path resolves outside the real managed root");
        break;
      }
      existing = dirname(existing);
      if (!isInside(managedRootPath, existing)) break;
    }
  }
  return { path: canonical.path, key: canonical.key, target };
}

function requestedChanges(value: unknown): RequestedChange[] {
  if (!Array.isArray(value) || value.length === 0) throw new Error("At least one output change is required");
  return value.map((item, index) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) throw new Error(`Change ${index} is invalid`);
    const input = item as Record<string, unknown>;
    if (typeof input.path !== "string") throw new Error(`Change ${index} path is required`);
    const managed = input.managedBlock;
    const managedValue = typeof managed === "object" && managed !== null && !Array.isArray(managed)
      ? managed as Record<string, unknown>
      : undefined;
    const managedBlock = managedValue && typeof managedValue.recordId === "string" && typeof managedValue.content === "string"
      ? { recordId: managedValue.recordId, content: managedValue.content }
      : managedValue && typeof managedValue.recordId === "string" && managedValue.delete === true
        ? { recordId: managedValue.recordId, delete: true as const }
        : undefined;
    const variants = [typeof input.content === "string", input.delete === true, Boolean(managedBlock)].filter(Boolean).length;
    if (variants !== 1) throw new Error(`Change ${index} must specify exactly one of content, delete, or managedBlock`);
    if (managedBlock && !stableId.safeParse(managedBlock.recordId).success) throw new Error(`Change ${index} recordId is not stable`);
    return {
      path: input.path,
      ...(typeof input.content === "string" ? { content: input.content } : {}),
      ...(input.delete === true ? { delete: true as const } : {}),
      ...(managedBlock ? { managedBlock } : {}),
      ...(typeof input.expectedContentHash === "string" ? { expectedContentHash: input.expectedContentHash } : {})
    };
  });
}

function redundancyDecisions(value: unknown): RedundancyDecision[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length === 0) throw new Error("At least one redundancy decision is required");
  return value.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error(`Redundancy decision ${index} is invalid`);
    const decision = item as Record<string, unknown>;
    if (typeof decision.candidateId !== "string" || !["merge", "keep-separate", "defer"].includes(String(decision.decision))) {
      throw new Error(`Redundancy decision ${index} is invalid`);
    }
    if (decision.survivorId !== undefined && typeof decision.survivorId !== "string") {
      throw new Error(`Redundancy decision ${index} survivorId is invalid`);
    }
    return {
      candidateId: decision.candidateId,
      decision: decision.decision as RedundancyDecision["decision"],
      ...(typeof decision.survivorId === "string" ? { survivorId: decision.survivorId } : {})
    };
  });
}

function escapedRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

interface ParsedManagedDocument {
  valid: boolean;
  fullyOwned: boolean;
  blockIds: Set<string>;
  derivedIds: Set<string>;
  conflict?: string;
}

function parseManagedDocument(contents: string): ParsedManagedDocument {
  const expression = /<!-- project-design-keeper:managed record-id="([A-Za-z0-9][A-Za-z0-9._:-]*)" content-hash="(sha256:[a-f0-9]{64})" -->/gu;
  const derivedExpression = /<!-- project-design-keeper:derived document-id="([A-Za-z0-9][A-Za-z0-9._:-]*)" content-hash="(sha256:[a-f0-9]{64})" -->/gu;
  const blockIds = new Set<string>();
  const derivedIds = new Set<string>();
  const spans: Array<[number, number]> = [];
  let match: RegExpExecArray | null;
  while ((match = expression.exec(contents)) !== null) {
    const bodyStart = expression.lastIndex;
    const bodyEnd = contents.indexOf(managedClose, bodyStart);
    if (bodyEnd < 0) break;
    expression.lastIndex = bodyEnd + managedClose.length;
    if (blockIds.has(match[1])) return { valid: false, fullyOwned: false, blockIds, derivedIds, conflict: `Duplicate managed block: ${match[1]}` };
    if (sha256(Buffer.from(contents.slice(bodyStart, bodyEnd), "utf8")) !== match[2]) {
      return { valid: false, fullyOwned: false, blockIds, derivedIds, conflict: `Managed block ${match[1]} content hash does not match its marker` };
    }
    blockIds.add(match[1]);
    spans.push([match.index, expression.lastIndex]);
  }
  while ((match = derivedExpression.exec(contents)) !== null) {
    const derivedClose = "<!-- /project-design-keeper:derived -->";
    const bodyStart = derivedExpression.lastIndex;
    const bodyEnd = contents.indexOf(derivedClose, bodyStart);
    if (bodyEnd < 0) break;
    derivedExpression.lastIndex = bodyEnd + derivedClose.length;
    if (derivedIds.has(match[1])) return { valid: false, fullyOwned: false, blockIds, derivedIds, conflict: `Duplicate derived block: ${match[1]}` };
    if (sha256(Buffer.from(contents.slice(bodyStart, bodyEnd), "utf8")) !== match[2]) {
      return { valid: false, fullyOwned: false, blockIds, derivedIds, conflict: `Derived block ${match[1]} content hash does not match its marker` };
    }
    derivedIds.add(match[1]);
    spans.push([match.index, derivedExpression.lastIndex]);
  }
  spans.sort((left, right) => left[0] - right[0]);
  let surrounding = "";
  let offset = 0;
  for (const [start, end] of spans) {
    surrounding += contents.slice(offset, start);
    offset = end;
  }
  surrounding += contents.slice(offset);
  if (surrounding.includes("project-design-keeper:managed") || surrounding.includes("project-design-keeper:derived")) {
    return { valid: false, fullyOwned: false, blockIds, derivedIds, conflict: "Malformed managed or derived marker" };
  }
  const ownedBlocks = blockIds.size + derivedIds.size;
  return { valid: ownedBlocks > 0, fullyOwned: ownedBlocks > 0 && surrounding.trim() === "", blockIds, derivedIds };
}

function hasOwnedMachineSchema(contents: Buffer): boolean {
  try {
    const value = JSON.parse(contents.toString("utf8")) as unknown;
    return typeof value === "object" && value !== null && !Array.isArray(value) &&
      (value as Record<string, unknown>).managedBy === "project-design-keeper" &&
      ((value as Record<string, unknown>).schemaVersion === "1.0" || (value as Record<string, unknown>).schemaVersion === "2.0" ||
        (value as Record<string, unknown>).schemaVersion === "3.0");
  } catch {
    return false;
  }
}

function parseCandidateManifest(contents: Buffer): Record<string, unknown> | undefined {
  try {
    const value = JSON.parse(contents.toString("utf8")) as unknown;
    return typeof value === "object" && value !== null && !Array.isArray(value) &&
      (value as Record<string, unknown>).managedBy === "project-design-keeper" &&
      typeof (value as Record<string, unknown>).schemaVersion === "string"
      ? value as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}

function conflictValidation(conflicts: string[]): Record<string, unknown> {
  return {
    valid: false,
    errors: conflicts.map((message) => ({
      code: /content hash/iu.test(message) ? "managed_block_hash_mismatch" : "candidate_conflict",
      path: "changes",
      message
    })),
    warnings: []
  };
}

const keeperSkillPathKey = windowsRepositoryPathKey(".agents/skills/project-design-context/SKILL.md");

function keeperSkillOwnership(contents: string): { owned: boolean; fullyOwned: boolean; conflict?: string } {
  const lines = contents.split("\n");
  if (lines.length < 7 || lines[0] !== "---" || lines[1] !== "name: project-design-context" ||
      !lines[2].startsWith("description: ") || lines[3] !== "metadata:" ||
      lines[4] !== "  managed-by: project-design-keeper" || lines[5] !== "---") {
    return { owned: false, fullyOwned: false, conflict: "Keeper Skill must use the unique canonical frontmatter envelope" };
  }
  const encodedDescription = lines[2].slice("description: ".length);
  let description: unknown;
  try {
    description = JSON.parse(encodedDescription) as unknown;
  } catch {
    return { owned: false, fullyOwned: false, conflict: "Keeper Skill description must be a canonical JSON string literal" };
  }
  if (typeof description !== "string" || JSON.stringify(description) !== encodedDescription || description.length === 0 || description.length > 1024 ||
      /[<>]/u.test(description) || !/^Use when\s+\S/iu.test(description) ||
      /(?:follow these steps|step-by-step|rewrite the project files)/iu.test(description)) {
    return { owned: false, fullyOwned: false, conflict: "Keeper Skill description must be nonempty trigger semantics only" };
  }
  const body = lines.slice(6).join("\n");
  const parsedBody = parseManagedDocument(body);
  if (!parsedBody.valid || !parsedBody.fullyOwned || parsedBody.derivedIds.size > 0) {
    return { owned: false, fullyOwned: false, conflict: parsedBody.conflict ?? "Keeper Skill body must contain only legal managed blocks" };
  }
  return { owned: true, fullyOwned: true };
}

function ownership(path: string, contents: Buffer): { owned: boolean; fullyOwned: boolean; conflict?: string } {
  if (windowsRepositoryPathKey(path) === keeperSkillPathKey) return keeperSkillOwnership(contents.toString("utf8"));
  if (path.toLocaleLowerCase("en-US").endsWith(".jsonl")) {
    const archivePath = windowsRepositoryPathKey(path).startsWith("docs/project-design/archive/");
    try {
      const values = decodeCanonicalJsonLines(contents, `Keeper archive output ${path}`).map(({ value }) => value);
      const generation = /\/generation-[0-9]{6}\.records\.jsonl$/u.test(windowsRepositoryPathKey(path));
      const tombstones = windowsRepositoryPathKey(path) === windowsRepositoryPathKey("docs/project-design/archive/tombstones.jsonl");
      const valid = archivePath && values.every((value) => {
        if (!value || typeof value !== "object" || Array.isArray(value)) return false;
        const item = value as Record<string, unknown>;
        return generation
          ? Boolean(item.record && typeof item.record === "object" && typeof item.contentHash === "string" && typeof item.archivedAt === "string")
          : tombstones && typeof item.id === "string" && typeof item.contentHash === "string" && typeof item.archivedAt === "string";
      });
      return { owned: valid, fullyOwned: valid, ...(valid ? {} : { conflict: "JSONL output is not a valid Keeper archive" }) };
    } catch {
      return { owned: false, fullyOwned: false, conflict: "JSONL output is not a valid Keeper archive" };
    }
  }
  if (path.toLocaleLowerCase("en-US").endsWith(".json")) {
    const owned = hasOwnedMachineSchema(contents);
    return { owned, fullyOwned: owned, ...(owned ? {} : { conflict: "JSON output lacks explicit Keeper ownership/schema" }) };
  }
  const parsed = parseManagedDocument(contents.toString("utf8"));
  return {
    owned: parsed.valid,
    fullyOwned: parsed.fullyOwned,
    ...(!parsed.valid ? { conflict: parsed.conflict ?? "Markdown output has no structurally valid managed block" } : {})
  };
}

function creationOwnership(path: string, contents: Buffer): { allowed: boolean; conflict?: string } {
  const candidate = ownership(path, contents);
  const machine = /\.jsonl?$/iu.test(path);
  const markdown = !machine;
  const allowed = markdown ? candidate.fullyOwned : candidate.owned;
  return {
    allowed,
    ...(!allowed ? { conflict: candidate.conflict ?? "new Markdown must contain only structurally valid managed blocks" } : {})
  };
}

function managedBlockHashes(contents: Buffer | string): Map<string, string> {
  const text = typeof contents === "string" ? contents : contents.toString("utf8");
  return new Map([...text.matchAll(
    /<!-- project-design-keeper:managed record-id="([A-Za-z0-9][A-Za-z0-9._:-]*)" content-hash="(sha256:[a-f0-9]{64})" -->/gu
  )].map((match) => [match[1], match[2]]));
}

function derivedReplacementAllowed(
  original: Buffer,
  candidate: Buffer,
  migratingToV2: boolean,
  allowSchemaMigrationRegrouping = false
): boolean {
  const before = parseManagedDocument(original.toString("utf8"));
  const after = parseManagedDocument(candidate.toString("utf8"));
  if (!before.valid || !before.fullyOwned || !after.valid || !after.fullyOwned || after.derivedIds.size !== 1) {
    return false;
  }
  if (before.blockIds.size === 0 && before.derivedIds.size === 1 && after.blockIds.size === 0) {
    return [...before.derivedIds][0] === [...after.derivedIds][0];
  }
  if (allowSchemaMigrationRegrouping && migratingToV2 && before.blockIds.size > 0) return true;
  if (!migratingToV2 || before.blockIds.size === 0 || before.derivedIds.size !== 0) return false;
  if (after.blockIds.size === 0) return true;
  if (before.blockIds.size !== after.blockIds.size) return false;
  const beforeHashes = managedBlockHashes(original);
  const afterHashes = managedBlockHashes(candidate);
  return [...beforeHashes].every(([id, fingerprint]) => afterHashes.get(id) === fingerprint);
}

async function migrationPreservationDiagnostics(
  root: string,
  currentPack: Record<string, unknown>,
  candidatePack: Record<string, unknown>,
  overlay: ReadonlyMap<string, Buffer | undefined>,
  readCurrentDocument: (path: string) => Promise<Buffer | undefined>
): Promise<Array<{ code: string; path: string; message: string }>> {
  if (!new Set(["1.0", "2.0"]).has(String(currentPack.schemaVersion)) || candidatePack.schemaVersion !== "3.0") return [];
  const diagnostics: Array<{ code: string; path: string; message: string }> = [];
  const normalizedOverlay = new Map([...overlay].map(([path, contents]) => [windowsRepositoryPathKey(path), contents]));

  const documentBlocks = async (pack: Record<string, unknown>, candidate: boolean): Promise<Map<string, string>> => {
    const blocks = new Map<string, string>();
    const documents = Array.isArray(pack.documents) ? pack.documents : [];
    for (const [index, value] of documents.entries()) {
      if (!value || typeof value !== "object" || Array.isArray(value) || typeof (value as Record<string, unknown>).path !== "string") continue;
      const path = (value as Record<string, unknown>).path as string;
      if (!safeRepositoryPath(path, true)) {
        diagnostics.push({ code: "migration_document_invalid", path: `documents.${index}.path`, message: `Migration document path is unsafe: ${path}` });
        continue;
      }
      let contents: Buffer | undefined;
      const key = windowsRepositoryPathKey(path);
      if (candidate && normalizedOverlay.has(key)) contents = normalizedOverlay.get(key);
      else contents = await readCurrentDocument(path);
      if (!contents) {
        diagnostics.push({ code: "migration_document_missing", path, message: `Migration document is missing: ${path}` });
        continue;
      }
      for (const [id, fingerprint] of managedBlockHashes(contents)) {
        if (blocks.has(id)) diagnostics.push({ code: "migration_record_duplicate", path, message: `Migration record block is duplicated: ${id}` });
        else blocks.set(id, fingerprint);
      }
    }
    return blocks;
  };

  const currentBlocks = await documentBlocks(currentPack, false);
  const candidateBlocks = await documentBlocks(candidatePack, true);
  const currentRecords = Array.isArray(currentPack.records) ? currentPack.records : [];
  const candidateRecords = new Map((Array.isArray(candidatePack.records) ? candidatePack.records : [])
    .filter((value): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value) && typeof (value as Record<string, unknown>).id === "string")
    .map((record) => [record.id as string, record]));
  const preservedFields = ["domain", "scope", "statement", "impact", "strength", "approval", "supersedes", "supersededBy"] as const;

  for (const [index, value] of currentRecords.entries()) {
    if (!value || typeof value !== "object" || Array.isArray(value) || typeof (value as Record<string, unknown>).id !== "string") continue;
    const record = value as Record<string, unknown>;
    const id = record.id as string;
    const candidate = candidateRecords.get(id);
    if (!candidate) {
      diagnostics.push({ code: "migration_record_missing", path: `records.${index}.id`, message: `Schema migration must preserve record ${id}` });
      continue;
    }
    if (!currentBlocks.has(id) || candidateBlocks.get(id) !== currentBlocks.get(id)) {
      diagnostics.push({ code: "migration_managed_body_changed", path: `records.${index}.id`, message: `Schema migration must preserve the exact managed body for ${id}` });
    }
    for (const field of preservedFields) {
      if (!isDeepStrictEqual(candidate[field], record[field])) {
        diagnostics.push({ code: "migration_record_changed", path: `records.${index}.${field}`, message: `Schema migration must preserve ${field} for ${id}` });
      }
    }
    if (candidate.assertedConfidence !== record.confidence) {
      diagnostics.push({ code: "migration_confidence_changed", path: `records.${index}.assertedConfidence`, message: `Schema migration must preserve asserted confidence for ${id}` });
    }
    if (!isDeepStrictEqual(candidate.legacyEvidence, record.evidence)) {
      diagnostics.push({ code: "migration_evidence_history_missing", path: `records.${index}.legacyEvidence`, message: `Schema migration must retain legacy evidence for ${id}` });
    }
    if (candidate.legacyStatus !== record.status) {
      diagnostics.push({ code: "migration_status_history_missing", path: `records.${index}.legacyStatus`, message: `Schema migration must retain legacy status for ${id}` });
    }
    if (record.status === "superseded") {
      const lifecycle = candidate.lifecycle;
      const terminal = lifecycle && typeof lifecycle === "object" && !Array.isArray(lifecycle)
        ? lifecycle as Record<string, unknown>
        : undefined;
      if (terminal?.state !== "terminal" || terminal.reason !== "superseded" || terminal.confirmedRefreshes !== 1) {
        diagnostics.push({
          code: "migration_terminal_lifecycle_invalid",
          path: `records.${index}.lifecycle`,
          message: `A legacy superseded record must migrate as terminal with one confirmed refresh: ${id}`
        });
      }
    }
  }
  return diagnostics;
}

function mergeManagedBlock(
  original: string,
  block: ManagedBlockInput,
  expectedHash: string | undefined
): { content?: string; conflict?: string } {
  const recordId = escapedRegularExpression(block.recordId);
  const expression = new RegExp(
    `<!-- project-design-keeper:managed record-id="${recordId}" content-hash="(sha256:[a-f0-9]{64})" -->`,
    "u"
  );
  const parsed = parseManagedDocument(original);
  if (original && !parsed.valid) return { conflict: parsed.conflict ?? `Managed block ${block.recordId} is in an unmanaged document` };
  const match = expression.exec(original);
  const opener = `<!-- project-design-keeper:managed record-id="${block.recordId}"`;
  if (match) {
    const bodyStart = match.index + match[0].length;
    const bodyEnd = original.indexOf(managedClose, bodyStart);
    if (bodyEnd < 0) return { conflict: `Managed block ${block.recordId} has no closing marker` };
    const blockEnd = bodyEnd + managedClose.length;
    const actual = sha256(Buffer.from(original.slice(bodyStart, bodyEnd), "utf8"));
    if (actual !== match[1]) return { conflict: `Managed block ${block.recordId} content hash does not match its marker` };
    if (expectedHash && expectedHash !== actual) return { conflict: `Managed block ${block.recordId} differs from the expected content hash` };
    if ("delete" in block) {
      return { content: `${original.slice(0, match.index)}${original.slice(blockEnd)}` };
    }
    const replacement = `${opener} content-hash="${sha256(Buffer.from(block.content, "utf8"))}" -->${block.content}${managedClose}`;
    return { content: `${original.slice(0, match.index)}${replacement}${original.slice(blockEnd)}` };
  }
  if ("delete" in block) return { conflict: `Managed block ${block.recordId} does not exist` };
  if (expectedHash) return { conflict: `Managed block ${block.recordId} does not exist for the expected content hash` };
  const replacement = `${opener} content-hash="${sha256(Buffer.from(block.content, "utf8"))}" -->${block.content}${managedClose}`;
  if (!original) return { content: replacement };
  return { content: `${original}${original.endsWith("\n") ? "" : "\n"}${replacement}` };
}

async function manifestFingerprint(root: string, budget: ProjectFileReadBudget): Promise<string | null> {
  await validateManagedRoots(root);
  const repositoryRoot = await realpath(root);
  const manifestPath = join(repositoryRoot, "docs", "project-design", "manifest.json");
  const contents = await boundedOptionalProjectRead(
    repositoryRoot,
    manifestPath,
    "docs/project-design/manifest.json",
    budget
  );
  return pathHash(contents);
}

async function sourceFingerprint(
  source: ScopeInput,
  options: ServiceOptions,
  budget?: ScopeOperationBudget
): Promise<Record<string, string>> {
  if (!source.root) throw new Error("Source fingerprint requires a repository root");
  await validateManagedRoots(source.root);
  return Object.fromEntries(Object.entries((await snapshotForFingerprint(source, options, budget)).files)
    .map(([path, fingerprint]) => [path.replaceAll("\\", "/"), fingerprint]));
}

interface ExactSourceReadBudget {
  readonly count: CounterBudget;
  readonly reads: ProjectFileReadBudget;
}

function createExactSourceReadBudget(limits: KeeperLimits): ExactSourceReadBudget {
  return {
    count: new CounterBudget("Source file reads", limits.scan.maxFiles),
    reads: projectFileReadBudget(
      "Source file reads",
      limits.scan.maxFileBytes,
      limits.scan.maxAggregateBytes,
      limits.scan.maxFiles,
      limits.scan.deadlineMs
    )
  };
}

async function exactSourceFingerprint(
  root: string,
  paths: string[],
  budget: ExactSourceReadBudget
): Promise<Record<string, string>> {
  await validateManagedRoots(root);
  const entries: Array<[string, string]> = [];
  for (const path of [...paths].sort()) {
    budget.count.consume();
    budget.reads.deadline.check();
    if (!safeRepositoryPath(path)) throw new Error(`Source path is unsafe: ${path}`);
    const target = resolve(root, ...path.split("/"));
    const contents = await boundedOptionalProjectRead(root, target, `source:${path}`, budget.reads);
    if (contents) entries.push([path, pathHash(contents)!]);
  }
  return Object.fromEntries(entries);
}

function equalFingerprints(left: Record<string, string>, right: Record<string, string>): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index] && left[key] === right[key]);
}

async function unmanagedOutputs(
  root: string,
  limits: KeeperLimits,
  readBudget: ProjectFileReadBudget,
  beforeEntry?: (path: string, kind: "file" | "directory") => Promise<void>
): Promise<string[]> {
  await validateManagedRoots(root);
  const directory = join(root, "docs", "project-design");
  if (!await optionalLstat(directory)) return [];
  const unmanaged: string[] = [];
  const entries = new CounterBudget("Project-design output inventory entries", Math.min(limits.scan.maxFiles, 4_096));
  const maximumDepth = 16;

  async function visit(current: string, depth: number): Promise<void> {
    readBudget.deadline.check();
    if (depth > maximumDepth) {
      throw new Error(`Project-design output inventory depth exceeds the limit of ${maximumDepth} levels`);
    }
    await captureProjectPathEvidence(root, current, "directory", relative(root, current).replaceAll("\\", "/"));
    const handle = await opendir(current);
    const children = [];
    for await (const entry of handle) {
      readBudget.deadline.check();
      entries.consume();
      children.push(entry);
    }
    children.sort((left, right) => left.name.localeCompare(right.name, "en-US"));
    for (const entry of children) {
      const path = join(current, entry.name);
      const relativePath = relative(root, path).replaceAll("\\", "/");
      if (beforeEntry) await beforeEntry(path, entry.isDirectory() ? "directory" : "file");
      if (entry.isDirectory()) {
        await visit(path, depth + 1);
        continue;
      }
      if (entry.isSymbolicLink() || !entry.isFile()) {
        unmanaged.push(relativePath);
        continue;
      }
      const contents = await boundedOptionalProjectRead(root, path, relativePath, readBudget);
      const fileOwnership = contents ? ownership(relativePath, contents) : { owned: false, conflict: "unreadable output" };
      if (!fileOwnership.owned) unmanaged.push(`${relativePath}: ${fileOwnership.conflict ?? "missing Keeper ownership"}`);
    }
  }

  await visit(directory, 0);
  return unmanaged.sort();
}

function normativeRecordIds(pack: Record<string, unknown> | undefined): string[] {
  if (!pack || !Array.isArray(pack.records)) return [];
  return pack.records.flatMap((candidate) => {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return [];
    const record = candidate as Record<string, unknown>;
    return typeof record.id === "string" &&
      (record.strength === "required" || record.strength === "preferred") &&
      record.approval === "confirmed"
      ? [record.id]
      : [];
  });
}

function semanticDecisionIds(
  currentPack: Record<string, unknown> | undefined,
  candidatePack: Record<string, unknown> | undefined,
  decisions: RedundancyDecision[] | undefined
): string[] {
  const currentNormative = new Set(normativeRecordIds(currentPack));
  const newlyNormative = normativeRecordIds(candidatePack).filter((id) => !currentNormative.has(id));
  const merges = decisions?.flatMap((decision) => decision.decision === "merge" ? [decision.candidateId] : []) ?? [];
  return [...new Set([...newlyNormative, ...merges])].sort();
}

type ArchiveActions = ChangesetApprovalBinding["archiveActions"];

function emptyArchiveActions(): ArchiveActions {
  return { archivedRecordIds: [], tombstonedRecordIds: [] };
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function archiveMetadata(pack: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  return objectRecord(pack?.archive);
}

function archiveGenerations(pack: Record<string, unknown> | undefined): Array<Record<string, unknown>> {
  const generations = archiveMetadata(pack)?.generations;
  return Array.isArray(generations)
    ? generations.flatMap((value) => {
      const generation = objectRecord(value);
      return generation ? [generation] : [];
    })
    : [];
}

function tombstoneMetadata(pack: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  return objectRecord(archiveMetadata(pack)?.tombstones);
}

function packHistoryPaths(pack: Record<string, unknown> | undefined): string[] {
  const paths = archiveGenerations(pack)
    .flatMap((generation) => typeof generation.path === "string" ? [generation.path] : []);
  const tombstones = tombstoneMetadata(pack);
  if (typeof tombstones?.path === "string") paths.push(tombstones.path);
  return [...new Set(paths)].sort();
}

function actionBearingHistoryPaths(
  currentPack: Record<string, unknown> | undefined,
  candidatePack: Record<string, unknown>
): string[] {
  const currentGenerationIds = new Set(archiveGenerations(currentPack)
    .flatMap((generation) => typeof generation.id === "string" ? [generation.id] : []));
  const paths = archiveGenerations(candidatePack).flatMap((generation) =>
    typeof generation.id === "string" && typeof generation.path === "string" && !currentGenerationIds.has(generation.id)
      ? [generation.path]
      : []);
  const currentTombstones = tombstoneMetadata(currentPack);
  const candidateTombstones = tombstoneMetadata(candidatePack);
  if (typeof candidateTombstones?.path === "string" &&
      Number(candidateTombstones.count) > Number(currentTombstones?.count ?? 0)) {
    paths.push(candidateTombstones.path);
  }
  return [...new Set(paths)].sort();
}

function jsonLineObjects(
  bytes: Buffer | undefined,
  expectedCount: unknown,
  label: string
): Array<Record<string, unknown>> {
  if (!bytes) {
    if (expectedCount === 0) return [];
    throw new Error(`${label} is missing`);
  }
  return decodeCanonicalJsonLines(bytes, label, { expectedCount }).map(({ value }) => {
    const record = objectRecord(value);
    if (!record) throw new Error("Validated archive history could not be summarized for approval");
    return record;
  });
}

async function referencedArchiveRecordIds(
  pack: Record<string, unknown> | undefined,
  read: (path: string) => Promise<Buffer | undefined>
): Promise<Set<string>> {
  const ids = new Set<string>();
  for (const generation of archiveGenerations(pack)) {
    if (!generation || typeof generation.path !== "string") continue;
    const entries = jsonLineObjects(
      await read(generation.path),
      generation.recordCount,
      `Archive history ${generation.path}`
    );
    for (const entry of entries) {
      const record = objectRecord(entry.record);
      if (typeof record?.id === "string") ids.add(record.id);
    }
  }
  return ids;
}

async function referencedTombstoneIds(
  pack: Record<string, unknown> | undefined,
  read: (path: string) => Promise<Buffer | undefined>
): Promise<Set<string>> {
  const tombstones = tombstoneMetadata(pack);
  if (!tombstones || typeof tombstones.path !== "string") return new Set();
  const records = jsonLineObjects(
    await read(tombstones.path),
    tombstones.count,
    `Tombstone history ${tombstones.path}`
  );
  return new Set(records.flatMap((record) => typeof record.id === "string" ? [record.id] : []));
}

async function deriveArchiveActions(
  currentPack: Record<string, unknown> | undefined,
  candidatePack: Record<string, unknown>,
  readCurrent: (path: string) => Promise<Buffer | undefined>,
  readCandidate: (path: string) => Promise<Buffer | undefined>
): Promise<ArchiveActions> {
  const [currentArchiveIds, candidateArchiveIds, currentTombstoneIds, candidateTombstoneIds] = await Promise.all([
    referencedArchiveRecordIds(currentPack, readCurrent),
    referencedArchiveRecordIds(candidatePack, readCandidate),
    referencedTombstoneIds(currentPack, readCurrent),
    referencedTombstoneIds(candidatePack, readCandidate)
  ]);
  return {
    archivedRecordIds: [...candidateArchiveIds].filter((id) => !currentArchiveIds.has(id)).sort(),
    tombstonedRecordIds: [...candidateTombstoneIds].filter((id) => !currentTombstoneIds.has(id)).sort()
  };
}

function approvalBinding(changeset: PersistedChangeset): ChangesetApprovalBinding {
  if (changeset.version !== 3 || !changeset.policy || changeset.diff === undefined) {
    throw new Error("Changeset uses a legacy preview format; regenerate the preview update");
  }
  if (changeset.sourcePaths && (!changeset.validatedPack || !changeset.validationDependencyDigest)) {
    throw new Error("Candidate changeset predates validation dependency binding; preview the update again");
  }
  const summary = { create: 0, update: 0, delete: 0 };
  for (const change of changeset.changes) {
    if (change.delete) summary.delete += 1;
    else if (change.previousHash) summary.update += 1;
    else summary.create += 1;
  }
  return {
    policy: { ...changeset.policy },
    authorizationSource: changeset.policy.easyMode ? "easy-policy" : "human-form",
    root: changeset.root,
    changesetId: changeset.changesetId,
    diffDigest: changeset.diffDigest,
    expiresAt: changeset.expiresAt,
    paths: changeset.changes.map((change) => change.path).sort(),
    summary,
    archiveActions: {
      archivedRecordIds: [...changeset.archiveActions.archivedRecordIds],
      tombstonedRecordIds: [...changeset.archiveActions.tombstonedRecordIds]
    },
    semanticDecisionIds: [...changeset.semanticDecisionIds]
  };
}

async function persistJson(cache: SecureCacheLayout, path: string, value: unknown): Promise<void> {
  const serialized = `${JSON.stringify(encodeStoredText(value), null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > recoverySnapshotMaxBytes) {
    throw new Error("Recovery snapshot exceeds its bounded serialized byte limit before publication");
  }
  await publishExclusiveFile(cache, path, serialized);
}

interface ChangesetRequest {
  changesetId: string;
  root: string;
}

async function resolveChangesetRequest(input: Record<string, unknown>): Promise<ChangesetRequest> {
  const adapter = typeof input.changeset === "object" && input.changeset !== null
    ? input.changeset as Record<string, unknown>
    : undefined;
  const changesetId = typeof input.changesetId === "string"
    ? input.changesetId
    : typeof adapter?.changesetId === "string"
      ? adapter.changesetId
      : undefined;
  if (!changesetId) throw new Error("A changeset id is required");
  if (typeof input.root !== "string") throw new Error("A repository root is required");
  return {
    changesetId,
    root: (await resolveScope({ root: input.root, path: "." })).root
  };
}

function summaryFor(changes: PersistedChange[]): string {
  return changes.map((change) => `${change.delete ? "delete" : change.previousHash ? "update" : "create"} ${change.path}`).join("\n");
}

function diffLines(contents: Buffer | string | undefined): { lines: string[]; terminated: boolean } {
  if (contents === undefined) return { lines: [], terminated: true };
  const text = Buffer.isBuffer(contents) ? contents.toString("utf8") : contents;
  const terminated = text.endsWith("\n");
  const lines = text.split(/\r?\n/u);
  if (terminated) lines.pop();
  return { lines, terminated };
}

function emitDiffLines(lines: string[], prefix: "+" | "-", terminated: boolean): string {
  if (lines.length === 0) return "";
  const output = lines.map((line) => `${prefix}${line}\n`).join("");
  return terminated ? output : `${output}\\ No newline at end of file\n`;
}

function unifiedDiff(changes: PersistedChange[], originals: ReadonlyMap<string, Buffer | undefined>): string {
  return changes.map((change) => {
    const original = originals.get(change.path);
    const next = change.delete ? undefined : change.content ?? "";
    if (original !== undefined && next !== undefined && original.equals(Buffer.from(next, "utf8"))) return "";
    const oldView = diffLines(original);
    const newView = diffLines(next);
    const oldPath = original === undefined ? "/dev/null" : `a/${change.path}`;
    const newPath = change.delete ? "/dev/null" : `b/${change.path}`;
    const oldStart = oldView.lines.length === 0 ? 0 : 1;
    const newStart = newView.lines.length === 0 ? 0 : 1;
    return [
      `--- ${oldPath}\n`,
      `+++ ${newPath}\n`,
      `@@ -${oldStart},${oldView.lines.length} +${newStart},${newView.lines.length} @@\n`,
      emitDiffLines(oldView.lines, "-", oldView.terminated),
      emitDiffLines(newView.lines, "+", newView.terminated)
    ].join("");
  }).join("");
}

interface RecoveryFileRecord {
  existed: boolean;
  content: string | null;
  contentBase64: string | null;
  mode: number | null;
  type: "file" | "missing";
  hash: string | null;
  previousHash: string | null;
}

interface RecoverySnapshotRecord {
  version: 1;
  root: string;
  changesetId: string;
  createdAt: number;
  files: Record<string, RecoveryFileRecord>;
  authorization?: { source: "easy-policy" | "human-form"; policy: import("./settings/policy.js").RuntimePolicy; diffDigest: string };
}

interface CapturedRecoverySnapshot {
  name: string;
  path: string;
  createdAt: number;
  changesetId: string;
  identity: SecurePathIdentity;
  metadata: BigIntStats;
  contentHash: string;
  value: RecoverySnapshotRecord;
}

interface RecoveryCaptureHooks {
  beforeRecoveryTargetOpen?: (path: string, index: number) => Promise<void>;
  afterRecoveryTargetOpen?: (path: string, index: number) => Promise<void>;
  afterRecoveryTargetRead?: (path: string, index: number) => Promise<void>;
  beforeRecoverySnapshotPublish?: (root: string, changesetId: string) => Promise<void>;
}

interface CapturedRecoveryFile {
  record: RecoveryFileRecord;
  validate(): Promise<void>;
}

const canonicalUuidPattern = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const recoverySnapshotNamePattern = new RegExp(`^(0|[1-9][0-9]*)-(${canonicalUuidPattern})-(${canonicalUuidPattern})\\.json$`, "u");
const recoverySnapshotMaxBytes = 512 * 1024 * 1024;
// A restorable snapshot keeps both UTF-8 text and base64. Three times the old
// file-read aggregate covers both representations plus bounded record metadata.
const recoverySnapshotExpandedMaxBytes = managedReadLimits.maxAggregateBytes * 3;
const recoverySnapshotMaxObservedFiles = keeperLimits.changesets.maxPairsPerProject;

function exactObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const observed = Object.keys(value).sort((left, right) => left.localeCompare(right, "en-US"));
  const expected = [...keys].sort((left, right) => left.localeCompare(right, "en-US"));
  return observed.length === expected.length && observed.every((key, index) => key === expected[index]);
}

function strictBase64(value: string): Buffer | undefined {
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64") === value ? decoded : undefined;
}

function parseRecoveryFileRecord(value: unknown): RecoveryFileRecord {
  if (!exactObject(value, ["existed", "content", "contentBase64", "mode", "type", "hash", "previousHash"])) {
    throw new Error("Recovery file record has an unexpected schema");
  }
  if (value.type === "missing") {
    if (value.existed !== false || value.content !== null || value.contentBase64 !== null ||
        value.mode !== null || value.hash !== null || value.previousHash !== null) {
      throw new Error("Missing recovery file record is inconsistent");
    }
    return value as unknown as RecoveryFileRecord;
  }
  if (value.type !== "file" || value.existed !== true || typeof value.content !== "string" ||
      typeof value.contentBase64 !== "string" || !Number.isSafeInteger(value.mode) ||
      Number(value.mode) < 0 || Number(value.mode) > 0o777 || typeof value.hash !== "string" ||
      typeof value.previousHash !== "string") {
    throw new Error("Recovery file record is inconsistent");
  }
  const decoded = strictBase64(value.contentBase64);
  if (!decoded || !decoded.equals(Buffer.from(value.content, "utf8")) ||
      sha256(decoded) !== value.hash || value.previousHash !== value.hash) {
    throw new Error("Recovery file record content binding is invalid");
  }
  return value as unknown as RecoveryFileRecord;
}

function parseRecoverySnapshotRecord(
  value: unknown,
  name: string,
  canonicalRoot: string,
  activeChangeset?: PersistedChangeset
): RecoverySnapshotRecord {
  const hasAuthorization = Boolean(value && typeof value === "object" && Object.hasOwn(value, "authorization"));
  if (!exactObject(value, ["version", "root", "changesetId", "createdAt", "files", ...(hasAuthorization ? ["authorization"] : [])]) ||
      value.version !== 1 || value.root !== canonicalRoot || typeof value.changesetId !== "string" ||
      !Number.isSafeInteger(value.createdAt) || Number(value.createdAt) < 0 ||
      !value.files || typeof value.files !== "object" || Array.isArray(value.files)) {
    throw new Error("Recovery snapshot has an unexpected schema");
  }
  let authorization: RecoverySnapshotRecord["authorization"];
  if (hasAuthorization) {
    const audit = value.authorization;
    if (!exactObject(audit, ["source", "policy", "diffDigest"]) ||
        !["easy-policy", "human-form"].includes(String(audit.source)) ||
        typeof audit.diffDigest !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(audit.diffDigest)) throw new Error("Recovery authorization audit is invalid");
    const policy = freezeRuntimePolicy(audit.policy as import("./settings/policy.js").RuntimePolicy);
    if ((audit.source === "easy-policy") !== policy.easyMode) throw new Error("Recovery authorization source does not match its policy");
    authorization = { source: audit.source as "easy-policy" | "human-form", policy, diffDigest: audit.diffDigest };
    if (activeChangeset?.changesetId === value.changesetId &&
        (!activeChangeset.policy || !sameRuntimePolicy(policy, activeChangeset.policy) || audit.diffDigest !== activeChangeset.diffDigest)) throw new Error("Recovery authorization audit does not match the authenticated changeset");
  }
  const match = recoverySnapshotNamePattern.exec(name);
  if (!match || Number(match[1]) !== value.createdAt || match[2] !== value.changesetId) {
    throw new Error("Recovery snapshot filename does not bind its metadata");
  }
  const files: Record<string, RecoveryFileRecord> = {};
  for (const [path, fileValue] of Object.entries(value.files)) {
    const canonical = canonicalRelativePath(path);
    if (canonical.path !== path) throw new Error("Recovery snapshot file path is not canonical");
    files[path] = parseRecoveryFileRecord(fileValue);
  }
  if (activeChangeset && value.changesetId === activeChangeset.changesetId) {
    const expectedPaths = activeChangeset.changes.map((change) => change.path)
      .sort((left, right) => left.localeCompare(right, "en-US"));
    const actualPaths = Object.keys(files).sort((left, right) => left.localeCompare(right, "en-US"));
    if (expectedPaths.length !== actualPaths.length ||
        expectedPaths.some((path, index) => path !== actualPaths[index])) {
      throw new Error("Active recovery snapshot files do not match the authenticated changeset");
    }
    for (const change of activeChangeset.changes) {
      if (files[change.path]!.previousHash !== change.previousHash) {
        throw new Error("Active recovery snapshot previousHash does not match the authenticated changeset");
      }
    }
  }
  return {
    version: 1,
    root: value.root,
    changesetId: value.changesetId,
    createdAt: value.createdAt,
    ...(authorization ? { authorization } : {}),
    files
  };
}

async function readExactRecoveryBytes(handle: FileHandle, size: bigint): Promise<Buffer> {
  if (size < 0n || size > BigInt(recoverySnapshotMaxBytes) || size > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("Recovery snapshot exceeds its bounded byte limit");
  }
  const contents = Buffer.alloc(Number(size));
  let offset = 0;
  while (offset < contents.byteLength) {
    const { bytesRead } = await handle.read(contents, offset, contents.byteLength - offset, offset);
    if (!Number.isSafeInteger(bytesRead) || bytesRead <= 0 || bytesRead > contents.byteLength - offset) {
      throw new Error("Recovery snapshot ended during its exact bounded read");
    }
    offset += bytesRead;
  }
  const overflow = Buffer.alloc(1);
  if ((await handle.read(overflow, 0, 1, contents.byteLength)).bytesRead !== 0) {
    throw new Error("Recovery snapshot grew beyond its exact bounded read");
  }
  return contents;
}

async function readRecoverySnapshot(
  cache: SecureCacheLayout,
  path: string,
  name: string,
  canonicalRoot: string,
  activeChangeset?: PersistedChangeset,
  expandedInventoryBudget?: ByteBudget
): Promise<CapturedRecoverySnapshot> {
  try {
    await validateCacheFile(cache, path, false);
    const identity = await captureSecurePathIdentity(cache, path, "file");
    const initial = await lstat(path, { bigint: true });
    assertSecureOwnerFileMetadata(initial, path, 1n);
    if (initial.dev !== identity.dev || initial.ino !== identity.ino) {
      throw new Error("Recovery snapshot identity changed before open");
    }
    const handle = await open(path, "r");
    let contents: Buffer;
    try {
      const opened = await handle.stat({ bigint: true });
      assertSecureOwnerFileMetadata(opened, path, 1n);
      if (!sameProjectMetadata(initial, opened)) throw new Error("Recovery snapshot version changed before read");
      contents = await readExactRecoveryBytes(handle, opened.size);
      const completed = await handle.stat({ bigint: true });
      if (!sameProjectMetadata(opened, completed)) throw new Error("Recovery snapshot version changed during read");
    } finally {
      await handle.close();
    }
    const finalMetadata = await lstat(path, { bigint: true });
    assertSecureOwnerFileMetadata(finalMetadata, path, 1n);
    if (!sameProjectMetadata(initial, finalMetadata)) throw new Error("Recovery snapshot final pathname version changed");
    await validateSecurePathIdentity(cache, identity);
    let parsed: unknown;
    try {
      const serialized = contents.toString("utf8");
      if (!Buffer.from(serialized, "utf8").equals(contents)) throw new Error("non-canonical UTF-8");
      const wire: unknown = JSON.parse(serialized);
      if (!(wire && typeof wire === "object" && Object.hasOwn(wire, "textStorage"))) expandedInventoryBudget?.consume(contents.byteLength);
      parsed = decodeStoredText(wire, (bytes) => expandedInventoryBudget?.consume(bytes));
    } catch {
      throw new Error("Recovery snapshot JSON is invalid");
    }
    const value = parseRecoverySnapshotRecord(parsed, name, canonicalRoot, activeChangeset);
    return {
      name,
      path,
      createdAt: value.createdAt,
      changesetId: value.changesetId,
      identity,
      metadata: initial,
      contentHash: sha256(contents),
      value
    };
  } catch (error) {
    throw new Error(`Recovery snapshot metadata is invalid: ${name}`, { cause: error });
  }
}

async function exactRemoveRecoverySnapshot(
  cache: SecureCacheLayout,
  snapshot: CapturedRecoverySnapshot,
  canonicalRoot: string
): Promise<void> {
  const current = await readRecoverySnapshot(cache, snapshot.path, snapshot.name, canonicalRoot);
  if (current.identity.dev !== snapshot.identity.dev || current.identity.ino !== snapshot.identity.ino ||
      !sameProjectMetadata(current.metadata, snapshot.metadata) || current.contentHash !== snapshot.contentHash) {
    throw new Error(`Recovery snapshot changed before exact retention cleanup: ${snapshot.name}`);
  }
  await safeRemoveExactCacheFile(cache, snapshot.identity);
}

async function captureRecoveryFile(
  changeset: PersistedChangeset,
  change: PersistedChange,
  index: number,
  hooks: RecoveryCaptureHooks
): Promise<CapturedRecoveryFile> {
  const target = join(changeset.root, ...change.path.split("/"));
  const metadata = await optionalLstat(target);
  if (!metadata) {
    if (change.previousHash !== null) throw new Error(`Recovery snapshot target is stale: ${change.path}`);
    const absentSuffix = [target];
    let existingAncestor = dirname(target);
    while (!sameFilesystemPath(existingAncestor, changeset.root)) {
      const ancestorMetadata = await optionalLstat(existingAncestor);
      if (ancestorMetadata) {
        if (ancestorMetadata.isSymbolicLink() || !ancestorMetadata.isDirectory()) {
          throw new Error(`Recovery snapshot missing target ancestor is not an ordinary directory: ${change.path}`);
        }
        break;
      }
      absentSuffix.push(existingAncestor);
      existingAncestor = dirname(existingAncestor);
    }
    const ancestorIdentity = await captureProjectPathIdentity(
      changeset.root,
      existingAncestor,
      "directory",
      change.path
    );
    for (const absent of absentSuffix) {
      if (await optionalLstat(absent)) throw new Error(`Recovery snapshot missing target changed during capture: ${change.path}`);
    }
    await hooks.beforeRecoveryTargetOpen?.(target, index);
    for (const absent of absentSuffix) {
      if (await optionalLstat(absent)) throw new Error(`Recovery snapshot missing target changed during capture: ${change.path}`);
    }
    await validateProjectPathIdentity(changeset.root, ancestorIdentity, change.path);
    return {
      record: {
        existed: false,
        content: null,
        contentBase64: null,
        mode: null,
        type: "missing",
        hash: null,
        previousHash: null
      },
      validate: async () => {
        try {
          await validateProjectPathIdentity(changeset.root, ancestorIdentity, change.path);
          for (const absent of absentSuffix) {
            if (await optionalLstat(absent)) {
              throw new Error(`Recovery snapshot missing target changed: ${change.path}`);
            }
          }
        } catch (error) {
          throw new Error(`Recovery snapshot missing target evidence changed: ${change.path}`, { cause: error });
        }
      }
    };
  }
  const parent = await captureProjectPathIdentity(changeset.root, dirname(target), "directory", change.path);
  let captured: Awaited<ReturnType<typeof captureProjectPathEvidence>>;
  try {
    captured = await captureProjectPathEvidence(changeset.root, target, "file", change.path, {
      beforeOpen: async () => { await hooks.beforeRecoveryTargetOpen?.(target, index); },
      afterOpen: async () => { await hooks.afterRecoveryTargetOpen?.(target, index); },
      afterRead: async () => { await hooks.afterRecoveryTargetRead?.(target, index); }
    });
  } catch (error) {
    throw new Error(`Recovery snapshot target identity or read is ambiguous: ${change.path}`, { cause: error });
  }
  const contents = captured.contents!;
  if (captured.identity.parentDev !== parent.dev || captured.identity.parentIno !== parent.ino ||
      !sameFilesystemPath(captured.identity.parent, parent.path)) {
    throw new Error(`Recovery snapshot target parent identity changed: ${change.path}`);
  }
  await validateProjectPathIdentity(changeset.root, parent, change.path);
  if (captured.identity.contentHash !== change.previousHash) {
    throw new Error(`Recovery snapshot target content is stale: ${change.path}`);
  }
  return {
    record: {
      existed: true,
      content: contents.toString("utf8"),
      contentBase64: contents.toString("base64"),
      mode: Number(captured.identity.mode & 0o777n),
      type: "file",
      hash: captured.identity.contentHash,
      previousHash: change.previousHash
    },
    validate: async () => {
      try {
        await validateProjectPathIdentity(changeset.root, parent, change.path);
        await validateProjectPathIdentity(changeset.root, captured.identity, change.path);
      } catch (error) {
        throw new Error(`Recovery snapshot target evidence changed: ${change.path}`, { cause: error });
      }
    }
  };
}

async function storeRecoverySnapshot(
  cache: SecureCacheLayout,
  changeset: PersistedChangeset,
  now: number,
  hooks: RecoveryCaptureHooks = {}
): Promise<void> {
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("Recovery snapshot timestamp is invalid");
  const canonicalRoot = await realpath(changeset.root);
  if (!sameFilesystemPath(canonicalRoot, changeset.root)) throw new Error("Recovery snapshot project root is not canonical");
  const files: Record<string, RecoveryFileRecord> = {};
  const capturedFiles: CapturedRecoveryFile[] = [];
  for (const [index, change] of changeset.changes.entries()) {
    const captured = await captureRecoveryFile(changeset, change, index, hooks);
    files[change.path] = captured.record;
    capturedFiles.push(captured);
  }
  const projectKey = createHash("sha256").update(canonicalRoot).digest("hex");
  const directory = join(cache.snapshots, projectKey);
  await createSecureCacheDirectory(cache, directory);
  let names = (await readdir(directory)).filter((name) => name.endsWith(".json"));
  if (names.length > recoverySnapshotMaxObservedFiles) {
    throw new Error("Recovery snapshot directory exceeds its bounded entry limit");
  }
  await validateCacheFiles(cache, names.map((name) => join(directory, name)));
  let snapshots: CapturedRecoverySnapshot[] = [];
  const recoveryInventoryBytes = new ByteBudget("Recovery snapshot inventory", 1024 * 1024 * 1024);
  const activeSnapshotBytes = new ByteBudget("Expanded active recovery snapshots", recoverySnapshotExpandedMaxBytes);
  const inventoryDeadline = new DeadlineBudget("Recovery snapshot inventory", 30_000);
  for (const name of names) {
    inventoryDeadline.check();
    const snapshotPath = join(directory, name);
    recoveryInventoryBytes.consume(Number((await lstat(snapshotPath)).size));
    const isActive = recoverySnapshotNamePattern.exec(name)?.[2] === changeset.changesetId;
    const snapshot = await readRecoverySnapshot(cache, snapshotPath, name, canonicalRoot, changeset,
      isActive ? activeSnapshotBytes : new ByteBudget("Expanded recovery snapshot", recoverySnapshotExpandedMaxBytes));
    // Inactive contents were fully verified; retention cleanup only needs their
    // exact identity/hash. Do not retain ten expanded large-file copies in RAM.
    if (!isActive) snapshot.value = { ...snapshot.value, files: {} };
    snapshots.push(snapshot);
    inventoryDeadline.check();
  }
  let active = snapshots.filter(({ changesetId }) => changesetId === changeset.changesetId)
    .sort((left, right) => right.createdAt - left.createdAt || right.name.localeCompare(left.name, "en-US"));
  if (active.some((snapshot) => !isDeepStrictEqual(snapshot.value.files, files))) {
    throw new Error("Active recovery snapshot does not match the currently authenticated pre-state");
  }
  if (active.length > 1) {
    const authoritative = active[0]!;
    for (const duplicate of active.slice(1)) {
      await exactRemoveRecoverySnapshot(cache, duplicate, canonicalRoot);
    }
    snapshots = snapshots.filter((snapshot) =>
      snapshot.changesetId !== changeset.changesetId || snapshot.name === authoritative.name);
    active = [authoritative];
  }
  if (active.length === 0) {
    await hooks.beforeRecoverySnapshotPublish?.(canonicalRoot, changeset.changesetId);
    for (const captured of capturedFiles) await captured.validate();
    const name = `${now}-${changeset.changesetId}-${randomUUID()}.json`;
    const path = join(directory, name);
    await persistJson(cache, path, {
      version: 1,
      root: canonicalRoot,
      changesetId: changeset.changesetId,
      createdAt: now,
      ...(changeset.policy ? { authorization: {
        source: changeset.policy.easyMode ? "easy-policy" as const : "human-form" as const,
        policy: { ...changeset.policy },
        diffDigest: changeset.diffDigest
      } } : {}),
      files
    } satisfies RecoverySnapshotRecord);
    const published = await readRecoverySnapshot(cache, path, name, canonicalRoot, changeset);
    snapshots.push(published);
    active = [published];
  }
  const newest = [...snapshots].sort((left, right) =>
    right.createdAt - left.createdAt || right.name.localeCompare(left.name, "en-US"));
  const retained = new Set(newest.slice(0, 10).map(({ name }) => name));
  const authoritative = active[0]!;
  if (!retained.has(authoritative.name)) {
    const replaceable = newest.filter(({ name, changesetId }) =>
      retained.has(name) && changesetId !== changeset.changesetId)
      .sort((left, right) => left.createdAt - right.createdAt || left.name.localeCompare(right.name, "en-US"))[0];
    if (!replaceable) throw new Error("Active recovery snapshot retention is ambiguous");
    retained.delete(replaceable.name);
    retained.add(authoritative.name);
  }
  for (const snapshot of snapshots) {
    if (!retained.has(snapshot.name)) await exactRemoveRecoverySnapshot(cache, snapshot, canonicalRoot);
  }
  names = (await readdir(directory)).filter((name) => name.endsWith(".json"));
  if (names.length > 10) throw new Error("Recovery snapshot retention did not converge to ten files");
  const activeNames = names.filter((name) => recoverySnapshotNamePattern.exec(name)?.[2] === changeset.changesetId);
  if (activeNames.length !== 1 || activeNames[0] !== authoritative.name) {
    throw new Error("Active recovery snapshot retention did not converge to one authoritative file");
  }
  for (const captured of capturedFiles) await captured.validate();
}

interface RegularFileState {
  contents: Buffer;
  mode: number;
}

interface ProjectPathIdentity {
  path: string;
  canonicalPath: string;
  parent: string;
  dev: bigint;
  ino: bigint;
  parentDev: bigint;
  parentIno: bigint;
  uid: bigint;
  gid: bigint;
  mode: bigint;
  nlink: bigint;
  size: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
  kind: "directory" | "file";
  reparsePoint: boolean;
  contentHash: string | null;
}

interface CapturedRegularFileState extends RegularFileState {
  identity: ProjectPathIdentity;
}

interface CreatedDirectory {
  path: string;
  identity: ProjectPathIdentity;
}

async function regularFileState(
  root: string,
  path: string,
  relativeLabel: string,
  budget: ProjectFileReadBudget
): Promise<RegularFileState | undefined> {
  const captured = await boundedOptionalProjectEvidence(root, path, relativeLabel, budget);
  if (!captured) return undefined;
  return { contents: captured.contents!, mode: Number(captured.identity.mode & 0o777n) };
}

function sameProjectIdentity(left: ProjectPathIdentity, right: ProjectPathIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.kind === right.kind &&
    left.parentDev === right.parentDev && left.parentIno === right.parentIno &&
    left.uid === right.uid && left.gid === right.gid && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs &&
    sameFilesystemPath(left.path, right.path) && sameFilesystemPath(left.canonicalPath, right.canonicalPath) &&
    sameFilesystemPath(left.parent, right.parent) && left.reparsePoint === right.reparsePoint &&
    left.contentHash === right.contentHash;
}

function sameProjectMetadata(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.gid === right.gid &&
    left.mode === right.mode && left.nlink === right.nlink && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs &&
    left.isFile() === right.isFile() && left.isDirectory() === right.isDirectory() &&
    left.isSymbolicLink() === right.isSymbolicLink();
}

function projectIdentityFromMetadata(
  path: string,
  canonicalPath: string,
  parent: string,
  metadata: BigIntStats,
  parentMetadata: BigIntStats,
  kind: "directory" | "file",
  contentHash: string | null
): ProjectPathIdentity {
  return {
    path: resolve(path),
    canonicalPath,
    parent,
    dev: metadata.dev,
    ino: metadata.ino,
    parentDev: parentMetadata.dev,
    parentIno: parentMetadata.ino,
    uid: metadata.uid,
    gid: metadata.gid,
    mode: metadata.mode,
    nlink: metadata.nlink,
    size: metadata.size,
    mtimeNs: metadata.mtimeNs,
    ctimeNs: metadata.ctimeNs,
    kind,
    reparsePoint: metadata.isSymbolicLink(),
    contentHash
  };
}

async function readExactProjectFile(
  handle: FileHandle,
  size: bigint,
  relativeLabel: string,
  budget?: ProjectFileReadBudget
): Promise<Buffer> {
  const maxFileBytes = budget?.maxFileBytes ?? managedReadLimits.maxFileBytes;
  if (size < 0n || size > BigInt(maxFileBytes)) {
    throw new Error(`${budget?.label ?? "Output file"} exceeds the per-file limit of ${maxFileBytes} bytes: ${relativeLabel}`);
  }
  const expected = Number(size);
  budget?.deadline.check();
  budget?.aggregate.consume(expected);
  const contents = Buffer.alloc(expected);
  let offset = 0;
  while (offset < expected) {
    budget?.deadline.check();
    const read = await handle.read(contents, offset, Math.min(64 * 1024, expected - offset), offset);
    if (read.bytesRead <= 0) throw new Error(`Output file ended during bounded identity read: ${relativeLabel}`);
    offset += read.bytesRead;
  }
  const overflow = Buffer.alloc(1);
  const eof = await handle.read(overflow, 0, 1, expected);
  if (eof.bytesRead !== 0) throw new Error(`Output file grew during bounded identity read: ${relativeLabel}`);
  return contents;
}

async function captureProjectPathEvidence(
  root: string,
  path: string,
  kind: "directory" | "file",
  relativeLabel: string,
  options: {
    ownedHandle?: FileHandle;
    beforeOpen?: () => Promise<void>;
    afterOpen?: () => Promise<void>;
    afterRead?: () => Promise<void>;
    readBudget?: ProjectFileReadBudget;
  } = {}
): Promise<{ identity: ProjectPathIdentity; contents?: Buffer }> {
  const [canonicalRoot, canonicalPath] = await Promise.all([realpath(root), realpath(path)]);
  if (!sameFilesystemPath(path, canonicalPath) || !isInside(canonicalRoot, canonicalPath)) {
    throw new Error(`Output ${kind === "directory" ? "parent" : "target"} containment changed: ${relativeLabel}`);
  }
  const parent = await realpath(dirname(canonicalPath));
  const [metadata, parentMetadata] = await Promise.all([
    lstat(path, { bigint: true }),
    lstat(parent, { bigint: true })
  ]);
  const reparsePoint = metadata.isSymbolicLink();
  if (reparsePoint || (kind === "directory" ? !metadata.isDirectory() : !metadata.isFile())) {
    throw new Error(`Output ${kind === "directory" ? "parent" : "target"} is not an ordinary ${kind}: ${relativeLabel}`);
  }
  if (parentMetadata.isSymbolicLink() || !parentMetadata.isDirectory()) {
    throw new Error(`Output parent identity is not an ordinary directory: ${relativeLabel}`);
  }
  if (kind === "file" && metadata.nlink !== 1n) {
    throw new Error(`Output file has an unexpected hard-link count: ${relativeLabel}`);
  }
  if (kind === "directory") {
    const [settled, settledParent, settledCanonical] = await Promise.all([
      lstat(path, { bigint: true }),
      lstat(parent, { bigint: true }),
      realpath(path)
    ]);
    if (!sameProjectMetadata(metadata, settled) || !sameProjectMetadata(parentMetadata, settledParent) ||
        !sameFilesystemPath(canonicalPath, settledCanonical)) {
      throw new Error(`Output directory identity changed during capture: ${relativeLabel}`);
    }
    return {
      identity: projectIdentityFromMetadata(
        path,
        canonicalPath,
        parent,
        settled,
        settledParent,
        kind,
        null
      )
    };
  }

  await options.beforeOpen?.();
  const handle = options.ownedHandle ?? await open(path, "r");
  let contents: Buffer;
  try {
    const before = await handle.stat({ bigint: true });
    if (!sameProjectMetadata(metadata, before) || before.nlink !== 1n || !before.isFile() || before.isSymbolicLink()) {
      throw new Error(`Output file identity changed before bounded read: ${relativeLabel}`);
    }
    await options.afterOpen?.();
    const immediatelyBeforeRead = await handle.stat({ bigint: true });
    if (!sameProjectMetadata(before, immediatelyBeforeRead) || immediatelyBeforeRead.nlink !== 1n) {
      throw new Error(`Output file identity changed after open: ${relativeLabel}`);
    }
    contents = await readExactProjectFile(handle, before.size, relativeLabel, options.readBudget);
    await options.afterRead?.();
    const after = await handle.stat({ bigint: true });
    if (!sameProjectMetadata(before, after) || after.size !== BigInt(contents.byteLength) || after.nlink !== 1n) {
      throw new Error(`Output file identity changed during bounded read: ${relativeLabel}`);
    }
  } finally {
    if (!options.ownedHandle) await handle.close();
  }
  const [settled, settledParent, settledCanonical] = await Promise.all([
    lstat(path, { bigint: true }),
    lstat(parent, { bigint: true }),
    realpath(path)
  ]);
  if (!sameProjectMetadata(metadata, settled) || !sameProjectMetadata(parentMetadata, settledParent) ||
      settled.nlink !== 1n || !sameFilesystemPath(canonicalPath, settledCanonical)) {
    throw new Error(`Output file identity changed after bounded read: ${relativeLabel}`);
  }
  return {
    contents,
    identity: projectIdentityFromMetadata(
      path,
      canonicalPath,
      parent,
      settled,
      settledParent,
      kind,
      pathHash(contents)!
    )
  };
}

async function boundedOptionalProjectEvidence(
  root: string,
  path: string,
  relativeLabel: string,
  budget: ProjectFileReadBudget
): Promise<{ identity: ProjectPathIdentity; contents: Buffer } | undefined> {
  budget.deadline.check();
  const key = windowsRepositoryPathKey(relativeLabel.replaceAll("\\", "/"));
  if (!budget.accountedFiles.has(key)) {
    budget.files.consume();
    budget.accountedFiles.add(key);
  }
  const metadata = await optionalLstat(path);
  if (!metadata) return undefined;
  const captured = await captureProjectPathEvidence(root, path, "file", relativeLabel, { readBudget: budget });
  return { identity: captured.identity, contents: captured.contents! };
}

async function boundedOptionalProjectRead(
  root: string,
  path: string,
  relativeLabel: string,
  budget: ProjectFileReadBudget
): Promise<Buffer | undefined> {
  return (await boundedOptionalProjectEvidence(root, path, relativeLabel, budget))?.contents;
}

async function captureProjectPathIdentity(
  root: string,
  path: string,
  kind: "directory" | "file",
  relativeLabel: string
): Promise<ProjectPathIdentity> {
  return (await captureProjectPathEvidence(root, path, kind, relativeLabel)).identity;
}

function sameProjectVersionAcrossRename(left: ProjectPathIdentity, right: ProjectPathIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.kind === right.kind &&
    left.uid === right.uid && left.gid === right.gid && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.reparsePoint === right.reparsePoint && left.contentHash === right.contentHash;
}

function sameDirectoryAcrossOwnedMutation(
  left: ProjectPathIdentity,
  right: ProjectPathIdentity,
  expectedChildDirectoryLinkDelta = 0n
): boolean {
  return left.kind === "directory" && right.kind === "directory" &&
    left.dev === right.dev && left.ino === right.ino &&
    left.parentDev === right.parentDev && left.parentIno === right.parentIno &&
    left.uid === right.uid && left.gid === right.gid && left.mode === right.mode &&
    right.nlink === left.nlink + expectedChildDirectoryLinkDelta &&
    left.reparsePoint === right.reparsePoint &&
    sameFilesystemPath(left.path, right.path) &&
    sameFilesystemPath(left.canonicalPath, right.canonicalPath) &&
    sameFilesystemPath(left.parent, right.parent);
}

function parentLinkDeltaForOwnedChildDirectory(
  child: ProjectPathIdentity,
  direction: 1n | -1n,
  relativeLabel: string
): bigint {
  if (process.platform === "win32") return 0n;
  if (child.kind !== "directory") throw new Error(`Owned child is not a directory: ${relativeLabel}`);
  if (child.nlink === 1n) return 0n;
  if (child.nlink === 2n) return direction;
  throw new Error(`Owned child directory link-count semantics are ambiguous: ${relativeLabel}`);
}

async function validateProjectPathIdentity(
  root: string,
  identity: ProjectPathIdentity,
  relativeLabel: string
): Promise<void> {
  let current: ProjectPathIdentity;
  try {
    current = await captureProjectPathIdentity(root, identity.path, identity.kind, relativeLabel);
  } catch (error) {
    throw new Error(`Output ${identity.kind === "directory" ? "parent" : "file"} identity changed: ${relativeLabel}`, { cause: error });
  }
  if (!sameProjectIdentity(identity, current)) {
    throw new Error(`Output ${identity.kind === "directory" ? "parent" : "file"} identity changed: ${relativeLabel}`);
  }
}

async function optionalCapturedRegularFileState(
  root: string,
  path: string,
  parentIdentity: ProjectPathIdentity,
  relativeLabel: string
): Promise<CapturedRegularFileState | undefined> {
  let first;
  try {
    first = await lstat(path, { bigint: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  if (first.isSymbolicLink() || !first.isFile()) {
    throw new Error(`Output target is not an ordinary regular file: ${relativeLabel}`);
  }
  await validateProjectPathIdentity(root, parentIdentity, relativeLabel);
  const captured = await captureProjectPathEvidence(root, path, "file", relativeLabel);
  const identity = captured.identity;
  if (identity.parentDev !== parentIdentity.dev || identity.parentIno !== parentIdentity.ino ||
      !sameFilesystemPath(identity.parent, parentIdentity.path)) {
    throw new Error(`Output parent identity changed: ${relativeLabel}`);
  }
  await validateProjectPathIdentity(root, identity, relativeLabel);
  await validateProjectPathIdentity(root, parentIdentity, relativeLabel);
  return { contents: captured.contents!, mode: Number(identity.mode & 0o777n), identity };
}

async function ensureParentDirectories(
  root: string,
  parent: string,
  created: CreatedDirectory[],
  relativeLabel: string,
  beforeOwnedParentMutation?: (identity: ProjectPathIdentity) => Promise<void>,
  afterOwnedParentMutation?: (before: ProjectPathIdentity, after: ProjectPathIdentity) => Promise<void>
): Promise<void> {
  const missing: string[] = [];
  let current = parent;
  while (isInside(root, current) && current !== root) {
    const metadata = await optionalLstat(current);
    if (metadata) {
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error(`Output parent is not an ordinary directory: ${current}`);
      break;
    }
    missing.push(current);
    current = dirname(current);
  }
  for (const directory of missing.reverse()) {
    const createdParent = created.find((entry) => sameFilesystemPath(entry.path, dirname(directory)));
    const parentBeforeCreation = createdParent?.identity ?? await captureProjectPathIdentity(
      root,
      dirname(directory),
      "directory",
      relativeLabel
    );
    try {
      await validateProjectPathIdentity(root, parentBeforeCreation, relativeLabel);
      await beforeOwnedParentMutation?.(parentBeforeCreation);
      await mkdir(directory);
      const identity = await captureProjectPathIdentity(root, directory, "directory", relativeLabel);
      created.push({
        path: directory,
        identity
      });
      const parentAfterCreation = await captureProjectPathIdentity(
        root,
        parentBeforeCreation.path,
        "directory",
        relativeLabel
      );
      // Empty child directories use nlink=2 on traditional POSIX filesystems and
      // nlink=1 on filesystems with synthetic counts, which selects one exact delta.
      const expectedLinkDelta = parentLinkDeltaForOwnedChildDirectory(identity, 1n, relativeLabel);
      if (!sameDirectoryAcrossOwnedMutation(parentBeforeCreation, parentAfterCreation, expectedLinkDelta)) {
        throw new Error(`Output parent stable identity changed during owned directory creation: ${relativeLabel}`);
      }
      if (createdParent) createdParent.identity = parentAfterCreation;
      await afterOwnedParentMutation?.(parentBeforeCreation, parentAfterCreation);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const metadata = await lstat(directory);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error(`Output parent is not an ordinary directory: ${directory}`);
    }
  }
}

async function captureRenamedFile(
  root: string,
  path: string,
  parentIdentity: ProjectPathIdentity,
  sourceIdentity: ProjectPathIdentity,
  relativeLabel: string
): Promise<ProjectPathIdentity> {
  const identity = await captureProjectPathIdentity(root, path, "file", relativeLabel);
  if (!sameProjectVersionAcrossRename(sourceIdentity, identity) ||
      identity.parentDev !== parentIdentity.dev || identity.parentIno !== parentIdentity.ino ||
      !sameFilesystemPath(identity.parent, parentIdentity.path)) {
    throw new Error(`Output file identity changed across rename: ${relativeLabel}`);
  }
  return identity;
}

async function assertTargetState(
  changeset: PersistedChangeset,
  item: {
    change: PersistedChange;
    target: string;
    parentIdentity: ProjectPathIdentity;
    targetIdentity?: ProjectPathIdentity;
  },
  expected: "original" | "missing"
): Promise<CapturedRegularFileState | undefined> {
  await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
  const current = await optionalCapturedRegularFileState(
    changeset.root,
    item.target,
    item.parentIdentity,
    item.change.path
  );
  if (expected === "missing") {
    if (current) throw new Error(`Target identity changed from missing before rename: ${item.change.path}`);
    return undefined;
  }
  if (!current || !item.targetIdentity || !sameProjectIdentity(current.identity, item.targetIdentity) ||
      pathHash(current.contents) !== item.change.previousHash) {
    throw new Error(`Target identity or content is stale before rename: ${item.change.path}`);
  }
  return current;
}

async function removeProjectArtifact(
  changeset: PersistedChangeset,
  parentIdentity: ProjectPathIdentity,
  identity: ProjectPathIdentity,
  relativePath: string,
  artifactName: string,
  label: "quarantine" | "temporary"
): Promise<void> {
  try {
    await validateProjectPathIdentity(changeset.root, parentIdentity, relativePath);
    await validateProjectPathIdentity(changeset.root, identity, relativePath);
    // Pure Node exposes neither handle-relative renameat nor unlinkat. Every final quarantine,
    // replacement, rollback-target, and rollback-restore rename below, plus this cleanup unlink,
    // therefore resolves a pathname one last time. POSIX rename may overwrite a destination that
    // appears after the last absence/CAS check, while Windows rename normally rejects an occupied
    // destination. The before/after identity closures detect observable changes and preserve
    // evidence, but a hostile same-user process can still race that final pathname syscall.
    await unlink(identity.path);
  } catch (error) {
    throw new Error(`${label === "quarantine" ? "Quarantine" : "Temporary"} cleanup is ambiguous for ${artifactName}`, { cause: error });
  }
}

function primaryMessage(error: unknown): string {
  return error instanceof Error ? error.message : "unknown apply failure";
}

async function atomicApply(
  changeset: PersistedChangeset,
  verifyBeforeCommit: () => Promise<void>,
  beforeCommit?: (root: string) => Promise<void>,
  beforeRename?: (path: string, index: number) => Promise<void>,
  beforeStageWrite?: (path: string, index: number) => Promise<void>,
  beforeMutationRename?: ServiceOptions["beforeMutationRename"],
  afterMutationRename?: ServiceOptions["afterMutationRename"],
  beforePostRenameIdentityCapture?: ServiceOptions["beforePostRenameIdentityCapture"],
  beforeQuarantineCleanup?: ServiceOptions["beforeQuarantineCleanup"],
  assertMutationAuthority: () => Promise<void> = async () => undefined
): Promise<void> {
  const staged: Array<{
    index: number;
    change: PersistedChange;
    target: string;
    parentIdentity: ProjectPathIdentity;
    targetIdentity?: ProjectPathIdentity;
    temporary?: string;
    temporaryIdentity?: ProjectPathIdentity;
    quarantine?: string;
    quarantineIdentity?: ProjectPathIdentity;
    quarantineRenamed: boolean;
    committedIdentity?: ProjectPathIdentity;
    replacementRenamed: boolean;
    rollbackDiscard?: string;
    rollbackDiscardIdentity?: ProjectPathIdentity;
    rollbackDiscardRenamed: boolean;
    committed: boolean;
  }> = [];
  let commitOrder: typeof staged = [];
  const createdDirectories: CreatedDirectory[] = [];
  let primaryError: unknown;
  const rollbackErrors: unknown[] = [];
  const assertTrackedParentBeforeOwnedMutation = async (current: ProjectPathIdentity): Promise<void> => {
    for (const item of staged) {
      if (!sameFilesystemPath(item.parentIdentity.path, current.path)) continue;
      if (!sameProjectIdentity(item.parentIdentity, current)) {
        throw new Error(`Output parent identity changed before owned directory creation: ${item.change.path}`);
      }
    }
  };
  const refreshTrackedParentAfterOwnedMutation = async (
    previous: ProjectPathIdentity,
    current: ProjectPathIdentity
  ): Promise<void> => {
    for (const item of staged) {
      if (sameFilesystemPath(item.parentIdentity.path, previous.path) &&
          sameProjectIdentity(item.parentIdentity, previous)) {
        item.parentIdentity = current;
      }
    }
  };
  const refreshParentAfterOwnedMutation = async (
    previous: ProjectPathIdentity,
    relativeLabel: string
  ): Promise<ProjectPathIdentity> => {
    const current = await captureProjectPathIdentity(changeset.root, previous.path, "directory", relativeLabel);
    if (!sameDirectoryAcrossOwnedMutation(previous, current)) {
      throw new Error(`Output parent stable identity changed during owned mutation: ${relativeLabel}`);
    }
    for (const item of staged) {
      if (sameFilesystemPath(item.parentIdentity.path, previous.path) &&
          item.parentIdentity.dev === previous.dev && item.parentIdentity.ino === previous.ino) {
        item.parentIdentity = current;
      }
    }
    for (const directory of createdDirectories) {
      if (sameFilesystemPath(directory.path, previous.path) &&
          directory.identity.dev === previous.dev && directory.identity.ino === previous.ino) {
        directory.identity = current;
      }
    }
    return current;
  };
  try {
    for (const [index, change] of changeset.changes.entries()) {
      const target = join(changeset.root, ...change.path.split("/"));
      await ensureParentDirectories(
        changeset.root,
        dirname(target),
        createdDirectories,
        change.path,
        assertTrackedParentBeforeOwnedMutation,
        refreshTrackedParentAfterOwnedMutation
      );
      const parentIdentity = await captureProjectPathIdentity(changeset.root, dirname(target), "directory", change.path);
      const original = await optionalCapturedRegularFileState(changeset.root, target, parentIdentity, change.path);
      if (pathHash(original?.contents) !== change.previousHash) throw new Error(`Target is stale before staging: ${change.path}`);
      if (change.delete) staged.push({
        index,
        change,
        target,
        parentIdentity,
        targetIdentity: original?.identity,
        quarantineRenamed: false,
        replacementRenamed: false,
        rollbackDiscardRenamed: false,
        committed: false
      });
      else {
        const temporary = join(dirname(target), `.${basename(target)}.project-design-keeper-${randomUUID()}.stage`);
        staged.push({
          index,
          change,
          target,
          parentIdentity,
          targetIdentity: original?.identity,
          temporary,
          quarantineRenamed: false,
          replacementRenamed: false,
          rollbackDiscardRenamed: false,
          committed: false
        });
      }
    }
    const manifestPathKey = windowsRepositoryPathKey("docs/project-design/manifest.json");
    commitOrder = [
      ...staged.filter((item) => windowsRepositoryPathKey(item.change.path) !== manifestPathKey),
      ...staged.filter((item) => windowsRepositoryPathKey(item.change.path) === manifestPathKey)
    ];

    await beforeCommit?.(changeset.root);
    for (const item of staged) {
      await beforeRename?.(item.change.path, item.index);
      if (item.temporary) await beforeStageWrite?.(item.change.path, item.index);
    }
    await verifyBeforeCommit();
    for (const item of staged) {
      const canonical = await canonicalOutput(changeset.root, item.change.path);
      if (canonical.target !== item.target) throw new Error(`Output target changed before staging: ${item.change.path}`);
      await assertTargetState(changeset, item, item.targetIdentity ? "original" : "missing");
    }
    for (const item of staged) {
      if (!item.temporary) continue;
      await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
      await assertTargetState(changeset, item, item.targetIdentity ? "original" : "missing");
      const parentBeforeCreate = item.parentIdentity;
      const handle = await open(item.temporary, "wx+", item.targetIdentity
        ? Number(item.targetIdentity.mode & 0o777n)
        : 0o600);
      try {
        await handle.writeFile(item.change.content!, { encoding: "utf8" });
        if (item.targetIdentity) {
          await handle.chmod(Number(item.targetIdentity.mode & 0o777n));
        }
        await handle.sync();
        const captured = await captureProjectPathEvidence(
          changeset.root,
          item.temporary,
          "file",
          item.change.path,
          { ownedHandle: handle }
        );
        const approvedHash = pathHash(Buffer.from(item.change.content!, "utf8"));
        if (captured.identity.contentHash !== approvedHash) {
          throw new Error(`Exclusive staging content differs from the approved output: ${item.change.path}`);
        }
        item.temporaryIdentity = captured.identity;
      } finally {
        await handle.close();
      }
      await refreshParentAfterOwnedMutation(parentBeforeCreate, item.change.path);
      const capturedTemporary = await captureProjectPathIdentity(changeset.root, item.temporary, "file", item.change.path);
      if (!item.temporaryIdentity || !sameProjectIdentity(item.temporaryIdentity, capturedTemporary)) {
        throw new Error(`Exclusive staging identity changed: ${item.change.path}`);
      }
    }

    for (const item of commitOrder) {
      const firstPhase = item.targetIdentity ? "quarantine" : "replacement";
      await beforeMutationRename?.(item.change.path, item.index, firstPhase);
      await verifyBeforeCommit();
      const canonical = await canonicalOutput(changeset.root, item.change.path);
      if (canonical.target !== item.target) throw new Error(`Output target changed during apply: ${item.change.path}`);
      if (item.targetIdentity) {
        item.quarantine = join(dirname(item.target), `.${basename(item.target)}.project-design-keeper-${randomUUID()}.quarantine`);
        if (await optionalLstat(item.quarantine)) throw new Error(`Random quarantine name was already occupied: ${item.change.path}`);
        await assertMutationAuthority();
        await assertTargetState(changeset, item, "original");
        if (await optionalLstat(item.quarantine)) throw new Error(`Random quarantine name was occupied before rename: ${item.change.path}`);
        const parentBeforeQuarantine = item.parentIdentity;
        await rename(item.target, item.quarantine);
        item.quarantineRenamed = true;
        await refreshParentAfterOwnedMutation(parentBeforeQuarantine, item.change.path);
        await beforePostRenameIdentityCapture?.(item.change.path, "quarantine", basename(item.quarantine));
        await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
        item.quarantineIdentity = await captureRenamedFile(
          changeset.root,
          item.quarantine,
          item.parentIdentity,
          item.targetIdentity,
          item.change.path
        );
        await afterMutationRename?.(item.change.path, "quarantine", basename(item.quarantine));
        await assertMutationAuthority();
      } else {
        await assertTargetState(changeset, item, "missing");
      }
      if (item.temporary && item.temporaryIdentity) {
        if (item.targetIdentity) await beforeMutationRename?.(item.change.path, item.index, "replacement");
        await assertMutationAuthority();
        await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
        await assertTargetState(changeset, item, "missing");
        await validateProjectPathIdentity(changeset.root, item.temporaryIdentity, item.change.path);
        const parentBeforeReplacement = item.parentIdentity;
        await rename(item.temporary, item.target);
        item.replacementRenamed = true;
        await refreshParentAfterOwnedMutation(parentBeforeReplacement, item.change.path);
        await beforePostRenameIdentityCapture?.(item.change.path, "replacement");
        await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
        item.committedIdentity = await captureRenamedFile(
          changeset.root,
          item.target,
          item.parentIdentity,
          item.temporaryIdentity,
          item.change.path
        );
        await afterMutationRename?.(item.change.path, "replacement");
        await assertMutationAuthority();
      }
      item.committed = true;
    }
  } catch (error) {
    primaryError = error;
    for (const item of [...commitOrder].reverse().filter((candidate) =>
      candidate.committed || candidate.replacementRenamed || candidate.quarantineRenamed ||
      candidate.committedIdentity !== undefined || candidate.quarantineIdentity !== undefined)) {
      try {
        await assertMutationAuthority();
        await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
        if (item.replacementRenamed && !item.committedIdentity) {
          if (!item.temporaryIdentity) throw new Error(`Replacement identity evidence is missing: ${item.change.path}`);
          item.committedIdentity = await captureRenamedFile(
            changeset.root,
            item.target,
            item.parentIdentity,
            item.temporaryIdentity,
            item.change.path
          );
        }
        if (item.quarantineRenamed && !item.quarantineIdentity) {
          if (!item.quarantine || !item.targetIdentity) {
            throw new Error(`Quarantine identity evidence is missing: ${item.change.path}`);
          }
          item.quarantineIdentity = await captureRenamedFile(
            changeset.root,
            item.quarantine,
            item.parentIdentity,
            item.targetIdentity,
            item.change.path
          );
        }
        if (item.committedIdentity) {
          await beforeMutationRename?.(item.change.path, item.index, "rollback-target");
          await assertMutationAuthority();
          await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
          await validateProjectPathIdentity(changeset.root, item.committedIdentity, item.change.path);
          item.rollbackDiscard = join(dirname(item.target), `.${basename(item.target)}.project-design-keeper-${randomUUID()}.rollback`);
          if (await optionalLstat(item.rollbackDiscard)) throw new Error(`Rollback quarantine name was occupied: ${item.change.path}`);
          const parentBeforeRollbackTarget = item.parentIdentity;
          await rename(item.target, item.rollbackDiscard);
          item.rollbackDiscardRenamed = true;
          item.replacementRenamed = false;
          await refreshParentAfterOwnedMutation(parentBeforeRollbackTarget, item.change.path);
          await beforePostRenameIdentityCapture?.(
            item.change.path,
            "rollback-target",
            basename(item.rollbackDiscard)
          );
          await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
          item.rollbackDiscardIdentity = await captureRenamedFile(
            changeset.root,
            item.rollbackDiscard,
            item.parentIdentity,
            item.committedIdentity,
            item.change.path
          );
          await afterMutationRename?.(item.change.path, "rollback-target", basename(item.rollbackDiscard));
        }
        await assertTargetState(changeset, item, "missing");
        if (item.quarantine && item.quarantineIdentity) {
          await beforeMutationRename?.(item.change.path, item.index, "rollback-restore");
          await assertMutationAuthority();
          await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
          await assertTargetState(changeset, item, "missing");
          await validateProjectPathIdentity(changeset.root, item.quarantineIdentity, item.change.path);
          const parentBeforeRollbackRestore = item.parentIdentity;
          await rename(item.quarantine, item.target);
          item.quarantineRenamed = false;
          await refreshParentAfterOwnedMutation(parentBeforeRollbackRestore, item.change.path);
          await beforePostRenameIdentityCapture?.(item.change.path, "rollback-restore");
          await validateProjectPathIdentity(changeset.root, item.parentIdentity, item.change.path);
          await captureRenamedFile(
            changeset.root,
            item.target,
            item.parentIdentity,
            item.quarantineIdentity,
            item.change.path
          );
          item.quarantineIdentity = undefined;
          await afterMutationRename?.(item.change.path, "rollback-restore");
        }
        if (item.rollbackDiscardRenamed && item.rollbackDiscard && item.rollbackDiscardIdentity) {
          const parentBeforeRollbackCleanup = item.parentIdentity;
          await removeProjectArtifact(
            changeset,
            item.parentIdentity,
            item.rollbackDiscardIdentity,
            item.change.path,
            basename(item.rollbackDiscard),
            "quarantine"
          );
          await refreshParentAfterOwnedMutation(parentBeforeRollbackCleanup, item.change.path);
          item.rollbackDiscardRenamed = false;
          item.rollbackDiscardIdentity = undefined;
        }
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      }
    }
  }

  const stagingCleanupErrors: unknown[] = [];
  for (const item of staged) {
    if (!item.temporary || !item.temporaryIdentity) continue;
    try {
      const metadata = await optionalLstat(item.temporary);
      if (metadata) {
        const parentBeforeTemporaryCleanup = item.parentIdentity;
        await removeProjectArtifact(
          changeset,
          item.parentIdentity,
          item.temporaryIdentity,
          item.change.path,
          basename(item.temporary),
          "temporary"
        );
        await refreshParentAfterOwnedMutation(parentBeforeTemporaryCleanup, item.change.path);
      }
    } catch (error) {
      stagingCleanupErrors.push(error);
    }
  }
  for (const directory of [...createdDirectories].sort((left, right) => right.path.length - left.path.length)) {
    try {
      const createdParent = createdDirectories.find((entry) => sameFilesystemPath(entry.path, dirname(directory.path)));
      const parentBeforeRemoval = createdParent?.identity;
      await validateProjectPathIdentity(changeset.root, directory.identity, relative(changeset.root, directory.path));
      if (parentBeforeRemoval) {
        await validateProjectPathIdentity(
          changeset.root,
          parentBeforeRemoval,
          relative(changeset.root, parentBeforeRemoval.path)
        );
      }
      await rmdir(directory.path);
      if (createdParent && parentBeforeRemoval) {
        const parentAfterRemoval = await captureProjectPathIdentity(
          changeset.root,
          parentBeforeRemoval.path,
          "directory",
          relative(changeset.root, parentBeforeRemoval.path)
        );
        const expectedLinkDelta = parentLinkDeltaForOwnedChildDirectory(
          directory.identity,
          -1n,
          relative(changeset.root, directory.path)
        );
        if (!sameDirectoryAcrossOwnedMutation(parentBeforeRemoval, parentAfterRemoval, expectedLinkDelta)) {
          throw new Error(`Output parent stable identity changed during owned directory cleanup: ${relative(changeset.root, parentBeforeRemoval.path)}`);
        }
        createdParent.identity = parentAfterRemoval;
      }
    } catch (error) {
      if (!new Set(["ENOENT", "ENOTEMPTY", "EEXIST"]).has((error as NodeJS.ErrnoException).code ?? "")) {
        stagingCleanupErrors.push(error);
      }
    }
  }

  if (primaryError !== undefined) {
    const incomplete = [...rollbackErrors, ...stagingCleanupErrors];
    if (incomplete.length > 0) {
      const retainedQuarantines = staged.flatMap((item) => [
        ...(item.quarantineRenamed && item.quarantine ? [basename(item.quarantine)] : []),
        ...(item.rollbackDiscardRenamed && item.rollbackDiscard ? [basename(item.rollbackDiscard)] : [])
      ]);
      const retainedEvidence = retainedQuarantines.length > 0
        ? `; retained quarantine evidence: ${retainedQuarantines.join(", ")}`
        : "";
      throw new AggregateError(
        [primaryError, ...incomplete],
        `Apply failed: ${primaryMessage(primaryError)}; rollback or cleanup was incomplete${retainedEvidence}`,
        { cause: primaryError }
      );
    }
    throw primaryError;
  }

  const quarantineCleanupErrors: unknown[] = [];
  for (const item of staged) {
    if (!item.quarantine || !item.quarantineIdentity) continue;
    try {
      await beforeQuarantineCleanup?.(item.change.path, basename(item.quarantine));
      await assertMutationAuthority();
      const parentBeforeQuarantineCleanup = item.parentIdentity;
      await removeProjectArtifact(
        changeset,
        item.parentIdentity,
        item.quarantineIdentity,
        item.change.path,
        basename(item.quarantine),
        "quarantine"
      );
      await refreshParentAfterOwnedMutation(parentBeforeQuarantineCleanup, item.change.path);
      item.quarantineIdentity = undefined;
      item.quarantineRenamed = false;
    } catch (error) {
      quarantineCleanupErrors.push(error);
    }
  }
  if (quarantineCleanupErrors.length > 0 || stagingCleanupErrors.length > 0) {
    const errors = [...quarantineCleanupErrors, ...stagingCleanupErrors];
    throw new AggregateError(
      errors,
      `Project update committed, but quarantine cleanup was ambiguous: ${errors.map(primaryMessage).join("; ")}`
    );
  }
}

export function createTransactionService(options: ServiceOptions = {}, sharedApprovalAuthority?: ApplyApprovalAuthority) {
  const cacheDirectory = resolveCacheDirectory(
    options,
    options.environment ?? process.env,
    options.homeDirectory ?? homedir()
  );
  const now = options.now ?? (() => Date.now());
  const policy = freezeRuntimePolicy(options.runtimePolicy);
  const limits = resolveKeeperLimits(options.limits, policy);
  const approvalAuthority = sharedApprovalAuthority ?? createApplyApprovalAuthority(now);
  const readFileBytes = Math.min(managedReadLimits.maxFileBytes, options.limits?.preview?.maxFileBytes ?? Infinity);
  const readAggregateBytes = Math.min(managedReadLimits.maxAggregateBytes, options.limits?.preview?.maxAggregateBytes ?? Infinity);
  const changesetStore = createChangesetStore({
    cacheDirectory,
    environment: options.environment,
    homeDirectory: options.homeDirectory,
    now,
    limits: options.limits,
    runtimePolicy: policy
  });

  async function loadAuthenticatedChangeset(request: ChangesetRequest): Promise<LoadedAuthenticatedChangeset> {
    await validateManagedRoots(request.root);
    const loaded = await changesetStore.loadAuthenticated(request.root, request.changesetId);
    approvalBinding(loaded.changeset);
    if (!sameRuntimePolicy(loaded.changeset.policy!, policy)) {
      throw new Error("Settings revision changed since preview; regenerate the preview update");
    }
    assertWriteBudget(loaded.changeset.changes);
    return loaded;
  }

  function assertWriteBudget(changes: PersistedChange[]): void {
    if (changes.length > limits.preview.maxChanges) throw new Error(`Preview changes exceeds the limit of ${limits.preview.maxChanges} items`);
    const aggregate = new ByteBudget("Preview aggregate bytes", limits.preview.maxAggregateBytes);
    for (const change of changes) {
      const bytes = change.delete ? 0 : Buffer.byteLength(change.content ?? "", "utf8");
      aggregate.consume(bytes);
      if (bytes > limits.preview.maxFileBytes) throw new Error(`Preview file ${change.path} exceeds the per-file limit of ${limits.preview.maxFileBytes} bytes`);
    }
  }

  function previewPage(changeset: PersistedChangeset, cursor?: unknown) {
    const bytes = Buffer.from(changeset.diff!, "utf8");
    let start = 0;
    if (cursor !== undefined) {
      if (typeof cursor !== "string" || cursor.length > 256) throw new Error("Invalid preview cursor");
      const prefix = `${changeset.changesetId}:${changeset.diffDigest}:`;
      if (!cursor.startsWith(prefix) || !/^(0|[1-9][0-9]*)$/u.test(cursor.slice(prefix.length))) throw new Error("Invalid preview cursor binding");
      start = Number(cursor.slice(prefix.length));
      if (!Number.isSafeInteger(start) || start >= bytes.length || (start > 0 && (bytes[start]! & 0xc0) === 0x80)) throw new Error("Invalid preview cursor offset");
    }
    // Worst-case JSON string escaping uses six bytes per byte. Keep every page
    // below the shared one-MiB envelope even for control-character-heavy diffs.
    const pageBytes = Math.max(4, Math.min(limits.preview.maxDiffBytes, 128 * 1024));
    let end = Math.min(bytes.length, start + pageBytes);
    while (end < bytes.length && (bytes[end]! & 0xc0) === 0x80) end -= 1;
    const complete = end === bytes.length;
    return { diff: bytes.subarray(start, end).toString("utf8"), nextCursor: complete ? null : `${changeset.changesetId}:${changeset.diffDigest}:${end}`, complete, totalBytes: bytes.length, diffDigest: changeset.diffDigest };
  }

  async function readPreview(input: Record<string, unknown>) {
    const request = await resolveChangesetRequest(input);
    const { changeset } = await loadAuthenticatedChangeset(request);
    const page = { changesetId: changeset.changesetId, policy: { ...policy }, ...previewPage(changeset, input.cursor) };
    assertToolResultBudget(page);
    return page;
  }

  async function inspectChangesetForApproval(input: Record<string, unknown>): Promise<ChangesetApprovalBinding> {
    const request = await resolveChangesetRequest(input);
    const { changeset } = await loadAuthenticatedChangeset(request);
    const binding = approvalBinding(changeset);
    assertSerializedWithin("Changeset approval summary", binding, 1024 * 1024);
    return binding;
  }

  function issueApplyAuthorization(
    binding: ChangesetApprovalBinding,
    requestIdentity: object
  ): ApplyAuthorization {
    return approvalAuthority.issue(binding, requestIdentity);
  }

  async function previewUpdate(input: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (typeof input.root !== "string") throw new Error("A repository root is required");
    const changes = requestedChanges(input.changes);
    if (changes.length > limits.preview.maxChanges) throw new Error(`Preview changes exceeds the limit of ${limits.preview.maxChanges} items`);
    let candidatePack = typeof input.pack === "object" && input.pack !== null && !Array.isArray(input.pack)
      ? input.pack as Record<string, unknown>
      : undefined;
    const previewReads = projectFileReadBudget(
      "Preview file reads",
      readFileBytes,
      readAggregateBytes,
      limits.scan.maxFiles,
      limits.scan.deadlineMs
    );
    const candidateValidationResources = {
      maxFileBytes: previewReads.maxFileBytes,
      files: previewReads.files,
      bytes: previewReads.aggregate,
      deadline: previewReads.deadline,
      accountedFiles: previewReads.accountedFiles
    };
    if (candidatePack) {
      assertPackValidationInputBounds(candidatePack, {
        runtimePolicy: policy,
        limits: options.limits,
        resourceBudget: candidateValidationResources
      });
      const serializedCandidatePack = JSON.stringify(candidatePack);
      if (serializedCandidatePack === undefined) throw new Error("Candidate pack must be serializable JSON");
      candidatePack = JSON.parse(serializedCandidatePack) as Record<string, unknown>;
    }
    assertSerializedWithin("Preview arguments", input, limits.mcpArgumentBytes);
    const decisions = redundancyDecisions(input.redundancyDecisions);
    const analysisId = typeof input.analysisId === "string" ? input.analysisId : undefined;
    if ((decisions && !analysisId) || (analysisId && !decisions)) {
      throw new Error("analysisId and redundancyDecisions must be supplied together");
    }
    if (decisions && !candidatePack) throw new Error("A candidate pack is required for redundancy decisions");
    const lexicalOutputs = changes.map((change) => canonicalRelativePath(change.path));
    if (lexicalOutputs.some((output) => output.managedRoot === "docs/project-design") && !candidatePack) {
      throw new Error("A candidate pack is required when previewing project-design documents");
    }
    const scope = await resolveScope({ root: input.root, path: "." });
    await validateManagedRoots(scope.root);
    const manifestPath = "docs/project-design/manifest.json";
    const manifestKey = windowsRepositoryPathKey(manifestPath);
    const currentManifestTarget = (await canonicalOutput(scope.root, manifestPath)).target;
    const currentManifestBytesAtPreview = await boundedOptionalProjectRead(
      scope.root,
      currentManifestTarget,
      manifestPath,
      previewReads
    );
    const currentPackAtPreview = currentManifestBytesAtPreview ? parseCandidateManifest(currentManifestBytesAtPreview) : undefined;
    if (options.afterCurrentManifestRead) await options.afterCurrentManifestRead(scope.root);
    const allowSchemaMigrationRegrouping = candidatePack?.schemaVersion === "3.0" &&
      (currentPackAtPreview?.schemaVersion === "1.0" || currentPackAtPreview?.schemaVersion === "2.0");
    await changesetStore.collectGarbage(scope.root);
    const resolvedChanges = await Promise.all(changes.map(async (change) => ({ change, ...(await canonicalOutput(scope.root, change.path)) })));
    const grouped = new Map<string, { path: string; target: string; changes: RequestedChange[] }>();
    for (const resolvedChange of resolvedChanges) {
      const existing = grouped.get(resolvedChange.key);
      if (existing) existing.changes.push(resolvedChange.change);
      else grouped.set(resolvedChange.key, { path: resolvedChange.path, target: resolvedChange.target, changes: [resolvedChange.change] });
    }
    for (const group of grouped.values()) {
      if (group.changes.length > 1 && group.changes.some((change) => !change.managedBlock)) {
        throw new Error(`Duplicate aliased output path must contain only managed-block updates: ${group.path}`);
      }
    }
    const changesProjectDesign = resolvedChanges.some(({ path }) => path.startsWith("docs/project-design/"));
    const unmanaged = changesProjectDesign
      ? await unmanagedOutputs(scope.root, limits, previewReads, options.beforeProjectDesignOutputEntry)
      : [];
    if (unmanaged.length > 0 && changesProjectDesign) {
      const unmanagedConflicts = [`Unmanaged project-design output exists: ${unmanaged.join(", ")}`];
      return {
        applicable: false,
        conflicts: unmanagedConflicts,
        ...(candidatePack ? { validation: conflictValidation(unmanagedConflicts) } : {}),
        changes: []
      };
    }

    const conflicts: string[] = [];
    const persisted: PersistedChange[] = [];
    const originals = new Map<string, Buffer | undefined>();
    for (const { path, target, changes: targetChanges } of grouped.values()) {
      const original = await boundedOptionalProjectRead(scope.root, target, path, previewReads);
      originals.set(path, original);
      const existingOwnership = original ? ownership(path, original) : undefined;
      if (original && !existingOwnership!.owned) {
        conflicts.push(`${path}: Existing output is unmanaged: ${existingOwnership!.conflict ?? "missing Keeper ownership"}`);
        continue;
      }
      const [firstChange] = targetChanges;
      if (firstChange.delete) {
        if (!original || !existingOwnership!.fullyOwned) {
          conflicts.push(`${path}: delete requires fully Keeper-owned content`);
          continue;
        }
        persisted.push({ path, delete: true, previousHash: pathHash(original) });
        continue;
      }
      if (firstChange.content !== undefined) {
        const candidateBytes = Buffer.from(firstChange.content, "utf8");
        const migratingToDerivedNavigation = candidatePack?.schemaVersion === "2.0" || candidatePack?.schemaVersion === "3.0";
        const machineOutput = /\.jsonl?$/iu.test(path);
        if (original && !machineOutput && !derivedReplacementAllowed(
          original,
          candidateBytes,
          migratingToDerivedNavigation,
          allowSchemaMigrationRegrouping
        )) {
          conflicts.push(`${path}: existing Markdown must be updated through managed blocks`);
          continue;
        }
        const isCandidateManifest = candidatePack !== undefined && windowsRepositoryPathKey(path) ===
          windowsRepositoryPathKey("docs/project-design/manifest.json") && parseCandidateManifest(candidateBytes) !== undefined;
        if (original && machineOutput && !ownership(path, candidateBytes).owned && !isCandidateManifest) {
          conflicts.push(`${path}: replacement machine output lacks Keeper ownership/schema`);
          continue;
        }
        if (!original) {
          const candidate = creationOwnership(path, candidateBytes);
          if (!candidate.allowed && !isCandidateManifest) {
            conflicts.push(`${path}: new output lacks Keeper ownership: ${candidate.conflict ?? "missing ownership"}`);
            continue;
          }
        }
        persisted.push({ path, content: firstChange.content, previousHash: pathHash(original) });
        continue;
      }

      if (/\.jsonl?$/iu.test(path)) {
        conflicts.push(`${path}: machine outputs cannot be updated through managed blocks`);
        continue;
      }
      if (!original && windowsRepositoryPathKey(path) === keeperSkillPathKey) {
        conflicts.push(`${path}: Keeper SKILL.md must be created with a valid Skill envelope through content`);
        continue;
      }
      let content = original?.toString("utf8") ?? "";
      const managedBlocks: NonNullable<PersistedChange["managedBlocks"]> = [];
      for (const change of targetChanges) {
        const expectedContentHash = change.expectedContentHash ?? (typeof input.expectedContentHash === "string" ? input.expectedContentHash : undefined);
        const merged = mergeManagedBlock(
          content,
          change.managedBlock!,
          expectedContentHash
        );
        if (merged.conflict) {
          conflicts.push(`${path}: ${merged.conflict}`);
          break;
        }
        content = merged.content!;
        managedBlocks.push({ ...change.managedBlock!, ...(expectedContentHash ? { expectedContentHash } : {}) });
      }
      if (conflicts.some((conflict) => conflict.startsWith(`${path}:`))) continue;
      persisted.push({
        path,
        content,
        previousHash: pathHash(original),
        managedBlocks
      });
    }
    if (conflicts.length > 0) {
      return {
        applicable: false,
        conflicts,
        ...(candidatePack ? { validation: conflictValidation(conflicts) } : {}),
        changes: responseChanges(persisted)
      };
    }

    assertWriteBudget(persisted);
    const capturedManifest = [...originals.entries()]
      .find(([path]) => windowsRepositoryPathKey(path) === manifestKey);
    const exactCurrentManifestBytes = capturedManifest
      ? capturedManifest[1]
      : await boundedOptionalProjectRead(scope.root, currentManifestTarget, manifestPath, previewReads);
    if (!equalOptionalBytes(currentManifestBytesAtPreview, exactCurrentManifestBytes)) {
      throw new Error("Project design manifest changed during preview; retry the preview against a stable baseline");
    }
    if (options.afterManifestBaselineValidation) await options.afterManifestBaselineValidation(scope.root);
    const currentPackForChangeset = exactCurrentManifestBytes
      ? parseCandidateManifest(exactCurrentManifestBytes)
      : undefined;
    let confirmedArchiveActions = emptyArchiveActions();
    let confirmedHistoryFiles: Record<string, string | null> = {};
    let confirmedValidationDependencyDigest: `sha256:${string}` | undefined;
    let validation: Record<string, unknown> | undefined;
    if (candidatePack) {
      const overlay = new Map<string, Buffer | undefined>(persisted.map((change) => [
        change.path,
        change.delete ? undefined : Buffer.from(change.content!, "utf8")
      ]));
      const persistedOverlayByKey = new Map(
        [...overlay.entries()].map(([path, value]) => [windowsRepositoryPathKey(path), value] as const)
      );
      const actionFileErrors = actionBearingHistoryPaths(currentPackForChangeset, candidatePack)
        .flatMap((path) => persistedOverlayByKey.get(windowsRepositoryPathKey(path)) !== undefined
          ? []
          : [{
            code: "archive_action_file_not_persisted",
            path,
            message: "New archive and tombstone actions must be supplied as exact persisted changes"
          }]);
      const originalsByKey = new Map(
        [...originals.entries()].map(([path, value]) => [windowsRepositoryPathKey(path), value] as const)
      );
      const historyDependencySnapshot = new Map<string, { path: string; bytes: Buffer | undefined }>();
      const readHistoryDependency = async (path: string): Promise<Buffer | undefined> => {
        const key = windowsRepositoryPathKey(path);
        const existing = historyDependencySnapshot.get(key);
        if (existing) return existing.bytes;
        const output = await canonicalOutput(scope.root, path);
        const bytes = await boundedOptionalProjectRead(scope.root, output.target, output.path, previewReads);
        historyDependencySnapshot.set(output.key, { path: output.path, bytes });
        return bytes;
      };
      for (const path of packHistoryPaths(candidatePack)) {
        const key = windowsRepositoryPathKey(path);
        if (persistedOverlayByKey.has(key)) continue;
        // Capture every unchanged final-view dependency into the overlay once;
        // the integrity loader itself never falls through to the live filesystem.
        const bytes = await readHistoryDependency(path);
        overlay.set(path, bytes);
      }
      const overlayByKey = new Map(
        [...overlay.entries()].map(([path, value]) => [windowsRepositoryPathKey(path), value] as const)
      );
      validation = await validatePack({ root: scope.root, pack: candidatePack }, {
        runtimePolicy: policy,
        overlay,
        preaccountedOverlay: new Set(historyDependencySnapshot.keys()),
        limits: options.limits,
        io: options.validationIo,
        resourceBudget: candidateValidationResources,
        onValidationDependencyDigest: (digest) => { confirmedValidationDependencyDigest = digest; }
      });
      const validationErrors = [
        ...(Array.isArray(validation.errors) ? [...validation.errors] as Array<Record<string, unknown>> : []),
        ...actionFileErrors
      ];
      if (currentPackForChangeset) {
        validationErrors.push(...await migrationPreservationDiagnostics(
          scope.root,
          currentPackForChangeset,
          candidatePack,
          overlay,
          async (path) => {
            const output = await canonicalOutput(scope.root, path);
            return boundedOptionalProjectRead(scope.root, output.target, output.path, previewReads);
          }
        ));
      }
      const overlayManifest = [...overlay.entries()].find(([path]) => windowsRepositoryPathKey(path) === manifestKey);
      const manifestBytes = overlayManifest
        ? overlayManifest[1]
        : exactCurrentManifestBytes;
      const manifest = manifestBytes ? parseCandidateManifest(manifestBytes) : undefined;
      if (!manifest) {
        validationErrors.push({ code: "manifest_missing_or_invalid", path: manifestPath, message: "Candidate manifest is missing or lacks Keeper ownership/schema" });
      } else if (!isDeepStrictEqual(manifest, candidatePack)) {
        validationErrors.push({ code: "manifest_pack_mismatch", path: manifestPath, message: "Candidate manifest does not equal the validated pack" });
      }
      const currentManifest = currentPackForChangeset;
      if (manifest) {
        const safeHistoryRead = async (path: string, candidate: boolean): Promise<Buffer | undefined> => {
          if (!safeRepositoryPath(path, true) || !path.startsWith("docs/project-design/")) return undefined;
          const key = windowsRepositoryPathKey(path);
          if (candidate) return overlayByKey.get(key);
          if (!candidate && originalsByKey.has(key)) return originalsByKey.get(key);
          return readHistoryDependency(path);
        };
        if (manifest.schemaVersion === "3.0") {
          try {
            await loadAndValidateHistoryOverlay(manifest, (path) => safeHistoryRead(path, true));
          } catch (error) {
            validationErrors.push({
              code: "history_integrity_invalid",
              path: "archive",
              message: `Candidate Schema 3.0 history is invalid: ${error instanceof Error ? error.message : "unknown history error"}`
            });
          }
        }
        const transitionIssues = currentManifest
          ? await validateArchiveTransition({
            currentPack: currentManifest,
            candidatePack: manifest,
            readCurrent: (path) => safeHistoryRead(path, false),
            readCandidate: (path) => safeHistoryRead(path, true),
            now
          })
          : [];
        validationErrors.push(...transitionIssues.map((issue) => ({ ...issue })));
        if (transitionIssues.length === 0 && validationErrors.length === 0) {
          confirmedArchiveActions = await deriveArchiveActions(
            currentManifest,
            manifest,
            (path) => safeHistoryRead(path, false),
            (path) => safeHistoryRead(path, true)
          );
        }
      }
      if (validationErrors.length === 0 && decisions && analysisId) {
        const candidateRecordAssessments = Array.isArray(validation.recordAssessments)
          ? validation.recordAssessments.filter((assessment): assessment is { id: string; effectiveConfidence: "high" | "medium" | "low" } =>
            Boolean(assessment) && typeof assessment === "object" && !Array.isArray(assessment) &&
            typeof (assessment as Record<string, unknown>).id === "string" &&
            ["high", "medium", "low"].includes(String((assessment as Record<string, unknown>).effectiveConfidence)))
          : [];
        await validateRedundancyDecisions({
          root: scope.root,
          analysisId,
          decisions,
          candidatePack,
          candidateRecordAssessments,
          now
        });
      }
      validation = { ...validation, valid: validationErrors.length === 0, errors: validationErrors };
      if (validationErrors.length > 0) {
        return {
          applicable: false,
          conflicts: ["Candidate pack validation failed"],
          validation,
          changes: responseChanges(persisted)
        };
      }
      if (!confirmedValidationDependencyDigest) {
        throw new Error("Candidate pack validation did not capture its dependency digest");
      }
      confirmedHistoryFiles = Object.fromEntries([...historyDependencySnapshot.values()]
        .sort((left, right) => left.path.localeCompare(right.path, "en-US"))
        .map(({ path, bytes }) => [path, pathHash(bytes)]));
    }

    if (candidatePack && options.afterCandidateValidation) await options.afterCandidateValidation(scope.root);
    const createdAt = now();
    const changesetId = randomUUID();
    const sourceScope: ScopeInput = { root: scope.root, ...(typeof input.path === "string" ? { path: input.path } : {}) };
    const candidateSourceRevision = candidatePack?.sourceRevision && typeof candidatePack.sourceRevision === "object" && !Array.isArray(candidatePack.sourceRevision)
      ? (candidatePack.sourceRevision as Record<string, unknown>).files
      : undefined;
    const sourcePaths = candidateSourceRevision && typeof candidateSourceRevision === "object" && !Array.isArray(candidateSourceRevision)
      ? Object.keys(candidateSourceRevision as Record<string, unknown>).sort()
      : undefined;
    const confirmedSemanticDecisionIds = semanticDecisionIds(currentPackForChangeset, candidatePack, decisions);
    const diff = unifiedDiff(persisted, originals);
    const changeset: PersistedChangeset = {
      version: 3,
      policy,
      diff,
      changesetId,
      root: scope.root,
      createdAt,
      expiresAt: createdAt + changesetLifetimeMs,
      diffDigest: persistedDiffDigest(persisted, confirmedSemanticDecisionIds, policy, diff),
      archiveActions: confirmedArchiveActions,
      semanticDecisionIds: confirmedSemanticDecisionIds,
      historyFiles: confirmedHistoryFiles,
      changes: persisted,
      manifestHash: pathHash(exactCurrentManifestBytes),
      sourceScope,
      ...(sourcePaths && sourcePaths.length > 0 ? { sourcePaths } : {}),
      sourceFiles: sourcePaths && sourcePaths.length > 0
        ? Object.fromEntries(sourcePaths.map((path) => [path, String((candidateSourceRevision as Record<string, unknown>)[path])]))
        : await sourceFingerprint(sourceScope, options),
      ...(candidatePack && confirmedValidationDependencyDigest
        ? { validatedPack: candidatePack, validationDependencyDigest: confirmedValidationDependencyDigest }
        : {})
    };
    const previewResult = {
      applicable: true,
      conflicts: [],
      ...(validation ? { validation } : {}),
      changesetId,
      createdAt: new Date(createdAt).toISOString(),
      expiresAt: new Date(changeset.expiresAt).toISOString(),
      summary: summaryFor(persisted),
      statistics: {
        files: persisted.length,
        writeBytes: persisted.reduce((total, change) => total + (change.delete ? 0 : Buffer.byteLength(change.content!, "utf8")), 0),
        ...approvalBinding(changeset).summary
      },
      policy: { ...policy },
      ...previewPage(changeset),
      changes: responseChanges(persisted)
    };
    assertToolResultBudget(previewResult);
    const prepared = await changesetStore.preparePublication(changeset);
    await changesetStore.publishPair(prepared);
    return previewResult;
  }

  async function applyUpdate(
    input: Record<string, unknown>,
    authorization?: ApplyAuthorization,
    requestIdentity?: object
  ): Promise<Record<string, unknown>> {
    const request = await resolveChangesetRequest(input);
    const layout = await prepareSecureCache({
      cacheDirectory,
      environment: options.environment,
      homeDirectory: options.homeDirectory
    }, request.root);
    return withProcessLease({
      layout,
      projectRoot: request.root,
      now,
      timeoutMs: options.processLeaseTimeoutMs,
      leaseMs: options.processLeaseMs
    }, async (lease) => {
      const loaded = await loadAuthenticatedChangeset(request);
      if (!authorization || !requestIdentity) throw new Error("Apply requires host-mediated authorization");
      const binding = approvalBinding(loaded.changeset);
      approvalAuthority.consume(authorization, binding, requestIdentity);
      const changeset: PersistedChangeset = {
        ...loaded.changeset,
        changes: loaded.changeset.changes.map((change) => ({
          ...change,
          ...(change.managedBlocks
            ? { managedBlocks: change.managedBlocks.map((block) => ({ ...block })) }
            : {})
        }))
      };
      const targetReads = projectFileReadBudget(
        "Apply target file reads",
        readFileBytes,
        readAggregateBytes,
        limits.scan.maxFiles,
        limits.scan.deadlineMs
      );
      for (const change of changeset.changes) {
        const { target } = await canonicalOutput(changeset.root, change.path);
        const current = await regularFileState(changeset.root, target, change.path, targetReads);
        if (pathHash(current?.contents) !== change.previousHash) throw new Error(`Target is stale: ${change.path}`);
        if (change.managedBlocks) {
          let content = current?.contents.toString("utf8") ?? "";
          for (const block of change.managedBlocks) {
            const merged = mergeManagedBlock(content, block, block.expectedContentHash);
            if (merged.conflict) throw new Error(`Managed operation is no longer applicable for ${change.path}: ${merged.conflict}`);
            content = merged.content!;
          }
          change.content = content;
        }
        if (current) {
          const currentOwnership = ownership(change.path, current.contents);
          if (!currentOwnership.owned) throw new Error(`Target lacks Keeper ownership/schema: ${change.path}`);
          if (change.delete && !currentOwnership.fullyOwned) throw new Error(`Delete target is not fully Keeper-owned: ${change.path}`);
          if (change.content !== undefined && !ownership(change.path, Buffer.from(change.content, "utf8")).owned) {
            throw new Error(`Replacement output lacks Keeper ownership/schema: ${change.path}`);
          }
        } else if (change.content !== undefined) {
          const candidate = creationOwnership(change.path, Buffer.from(change.content, "utf8"));
          if (!candidate.allowed) throw new Error(`New output lacks Keeper ownership/schema: ${change.path}`);
        }
      }
      // One initial check, one after staging hooks, then one before each output.
      // A single-pass input ceiling must not be spent again as if rereading the
      // same authenticated input introduced new project data. Bound both each
      // pass and the complete, finite verification schedule instead.
      const maximumValidationPasses = changeset.changes.length + 2;
      const validationPasses = new CounterBudget("Apply validation passes", maximumValidationPasses);
      const validationDeadline = new DeadlineBudget(
        "Apply validation", Math.min(5 * 60_000, limits.scan.deadlineMs * maximumValidationPasses)
      );
      const validationOverlay = changeset.validatedPack ? new Map<string, Buffer | undefined>() : undefined;
      let validationOverlayBytes = 0;
      if (validationOverlay) {
        for (const change of changeset.changes) {
          const contents = change.delete ? undefined : Buffer.from(change.content!, "utf8");
          if (contents && contents.byteLength > readFileBytes) {
            throw new Error(`Apply validation overlay exceeds the per-file limit of ${readFileBytes} bytes: ${change.path}`);
          }
          validationOverlayBytes += contents?.byteLength ?? 0;
          validationOverlay.set(change.path, contents);
        }
      }
      const validationOverlayKeys = validationOverlay
        ? new Set([...validationOverlay.keys()].map(windowsRepositoryPathKey))
        : undefined;
      const validationAnalysisBytes = new ByteBudget(
        "Apply candidate validation analysis",
        limits.scan.maxAggregateBytes * maximumValidationPasses
      );
      const validationWork = new CounterBudget("Apply candidate validation work", limits.scan.maxEvidence * maximumValidationPasses);
      const validationManagedEntries = new CounterBudget(
        "Apply candidate validation managed-tree entries",
        Math.min(limits.scan.maxFiles, 4_096) * maximumValidationPasses
      );
      const verifyManifestAndSource = async () => {
        validationPasses.consume();
        validationDeadline.check();
        const dependencyReads = projectFileReadBudget(
          "Apply dependency file reads", readFileBytes, readAggregateBytes,
          limits.scan.maxFiles, limits.scan.deadlineMs
        );
        dependencyReads.aggregate.consume(validationOverlayBytes);
        const exactSourceReads = changeset.sourcePaths ? createExactSourceReadBudget(limits) : undefined;
        const scopedSourceReads = changeset.sourcePaths ? undefined : createScopeOperationBudget(options);
        const validationResources = {
          maxFileBytes: dependencyReads.maxFileBytes,
          files: dependencyReads.files,
          bytes: dependencyReads.aggregate,
          deadline: { check: () => { dependencyReads.deadline.check(); validationDeadline.check(); } },
          analysisBytes: validationAnalysisBytes,
          work: validationWork,
          managedEntries: validationManagedEntries,
          accountedFiles: dependencyReads.accountedFiles
        };
        await lease.assertOwned();
        if (await manifestFingerprint(changeset.root, dependencyReads) !== changeset.manifestHash) {
          throw new Error("Project design manifest is stale");
        }
        for (const [path, expectedHash] of Object.entries(changeset.historyFiles).sort(([left], [right]) => left.localeCompare(right, "en-US"))) {
          const { target } = await canonicalOutput(changeset.root, path);
          const current = await regularFileState(changeset.root, target, path, dependencyReads);
          if (pathHash(current?.contents) !== expectedHash) {
            throw new Error(`Project design history dependency is stale: ${path}`);
          }
        }
        const currentSources = changeset.sourcePaths
          ? await exactSourceFingerprint(changeset.root, changeset.sourcePaths, exactSourceReads!)
          : await sourceFingerprint(changeset.sourceScope, options, scopedSourceReads);
        if (!equalFingerprints(currentSources, changeset.sourceFiles)) throw new Error("Selected source snapshot is stale");
        if (changeset.validatedPack && changeset.validationDependencyDigest) {
          let currentDependencyDigest: `sha256:${string}` | undefined;
          const currentValidation = await validatePack({ root: changeset.root, pack: changeset.validatedPack }, {
            runtimePolicy: policy,
            overlay: validationOverlay,
            preaccountedOverlay: validationOverlayKeys,
            limits: options.limits,
            io: options.validationIo,
            resourceBudget: validationResources,
            onValidationDependencyDigest: (digest) => { currentDependencyDigest = digest; }
          });
          if (currentValidation.valid !== true || currentDependencyDigest !== changeset.validationDependencyDigest) {
            throw new Error("Candidate pack validation dependency is stale");
          }
        }
        validationDeadline.check();
      };
      await verifyManifestAndSource();
      await storeRecoverySnapshot(loaded.cache, changeset, now(), {
        beforeRecoveryTargetOpen: options.beforeRecoveryTargetOpen,
        afterRecoveryTargetOpen: options.afterRecoveryTargetOpen,
        afterRecoveryTargetRead: options.afterRecoveryTargetRead,
        beforeRecoverySnapshotPublish: options.beforeRecoverySnapshotPublish
      });
      await atomicApply(
        changeset,
        verifyManifestAndSource,
        options.beforeCommit,
        options.beforeRename,
        options.beforeStageWrite,
        options.beforeMutationRename,
        options.afterMutationRename,
        options.beforePostRenameIdentityCapture,
        options.beforeQuarantineCleanup,
        lease.assertOwned
      );
      try {
        await options.beforeChangesetConsume?.(changeset.root, changeset.changesetId);
        await changesetStore.consumePair(loaded);
        await reconcileExactRemovalIntents(loaded.cache);
      } catch (error) {
        throw new Error(
          "Project update committed successfully, but the exact authenticated changeset pair could not be consumed; project files remain applied and remaining cache evidence was preserved",
          { cause: error }
        );
      }
      return {
        applied: true,
        policy: { ...policy },
        authorizationSource: binding.authorizationSource,
        changesetId: request.changesetId,
        changes: responseChanges(changeset.changes)
      };
    });
  }

  return { previewUpdate, readPreview, inspectChangesetForApproval, issueApplyAuthorization, applyUpdate };
}

function responseChanges(changes: PersistedChange[]) {
  const full = changes.map(({ previousHash: _previousHash, managedBlocks: _managedBlocks, ...change }) => change);
  if (Buffer.byteLength(JSON.stringify(full), "utf8") < 128 * 1024) return full;
  return changes.map((change) => ({ path: change.path, ...(change.delete ? { delete: true as const } : { contentBytes: Buffer.byteLength(change.content!, "utf8"), contentOmitted: true }) }));
}
