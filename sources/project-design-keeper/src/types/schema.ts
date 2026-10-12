import { z } from "zod";
import { createHash } from "node:crypto";
import type { BigIntStats } from "node:fs";
import { lstat, open, opendir, realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep, win32 } from "node:path";
import { assessRecord, type EvidenceRef, type RecordLifecycle } from "../knowledge/model.js";
import { CanonicalJsonLinesError, decodeCanonicalJsonLines } from "../knowledge/jsonl.js";
import type { ChangesetApprovalBinding } from "../security/approval.js";
import { managedReadLimits, type RuntimePolicy } from "../settings/policy.js";
import {
  ByteBudget,
  CounterBudget,
  DeadlineBudget,
  keeperLimits,
  resolveKeeperLimits,
  type KeeperLimitOverrides,
  type KeeperLimits
} from "../security/limits.js";

export interface ScopeInput {
  path?: string;
  root?: string;
}

export interface ResolvedScope {
  root: string;
  target: string;
  isGitRepository: boolean;
  repositoryRoot?: string;
}

export interface Evidence {
  path: string;
  line: number;
  text: string;
  truncated?: boolean;
  textBytes?: number;
}

export interface Snapshot {
  root: string;
  isGitRepository: boolean;
  repositoryRoot?: string;
  files: Record<string, string>;
  changed: string[];
  new: string[];
  deleted: string[];
}

export interface ScopeFileEntry {
  path: string;
  fingerprint: string;
  size: number;
  lineCount: number;
}

export interface ScopePage {
  limit: number;
  nextCursor?: string;
  complete: boolean;
}

export interface ScanResult {
  schemaVersion: 2;
  snapshotId: string;
  scope: { root: string; paths: string[] };
  repository?: { root: string; head: string; branch?: string };
  totals: { files: number; evidence: number; omitted: number };
  candidateModules: CandidateModule[];
  items?: ScopeFileEntry[] | Evidence[];
  page?: ScopePage;
}

export interface CandidateModule {
  id: string;
  paths: string[];
  fileCount: number;
  evidenceCount: number;
}

export const scopeOmissionReasons = [
  "file-limit", "file-bytes", "aggregate-bytes", "evidence-limit", "deadline", "binary", "unsafe", "unreadable"
] as const;

export interface ScopeOmission {
  path: string;
  reason: typeof scopeOmissionReasons[number];
  size?: number;
}

export const scopeFileEntrySchema: z.ZodType<ScopeFileEntry, z.ZodTypeDef, unknown> = z.object({
  path: z.string().refine((path) => safeRepositoryPath(path), "must be a safe repository path"),
  fingerprint: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
  size: z.number().int().nonnegative().max(keeperLimits.scan.maxFileBytes),
  lineCount: z.number().int().nonnegative().max(keeperLimits.scan.maxEvidence)
}).strict();

export const scopeEvidenceSchema: z.ZodType<Evidence, z.ZodTypeDef, unknown> = z.object({
  path: z.string().refine((path) => safeRepositoryPath(path), "must be a safe repository path"),
  line: z.number().int().positive().max(keeperLimits.scan.maxEvidence),
  text: z.string(),
  truncated: z.literal(true).optional(),
  textBytes: z.number().int().positive().max(keeperLimits.scan.maxFileBytes).optional()
}).strict().superRefine((evidence, context) => {
  const prefixBytes = Buffer.byteLength(evidence.text, "utf8");
  if (prefixBytes > 16 * 1024) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["text"], message: "must be at most 16 KiB" });
  }
  if (evidence.truncated === true) {
    if (evidence.textBytes === undefined || evidence.textBytes <= prefixBytes) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["textBytes"], message: "must exceed the returned prefix bytes" });
    }
  } else if (evidence.textBytes !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["textBytes"], message: "is only allowed for truncated evidence" });
  }
});

const scopePathArraySchema = z.array(z.union([
  z.literal("."),
  z.string().refine((path) => safeRepositoryPath(path))
])).min(1).max(keeperLimits.scan.maxFiles).superRefine((paths, context) => {
  const seen = new Set<string>();
  for (const [index, path] of paths.entries()) {
    const key = path === "." ? path : windowsRepositoryPathKey(path);
    if (seen.has(key)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: [index],
        message: "scope paths must not contain Windows-equivalent aliases"
      });
    }
    seen.add(key);
  }
});

export const candidateModuleSchema: z.ZodType<CandidateModule, z.ZodTypeDef, unknown> = z.object({
  id: z.string().min(1).max(512),
  paths: scopePathArraySchema,
  fileCount: z.number().int().nonnegative().max(keeperLimits.scan.maxFiles),
  evidenceCount: z.number().int().nonnegative().max(keeperLimits.scan.maxEvidence)
}).strict();

export const scopeOmissionSchema: z.ZodType<ScopeOmission, z.ZodTypeDef, unknown> = z.object({
  path: z.union([z.literal("."), z.string().refine((path) => safeRepositoryPath(path))]),
  reason: z.enum(scopeOmissionReasons),
  size: z.number().int().nonnegative().optional()
}).strict();

export interface ScopeIndexShardMetadata {
  path: "files.jsonl" | "evidence.jsonl" | "details.jsonl";
  bytes: number;
  hash: string;
  count: number;
}

export interface ScopeRelocationCandidate {
  recordId: string;
  evidenceIndex: number;
  path: string;
  from: { startLine: number; endLine?: number };
  to: { startLine: number; endLine?: number };
}

export type ScopeDriftDetail =
  | { kind: "new" | "modified" | "deleted"; path: string }
  | { kind: "missing-evidence"; evidence: string; recordId?: string }
  | { kind: "deleted-evidence" | "modified-evidence"; recordId: string; evidence: string }
  | { kind: "invalid-evidence"; recordId: string; evidence: string; reason: "line-invalid" };

export interface ScopeIndexMetadataV3 {
  version: 3;
  createdAt: number;
  expiresAt: number;
  projectKey: string;
  scopeKey: string;
  cursorScopeKey: string;
  scopePaths: string[];
  snapshotId: string;
  shards: {
    files: ScopeIndexShardMetadata;
    evidence: ScopeIndexShardMetadata;
    details?: ScopeIndexShardMetadata;
  };
  totals: { files: number; evidence: number; omitted: number; details?: number };
  candidateModules: CandidateModule[];
  omissions: ScopeOmission[];
  driftSummary?: {
    freshness: "unknown" | "stale" | "fresh";
    counts: { new: number; modified: number; deleted: number; invalidated: number };
    invalidatedRecordIds: string[];
    relocationCandidates: ScopeRelocationCandidate[];
    archiveEligibleRecordIds: string[];
  };
}

const scopeShardSchema: z.ZodType<ScopeIndexShardMetadata, z.ZodTypeDef, unknown> = z.object({
  path: z.enum(["files.jsonl", "evidence.jsonl", "details.jsonl"]),
  bytes: z.number().int().nonnegative().max(keeperLimits.scan.maxAggregateBytes),
  hash: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
  count: z.number().int().nonnegative().max(keeperLimits.scan.maxEvidence)
}).strict();

const scopeLineRangeSchema = z.object({
  startLine: z.number().int().positive().safe(),
  endLine: z.number().int().positive().safe().optional()
}).strict().superRefine((range, context) => {
  if (range.endLine !== undefined && range.endLine < range.startLine) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["endLine"], message: "must not precede startLine" });
  }
});

const scopeRepositoryPathSchema = z.string().refine((path) => safeRepositoryPath(path), "must be a canonical repository-relative path");

export const scopeRelocationCandidateSchema: z.ZodType<ScopeRelocationCandidate, z.ZodTypeDef, unknown> = z.object({
  recordId: z.string().min(1).max(512),
  evidenceIndex: z.number().int().nonnegative().safe().max(keeperLimits.pack.maxEvidencePerRecord - 1),
  path: scopeRepositoryPathSchema,
  from: scopeLineRangeSchema,
  to: scopeLineRangeSchema
}).strict();

const scopeDriftRecordId = z.string().min(1).max(512);
const scopeDriftEvidence = z.string().min(1).max(keeperLimits.scan.maxFileBytes);
export const scopeDriftDetailSchema: z.ZodType<ScopeDriftDetail, z.ZodTypeDef, unknown> = z.discriminatedUnion("kind", [
  z.object({ kind: z.enum(["new", "modified", "deleted"]), path: scopeRepositoryPathSchema }).strict(),
  z.object({ kind: z.literal("missing-evidence"), evidence: scopeDriftEvidence, recordId: scopeDriftRecordId.optional() }).strict(),
  z.object({ kind: z.enum(["deleted-evidence", "modified-evidence"]), recordId: scopeDriftRecordId, evidence: scopeDriftEvidence }).strict(),
  z.object({
    kind: z.literal("invalid-evidence"),
    recordId: scopeDriftRecordId,
    evidence: scopeDriftEvidence,
    reason: z.literal("line-invalid")
  }).strict()
]);

const scopeDriftSummarySchema = z.object({
  freshness: z.enum(["unknown", "stale", "fresh"]),
  counts: z.object({
    new: z.number().int().nonnegative().max(keeperLimits.scan.maxFiles),
    modified: z.number().int().nonnegative().max(keeperLimits.scan.maxFiles),
    deleted: z.number().int().nonnegative().max(keeperLimits.scan.maxFiles),
    invalidated: z.number().int().nonnegative().max(keeperLimits.pack.maxRecords)
  }).strict(),
  invalidatedRecordIds: z.array(z.string().min(1).max(512)).max(keeperLimits.pack.maxRecords),
  relocationCandidates: z.array(scopeRelocationCandidateSchema).max(keeperLimits.scan.maxEvidence),
  archiveEligibleRecordIds: z.array(z.string().min(1).max(512)).max(keeperLimits.pack.maxRecords)
}).strict().superRefine((summary, context) => {
  if (summary.counts.invalidated !== summary.invalidatedRecordIds.length) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["counts", "invalidated"], message: "must match invalidated record IDs" });
  }
  for (const [field, values] of [
    ["invalidatedRecordIds", summary.invalidatedRecordIds],
    ["archiveEligibleRecordIds", summary.archiveEligibleRecordIds]
  ] as const) {
    if (new Set(values).size !== values.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: [field], message: "must contain unique IDs" });
    }
  }
});

export const scopeIndexMetadataV3Schema: z.ZodType<ScopeIndexMetadataV3, z.ZodTypeDef, unknown> = z.object({
  version: z.literal(3),
  createdAt: z.number().int().nonnegative().safe(),
  expiresAt: z.number().int().positive().safe(),
  projectKey: z.string().regex(/^[a-f0-9]{64}$/u),
  scopeKey: z.string().regex(/^[a-f0-9]{64}$/u),
  cursorScopeKey: z.string().regex(/^[a-f0-9]{64}$/u),
  scopePaths: scopePathArraySchema,
  snapshotId: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
  shards: z.object({
    files: scopeShardSchema.refine((shard) => shard.path === "files.jsonl"),
    evidence: scopeShardSchema.refine((shard) => shard.path === "evidence.jsonl"),
    details: scopeShardSchema.refine((shard) => shard.path === "details.jsonl").optional()
  }).strict(),
  totals: z.object({
    files: z.number().int().nonnegative().max(keeperLimits.scan.maxFiles),
    evidence: z.number().int().nonnegative().max(keeperLimits.scan.maxEvidence),
    omitted: z.number().int().nonnegative().max(keeperLimits.scan.maxFiles + 1),
    details: z.number().int().nonnegative().max(keeperLimits.scan.maxEvidence).optional()
  }).strict(),
  candidateModules: z.array(candidateModuleSchema).max(keeperLimits.scan.maxFiles),
  omissions: z.array(scopeOmissionSchema).max(keeperLimits.scan.maxFiles + 1),
  driftSummary: scopeDriftSummarySchema.optional()
}).strict().superRefine((metadata, context) => {
  if (metadata.expiresAt !== metadata.createdAt + 7 * 24 * 60 * 60 * 1000) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["expiresAt"], message: "must be exactly seven days after createdAt" });
  }
  if (metadata.totals.files !== metadata.shards.files.count ||
      metadata.totals.evidence !== metadata.shards.evidence.count ||
      metadata.totals.omitted !== metadata.omissions.length ||
      metadata.totals.details !== metadata.shards.details?.count) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["totals"], message: "must exactly match shard and omission counts" });
  }
  if (Boolean(metadata.shards.details) !== Boolean(metadata.driftSummary)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["driftSummary"], message: "must be present exactly when a detail shard is present" });
  }
  const omissionPaths = new Set<string>();
  for (const [index, omission] of metadata.omissions.entries()) {
    const key = omission.path === "." ? omission.path : windowsRepositoryPathKey(omission.path);
    if (omissionPaths.has(key)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["omissions", index, "path"],
        message: "must not duplicate a Windows-equivalent omission path"
      });
    }
    omissionPaths.add(key);
  }
});

export interface PackValidationIo {
  afterProjectFileOpen?: (path: string) => Promise<void>;
  beforeProjectFileFinalIdentityCheck?: (path: string) => Promise<void>;
  beforeManagedDirectoryEntry?: (path: string, depth: number) => Promise<void>;
}

export interface ServiceOptions {
  /** Internal trusted operation snapshot; never populated from tool arguments. */
  runtimePolicy?: import("../settings/policy.js").RuntimePolicy;
  cacheDirectory?: string;
  environment?: Record<string, string | undefined>;
  homeDirectory?: string;
  now?: () => number;
  processLeaseTimeoutMs?: number;
  processLeaseMs?: number;
  beforeCommit?: (root: string) => Promise<void>;
  beforeRename?: (path: string, index: number) => Promise<void>;
  beforeStageWrite?: (path: string, index: number) => Promise<void>;
  beforeMutationRename?: (
    path: string,
    index: number,
    phase: "quarantine" | "replacement" | "rollback-target" | "rollback-restore"
  ) => Promise<void>;
  afterMutationRename?: (
    path: string,
    phase: "quarantine" | "replacement" | "rollback-target" | "rollback-restore",
    quarantineName?: string
  ) => Promise<void>;
  beforePostRenameIdentityCapture?: (
    path: string,
    phase: "quarantine" | "replacement" | "rollback-target" | "rollback-restore",
    quarantineName?: string
  ) => Promise<void>;
  beforeQuarantineCleanup?: (path: string, quarantineName: string) => Promise<void>;
  beforeRecoveryTargetOpen?: (path: string, index: number) => Promise<void>;
  afterRecoveryTargetOpen?: (path: string, index: number) => Promise<void>;
  afterRecoveryTargetRead?: (path: string, index: number) => Promise<void>;
  beforeRecoverySnapshotPublish?: (root: string, changesetId: string) => Promise<void>;
  beforeChangesetConsume?: (root: string, changesetId: string) => Promise<void>;
  afterCurrentManifestRead?: (root: string) => Promise<void>;
  afterManifestBaselineValidation?: (root: string) => Promise<void>;
  afterCandidateValidation?: (root: string) => Promise<void>;
  beforeProjectDesignOutputEntry?: (path: string, kind: "file" | "directory") => Promise<void>;
  limits?: KeeperLimitOverrides;
  validationIo?: PackValidationIo;
  scopeIo?: {
    beforeRepositoryDiscovery?: (path: string) => Promise<void>;
    beforeRepositoryFileStat?: (path: string) => Promise<void>;
    beforeRepositoryContentRead?: (path: string) => Promise<void>;
    beforeGitCommand?: (args: readonly string[]) => Promise<void>;
    onSelectorWork?: (kind: "record-filter" | "reference-index" | "chunk-filter") => void;
  };
  redundancyIo?: {
    onRecordDigest?: (recordId: string) => void;
    beforeRepositoryContentRead?: (path: string) => Promise<void>;
  };
  trustedApprovalProvider?: (summary: ChangesetApprovalBinding) => Promise<{ approved: boolean }>;
}

export type ManagedBlockInput =
  | { recordId: string; content: string }
  | { recordId: string; delete: true };

export interface RequestedChange {
  path: string;
  content?: string;
  delete?: true;
  managedBlock?: ManagedBlockInput;
  expectedContentHash?: string;
}

export interface PersistedChange {
  path: string;
  content?: string;
  delete?: true;
  previousHash: string | null;
  managedBlocks?: Array<ManagedBlockInput & { expectedContentHash?: string }>;
}

export interface PersistedChangeset {
  version: 2 | 3;
  policy?: import("../settings/policy.js").RuntimePolicy;
  diff?: string;
  changesetId: string;
  root: string;
  createdAt: number;
  expiresAt: number;
  diffDigest: `sha256:${string}`;
  archiveActions: {
    archivedRecordIds: string[];
    tombstonedRecordIds: string[];
  };
  semanticDecisionIds: string[];
  historyFiles: Record<string, string | null>;
  changes: PersistedChange[];
  manifestHash: string | null;
  sourceScope: ScopeInput;
  sourcePaths?: string[];
  sourceFiles: Record<string, string>;
  /** Authenticated candidate pack whose validation dependencies were captured at preview. */
  validatedPack?: Record<string, unknown>;
  /** Stable digest of the exact files, managed Markdown inventory, and portable path states used by validation. */
  validationDependencyDigest?: `sha256:${string}`;
}

/** Strict legacy shape used only to authenticate and age out retired version-one cache evidence. */
export interface ExpiredPersistedChangesetV1 {
  version: 1;
  changesetId: string;
  root: string;
  createdAt: number;
  expiresAt: number;
  changes: PersistedChange[];
  manifestHash: string | null;
  sourceScope: ScopeInput;
  sourcePaths?: string[];
  sourceFiles: Record<string, string>;
}

export const changesetLifetimeMs = 30 * 60 * 1000;

export const stableId = z.string().min(1).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u, "must be a stable identifier");
export const canonicalUuidSchema = z.string().regex(
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  "must be a lowercase canonical UUID"
);

export function isCanonicalUuid(value: string): boolean {
  return canonicalUuidSchema.safeParse(value).success;
}
const sha256Hash = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const diffDigestSchema = sha256Hash.transform((value) => value as `sha256:${string}`);

const reservedWindowsName = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu;
const invalidWindowsCharacters = /[\u0000-\u001f<>:"|?*]/u;

export function safeRepositoryPath(path: string, managedOnly = false): boolean {
  if (!path || path.includes("\\") || /^[A-Za-z]:|^\//u.test(path)) return false;
  const parts = path.split("/");
  if (parts.some((part) => !part || part === "." || part === ".." || /[. ]$/u.test(part) ||
    invalidWindowsCharacters.test(part) || reservedWindowsName.test(part))) return false;
  return !managedOnly || path.startsWith("docs/project-design/") || path.startsWith(".agents/skills/project-design-context/");
}

export function windowsRepositoryPathKey(path: string): string {
  return path.split("/").map((part) => part.toLocaleLowerCase("en-US")).join("/");
}

const repositoryPath = z.string().refine((path) => safeRepositoryPath(path), "must be a canonical repository-relative path");
const documentPath = z.string().refine((path) => safeRepositoryPath(path, true), "must be a safe canonical managed document path");
const manifestDocumentPath = z.string().refine(
  (path) => safeRepositoryPath(path) && path.startsWith("docs/project-design/") && path.endsWith(".md"),
  "must be a canonical Markdown path under docs/project-design"
);
const requiredDocumentPaths = [
  "docs/project-design/index.md",
  "docs/project-design/intent.md",
  "docs/project-design/principles.md",
  "docs/project-design/architecture.md",
  "docs/project-design/conventions.md",
  "docs/project-design/decisions.md",
  "docs/project-design/open-questions.md",
  "docs/project-design/evidence-map.md"
] as const;
const v2RequiredDocumentPaths = [
  ...requiredDocumentPaths,
  "docs/project-design/tuning.md",
  "docs/project-design/verification.md"
] as const;
const knowledgeKinds = [
  "intent", "principle", "architecture", "module", "convention", "decision", "tuning", "verification", "open-question"
] as const;

const evidenceRoleSchema = z.enum(["design", "implementation", "test", "configuration", "runtime"]);
const typedEvidenceSchema = z.object({
  path: repositoryPath,
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1).optional(),
  role: evidenceRoleSchema,
  excerptHash: sha256Hash
}).strict().superRefine((evidence, context) => {
  if (evidence.endLine !== undefined && evidence.endLine < evidence.startLine) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["endLine"], message: "must be greater than or equal to startLine" });
  }
});

const lifecycleSchema = z.discriminatedUnion("state", [
  z.object({ state: z.literal("active") }).strict(),
  z.object({
    state: z.literal("terminal"),
    reason: z.enum(["superseded", "resolved", "replaced", "merged"]),
    sinceRevision: z.number().int().nonnegative(),
    confirmedRefreshes: z.number().int().min(0),
    successorIds: z.array(stableId).max(keeperLimits.pack.maxRecords)
  }).strict()
]);

export const tombstoneSchema = z.object({
  id: stableId.max(256),
  reason: z.enum(["superseded", "resolved", "replaced", "merged"]),
  successorIds: z.array(stableId.max(256)).max(256),
  contentHash: sha256Hash,
  archivedAt: z.string().datetime()
}).strict();

const knowledgeRecordSchema = z.object({
  id: stableId,
  domain: z.string().min(1),
  scope: z.string().min(1),
  statement: z.string().min(1),
  evidence: z.array(z.union([z.string().min(1), typedEvidenceSchema])),
  impact: z.array(z.string().min(1)),
  status: z.enum(["declared", "observed", "inferred", "proposed", "conflicted", "superseded"]),
  strength: z.enum(["required", "preferred", "informational", "pending"]),
  approval: z.enum(["confirmed", "pending", "not-required"]),
  confidence: z.enum(["high", "medium", "low"]).optional(),
  assertedConfidence: z.enum(["high", "medium", "low"]).optional(),
  lifecycle: lifecycleSchema.optional(),
  kind: z.enum(knowledgeKinds).optional(),
  ownerDocument: stableId.optional(),
  supersedes: stableId.optional(),
  supersededBy: stableId.optional()
}).passthrough().superRefine((record, context) => {
  if ((record.strength === "required" || record.strength === "preferred") && record.approval !== "confirmed") {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["approval"],
      message: `${record.strength} knowledge must be user-confirmed`
    });
  }
});

const strictHistoryLifecycleSchema = z.discriminatedUnion("state", [
  z.object({ state: z.literal("active") }).strict(),
  z.object({
    state: z.literal("terminal"),
    reason: z.enum(["superseded", "resolved", "replaced", "merged"]),
    sinceRevision: z.number().int().nonnegative().safe(),
    confirmedRefreshes: z.number().int().nonnegative().safe(),
    successorIds: z.array(stableId.max(256)).max(256)
  }).strict()
]);

const strictHistoryStatusSchema = z.enum(["declared", "observed", "inferred", "proposed", "conflicted", "superseded"]);
const strictHistoryStringArray = z.array(z.string().min(1)).max(keeperLimits.pack.maxImpactPerRecord);
const strictHistoryTypedEvidenceSchema = typedEvidenceSchema.superRefine((evidence, context) => {
  if (!Number.isSafeInteger(evidence.startLine)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["startLine"], message: "must be a safe integer" });
  }
  if (evidence.endLine !== undefined && !Number.isSafeInteger(evidence.endLine)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["endLine"], message: "must be a safe integer" });
  }
});

/** Exact Schema 3.0 record shape used only while authenticating historical material. */
export const strictHistoryKnowledgeRecordSchema = z.object({
  id: stableId.max(256),
  domain: z.string().min(1),
  scope: z.string().min(1),
  statement: z.string().min(1),
  evidence: z.array(strictHistoryTypedEvidenceSchema).max(keeperLimits.pack.maxEvidencePerRecord),
  impact: z.array(z.string().min(1)).max(keeperLimits.pack.maxImpactPerRecord),
  status: strictHistoryStatusSchema,
  strength: z.enum(["required", "preferred", "informational", "pending"]),
  approval: z.enum(["confirmed", "pending", "not-required"]),
  assertedConfidence: z.enum(["high", "medium", "low"]),
  lifecycle: strictHistoryLifecycleSchema,
  kind: z.enum(knowledgeKinds),
  ownerDocument: stableId.max(256),
  supersedes: stableId.max(256).optional(),
  supersededBy: stableId.max(256).optional(),
  legacyEvidence: z.array(z.union([z.string().min(1), strictHistoryTypedEvidenceSchema]))
    .max(keeperLimits.pack.maxEvidencePerRecord).optional(),
  legacyStatus: strictHistoryStatusSchema.optional(),
  conflicts: strictHistoryStringArray.optional(),
  openQuestions: strictHistoryStringArray.optional(),
  module: z.union([z.string().min(1), strictHistoryStringArray]).optional(),
  modules: strictHistoryStringArray.optional(),
  path: repositoryPath.optional(),
  paths: z.array(repositoryPath).max(keeperLimits.pack.maxEvidencePerRecord).optional(),
  summary: z.string().min(1).optional()
}).strict().superRefine((record, context) => {
  if ((record.strength === "required" || record.strength === "preferred") && record.approval !== "confirmed") {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["approval"],
      message: `${record.strength} knowledge must be user-confirmed`
    });
  }
  if (record.statement !== record.statement.trim() || /\r|\n/u.test(record.statement)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["statement"],
      message: "Schema 3.0 historical statements must be one trimmed atomic line"
    });
  }
});

export const archiveEntrySchema = z.object({
  record: strictHistoryKnowledgeRecordSchema,
  originalOwnerDocument: stableId,
  managedBody: z.string(),
  contentHash: sha256Hash,
  evidenceHash: sha256Hash,
  terminalReason: z.enum(["superseded", "resolved", "replaced", "merged"]),
  maintenanceRevision: z.number().int().nonnegative().safe(),
  archivedAt: z.string().datetime()
}).strict();

export function isCompleteArchiveEntry(value: unknown): boolean {
  const parsed = archiveEntrySchema.safeParse(value);
  if (!parsed.success) return false;
  const entry = parsed.data;
  const record = entry.record;
  const terminal = record.lifecycle;
  return typeof record.kind === "string" &&
    typeof record.ownerDocument === "string" &&
    typeof record.assertedConfidence === "string" &&
    record.evidence.every((evidence) => typeof evidence !== "string") &&
    terminal?.state === "terminal" &&
    Number.isSafeInteger(terminal.confirmedRefreshes) &&
    terminal.confirmedRefreshes >= 2 &&
    entry.contentHash === `sha256:${createHash("sha256").update(entry.managedBody, "utf8").digest("hex")}` &&
    entry.evidenceHash === `sha256:${createHash("sha256").update(JSON.stringify(record.evidence), "utf8").digest("hex")}` &&
    entry.originalOwnerDocument === record.ownerDocument &&
    entry.terminalReason === terminal.reason;
}

const canonicalPackSchema = z.object({
  managedBy: z.literal("project-design-keeper"),
  schemaVersion: z.enum(["1.0", "2.0", "3.0"]),
  scope: z.object({
    root: z.literal("."),
    paths: z.array(repositoryPath).nonempty().optional()
  }).passthrough(),
  sourceRevision: z.object({
    kind: z.string().min(1),
    files: z.record(repositoryPath, sha256Hash).refine((files) => Object.keys(files).length > 0, "must contain source files")
  }).passthrough(),
  documents: z.array(z.object({ id: stableId, path: manifestDocumentPath }).passthrough()),
  records: z.array(knowledgeRecordSchema),
  maintenanceRevision: z.number().int().nonnegative().optional(),
  archive: z.object({
    generations: z.array(z.object({
      id: z.string().regex(/^generation-[0-9]{6}$/u),
      path: repositoryPath,
      recordCount: z.number().int().nonnegative(),
      createdAt: z.string().datetime()
    }).strict()),
    tombstones: z.object({ path: repositoryPath, count: z.number().int().nonnegative() }).strict()
  }).strict().optional(),
  dedupeExceptions: z.array(z.object({
    leftId: stableId,
    rightId: stableId,
    leftDigest: sha256Hash,
    rightDigest: sha256Hash
  }).strict()).optional()
}).passthrough().superRefine((pack, context) => {
  const seenIds = new Set<string>();
  const duplicateIds = new Set<string>();
  for (const id of [...pack.documents.map((document) => document.id), ...pack.records.map((record) => record.id)]) {
    if (seenIds.has(id)) duplicateIds.add(id);
    else seenIds.add(id);
  }
  for (const duplicate of duplicateIds) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["records"], message: `duplicate id: ${duplicate}` });
  }

  const recordIds = new Set(pack.records.map((record) => record.id));
  const edges = new Map<string, Set<string>>();
  const indegree = new Map([...recordIds].map((id) => [id, 0]));
  const addEdge = (from: string, to: string, path: Array<string | number>) => {
    if (!recordIds.has(from)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path, message: `unknown supersession record: ${from}` });
      return;
    }
    if (!recordIds.has(to)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path, message: `unknown supersession record: ${to}` });
      return;
    }
    if (from === to) {
      context.addIssue({ code: z.ZodIssueCode.custom, path, message: "a record cannot supersede itself" });
      return;
    }
    const outgoing = edges.get(from) ?? new Set<string>();
    if (!outgoing.has(to)) {
      outgoing.add(to);
      indegree.set(to, (indegree.get(to) ?? 0) + 1);
    }
    edges.set(from, outgoing);
  };
  pack.records.forEach((record, index) => {
    if (pack.schemaVersion !== "3.0" && !record.confidence) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["records", index, "confidence"], message: "Required" });
    }
    if (record.supersedes) addEdge(record.id, record.supersedes, ["records", index, "supersedes"]);
    if (record.supersededBy) addEdge(record.supersededBy, record.id, ["records", index, "supersededBy"]);
    if (record.lifecycle?.state === "terminal") {
      for (const [successorIndex, successorId] of record.lifecycle.successorIds.entries()) {
        addEdge(successorId, record.id, ["records", index, "lifecycle", "successorIds", successorIndex]);
      }
    }
  });
  const pending = [...recordIds].filter((id) => indegree.get(id) === 0);
  let processed = 0;
  for (let index = 0; index < pending.length; index += 1) {
    const id = pending[index];
    processed += 1;
    for (const successor of edges.get(id) ?? []) {
      const remaining = (indegree.get(successor) ?? 0) - 1;
      indegree.set(successor, remaining);
      if (remaining === 0) pending.push(successor);
    }
  }
  if (processed !== recordIds.size) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["records"], message: "supersession graph contains a cycle" });
  }
});

interface ValidationDiagnostic {
  code: string;
  path: string;
  message: string;
}

export interface PackValidationOptions {
  runtimePolicy?: RuntimePolicy;
  overlay?: ReadonlyMap<string, Buffer | undefined>;
  /** Overlay entries whose bytes were already charged to a shared caller budget. */
  preaccountedOverlay?: ReadonlySet<string>;
  limits?: KeeperLimitOverrides;
  io?: PackValidationIo;
  resourceBudget?: PackValidationResourceBudget;
  /** Internal transaction hook; invoked only after a fully valid, race-checked pack validation. */
  onValidationDependencyDigest?: (digest: `sha256:${string}`) => void;
}

export interface PackValidationResourceBudget {
  readonly maxFileBytes: number;
  readonly files: CounterBudget;
  readonly bytes: ByteBudget;
  readonly deadline: Pick<DeadlineBudget, "check">;
  /** Optional operation-wide validation counters reused by repeated validation passes. */
  readonly analysisBytes?: ByteBudget;
  readonly work?: CounterBudget;
  readonly managedEntries?: CounterBudget;
  /** Mutable operation-wide set used to count each dependency path only once. */
  readonly accountedFiles?: Set<string>;
}

interface ProjectFileView {
  kind: "missing" | "regular" | "unsafe";
  lexical: string;
  canonical?: string;
  contents?: Buffer;
  text?: string;
  lines?: string[];
  unsafeReason?: "outside-root" | "not-regular";
}

interface FinalPathEvidence {
  readonly label: string;
  readonly lexical: string;
  readonly kind: "missing" | "file" | "directory" | "path";
  readonly metadata?: BigIntStats;
  /** `null` records an observed realpath failure; `undefined` means canonical identity was not relevant. */
  readonly canonical?: string | null;
}

interface PackValidationBudget {
  readonly limits: KeeperLimits;
  readonly maxFileBytes: number;
  readonly files: CounterBudget;
  readonly bytes: ByteBudget;
  readonly externalFiles?: CounterBudget;
  readonly externalBytes?: ByteBudget;
  readonly externalAccountedFiles?: Set<string>;
  readonly analysisBytes: Pick<ByteBudget, "consume">;
  readonly work: Pick<CounterBudget, "consume">;
  readonly managedEntries: Pick<CounterBudget, "consume">;
  readonly deadline: Pick<DeadlineBudget, "check">;
}

const packValidationManagedTreeMaximumDepth = 16;
const packValidationManagedTreeMaximumEntries = 4_096;

function validationDiagnostic(code: string, path: string, message: string): ValidationDiagnostic {
  return { code, path, message };
}

function repositoryPathAliasDiagnostics(
  pack: z.infer<typeof canonicalPackSchema>,
  overlay: ReadonlyMap<string, Buffer | undefined> | undefined,
  onPath: () => void
): ValidationDiagnostic[] {
  const diagnostics: ValidationDiagnostic[] = [];
  const seen = new Map<string, { path: string; location: string }>();
  const register = (path: string | undefined, location: string): void => {
    if (path === undefined) return;
    onPath();
    const key = windowsRepositoryPathKey(path);
    const prior = seen.get(key);
    if (prior && prior.path !== path) {
      diagnostics.push(validationDiagnostic(
        "repository_path_alias",
        location,
        `Repository path ${path} aliases ${prior.path} from ${prior.location} under Windows path rules`
      ));
    } else if (!prior) {
      seen.set(key, { path, location });
    }
  };

  for (const [index, path] of (pack.scope.paths ?? []).entries()) register(path, `scope.paths.${index}`);
  for (const path of Object.keys(pack.sourceRevision.files)) register(path, `sourceRevision.files.${path}`);
  for (const [index, document] of pack.documents.entries()) register(document.path, `documents.${index}.path`);
  for (const [recordIndex, record] of pack.records.entries()) {
    for (const [evidenceIndex, evidence] of record.evidence.entries()) {
      const path = typeof evidence === "string" ? /^(.*):[0-9]+$/u.exec(evidence)?.[1] : evidence.path;
      register(path, `records.${recordIndex}.evidence.${evidenceIndex}`);
    }
  }
  for (const [index, generation] of (pack.archive?.generations ?? []).entries()) {
    register(generation.path, `archive.generations.${index}.path`);
  }
  if (pack.archive) register(pack.archive.tombstones.path, "archive.tombstones.path");
  let overlayIndex = 0;
  for (const [path] of overlay ?? []) {
    register(path, `overlay.${overlayIndex}`);
    overlayIndex += 1;
  }
  return diagnostics;
}

function isInsideRoot(root: string, target: string): boolean {
  const difference = relative(root, target);
  return difference === "" || (!difference.startsWith(`..${sep}`) && difference !== ".." && !isAbsolute(difference));
}

function sameResolvedPath(left: string, right: string): boolean {
  const normalizedLeft = resolve(left);
  const normalizedRight = resolve(right);
  return process.platform === "win32"
    ? normalizedLeft.toLocaleLowerCase("en-US") === normalizedRight.toLocaleLowerCase("en-US")
    : normalizedLeft === normalizedRight;
}

function sameFileVersion(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid &&
    left.gid === right.gid && left.mode === right.mode && left.nlink === right.nlink &&
    left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs &&
    left.isFile() && right.isFile() && !left.isSymbolicLink() && !right.isSymbolicLink();
}

function sameDirectoryVersion(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid &&
    left.gid === right.gid && left.mode === right.mode && left.nlink === right.nlink &&
    left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs &&
    left.isDirectory() && right.isDirectory() && !left.isSymbolicLink() && !right.isSymbolicLink();
}

function samePathVersion(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid &&
    left.gid === right.gid && left.mode === right.mode && left.nlink === right.nlink &&
    left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs &&
    left.isFile() === right.isFile() && left.isDirectory() === right.isDirectory() &&
    left.isSymbolicLink() === right.isSymbolicLink();
}

async function optionalMetadata(path: string): Promise<BigIntStats | undefined> {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function assertPackArrayLimit(label: string, value: unknown, maximum: number): void {
  if (Array.isArray(value) && value.length > maximum) {
    throw new Error(`${label} exceeds the limit of ${maximum} items`);
  }
}

function consumeJsonStringBytes(
  value: string,
  bytes: Pick<ByteBudget, "consume">,
  deadline: Pick<DeadlineBudget, "check">
): void {
  bytes.consume(2);
  let pendingBytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    if ((index & 0x0fff) === 0) {
      bytes.consume(pendingBytes);
      pendingBytes = 0;
      deadline.check();
    }
    const code = value.charCodeAt(index);
    if (code === 0x22 || code === 0x5c || code === 0x08 || code === 0x09 || code === 0x0a ||
      code === 0x0c || code === 0x0d) {
      pendingBytes += 2;
    } else if (code <= 0x1f) {
      pendingBytes += 6;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        pendingBytes += 4;
        index += 1;
      } else {
        pendingBytes += 6;
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      pendingBytes += 6;
    } else if (code <= 0x7f) {
      pendingBytes += 1;
    } else if (code <= 0x7ff) {
      pendingBytes += 2;
    } else {
      pendingBytes += 3;
    }
  }
  bytes.consume(pendingBytes);
}

function assertBoundedPackStructure(pack: unknown, budget: PackValidationBudget): void {
  const bytes = new ByteBudget("Pack validation input", budget.limits.mcpArgumentBytes);
  const active = new WeakSet<object>();
  const pending: Array<
    { readonly kind: "value"; readonly value: unknown } |
    { readonly kind: "leave"; readonly value: object }
  > = [{ kind: "value", value: pack }];
  budget.work.consume();
  while (pending.length > 0) {
    budget.deadline.check();
    const entry = pending.pop()!;
    if (entry.kind === "leave") {
      active.delete(entry.value);
      continue;
    }
    const value = entry.value;
    if (typeof value === "string") {
      consumeJsonStringBytes(value, bytes, budget.deadline);
      continue;
    }
    if (value === null) {
      bytes.consume(4);
      continue;
    }
    if (typeof value === "number") {
      bytes.consume(Number.isFinite(value) ? Buffer.byteLength(String(value), "utf8") : 4);
      continue;
    }
    if (typeof value === "boolean") {
      bytes.consume(value ? 4 : 5);
      continue;
    }
    if (typeof value === "bigint") {
      throw new Error("Pack validation input must contain only JSON values");
    }
    if (typeof value !== "object") {
      bytes.consume(4);
      continue;
    }
    if (active.has(value)) throw new Error("Pack validation input must not contain circular references");
    active.add(value);
    if (Array.isArray(value)) {
      bytes.consume(2 + Math.max(0, value.length - 1));
      budget.work.consume(value.length);
      pending.push({ kind: "leave", value });
      for (let index = value.length - 1; index >= 0; index -= 1) {
        pending.push({ kind: "value", value: value[index] });
      }
      continue;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("Pack validation input must contain only plain JSON objects and arrays");
    }
    const children: unknown[] = [];
    let propertyCount = 0;
    for (const key in value) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
      budget.deadline.check();
      budget.work.consume();
      if (propertyCount > 0) bytes.consume(1);
      consumeJsonStringBytes(key, bytes, budget.deadline);
      bytes.consume(1);
      children.push((value as Record<string, unknown>)[key]);
      propertyCount += 1;
    }
    bytes.consume(2);
    pending.push({ kind: "leave", value });
    for (let index = children.length - 1; index >= 0; index -= 1) {
      pending.push({ kind: "value", value: children[index] });
    }
  }
  budget.deadline.check();
}

function assertPackInputLimits(pack: unknown, budget: PackValidationBudget): void {
  const { limits, deadline } = budget;
  deadline.check();
  if (!pack || typeof pack !== "object" || Array.isArray(pack)) return;
  const candidate = pack as Record<string, unknown>;
  assertPackArrayLimit("Pack documents", candidate.documents, limits.pack.maxDocuments);
  assertPackArrayLimit("Pack records", candidate.records, limits.pack.maxRecords);
  const scope = candidate.scope;
  if (scope && typeof scope === "object" && !Array.isArray(scope)) {
    assertPackArrayLimit("Pack scope paths", (scope as Record<string, unknown>).paths, limits.scan.maxFiles);
  }
  const sourceRevision = candidate.sourceRevision;
  const files = sourceRevision && typeof sourceRevision === "object" && !Array.isArray(sourceRevision)
    ? (sourceRevision as Record<string, unknown>).files
    : undefined;
  if (files && typeof files === "object" && !Array.isArray(files)) {
    let count = 0;
    for (const _key in files) {
      deadline.check();
      count += 1;
      if (count > limits.scan.maxFiles) {
        throw new Error(`Pack source files exceeds the limit of ${limits.scan.maxFiles} items`);
      }
    }
  }
  const archive = candidate.archive;
  if (archive && typeof archive === "object" && !Array.isArray(archive)) {
    assertPackArrayLimit("Pack archive generations", (archive as Record<string, unknown>).generations, 2);
  }
  assertPackArrayLimit("Pack dedupe exceptions", candidate.dedupeExceptions, limits.redundancy.maxDecisions);
  if (Array.isArray(candidate.records)) {
    for (const record of candidate.records) {
      deadline.check();
      if (!record || typeof record !== "object" || Array.isArray(record)) continue;
      const typed = record as Record<string, unknown>;
      assertPackArrayLimit("Pack record evidence", typed.evidence, limits.pack.maxEvidencePerRecord);
      assertPackArrayLimit("Pack record impact", typed.impact, limits.pack.maxImpactPerRecord);
      const lifecycle = typed.lifecycle;
      if (lifecycle && typeof lifecycle === "object" && !Array.isArray(lifecycle)) {
        assertPackArrayLimit(
          "Pack record successors",
          (lifecycle as Record<string, unknown>).successorIds,
          Math.min(limits.pack.maxRecords, limits.scan.maxEvidence)
        );
      }
    }
  }
  assertBoundedPackStructure(pack, budget);
}

function managedBlocks(
  markdown: string,
  onMatch: () => void = () => undefined
): Array<{ id: string; declaredHash: string; content: string }> {
  const blocks: Array<{ id: string; declaredHash: string; content: string }> = [];
  const expression = /<!-- project-design-keeper:managed record-id="([A-Za-z0-9][A-Za-z0-9._:-]*)" content-hash="(sha256:[a-f0-9]{64})" -->/gu;
  const close = "<!-- /project-design-keeper:managed -->";
  let match: RegExpExecArray | null;
  while ((match = expression.exec(markdown)) !== null) {
    const bodyStart = expression.lastIndex;
    const bodyEnd = markdown.indexOf(close, bodyStart);
    if (bodyEnd < 0) break;
    expression.lastIndex = bodyEnd + close.length;
    onMatch();
    blocks.push({ id: match[1], declaredHash: match[2], content: markdown.slice(bodyStart, bodyEnd) });
  }
  return blocks;
}

function derivedBlocks(
  markdown: string,
  onMatch: () => void = () => undefined
): Array<{ id: string; declaredHash: string; content: string }> {
  const blocks: Array<{ id: string; declaredHash: string; content: string }> = [];
  const expression = /<!-- project-design-keeper:derived document-id="([A-Za-z0-9][A-Za-z0-9._:-]*)" content-hash="(sha256:[a-f0-9]{64})" -->/gu;
  const close = "<!-- /project-design-keeper:derived -->";
  let match: RegExpExecArray | null;
  while ((match = expression.exec(markdown)) !== null) {
    const bodyStart = expression.lastIndex;
    const bodyEnd = markdown.indexOf(close, bodyStart);
    if (bodyEnd < 0) break;
    expression.lastIndex = bodyEnd + close.length;
    onMatch();
    blocks.push({ id: match[1], declaredHash: match[2], content: markdown.slice(bodyStart, bodyEnd) });
  }
  return blocks;
}

function markdownLinks(markdown: string, onMatch: () => void = () => undefined): string[] {
  const links: string[] = [];
  const expression = /!?\[[^\]]*\]\(\s*<?([^\s)>]+)>?(?:\s+["'][^"']*["'])?\s*\)/gu;
  let match: RegExpExecArray | null;
  while ((match = expression.exec(markdown)) !== null) {
    onMatch();
    links.push(match[1]);
  }
  return links;
}

function currentKnowledgeMarkdown(markdown: string, terminalRecordIds: ReadonlySet<string>): string {
  const expression = /<!-- project-design-keeper:managed record-id="([A-Za-z0-9][A-Za-z0-9._:-]*)" content-hash="sha256:[a-f0-9]{64}" -->/gu;
  const close = "<!-- /project-design-keeper:managed -->";
  const retained: string[] = [];
  let offset = 0;
  let match: RegExpExecArray | null;
  while ((match = expression.exec(markdown)) !== null) {
    const bodyEnd = markdown.indexOf(close, expression.lastIndex);
    if (bodyEnd < 0) break;
    expression.lastIndex = bodyEnd + close.length;
    if (terminalRecordIds.has(match[1])) {
      retained.push(markdown.slice(offset, match.index));
      offset = expression.lastIndex;
    }
  }
  retained.push(markdown.slice(offset));
  return retained.join("");
}

function normalizedStatement(statement: string): string {
  return statement.normalize("NFKC").toLocaleLowerCase("en-US").replace(/[\p{P}\p{S}\s]+/gu, "");
}

function createPackValidationBudget(options: PackValidationOptions): PackValidationBudget {
  const limits = resolveKeeperLimits(options.limits, options.runtimePolicy);
  const externalBudget = options.resourceBudget;
  if (externalBudget && (!Number.isSafeInteger(externalBudget.maxFileBytes) || externalBudget.maxFileBytes < 0)) {
    throw new Error("Pack validation shared file byte limit must be a non-negative integer");
  }
  const localDeadline = new DeadlineBudget("Pack validation", limits.scan.deadlineMs);
  const localAnalysisBytes = new ByteBudget("Pack validation analysis bytes", limits.scan.maxAggregateBytes);
  const localWork = new CounterBudget("Pack validation work", limits.scan.maxEvidence);
  const localManagedEntries = new CounterBudget(
    "Pack validation managed-tree entries",
    Math.min(limits.scan.maxFiles, packValidationManagedTreeMaximumEntries)
  );
  return {
    limits,
    maxFileBytes: Math.min(limits.scan.maxFileBytes, externalBudget?.maxFileBytes ?? limits.scan.maxFileBytes),
    files: new CounterBudget("Pack validation files", limits.scan.maxFiles),
    bytes: new ByteBudget("Pack validation aggregate bytes", limits.scan.maxAggregateBytes),
    ...(externalBudget ? {
      externalFiles: externalBudget.files,
      externalBytes: externalBudget.bytes,
      ...(externalBudget.accountedFiles ? { externalAccountedFiles: externalBudget.accountedFiles } : {})
    } : {}),
    analysisBytes: externalBudget?.analysisBytes ? {
      consume: (bytes) => {
        localAnalysisBytes.consume(bytes);
        externalBudget.analysisBytes!.consume(bytes);
      }
    } : localAnalysisBytes,
    work: externalBudget?.work ? {
      consume: (items = 1) => {
        localWork.consume(items);
        externalBudget.work!.consume(items);
      }
    } : localWork,
    managedEntries: externalBudget?.managedEntries ? {
      consume: (items = 1) => {
        localManagedEntries.consume(items);
        externalBudget.managedEntries!.consume(items);
      }
    } : localManagedEntries,
    deadline: externalBudget ? {
      check: () => {
        localDeadline.check();
        externalBudget.deadline.check();
      }
    } : localDeadline
  };
}

/** Bound a public candidate pack before callers perform any pack-directed work or repository I/O. */
export function assertPackValidationInputBounds(
  pack: unknown,
  options: Omit<PackValidationOptions, "overlay" | "preaccountedOverlay" | "io"> = {}
): void {
  const budget = createPackValidationBudget(options);
  assertPackInputLimits(pack, budget);
  budget.deadline.check();
}

export async function validatePack(
  input: Record<string, unknown>,
  options: PackValidationOptions = {}
): Promise<Record<string, unknown>> {
  const budget = createPackValidationBudget(options);
  const { limits } = budget;
  const pack = input.pack;
  assertPackInputLimits(pack, budget);
  budget.deadline.check();
  const schemaResult = canonicalPackSchema.safeParse(pack);
  budget.deadline.check();
  if (!schemaResult.success) {
    return {
      valid: false,
      errors: schemaResult.error.issues.map((issue) => validationDiagnostic(
        "schema_invalid",
        issue.path.join(".") || "pack",
        issue.message
      )),
      warnings: []
    };
  }
  const canonicalPack = schemaResult.data as z.infer<typeof canonicalPackSchema>;
  const aliasErrors = repositoryPathAliasDiagnostics(canonicalPack, options.overlay, () => {
    budget.deadline.check();
    budget.work.consume();
    budget.deadline.check();
  });
  if (aliasErrors.length > 0) return { valid: false, errors: aliasErrors, warnings: [] };

  if (typeof input.root !== "string") {
    return { valid: false, errors: [validationDiagnostic("root_required", "root", "A repository root is required")], warnings: [] };
  }
  let root: string;
  let rootIdentity: BigIntStats;
  try {
    root = await realpath(resolve(input.root));
    rootIdentity = await lstat(root, { bigint: true });
    if (rootIdentity.isSymbolicLink() || !rootIdentity.isDirectory()) throw new Error("root is not a directory");
  } catch {
    return { valid: false, errors: [validationDiagnostic("root_invalid", "root", "The repository root cannot be resolved")], warnings: [] };
  }
  const overlay = new Map<string, Buffer | undefined>();
  const managedFileBytes = options.runtimePolicy
    ? Math.min(managedReadLimits.maxFileBytes, options.resourceBudget?.maxFileBytes ?? managedReadLimits.maxFileBytes,
      options.limits?.scan?.maxFileBytes ?? Infinity)
    : budget.maxFileBytes;
  const overlayPaths = new Map<string, string>();
  const preaccountedOverlay = new Set(
    [...(options.preaccountedOverlay ?? [])].map(windowsRepositoryPathKey)
  );
  const accountedFiles = new Set<string>();
  const accountFile = (key: string): void => {
    if (accountedFiles.has(key)) return;
    budget.files.consume();
    accountedFiles.add(key);
    if (!budget.externalFiles) return;
    if (budget.externalAccountedFiles?.has(key)) return;
    budget.externalFiles.consume();
    budget.externalAccountedFiles?.add(key);
  };
  for (const [path, contents] of options.overlay ?? []) {
    budget.deadline.check();
    if (!safeRepositoryPath(path, true)) {
      return {
        valid: false,
        errors: [validationDiagnostic("overlay_path_invalid", "overlay", "Candidate overlay contains an unsafe managed path")],
        warnings: []
      };
    }
    const key = windowsRepositoryPathKey(path);
    accountFile(key);
    if (contents !== undefined) {
      if (contents.byteLength > managedFileBytes) {
        throw new Error(`Pack validation file ${path} exceeds the limit of ${managedFileBytes} bytes`);
      }
      budget.bytes.consume(contents.byteLength);
      if (!preaccountedOverlay.has(key)) budget.externalBytes?.consume(contents.byteLength);
    }
    overlay.set(key, contents === undefined ? undefined : Buffer.from(contents));
    overlayPaths.set(key, path);
  }

  const finalPathEvidence = new Map<string, FinalPathEvidence>();
  const finalEvidenceKey = (path: string): string => {
    const normalized = resolve(path);
    return process.platform === "win32" ? normalized.toLocaleLowerCase("en-US") : normalized;
  };
  const rememberFinalEvidence = (evidence: FinalPathEvidence): void => {
    const key = finalEvidenceKey(evidence.lexical);
    if (!finalPathEvidence.has(key)) finalPathEvidence.set(key, evidence);
  };
  const projectFiles = new Map<string, Promise<ProjectFileView>>();
  const validationFileDependencies = new Map<string, string | null>();
  const validationPathStates = new Map<string, string>();
  const contentHash = (contents: Buffer): `sha256:${string}` =>
    `sha256:${createHash("sha256").update(contents).digest("hex")}`;
  const rememberFileDependency = (path: string, contents: Buffer | undefined): void => {
    validationFileDependencies.set(path, contents === undefined ? null : contentHash(contents));
  };
  const rememberPathState = (path: string, metadata: BigIntStats, canonical: string): void => {
    const canonicalRelative = relative(root, canonical).replaceAll(sep, "/");
    const kind = metadata.isFile() ? "file" : metadata.isDirectory() ? "directory" : "other";
    validationPathStates.set(path, `${kind}:${canonicalRelative}`);
  };
  const consumeWork = (items = 1): void => {
    budget.deadline.check();
    budget.work.consume(items);
    budget.deadline.check();
  };
  const fileText = (view: ProjectFileView): string => {
    if (view.kind !== "regular" || !view.contents) throw new Error("Pack validation file text requires a regular file");
    if (view.text === undefined) {
      budget.deadline.check();
      budget.analysisBytes.consume(view.contents.byteLength);
      view.text = view.contents.toString("utf8");
      budget.deadline.check();
    }
    return view.text;
  };
  const fileLines = (view: ProjectFileView): string[] => {
    if (view.lines !== undefined) return view.lines;
    const text = fileText(view);
    const lines: string[] = [];
    let start = 0;
    for (let index = 0; index < text.length; index += 1) {
      if ((index & 0x3fff) === 0) budget.deadline.check();
      if (text.charCodeAt(index) !== 10) continue;
      consumeWork();
      const end = index > start && text.charCodeAt(index - 1) === 13 ? index - 1 : index;
      lines.push(text.slice(start, end));
      start = index + 1;
    }
    consumeWork();
    lines.push(text.slice(start));
    view.lines = lines;
    return view.lines;
  };

  const assertRootIdentity = async (): Promise<void> => {
    budget.deadline.check();
    const current = await optionalMetadata(root);
    if (!current || !sameDirectoryVersion(rootIdentity, current)) {
      throw new Error("Pack validation repository root identity changed during validation");
    }
    budget.deadline.check();
  };

  const assertFinalPathEvidence = async (): Promise<void> => {
    for (const evidence of finalPathEvidence.values()) {
      consumeWork();
      const current = await optionalMetadata(evidence.lexical);
      if (evidence.kind === "missing") {
        if (current) throw new Error(`Pack validation ${evidence.label} identity changed after validation`);
        continue;
      }
      const stable = Boolean(current && evidence.metadata) && (
        evidence.kind === "file" ? sameFileVersion(evidence.metadata!, current!) :
          evidence.kind === "directory" ? sameDirectoryVersion(evidence.metadata!, current!) :
            samePathVersion(evidence.metadata!, current!)
      );
      if (!stable) throw new Error(`Pack validation ${evidence.label} identity changed after validation`);
      if (evidence.canonical !== undefined) {
        let currentCanonical: string | null;
        try {
          currentCanonical = await realpath(evidence.lexical);
        } catch {
          currentCanonical = null;
        }
        if ((evidence.canonical === null && currentCanonical !== null) ||
          (evidence.canonical !== null && (currentCanonical === null ||
            !sameResolvedPath(evidence.canonical, currentCanonical)))) {
          throw new Error(`Pack validation ${evidence.label} identity changed after validation`);
        }
      }
      budget.deadline.check();
    }
  };

  async function loadProjectFile(path: string): Promise<ProjectFileView> {
    budget.deadline.check();
    const lexical = resolve(root, ...path.split("/"));
    if (!isInsideRoot(root, lexical)) return { kind: "unsafe", lexical, unsafeReason: "outside-root" };
    const key = windowsRepositoryPathKey(path);
    if (overlay.has(key)) {
      const contents = overlay.get(key);
      rememberFileDependency(path, contents);
      if (contents === undefined) return { kind: "missing", lexical };
      return { kind: "regular", lexical, canonical: lexical, contents };
    }
    const metadata = await optionalMetadata(lexical);
    if (!metadata) {
      rememberFileDependency(path, undefined);
      rememberFinalEvidence({ label: `file ${path}`, lexical, kind: "missing" });
      return { kind: "missing", lexical };
    }
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1n) {
      rememberFinalEvidence({ label: `file ${path}`, lexical, kind: "path", metadata });
      return { kind: "unsafe", lexical, unsafeReason: "not-regular" };
    }
    const size = Number(metadata.size);
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new Error(`Pack validation file ${path} has an invalid byte length`);
    }
    const fileLimit = safeRepositoryPath(path, true) ? managedFileBytes : budget.maxFileBytes;
    if (size > fileLimit) {
      throw new Error(`Pack validation file ${path} exceeds the limit of ${fileLimit} bytes`);
    }
    let canonical: string;
    try {
      canonical = await realpath(lexical);
    } catch {
      rememberFileDependency(path, undefined);
      rememberFinalEvidence({ label: `file ${path}`, lexical, kind: "file", metadata, canonical: null });
      return { kind: "missing", lexical };
    }
    if (!isInsideRoot(root, canonical) || !sameResolvedPath(canonical, lexical)) {
      rememberFinalEvidence({ label: `file ${path}`, lexical, kind: "file", metadata, canonical });
      return { kind: "unsafe", lexical, canonical, unsafeReason: "outside-root" };
    }
    budget.bytes.consume(size);
    budget.externalBytes?.consume(size);
    await assertRootIdentity();
    budget.deadline.check();
    const handle = await open(lexical, "r");
    try {
      const opened = await handle.stat({ bigint: true });
      if (!sameFileVersion(metadata, opened)) {
        throw new Error(`Pack validation file ${path} identity changed before bounded read`);
      }
      await options.io?.afterProjectFileOpen?.(path);
      budget.deadline.check();
      const contents = Buffer.allocUnsafe(size);
      let offset = 0;
      while (offset < size) {
        budget.deadline.check();
        const result = await handle.read(contents, offset, size - offset, offset);
        if (result.bytesRead === 0) {
          throw new Error(`Pack validation file ${path} ended during bounded read`);
        }
        offset += result.bytesRead;
      }
      const overflow = Buffer.allocUnsafe(1);
      if ((await handle.read(overflow, 0, 1, size)).bytesRead !== 0) {
        throw new Error(`Pack validation file ${path} exceeded its validated byte length during bounded read`);
      }
      await options.io?.beforeProjectFileFinalIdentityCheck?.(path);
      budget.deadline.check();
      const finalHandle = await handle.stat({ bigint: true });
      const finalPath = await optionalMetadata(lexical);
      let finalCanonical: string | undefined;
      try {
        finalCanonical = await realpath(lexical);
      } catch {
        finalCanonical = undefined;
      }
      if (!sameFileVersion(opened, finalHandle) || !finalPath || !sameFileVersion(opened, finalPath) ||
        finalCanonical === undefined || !sameResolvedPath(finalCanonical, canonical) || !isInsideRoot(root, finalCanonical)) {
        throw new Error(`Pack validation file ${path} identity changed during bounded read`);
      }
      await assertRootIdentity();
      rememberFinalEvidence({ label: `file ${path}`, lexical, kind: "file", metadata: finalHandle, canonical });
      rememberFileDependency(path, contents);
      return { kind: "regular", lexical, canonical, contents };
    } finally {
      await handle.close();
    }
  }

  function projectFile(path: string): Promise<ProjectFileView> {
    const key = windowsRepositoryPathKey(path);
    const existing = projectFiles.get(key);
    if (existing) return existing;
    accountFile(key);
    const capture = loadProjectFile(path);
    projectFiles.set(key, capture);
    return capture;
  }

  const terminalRecordIds = new Set(canonicalPack.records
    .filter((record) => record.lifecycle?.state === "terminal")
    .map((record) => record.id));
  const errors: ValidationDiagnostic[] = [];
  const warnings: ValidationDiagnostic[] = [];
  const freshnessChanged = new Set<string>();
  const freshnessDeleted = new Set<string>();
  const relocationCandidates: Array<{
    recordId: string;
    evidenceIndex: number;
    path: string;
    from: { startLine: number; endLine?: number };
    to: { startLine: number; endLine?: number };
  }> = [];
  const recordAssessments: Array<{ id: string; effectiveConfidence: "high" | "medium" | "low"; reasons: string[] }> = [];
  const mappedRecordIds = new Set<string>();
  const managedBlockLocations = new Map<string, string>();
  const managedBlockOwners = new Map<string, string>();
  const documentKeys = new Map<string, string>();
  const declaredDocumentKeys = new Set(canonicalPack.documents.map((document) => windowsRepositoryPathKey(document.path)));

  const requiredPaths = canonicalPack.schemaVersion === "2.0" || canonicalPack.schemaVersion === "3.0"
    ? v2RequiredDocumentPaths
    : requiredDocumentPaths;
  for (const requiredPath of requiredPaths) {
    if (!declaredDocumentKeys.has(windowsRepositoryPathKey(requiredPath))) {
      errors.push(validationDiagnostic("required_document_missing", "documents", `Required document is not mapped: ${requiredPath}`));
    }
  }
  if (canonicalPack.schemaVersion === "3.0") {
    if (canonicalPack.maintenanceRevision === undefined) {
      errors.push(validationDiagnostic("maintenance_revision_required", "maintenanceRevision", "Schema 3.0 requires maintenanceRevision"));
    }
    if (!canonicalPack.archive) {
      errors.push(validationDiagnostic("archive_metadata_required", "archive", "Schema 3.0 requires archive metadata"));
    }
    if (!canonicalPack.dedupeExceptions) {
      errors.push(validationDiagnostic("dedupe_exceptions_required", "dedupeExceptions", "Schema 3.0 requires dedupe exceptions"));
    }
    if (canonicalPack.pendingSync === true || (Array.isArray(canonicalPack.pendingDesignDecisions) && canonicalPack.pendingDesignDecisions.length > 0)) {
      errors.push(validationDiagnostic("pending_knowledge_sync", "pendingSync", "The implementation has pending design knowledge that must be previewed, applied, and validated"));
    }
  }

  const finalMarkdown = new Map<string, string>();
  const registerFinalMarkdown = (path: string, diagnosticPath: string): boolean => {
    const key = windowsRepositoryPathKey(path);
    const prior = finalMarkdown.get(key);
    if (prior !== undefined && prior !== path) {
      errors.push(validationDiagnostic(
        "repository_path_alias",
        diagnosticPath,
        `Managed path ${path} aliases ${prior} under Windows path rules`
      ));
      return false;
    }
    finalMarkdown.set(key, path);
    return true;
  };
  const managedDirectory = resolve(root, "docs", "project-design");
  async function visit(directory: string, depth: number): Promise<void> {
    budget.deadline.check();
    await assertRootIdentity();
    if (depth > packValidationManagedTreeMaximumDepth) {
      throw new Error(
        `Pack validation managed-tree depth exceeds the limit of ${packValidationManagedTreeMaximumDepth} levels`
      );
    }
    const directoryMetadata = await optionalMetadata(directory);
    if (!directoryMetadata) {
      if (depth === 0) {
        rememberFinalEvidence({ label: "managed-tree directory", lexical: directory, kind: "missing" });
        return;
      }
      throw new Error("Pack validation managed-tree identity changed during bounded enumeration");
    }
    const relativeDirectory = relative(root, directory).replaceAll(sep, "/");
    if (directoryMetadata.isSymbolicLink() || !directoryMetadata.isDirectory()) {
      errors.push(validationDiagnostic("managed_document_not_regular", relativeDirectory, "Managed document tree contains a symbolic link or non-directory entry"));
      return;
    }
    let canonicalDirectory: string;
    try {
      canonicalDirectory = await realpath(directory);
    } catch {
      errors.push(validationDiagnostic("managed_document_not_regular", relativeDirectory, "Managed document directory cannot be resolved safely"));
      return;
    }
    if (!isInsideRoot(root, canonicalDirectory) || !sameResolvedPath(canonicalDirectory, directory)) {
      errors.push(validationDiagnostic("managed_document_not_regular", relativeDirectory, "Managed document directory resolves through a symbolic link or outside the repository"));
      return;
    }
    const childNames: string[] = [];
    const directoryHandle = await opendir(directory);
    for await (const entry of directoryHandle) {
      budget.deadline.check();
      budget.managedEntries.consume();
      consumeWork();
      childNames.push(entry.name);
    }
    const afterEnumeration = await optionalMetadata(directory);
    let afterEnumerationCanonical: string | undefined;
    try {
      afterEnumerationCanonical = await realpath(directory);
    } catch {
      afterEnumerationCanonical = undefined;
    }
    if (!afterEnumeration || !sameDirectoryVersion(directoryMetadata, afterEnumeration) ||
      afterEnumerationCanonical === undefined || !sameResolvedPath(afterEnumerationCanonical, canonicalDirectory)) {
      throw new Error("Pack validation managed-tree identity changed during bounded enumeration");
    }
    childNames.sort((left, right) => left.localeCompare(right, "en-US"));
    for (const name of childNames) {
      budget.deadline.check();
      const lexical = resolve(directory, name);
      const relativePath = relative(root, lexical).replaceAll(sep, "/");
      await options.io?.beforeManagedDirectoryEntry?.(relativePath, depth);
      budget.deadline.check();
      const metadata = await optionalMetadata(lexical);
      if (!metadata) {
        throw new Error(`Pack validation managed-tree entry identity changed: ${relativePath}`);
      }
      if (metadata.isSymbolicLink()) {
        errors.push(validationDiagnostic("managed_document_not_regular", relativePath, "Managed document tree contains a symbolic link or unreadable entry"));
        continue;
      }
      if (metadata.isDirectory()) {
        if (relativePath.toLocaleLowerCase("en-US").endsWith(".md")) {
          errors.push(validationDiagnostic("managed_document_not_regular", relativePath, "Managed Markdown path is a directory, not a regular file"));
          continue;
        }
        await visit(lexical, depth + 1);
        continue;
      }
      if (!metadata.isFile() || metadata.nlink !== 1n) {
        errors.push(validationDiagnostic("managed_document_not_regular", relativePath, "Managed document tree contains a non-regular entry"));
        continue;
      }
      if (relativePath.toLocaleLowerCase("en-US").endsWith(".md")) {
        const canonicalFile = await realpath(lexical);
        const finalMetadata = await optionalMetadata(lexical);
        if (!isInsideRoot(root, canonicalFile) || !sameResolvedPath(canonicalFile, lexical) || !finalMetadata ||
          !sameFileVersion(metadata, finalMetadata)) {
          errors.push(validationDiagnostic("managed_document_not_regular", relativePath, "Managed Markdown resolves through a symbolic link or outside the repository"));
        } else {
          rememberFinalEvidence({
            label: `managed-tree file ${relativePath}`,
            lexical,
            kind: "file",
            metadata: finalMetadata,
            canonical: canonicalFile
          });
          registerFinalMarkdown(relativePath, relativePath);
        }
      }
    }
    const finalDirectory = await optionalMetadata(directory);
    let finalDirectoryCanonical: string | undefined;
    try {
      finalDirectoryCanonical = await realpath(directory);
    } catch {
      finalDirectoryCanonical = undefined;
    }
    if (!finalDirectory || !sameDirectoryVersion(directoryMetadata, finalDirectory) ||
      finalDirectoryCanonical === undefined || !sameResolvedPath(finalDirectoryCanonical, canonicalDirectory)) {
      throw new Error("Pack validation managed-tree identity changed during bounded enumeration");
    }
    rememberFinalEvidence({
      label: `managed-tree directory ${relativeDirectory || "."}`,
      lexical: directory,
      kind: "directory",
      metadata: finalDirectory,
      canonical: finalDirectoryCanonical
    });
  }

  await visit(managedDirectory, 0);
  for (const [key, contents] of overlay) {
    consumeWork();
    if (!key.startsWith("docs/project-design/") || !key.endsWith(".md")) continue;
    const path = overlayPaths.get(key) ?? key;
    const prior = finalMarkdown.get(key);
    if (prior !== undefined && prior !== path) {
      errors.push(validationDiagnostic(
        "repository_path_alias",
        "overlay",
        `Candidate overlay path ${path} aliases ${prior} under Windows path rules`
      ));
      continue;
    }
    if (contents === undefined) finalMarkdown.delete(key);
    else registerFinalMarkdown(path, "overlay");
  }
  for (const [key, path] of finalMarkdown) {
    consumeWork();
    if (!declaredDocumentKeys.has(key)) {
      errors.push(validationDiagnostic("document_unmapped", "documents", `Final managed Markdown is not mapped by the manifest: ${path}`));
    }
  }

  for (const [index, document] of canonicalPack.documents.entries()) {
    consumeWork();
    const diagnosticPath = `documents.${index}.path`;
    const key = document.path.toLocaleLowerCase("en-US");
    const prior = documentKeys.get(key);
    if (prior) errors.push(validationDiagnostic("document_path_duplicate", diagnosticPath, `Document path aliases ${prior}`));
    else documentKeys.set(key, document.path);

    const view = await projectFile(document.path);
    if (view.kind === "missing") {
      errors.push(validationDiagnostic("document_missing", diagnosticPath, `Document does not exist: ${document.path}`));
      continue;
    }
    if (view.kind === "unsafe") {
      errors.push(view.unsafeReason === "outside-root"
        ? validationDiagnostic("document_outside_root", diagnosticPath, "Document resolves outside the repository root")
        : validationDiagnostic("document_not_regular", diagnosticPath, "Document must be an ordinary regular file"));
      continue;
    }
    const realDocument = view.canonical!;
    const markdown = fileText(view);
    const managed = managedBlocks(markdown, consumeWork);
    const derived = derivedBlocks(markdown, consumeWork);
    const navigationDocument = document.path === "docs/project-design/index.md" || document.path === "docs/project-design/evidence-map.md" ||
      (canonicalPack.schemaVersion === "3.0" && document.path === "docs/project-design/archive/index.md");
    if (canonicalPack.schemaVersion === "3.0") {
      if (derived.length !== 1 || derived[0]?.id !== document.id || (navigationDocument && managed.length > 0)) {
        errors.push(validationDiagnostic("derived_document_invalid", diagnosticPath, `Schema 3.0 document must contain one derived header owned by ${document.id}${navigationDocument ? " and no managed records" : ""}`));
      }
    } else if (canonicalPack.schemaVersion === "2.0" && navigationDocument) {
      if (managed.length > 0 || derived.length !== 1 || derived[0]?.id !== document.id) {
        errors.push(validationDiagnostic("derived_document_invalid", diagnosticPath, `Navigation document must contain one derived block owned by ${document.id}`));
      }
    } else if (derived.length > 0) {
      errors.push(validationDiagnostic("derived_document_invalid", diagnosticPath, "Derived blocks are allowed only in schema 2.0 or 3.0 navigation documents"));
    }
    if (markdown.includes("project-design-keeper:derived") && derived.length === 0) {
      errors.push(validationDiagnostic("derived_document_invalid", diagnosticPath, "Derived document marker is malformed"));
    }
    for (const derivedBlock of derived) {
      consumeWork();
      const actualHash = `sha256:${createHash("sha256").update(derivedBlock.content, "utf8").digest("hex")}`;
      if (actualHash !== derivedBlock.declaredHash) {
        errors.push(validationDiagnostic("derived_block_hash_mismatch", diagnosticPath, `Derived block ${derivedBlock.id} content hash does not match its marker`));
      }
    }
    for (const managedBlock of managed) {
      consumeWork();
      mappedRecordIds.add(managedBlock.id);
      managedBlockOwners.set(managedBlock.id, document.id);
      const priorLocation = managedBlockLocations.get(managedBlock.id);
      if (priorLocation) {
        errors.push(validationDiagnostic("managed_block_duplicate", diagnosticPath, `Managed block ${managedBlock.id} also appears at ${priorLocation}`));
      } else {
        managedBlockLocations.set(managedBlock.id, diagnosticPath);
      }
      const actualHash = `sha256:${createHash("sha256").update(managedBlock.content, "utf8").digest("hex")}`;
      if (actualHash !== managedBlock.declaredHash) {
        errors.push(validationDiagnostic(
          "managed_block_hash_mismatch",
          diagnosticPath,
          `Managed block ${managedBlock.id} content hash does not match its marker`
        ));
      }
    }

    for (const link of markdownLinks(currentKnowledgeMarkdown(markdown, terminalRecordIds), consumeWork)) {
      if (win32.isAbsolute(link)) {
        errors.push(validationDiagnostic("markdown_link_outside_root", diagnosticPath, `Markdown link is an absolute local path: ${link}`));
        continue;
      }
      if (link.startsWith("#") || /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(link)) continue;
      const withoutFragment = link.split(/[?#]/u, 1)[0];
      if (!withoutFragment) continue;
      let decoded: string;
      try {
        decoded = decodeURIComponent(withoutFragment);
      } catch {
        errors.push(validationDiagnostic("markdown_link_invalid", diagnosticPath, `Markdown link is not valid URI text: ${link}`));
        continue;
      }
      const linked = resolve(dirname(realDocument), decoded.replaceAll("/", sep));
      if (!isInsideRoot(root, linked)) {
        errors.push(validationDiagnostic("markdown_link_outside_root", diagnosticPath, `Markdown link escapes the repository: ${link}`));
        continue;
      }
      const linkedRelative = relative(root, linked).replaceAll(sep, "/");
      const linkedKey = windowsRepositoryPathKey(linkedRelative);
      accountFile(linkedKey);
      if (overlay.has(linkedKey)) {
        if (overlay.get(linkedKey) === undefined) {
          errors.push(validationDiagnostic("markdown_link_missing", diagnosticPath, `Markdown link target does not exist: ${link}`));
        } else {
          validationPathStates.set(linkedRelative, `file:${linkedRelative}`);
        }
        continue;
      }
      const linkedMetadata = await optionalMetadata(linked);
      if (!linkedMetadata) {
        rememberFinalEvidence({ label: `linked path ${linkedRelative}`, lexical: linked, kind: "missing" });
        errors.push(validationDiagnostic("markdown_link_missing", diagnosticPath, `Markdown link target does not exist: ${link}`));
        continue;
      }
      const realLinked = await realpath(linked);
      const finalLinkedMetadata = await optionalMetadata(linked);
      let finalRealLinked: string | undefined;
      try {
        finalRealLinked = await realpath(linked);
      } catch {
        finalRealLinked = undefined;
      }
      if (!isInsideRoot(root, realLinked) || linkedMetadata.isSymbolicLink()) {
        errors.push(validationDiagnostic("markdown_link_outside_root", diagnosticPath, `Markdown link resolves outside the repository: ${link}`));
      } else if (!finalLinkedMetadata || !samePathVersion(linkedMetadata, finalLinkedMetadata) ||
        finalRealLinked === undefined || !sameResolvedPath(realLinked, finalRealLinked)) {
        throw new Error(`Pack validation linked path identity changed during validation: ${linkedRelative}`);
      }
      if (finalLinkedMetadata && finalRealLinked !== undefined) {
        rememberPathState(linkedRelative, finalLinkedMetadata, finalRealLinked);
        rememberFinalEvidence({
          label: `linked path ${linkedRelative}`,
          lexical: linked,
          kind: "path",
          metadata: finalLinkedMetadata,
          canonical: finalRealLinked
        });
      }
    }
  }

  const statementIds = new Map<string, string>();
  const declaredRecordIds = new Set(canonicalPack.records.map((record) => record.id));
  for (const [managedId, diagnosticPath] of managedBlockLocations) {
    consumeWork();
    if (!declaredRecordIds.has(managedId)) {
      errors.push(validationDiagnostic("managed_block_unlisted", diagnosticPath, `Managed block is not listed in pack records: ${managedId}`));
    }
  }
  const relocationMatches = new Map<string, number[]>();
  const documentsById = new Map(canonicalPack.documents.map((document) => [document.id, document] as const));
  for (const [index, record] of canonicalPack.records.entries()) {
    consumeWork();
    if (canonicalPack.schemaVersion === "2.0" || canonicalPack.schemaVersion === "3.0") {
      if (!record.kind) errors.push(validationDiagnostic("record_kind_required", `records.${index}.kind`, `Schema ${canonicalPack.schemaVersion} record requires kind: ${record.id}`));
      if (!record.ownerDocument) {
        errors.push(validationDiagnostic("record_owner_required", `records.${index}.ownerDocument`, `Schema 2.0 record requires ownerDocument: ${record.id}`));
      } else {
        const owner = documentsById.get(record.ownerDocument);
        if (!owner) {
          errors.push(validationDiagnostic("record_owner_missing", `records.${index}.ownerDocument`, `Owning document is not declared: ${record.ownerDocument}`));
        } else {
          const expectedPath: Partial<Record<(typeof knowledgeKinds)[number], string>> = {
            intent: "docs/project-design/intent.md",
            principle: "docs/project-design/principles.md",
            architecture: "docs/project-design/architecture.md",
            convention: "docs/project-design/conventions.md",
            decision: "docs/project-design/decisions.md",
            tuning: "docs/project-design/tuning.md",
            verification: "docs/project-design/verification.md",
            "open-question": "docs/project-design/open-questions.md"
          };
          const compatible = record.kind === "module"
            ? owner.path.startsWith("docs/project-design/modules/") && owner.path.endsWith(".md")
            : Boolean(record.kind && expectedPath[record.kind] === owner.path);
          if (!compatible) {
            errors.push(validationDiagnostic("record_owner_incompatible", `records.${index}.ownerDocument`, `Record kind ${record.kind ?? "missing"} cannot be owned by ${owner.path}`));
          }
          if (managedBlockOwners.get(record.id) !== record.ownerDocument) {
            errors.push(validationDiagnostic("record_owner_mismatch", `records.${index}.ownerDocument`, `Record ${record.id} is not rendered in its declared owning document`));
          }
        }
      }
    }
    if (canonicalPack.schemaVersion === "3.0") {
      if (!record.assertedConfidence) {
        errors.push(validationDiagnostic("record_asserted_confidence_required", `records.${index}.assertedConfidence`, `Schema 3.0 record requires assertedConfidence: ${record.id}`));
      }
      if (!record.lifecycle) {
        errors.push(validationDiagnostic("record_lifecycle_required", `records.${index}.lifecycle`, `Schema 3.0 record requires lifecycle: ${record.id}`));
      }
      if (record.confidence !== undefined) {
        errors.push(validationDiagnostic("record_legacy_confidence_forbidden", `records.${index}.confidence`, `Schema 3.0 uses assertedConfidence instead of confidence: ${record.id}`));
      }
      if (record.statement !== record.statement.trim() || /\r|\n/u.test(record.statement)) {
        errors.push(validationDiagnostic("record_statement_non_atomic", `records.${index}.statement`, `Schema 3.0 statements must be one trimmed atomic line: ${record.id}`));
      }
      if (record.assertedConfidence) {
        recordAssessments.push(assessRecord({
          id: record.id,
          kind: record.kind,
          approval: record.approval,
          assertedConfidence: record.assertedConfidence,
          evidence: record.evidence as Array<string | EvidenceRef>
        }));
      }
    }
    if (!mappedRecordIds.has(record.id)) {
      errors.push(validationDiagnostic("record_orphan", `records.${index}.id`, `Record is not mapped by any declared document: ${record.id}`));
    }
    const normalized = normalizedStatement(record.statement);
    const prior = statementIds.get(normalized);
    if (prior && prior !== record.id) {
      errors.push(validationDiagnostic("record_statement_duplicate", `records.${index}.statement`, `Statement duplicates record ${prior}`));
    } else {
      statementIds.set(normalized, record.id);
    }
    if (record.evidence.length === 0) {
      warnings.push(validationDiagnostic("record_evidence_empty", `records.${index}.evidence`, `Record has no source evidence: ${record.id}`));
    }

    for (const [evidenceIndex, evidence] of record.evidence.entries()) {
      consumeWork();
      const evidencePath = `records.${index}.evidence.${evidenceIndex}`;
      if (canonicalPack.schemaVersion === "3.0" && typeof evidence === "string") {
        errors.push(validationDiagnostic("record_evidence_typed_required", evidencePath, `Schema 3.0 evidence must be a typed object: ${record.id}`));
        continue;
      }
      const legacyMatch = typeof evidence === "string" ? /^(.*):([0-9]+)$/u.exec(evidence) : undefined;
      const sourcePath = typeof evidence === "string" ? legacyMatch?.[1] : evidence.path;
      const startLine = typeof evidence === "string" ? Number(legacyMatch?.[2]) : evidence.startLine;
      const endLine = typeof evidence === "string" ? startLine : (evidence.endLine ?? evidence.startLine);
      if (!sourcePath || !safeRepositoryPath(sourcePath)) {
        errors.push(validationDiagnostic("evidence_path_invalid", evidencePath, "Evidence must use a safe repository path and one-based line"));
        continue;
      }
      if (!Number.isSafeInteger(startLine) || startLine < 1 || !Number.isSafeInteger(endLine) || endLine < startLine) {
        errors.push(validationDiagnostic("evidence_line_invalid", evidencePath, "Evidence lines must be one-based and ordered"));
        continue;
      }
      const sourceView = await projectFile(sourcePath);
      if (sourceView.kind === "missing") {
        errors.push(validationDiagnostic("evidence_source_missing", evidencePath, `Evidence source does not exist: ${sourcePath}`));
        continue;
      }
      if (sourceView.kind === "unsafe") {
        errors.push(validationDiagnostic("evidence_path_invalid", evidencePath, `Evidence source is not a safe in-repository file: ${sourcePath}`));
        continue;
      }
      const sourceLines = fileLines(sourceView);
      const lineCount = sourceLines.at(-1) === "" ? sourceLines.length - 1 : sourceLines.length;
      if (endLine > lineCount) {
        errors.push(validationDiagnostic("evidence_line_invalid", evidencePath, `Evidence line ${endLine} exceeds ${sourcePath}'s ${lineCount} lines`));
        continue;
      }
      if (typeof evidence !== "string") {
        const excerpt = sourceLines.slice(startLine - 1, endLine).join("\n");
        budget.analysisBytes.consume(Buffer.byteLength(excerpt, "utf8"));
        const excerptHash = `sha256:${createHash("sha256").update(excerpt, "utf8").digest("hex")}`;
        if (excerptHash !== evidence.excerptHash) {
          errors.push(validationDiagnostic("evidence_excerpt_hash_mismatch", `${evidencePath}.excerptHash`, `Evidence excerpt hash does not match repository text: ${sourcePath}:${startLine}`));
          const span = endLine - startLine + 1;
          const relocationKey = `${windowsRepositoryPathKey(sourcePath)}\u0000${span}\u0000${evidence.excerptHash}`;
          let matches = relocationMatches.get(relocationKey);
          if (!matches) {
            matches = [];
            for (let candidate = 1; candidate + span - 1 <= lineCount; candidate += 1) {
              consumeWork(span);
              const candidateText = sourceLines.slice(candidate - 1, candidate - 1 + span).join("\n");
              budget.analysisBytes.consume(Buffer.byteLength(candidateText, "utf8"));
              const candidateHash = `sha256:${createHash("sha256").update(candidateText, "utf8").digest("hex")}`;
              if (candidateHash === evidence.excerptHash) matches.push(candidate);
            }
            relocationMatches.set(relocationKey, matches);
          }
          if (matches.length === 1 && matches[0] !== startLine) {
            const relocatedEnd = matches[0] + span - 1;
            relocationCandidates.push({
              recordId: record.id,
              evidenceIndex,
              path: sourcePath,
              from: { startLine, ...(endLine !== startLine ? { endLine } : {}) },
              to: { startLine: matches[0], ...(relocatedEnd !== matches[0] ? { endLine: relocatedEnd } : {}) }
            });
          }
        }
      }
    }
  }

  if (canonicalPack.schemaVersion === "3.0") {
    const rawRecords = Array.isArray((pack as Record<string, unknown>).records)
      ? ((pack as Record<string, unknown>).records as unknown[]).filter((record): record is Record<string, unknown> => Boolean(record) && typeof record === "object" && !Array.isArray(record))
      : [];
    const byId = new Map(rawRecords.map((record) => [String(record.id), record]));
    const digestById = new Map<string, string>();
    const digest = (record: Record<string, unknown>): string => {
      const id = String(record.id);
      const existing = digestById.get(id);
      if (existing) return existing;
      consumeWork();
      const value = `sha256:${createHash("sha256").update(JSON.stringify(record), "utf8").digest("hex")}`;
      digestById.set(id, value);
      return value;
    };
    for (const [index, exception] of (canonicalPack.dedupeExceptions ?? []).entries()) {
      consumeWork();
      const left = byId.get(exception.leftId);
      const right = byId.get(exception.rightId);
      if (!left || !right || left.id === right.id || digest(left) !== exception.leftDigest || digest(right) !== exception.rightDigest) {
        errors.push(validationDiagnostic("dedupe_exception_invalidated", `dedupeExceptions.${index}`, "Keep-separate exception IDs and content digests must match the current records"));
      }
    }
  }

  if (canonicalPack.schemaVersion === "3.0" && canonicalPack.archive) {
    const activeIds = new Set(canonicalPack.records.map((record) => record.id));
    const historicalIds = new Set<string>();
    if (canonicalPack.archive.generations.length > 2) {
      errors.push(validationDiagnostic("archive_generation_limit", "archive.generations", "Only the two newest full archive generations may be retained"));
    }
    for (const [generationIndex, generation] of canonicalPack.archive.generations.entries()) {
      consumeWork();
      const metadataPath = `archive.generations.${generationIndex}`;
      const expectedPath = `docs/project-design/archive/${generation.id}.records.jsonl`;
      if (generation.path !== expectedPath) {
        errors.push(validationDiagnostic("archive_generation_path_invalid", `${metadataPath}.path`, `Archive generation path must be ${expectedPath}`));
        continue;
      }
      const view = await projectFile(generation.path);
      if (view.kind !== "regular") {
        errors.push(validationDiagnostic("archive_generation_missing", `${metadataPath}.path`, `Archive generation is missing or unsafe: ${generation.path}`));
        continue;
      }
      let lines: ReturnType<typeof decodeCanonicalJsonLines>;
      try {
        lines = decodeCanonicalJsonLines(view.contents!, `Archive generation ${generation.path}`, {
          expectedCount: generation.recordCount,
          maxBytes: managedFileBytes,
          maxLines: Math.min(limits.pack.maxRecords, limits.scan.maxEvidence)
        });
      } catch (error) {
        const count = error instanceof CanonicalJsonLinesError && error.kind === "count";
        errors.push(validationDiagnostic(
          count ? "archive_record_count_mismatch" : "archive_jsonl_invalid",
          count ? `${metadataPath}.recordCount` : generation.path,
          error instanceof Error ? error.message : "Archive generation JSONL is invalid"
        ));
        continue;
      }
      for (const { value, line } of lines) {
        consumeWork();
        const entry = value && typeof value === "object" && !Array.isArray(value)
          ? value as Record<string, unknown>
          : undefined;
        const linePath = `${generation.path}:${line}`;
        if (!isCompleteArchiveEntry(entry)) {
          errors.push(validationDiagnostic("archive_record_invalid", linePath, "Archive line must contain only the complete Schema 3.0 archive record fields"));
        }
        const archivedRecord = entry?.record;
        if (!entry || !archivedRecord || typeof archivedRecord !== "object" || Array.isArray(archivedRecord)) {
          errors.push(validationDiagnostic("archive_record_invalid", linePath, "Archive line must contain a complete record object"));
          continue;
        }
        const record = archivedRecord as Record<string, unknown>;
        const lifecycle = record.lifecycle;
        const terminal = lifecycle && typeof lifecycle === "object" && !Array.isArray(lifecycle) ? lifecycle as Record<string, unknown> : undefined;
        const parsedRecord = knowledgeRecordSchema.safeParse(record);
        if (!parsedRecord.success || typeof record.kind !== "string" || typeof record.ownerDocument !== "string" ||
          typeof record.assertedConfidence !== "string" || record.confidence !== undefined) {
          errors.push(validationDiagnostic("archive_record_invalid", linePath, "Archive line must retain a complete Schema 3.0 knowledge record"));
        }
        if (terminal?.state !== "terminal" || !Number.isSafeInteger(terminal.confirmedRefreshes) || Number(terminal.confirmedRefreshes) < 2) {
          errors.push(validationDiagnostic("archive_record_ineligible", linePath, "Archived record must be terminal for at least two confirmed refreshes"));
        }
        if (typeof record.id !== "string" || !stableId.safeParse(record.id).success) {
          errors.push(validationDiagnostic("archive_record_invalid", linePath, "Archived record must retain a stable ID"));
        } else if (activeIds.has(record.id) || historicalIds.has(record.id)) {
          errors.push(validationDiagnostic("archive_record_duplicate", linePath, `Archived record ID is duplicated: ${record.id}`));
        } else {
          historicalIds.add(record.id);
        }
        for (const field of ["originalOwnerDocument", "managedBody", "contentHash", "evidenceHash", "archivedAt"] as const) {
          if (typeof entry[field] !== "string") errors.push(validationDiagnostic("archive_record_invalid", linePath, `Archive record is missing ${field}`));
        }
        if (typeof entry.managedBody === "string" && entry.contentHash !== `sha256:${createHash("sha256").update(entry.managedBody, "utf8").digest("hex")}`) {
          errors.push(validationDiagnostic("archive_record_content_hash_mismatch", linePath, "Archive contentHash must match managedBody bytes"));
        }
        if (entry.evidenceHash !== `sha256:${createHash("sha256").update(JSON.stringify(record.evidence), "utf8").digest("hex")}`) {
          errors.push(validationDiagnostic("archive_record_evidence_hash_mismatch", linePath, "Archive evidenceHash must match the archived record evidence"));
        }
        if (entry.originalOwnerDocument !== record.ownerDocument) {
          errors.push(validationDiagnostic("archive_record_owner_mismatch", linePath, "Archive originalOwnerDocument must match the archived record owner"));
        }
        if (typeof entry.contentHash !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(entry.contentHash) ||
          typeof entry.evidenceHash !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(entry.evidenceHash) ||
          entry.terminalReason !== terminal?.reason || !Number.isSafeInteger(entry.maintenanceRevision) || Number.isNaN(Date.parse(String(entry.archivedAt)))) {
          errors.push(validationDiagnostic("archive_record_invalid", linePath, "Archive record hashes, terminal reason, revision, and timestamp must be complete and consistent"));
        }
      }
    }
    const tombstones = canonicalPack.archive.tombstones;
    if (tombstones.path !== "docs/project-design/archive/tombstones.jsonl") {
      errors.push(validationDiagnostic("tombstone_path_invalid", "archive.tombstones.path", "Tombstones must use docs/project-design/archive/tombstones.jsonl"));
    } else {
      const view = await projectFile(tombstones.path);
      if (view.kind === "missing" && tombstones.count !== 0) {
        errors.push(validationDiagnostic("tombstone_file_missing", "archive.tombstones.path", "Tombstone file is missing"));
      } else if (view.kind === "unsafe") {
        errors.push(validationDiagnostic("tombstone_file_unsafe", "archive.tombstones.path", "Tombstone file must be a safe regular file"));
      } else if (view.kind === "regular") {
        let lines: ReturnType<typeof decodeCanonicalJsonLines>;
        try {
          lines = decodeCanonicalJsonLines(view.contents!, `History tombstone ${tombstones.path}`, {
            expectedCount: tombstones.count,
            maxBytes: managedFileBytes,
            maxLines: Math.min(limits.pack.maxRecords, limits.scan.maxEvidence)
          });
        } catch (error) {
          const count = error instanceof CanonicalJsonLinesError && error.kind === "count";
          errors.push(validationDiagnostic(
            count ? "tombstone_count_mismatch" : "tombstone_jsonl_invalid",
            count ? "archive.tombstones.count" : tombstones.path,
            error instanceof Error ? error.message : "Tombstone JSONL is invalid"
          ));
          lines = [];
        }
        for (const { value, line } of lines) {
          consumeWork();
          const parsedTombstone = tombstoneSchema.safeParse(value);
          const id = parsedTombstone.success ? parsedTombstone.data.id : undefined;
          if (!parsedTombstone.success) {
            errors.push(validationDiagnostic("tombstone_invalid", `${tombstones.path}:${line}`, "Tombstone must retain a stable ID, terminal relationship, content hash, and archive time"));
          } else if (activeIds.has(id!) || historicalIds.has(id!)) {
            errors.push(validationDiagnostic("archive_record_duplicate", `${tombstones.path}:${line}`, `Historical record ID is duplicated: ${id}`));
          } else {
            historicalIds.add(id!);
          }
        }
      }
    }
  }

  for (const [scopeIndex, scopePath] of (canonicalPack.scope.paths ?? []).entries()) {
    consumeWork();
    accountFile(windowsRepositoryPathKey(scopePath));
    const target = resolve(root, ...scopePath.split("/"));
    const metadata = await optionalMetadata(target);
    if (!metadata) {
      rememberFinalEvidence({ label: `source scope ${scopePath}`, lexical: target, kind: "missing" });
      errors.push(validationDiagnostic("source_scope_missing", `scope.paths.${scopeIndex}`, `Source scope does not exist: ${scopePath}`));
      continue;
    }
    const canonicalTarget = await realpath(target);
    const finalMetadata = await optionalMetadata(target);
    let finalCanonicalTarget: string | undefined;
    try {
      finalCanonicalTarget = await realpath(target);
    } catch {
      finalCanonicalTarget = undefined;
    }
    if (metadata.isSymbolicLink() || !isInsideRoot(root, canonicalTarget) || !sameResolvedPath(canonicalTarget, target)) {
      errors.push(validationDiagnostic("source_scope_outside_root", `scope.paths.${scopeIndex}`, `Source scope resolves outside the repository: ${scopePath}`));
    } else if (!finalMetadata || !samePathVersion(metadata, finalMetadata) || finalCanonicalTarget === undefined ||
      !sameResolvedPath(canonicalTarget, finalCanonicalTarget)) {
      throw new Error(`Pack validation source scope identity changed during validation: ${scopePath}`);
    }
    if (finalMetadata && finalCanonicalTarget !== undefined) {
      rememberPathState(scopePath, finalMetadata, finalCanonicalTarget);
      rememberFinalEvidence({
        label: `source scope ${scopePath}`,
        lexical: target,
        kind: "path",
        metadata: finalMetadata,
        canonical: finalCanonicalTarget
      });
    }
  }
  for (const [sourcePath, declaredHash] of Object.entries(canonicalPack.sourceRevision.files)) {
    consumeWork();
    const sourceView = await projectFile(sourcePath);
    if (sourceView.kind === "missing") {
      freshnessDeleted.add(sourcePath);
      errors.push(validationDiagnostic("source_revision_missing", `sourceRevision.files.${sourcePath}`, `Source revision file does not exist: ${sourcePath}`));
    }
    else if (sourceView.kind === "unsafe") {
      errors.push(validationDiagnostic("source_revision_outside_root", `sourceRevision.files.${sourcePath}`, `Source revision is not a safe in-repository file: ${sourcePath}`));
    } else {
      const actualHash = `sha256:${createHash("sha256").update(sourceView.contents!).digest("hex")}`;
      if (actualHash !== declaredHash) {
        freshnessChanged.add(sourcePath);
        errors.push(validationDiagnostic("source_revision_hash_mismatch", `sourceRevision.files.${sourcePath}`, `Source revision hash does not match repository bytes: ${sourcePath}`));
      }
    }
  }

  if (canonicalPack.schemaVersion === "3.0") {
    const revisionPaths = new Set(Object.keys(canonicalPack.sourceRevision.files).map(windowsRepositoryPathKey));
    for (const [recordIndex, record] of canonicalPack.records.entries()) {
      consumeWork();
      for (const [evidenceIndex, evidence] of record.evidence.entries()) {
        consumeWork();
        const path = typeof evidence === "string" ? /^(.*):([0-9]+)$/u.exec(evidence)?.[1] : evidence.path;
        if (path && !revisionPaths.has(windowsRepositoryPathKey(path))) {
          errors.push(validationDiagnostic(
            "evidence_source_revision_missing",
            `records.${recordIndex}.evidence.${evidenceIndex}.path`,
            `Evidence source is not bound to sourceRevision.files: ${path}`
          ));
        }
      }
    }
  }

  const stalePaths = new Set([...freshnessChanged, ...freshnessDeleted].map(windowsRepositoryPathKey));
  const invalidatedRecordIds: string[] = [];
  for (const record of canonicalPack.records) {
    consumeWork();
    let invalidated = false;
    for (const evidence of record.evidence) {
      consumeWork();
      const path = typeof evidence === "string" ? /^(.*):([0-9]+)$/u.exec(evidence)?.[1] : evidence.path;
      if (path && stalePaths.has(windowsRepositoryPathKey(path))) invalidated = true;
    }
    if (invalidated) invalidatedRecordIds.push(record.id);
  }
  await assertFinalPathEvidence();
  await assertRootIdentity();
  if (errors.length === 0 && options.onValidationDependencyDigest) {
    const dependencyHash = createHash("sha256");
    const updateField = (value: string | null): void => {
      const text = value ?? "";
      dependencyHash.update(value === null ? "n" : "s");
      dependencyHash.update(String(Buffer.byteLength(text, "utf8")));
      dependencyHash.update(":");
      dependencyHash.update(text, "utf8");
      dependencyHash.update(";");
    };
    dependencyHash.update("files;");
    for (const [path, hash] of [...validationFileDependencies.entries()]
      .sort(([left], [right]) => left.localeCompare(right, "en-US"))) {
      consumeWork();
      updateField(path);
      updateField(hash);
    }
    dependencyHash.update("managed-markdown;");
    for (const path of [...finalMarkdown.values()].sort((left, right) => left.localeCompare(right, "en-US"))) {
      consumeWork();
      updateField(path);
    }
    dependencyHash.update("path-states;");
    for (const [path, state] of [...validationPathStates.entries()]
      .sort(([left], [right]) => left.localeCompare(right, "en-US"))) {
      consumeWork();
      updateField(path);
      updateField(state);
    }
    budget.deadline.check();
    options.onValidationDependencyDigest(`sha256:${dependencyHash.digest("hex")}`);
  }
  return {
    valid: errors.length === 0,
    errors,
    warnings,
    ...(canonicalPack.schemaVersion === "3.0" ? { recordAssessments, relocationCandidates } : {}),
    freshness: {
      status: stalePaths.size > 0 ? "stale" : "fresh",
      changedFiles: [...freshnessChanged].sort(),
      deletedFiles: [...freshnessDeleted].sort(),
      invalidatedRecordIds
    }
  };
}

const persistedChangeSchema = z.union([
  z.object({
    path: documentPath,
    content: z.string(),
    previousHash: sha256Hash.nullable(),
    managedBlocks: z.array(z.union([
      z.object({ recordId: stableId, content: z.string(), expectedContentHash: sha256Hash.optional() }).strict(),
      z.object({ recordId: stableId, delete: z.literal(true), expectedContentHash: sha256Hash.optional() }).strict()
    ])).nonempty().optional()
  }).strict(),
  z.object({ path: documentPath, delete: z.literal(true), previousHash: sha256Hash }).strict()
]);

export const expiredPersistedChangesetV1Schema: z.ZodType<ExpiredPersistedChangesetV1, z.ZodTypeDef, unknown> = z.object({
  version: z.literal(1),
  changesetId: canonicalUuidSchema,
  root: z.string().min(1),
  createdAt: z.number().finite().int().nonnegative(),
  expiresAt: z.number().finite().int().positive(),
  changes: z.array(persistedChangeSchema).nonempty(),
  manifestHash: sha256Hash.nullable(),
  sourceScope: z.object({ root: z.string().min(1), path: z.union([z.literal("."), repositoryPath]).optional() }).strict(),
  sourcePaths: z.array(repositoryPath).nonempty().optional(),
  sourceFiles: z.record(repositoryPath, sha256Hash)
}).strict().superRefine((changeset, context) => {
  if (changeset.sourceScope.root !== changeset.root) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["sourceScope", "root"], message: "must equal the changeset root" });
  }
  if (changeset.expiresAt !== changeset.createdAt + changesetLifetimeMs) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["expiresAt"], message: "must be exactly thirty minutes after createdAt" });
  }
  const reportAliases = (paths: string[], issuePath: Array<string | number>) => {
    const seen = new Map<string, string>();
    paths.forEach((path, index) => {
      const key = windowsRepositoryPathKey(path);
      const previous = seen.get(key);
      if (previous !== undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [...issuePath, index],
          message: `duplicates or aliases ${previous} under Windows path rules`
        });
      } else {
        seen.set(key, path);
      }
    });
  };
  reportAliases(changeset.changes.map((change) => change.path), ["changes"]);
  reportAliases(Object.keys(changeset.sourceFiles), ["sourceFiles"]);
  if (changeset.sourcePaths) {
    reportAliases(changeset.sourcePaths, ["sourcePaths"]);
    const declared = [...changeset.sourcePaths].sort();
    const fingerprinted = Object.keys(changeset.sourceFiles).sort();
    if (declared.length !== fingerprinted.length || declared.some((path, index) => path !== fingerprinted[index])) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["sourcePaths"], message: "must exactly match sourceFiles keys" });
    }
  }
  changeset.changes.forEach((change, changeIndex) => {
    if (!("managedBlocks" in change) || !change.managedBlocks) return;
    const ids = change.managedBlocks.map((block) => block.recordId);
    ids.forEach((id, index) => {
      if (ids.indexOf(id) !== index) {
        context.addIssue({ code: z.ZodIssueCode.custom, path: ["changes", changeIndex, "managedBlocks", index], message: `duplicate managed block operation: ${id}` });
      }
    });
  });
});

export const persistedChangesetSchema: z.ZodType<PersistedChangeset, z.ZodTypeDef, unknown> = z.object({
  version: z.union([z.literal(2), z.literal(3)]),
  policy: z.object({ revision: z.string().min(1).max(128), easyMode: z.boolean(), maxUpdateMiB: z.number().int().min(1).max(64) }).strict().optional(),
  diff: z.string().optional(),
  changesetId: canonicalUuidSchema,
  root: z.string().min(1),
  createdAt: z.number().finite().int().nonnegative(),
  expiresAt: z.number().finite().int().positive(),
  diffDigest: diffDigestSchema,
  archiveActions: z.object({
    archivedRecordIds: z.array(stableId).max(10_000),
    tombstonedRecordIds: z.array(stableId).max(10_000)
  }).strict(),
  semanticDecisionIds: z.array(stableId).max(11_000),
  historyFiles: z.record(documentPath, sha256Hash.nullable()),
  changes: z.array(persistedChangeSchema).nonempty(),
  manifestHash: sha256Hash.nullable(),
  sourceScope: z.object({ root: z.string().min(1), path: z.union([z.literal("."), repositoryPath]).optional() }).strict(),
  sourcePaths: z.array(repositoryPath).nonempty().optional(),
  sourceFiles: z.record(repositoryPath, sha256Hash),
  validatedPack: canonicalPackSchema.optional(),
  validationDependencyDigest: diffDigestSchema.optional()
}).strict().superRefine((changeset, context) => {
  if (changeset.version === 3 && (!changeset.policy || changeset.diff === undefined)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["policy"], message: "version three requires authenticated runtime policy and full diff" });
  }
  if (changeset.sourceScope.root !== changeset.root) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["sourceScope", "root"], message: "must equal the changeset root" });
  }
  if (changeset.expiresAt !== changeset.createdAt + changesetLifetimeMs) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["expiresAt"], message: "must be exactly thirty minutes after createdAt" });
  }
  const hasValidatedPack = changeset.validatedPack !== undefined;
  const hasValidationDependencyDigest = changeset.validationDependencyDigest !== undefined;
  if (hasValidatedPack !== hasValidationDependencyDigest || (hasValidatedPack && !changeset.sourcePaths)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["validationDependencyDigest"],
      message: "must accompany validatedPack and candidate-pack sourcePaths"
    });
  }
  const requireSortedUnique = (ids: string[], path: Array<string | number>) => {
    const sorted = [...ids].sort();
    if (sorted.some((id, index) => id !== ids[index]) || new Set(sorted).size !== sorted.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path,
        message: "must be sorted and unique"
      });
    }
  };
  requireSortedUnique(changeset.archiveActions.archivedRecordIds, ["archiveActions", "archivedRecordIds"]);
  requireSortedUnique(changeset.archiveActions.tombstonedRecordIds, ["archiveActions", "tombstonedRecordIds"]);
  const semanticDecisionIds = [...changeset.semanticDecisionIds].sort();
  if (semanticDecisionIds.some((id, index) => id !== changeset.semanticDecisionIds[index]) ||
      new Set(semanticDecisionIds).size !== semanticDecisionIds.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["semanticDecisionIds"],
      message: "must be sorted and unique"
    });
  }

  const reportAliases = (paths: string[], issuePath: Array<string | number>) => {
    const seen = new Map<string, string>();
    paths.forEach((path, index) => {
      const key = windowsRepositoryPathKey(path);
      const previous = seen.get(key);
      if (previous !== undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [...issuePath, index],
          message: `duplicates or aliases ${previous} under Windows path rules`
        });
      } else {
        seen.set(key, path);
      }
    });
  };
  reportAliases(changeset.changes.map((change) => change.path), ["changes"]);
  reportAliases(Object.keys(changeset.historyFiles), ["historyFiles"]);
  if (Object.keys(changeset.historyFiles).length > 1_024) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["historyFiles"], message: "must contain at most 1024 files" });
  }
  reportAliases(Object.keys(changeset.sourceFiles), ["sourceFiles"]);
  if (changeset.sourcePaths) {
    reportAliases(changeset.sourcePaths, ["sourcePaths"]);
    const declared = [...changeset.sourcePaths].sort();
    const fingerprinted = Object.keys(changeset.sourceFiles).sort();
    if (declared.length !== fingerprinted.length || declared.some((path, index) => path !== fingerprinted[index])) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["sourcePaths"], message: "must exactly match sourceFiles keys" });
    }
  }
  changeset.changes.forEach((change, changeIndex) => {
    if (!("managedBlocks" in change) || !change.managedBlocks) return;
    const ids = change.managedBlocks.map((block) => block.recordId);
    ids.forEach((id, index) => {
      if (ids.indexOf(id) !== index) {
        context.addIssue({ code: z.ZodIssueCode.custom, path: ["changes", changeIndex, "managedBlocks", index], message: `duplicate managed block operation: ${id}` });
      }
    });
  });
});
