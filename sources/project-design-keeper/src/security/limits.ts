import { performance } from "node:perf_hooks";
import { freezeRuntimePolicy, maximumUpdateBytes, type RuntimePolicy } from "../settings/policy.js";

export interface KeeperLimits {
  readonly mcpArgumentBytes: number;
  readonly preview: Readonly<{ maxChanges: number; maxFileBytes: number; maxAggregateBytes: number; maxDiffBytes: number }>;
  readonly changesets: Readonly<{
    maxPairsPerProject: number;
    maxPairsGlobal: number;
    maxTotalBytes: number;
    maxChangesetBytes: number;
    maxSignatureBytes: number;
  }>;
  readonly pack: Readonly<{ maxDocuments: number; maxRecords: number; maxEvidencePerRecord: number; maxImpactPerRecord: number }>;
  readonly scan: Readonly<{ maxFiles: number; maxFileBytes: number; maxAggregateBytes: number; maxEvidence: number; deadlineMs: number }>;
  readonly redundancy: Readonly<{ maxRecords: number; maxPairs: number; maxDecisions: number }>;
}

export type DeepPartial<T> = {
  -readonly [Key in keyof T]?: T[Key] extends object ? DeepPartial<T[Key]> : T[Key];
};

export type KeeperLimitOverrides = DeepPartial<KeeperLimits>;

export const keeperLimits: KeeperLimits = Object.freeze({
  mcpArgumentBytes: 8 * 1024 * 1024,
  preview: Object.freeze({
    maxChanges: 200,
    maxFileBytes: 2 * 1024 * 1024,
    maxAggregateBytes: 8 * 1024 * 1024,
    maxDiffBytes: 768 * 1024
  }),
  changesets: Object.freeze({
    maxPairsPerProject: 64,
    maxPairsGlobal: 256,
    maxTotalBytes: 128 * 1024 * 1024,
    maxChangesetBytes: 12 * 1024 * 1024,
    maxSignatureBytes: 4 * 1024
  }),
  pack: Object.freeze({
    maxDocuments: 256,
    maxRecords: 10_000,
    maxEvidencePerRecord: 128,
    maxImpactPerRecord: 128
  }),
  scan: Object.freeze({
    maxFiles: 100_000,
    maxFileBytes: 8 * 1024 * 1024,
    maxAggregateBytes: 256 * 1024 * 1024,
    maxEvidence: 250_000,
    deadlineMs: 60_000
  }),
  redundancy: Object.freeze({
    maxRecords: 10_000,
    maxPairs: 20_000,
    maxDecisions: 1_000
  })
});

/** Independent hard ceilings for exact-removal recovery state under the cache lock directory. */
export const changesetRemovalRecoveryLimits = Object.freeze({
  maxEntries: keeperLimits.changesets.maxPairsGlobal * 4,
  maxWork: keeperLimits.changesets.maxPairsGlobal * 16,
  maxBytes: 2 * 1024 * 1024 * 1024,
  maxArtifactBytes: 512 * 1024 * 1024,
  deadlineMs: 30_000
});

function cappedOverride(label: string, hardLimit: number, override: number | undefined): number {
  if (override === undefined) return hardLimit;
  positiveLimit(label, override, "units");
  return Math.min(override, hardLimit);
}

/** Resolve test overrides without allowing any effective production limit above its hard ceiling. */
export function resolveKeeperLimits(overrides: KeeperLimitOverrides = {}, runtimePolicy?: RuntimePolicy): KeeperLimits {
  const policy = runtimePolicy ? freezeRuntimePolicy(runtimePolicy) : undefined;
  const writeBytes = policy ? policy.maxUpdateMiB * 1024 * 1024 : keeperLimits.preview.maxAggregateBytes;
  // JSON can escape each content byte to six bytes. Managed operations may carry
  // multiple final-file copies; metadata has its own allowance, not a write charge.
  const argumentBytes = policy ? writeBytes * 12 + keeperLimits.mcpArgumentBytes : keeperLimits.mcpArgumentBytes;
  const fileBytes = policy?.easyMode ? writeBytes : keeperLimits.preview.maxFileBytes;
  const preview = overrides.preview;
  const changesets = overrides.changesets;
  const pack = overrides.pack;
  const scan = overrides.scan;
  const redundancy = overrides.redundancy;
  return Object.freeze({
    mcpArgumentBytes: cappedOverride("MCP argument bytes", argumentBytes, overrides.mcpArgumentBytes),
    preview: Object.freeze({
      maxChanges: cappedOverride("Preview changes", keeperLimits.preview.maxChanges, preview?.maxChanges),
      maxFileBytes: cappedOverride("Preview file bytes", fileBytes, preview?.maxFileBytes),
      maxAggregateBytes: cappedOverride("Preview aggregate bytes", writeBytes, preview?.maxAggregateBytes),
      maxDiffBytes: cappedOverride("Preview diff bytes", keeperLimits.preview.maxDiffBytes, preview?.maxDiffBytes)
    }),
    changesets: Object.freeze({
      maxPairsPerProject: cappedOverride("Changesets per project", keeperLimits.changesets.maxPairsPerProject, changesets?.maxPairsPerProject),
      maxPairsGlobal: cappedOverride("Global changesets", keeperLimits.changesets.maxPairsGlobal, changesets?.maxPairsGlobal),
      maxTotalBytes: cappedOverride("Changeset cache bytes", policy ? 2 * 1024 * 1024 * 1024 : keeperLimits.changesets.maxTotalBytes, changesets?.maxTotalBytes),
      maxChangesetBytes: cappedOverride("Changeset bytes", policy ? maximumUpdateBytes * 8 : keeperLimits.changesets.maxChangesetBytes, changesets?.maxChangesetBytes),
      maxSignatureBytes: cappedOverride("Changeset signature bytes", keeperLimits.changesets.maxSignatureBytes, changesets?.maxSignatureBytes)
    }),
    pack: Object.freeze({
      maxDocuments: cappedOverride("Pack documents", keeperLimits.pack.maxDocuments, pack?.maxDocuments),
      maxRecords: cappedOverride("Pack records", keeperLimits.pack.maxRecords, pack?.maxRecords),
      maxEvidencePerRecord: cappedOverride("Pack evidence", keeperLimits.pack.maxEvidencePerRecord, pack?.maxEvidencePerRecord),
      maxImpactPerRecord: cappedOverride("Pack impact", keeperLimits.pack.maxImpactPerRecord, pack?.maxImpactPerRecord)
    }),
    scan: Object.freeze({
      maxFiles: cappedOverride("Scan files", keeperLimits.scan.maxFiles, scan?.maxFiles),
      maxFileBytes: cappedOverride("Scan file bytes", keeperLimits.scan.maxFileBytes, scan?.maxFileBytes),
      maxAggregateBytes: cappedOverride("Scan aggregate bytes", keeperLimits.scan.maxAggregateBytes, scan?.maxAggregateBytes),
      maxEvidence: cappedOverride("Scan evidence", keeperLimits.scan.maxEvidence, scan?.maxEvidence),
      deadlineMs: cappedOverride("Scan deadline", keeperLimits.scan.deadlineMs, scan?.deadlineMs)
    }),
    redundancy: Object.freeze({
      maxRecords: cappedOverride("Redundancy records", keeperLimits.redundancy.maxRecords, redundancy?.maxRecords),
      maxPairs: cappedOverride("Redundancy pairs", keeperLimits.redundancy.maxPairs, redundancy?.maxPairs),
      maxDecisions: cappedOverride("Redundancy decisions", keeperLimits.redundancy.maxDecisions, redundancy?.maxDecisions)
    })
  });
}

function positiveLimit(label: string, value: number, unit: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} limit must be a non-negative integer ${unit}`);
}

function exceeded(label: string, max: number, unit: string): Error {
  return new Error(`${label} exceeds the limit of ${max} ${unit}`);
}

export function serializedBytes(value: unknown): number {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new Error("Value cannot be serialized for resource-limit measurement");
  }
  if (serialized === undefined) throw new Error("Value cannot be serialized for resource-limit measurement");
  return Buffer.byteLength(serialized, "utf8");
}

export function assertSerializedWithin(label: string, value: unknown, maxBytes: number): void {
  positiveLimit(label, maxBytes, "bytes");
  if (serializedBytes(value) > maxBytes) throw exceeded(label, maxBytes, "bytes");
}

export const mcpToolResultBudgetBytes = 1024 * 1024;
export const mcpToolResultEnvelopeReserveBytes = 16 * 1024;

/** Assert the structured value can be wrapped by the shared MCP result envelope. */
export function assertToolResultBudget(value: unknown): void {
  if (serializedBytes(value) > mcpToolResultBudgetBytes - mcpToolResultEnvelopeReserveBytes) {
    throw new Error("MCP structured response exceeds the one MiB response budget; narrow the request or use pagination");
  }
}

export function assertArrayWithin(label: string, value: unknown, maxItems: number): asserts value is unknown[] {
  positiveLimit(label, maxItems, "items");
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  if (value.length > maxItems) throw exceeded(label, maxItems, "items");
}

export function assertStringWithin(label: string, value: unknown, maxBytes: number): asserts value is string {
  positiveLimit(label, maxBytes, "bytes");
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  if (Buffer.byteLength(value, "utf8") > maxBytes) throw exceeded(label, maxBytes, "bytes");
}

export class ByteBudget {
  #used = 0;

  constructor(private readonly label: string, private readonly maxBytes: number) {
    positiveLimit(label, maxBytes, "bytes");
  }

  consume(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error(`${this.label} consumption must be a non-negative integer number of bytes`);
    if (this.#used + bytes > this.maxBytes) throw exceeded(this.label, this.maxBytes, "bytes");
    this.#used += bytes;
  }
}

export class CounterBudget {
  #used = 0;

  constructor(private readonly label: string, private readonly maxItems: number) {
    positiveLimit(label, maxItems, "items");
  }

  consume(items = 1): void {
    if (!Number.isSafeInteger(items) || items < 0) throw new Error(`${this.label} consumption must be a non-negative integer number of items`);
    if (this.#used + items > this.maxItems) throw exceeded(this.label, this.maxItems, "items");
    this.#used += items;
  }
}

export class DeadlineBudget {
  readonly #startedAt: number;

  constructor(
    private readonly label: string,
    private readonly durationMs: number,
    private readonly now: () => number = () => performance.now()
  ) {
    positiveLimit(label, durationMs, "milliseconds");
    this.#startedAt = now();
  }

  check(): void {
    if (this.now() - this.#startedAt >= this.durationMs) {
      throw new Error(`${this.label} deadline of ${this.durationMs} milliseconds exceeded`);
    }
  }
}
