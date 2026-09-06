import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { lstat, open, opendir } from "node:fs/promises";
import { join } from "node:path";
import {
  assertSecureOwnerFileMetadata,
  captureSecurePathIdentity,
  prepareSecureCache,
  publishExclusiveFile,
  reconcileExactRemovalIntents,
  reconcileCacheFilePublication,
  safeRemoveExactCacheFile,
  sameFilesystemPath,
  validateCacheFile,
  validateSecurePathIdentity,
  type SecureCacheLayout,
  type SecureCachePublicationHooks,
  type SecurePathIdentity
} from "../security/cache.js";
import { keeperLimits, resolveKeeperLimits, type KeeperLimitOverrides } from "../security/limits.js";
import {
  changesetLifetimeMs,
  expiredPersistedChangesetV1Schema,
  isCanonicalUuid,
  persistedChangesetSchema,
  type PersistedChange,
  type PersistedChangeset,
  type ServiceOptions
} from "../types/schema.js";

const uuidV4Pattern = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const publicationTemporaryEntryPattern = new RegExp(`^\\.${uuidV4Pattern}\\.tmp$`, "u");
const claimInitializationEntryPattern = new RegExp(`^\\.claim-${uuidV4Pattern}\\.tmp$`, "u");
const releasedClaimEntryPattern = /^(\.publish-.+\.json)\.release-[a-f0-9]{32}$/u;
// Two final halves per global live-pair slot, plus equal bounded headroom for orphans/artifacts.
const maximumInventoryEntries = keeperLimits.changesets.maxPairsGlobal * 4;
// During the second half, the first final plus claim, temporary, and new final may coexist.
const pairPublicationEntryHeadroom = 4;

function parseChangesetEntryName(name: string): { id: string; kind: "changeset" | "signature" } | undefined {
  const signature = name.endsWith(".sig.json");
  if (!signature && !name.endsWith(".json")) return undefined;
  const id = name.slice(0, signature ? -".sig.json".length : -".json".length);
  if (!isCanonicalUuid(id)) return undefined;
  return { id, kind: signature ? "signature" : "changeset" };
}

function publicationClaimTargetName(name: string): string | undefined {
  if (!name.startsWith(".publish-")) return undefined;
  const targetName = name.slice(".publish-".length);
  return parseChangesetEntryName(targetName) ? targetName : undefined;
}

function isReleasedClaimEntry(name: string): boolean {
  const match = releasedClaimEntryPattern.exec(name);
  return Boolean(match && publicationClaimTargetName(match[1]!));
}

interface ChangesetSignature {
  version: 1;
  algorithm: "hmac-sha256";
  changesetId: string;
  mac: string;
}

interface CacheFileMetadata {
  path: string;
  identity: SecurePathIdentity;
  size: number;
  mtimeMs: number;
}

interface PairMetadata {
  changeset?: CacheFileMetadata;
  signature?: CacheFileMetadata;
}

interface StoreInventory {
  livePairs: number;
  projectPairs: Map<string, number>;
  retainedBytes: number;
  retainedEntries: number;
}

interface PreparedState {
  cache: SecureCacheLayout;
  changesetId: string;
  root: string;
  projectDigest: string;
  expiresAt: number;
  changesetBytes: Buffer;
  signatureBytes: Buffer;
  changesetDigest: string;
  signatureDigest: string;
  pairBytes: number;
}

export interface PreparedChangesetPublication {
  changesetId: string;
  changesetPath: string;
  signaturePath: string;
  changesetBytes: Buffer;
  signatureBytes: Buffer;
  projectDigest: string;
  expiresAt: number;
}

export interface LoadedAuthenticatedChangeset {
  changeset: PersistedChangeset;
  cache: SecureCacheLayout;
  changesetPath: string;
  signaturePath: string;
  changesetBytes: Buffer;
  signatureBytes: Buffer;
  changesetIdentity: SecurePathIdentity;
  signatureIdentity: SecurePathIdentity;
}

export interface ChangesetStoreIo {
  publishFile(
    layout: SecureCacheLayout,
    path: string,
    bytes: string | Uint8Array,
    hooks?: SecureCachePublicationHooks
  ): Promise<void>;
  removeExactFile(layout: SecureCacheLayout, identity: SecurePathIdentity): Promise<void>;
  beforePairPublication(prepared: PreparedChangesetPublication): Promise<void>;
  afterInventoryClaimReconciliation(): Promise<void>;
  beforeBoundedReadFinalValidation(path: string): Promise<void>;
}

export interface ChangesetStoreOptions extends Pick<
  ServiceOptions,
  "cacheDirectory" | "environment" | "homeDirectory" | "now"
> {
  limits?: KeeperLimitOverrides;
  io?: Partial<ChangesetStoreIo>;
}

export interface ChangesetStore {
  loadAuthenticated(root: string, changesetId: string): Promise<LoadedAuthenticatedChangeset>;
  preparePublication(changeset: PersistedChangeset): Promise<PreparedChangesetPublication>;
  publishPair(prepared: PreparedChangesetPublication): Promise<void>;
  consumePair(loaded: LoadedAuthenticatedChangeset): Promise<void>;
  collectGarbage(root: string): Promise<void>;
}

const cacheStoreLocks = new Map<string, { tail: Promise<void>; users: number }>();

async function withCacheStoreLock<T>(cacheRoot: string, operation: () => Promise<T>): Promise<T> {
  const key = process.platform === "win32" ? cacheRoot.toLocaleLowerCase("en-US") : cacheRoot;
  let state = cacheStoreLocks.get(key);
  if (!state) {
    state = { tail: Promise.resolve(), users: 0 };
    cacheStoreLocks.set(key, state);
  }
  state.users += 1;
  const predecessor = state.tail;
  let release!: () => void;
  const turn = new Promise<void>((resolveTurn) => { release = resolveTurn; });
  state.tail = predecessor.then(() => turn);
  await predecessor;
  try {
    return await operation();
  } finally {
    release();
    state.users -= 1;
    if (state.users === 0 && cacheStoreLocks.get(key) === state) cacheStoreLocks.delete(key);
  }
}

function changesetPath(cache: SecureCacheLayout, changesetId: string): string {
  if (!isCanonicalUuid(changesetId)) throw new Error("Invalid canonical changeset id");
  return join(cache.changesets, `${changesetId}.json`);
}

function signaturePath(cache: SecureCacheLayout, changesetId: string): string {
  if (!isCanonicalUuid(changesetId)) throw new Error("Invalid canonical changeset id");
  return join(cache.changesets, `${changesetId}.sig.json`);
}

function canonicalJson(value: unknown): string {
  const normalize = (candidate: unknown): unknown => {
    if (Array.isArray(candidate)) return candidate.map(normalize);
    if (typeof candidate === "object" && candidate !== null) {
      return Object.fromEntries(Object.entries(candidate as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right, "en-US"))
        .map(([key, nested]) => [key, normalize(nested)]));
    }
    return candidate;
  };
  return JSON.stringify(normalize(value));
}

export function persistedDiffDigest(
  changes: PersistedChange[],
  semanticDecisionIds: string[]
): `sha256:${string}` {
  return `sha256:${createHash("sha256")
    .update(canonicalJson({ changes, semanticDecisionIds }), "utf8")
    .digest("hex")}`;
}

function projectDigest(root: string): string {
  const canonical = process.platform === "win32" ? root.toLocaleLowerCase("en-US") : root;
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function bytesDigest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function changesetMac(key: Buffer, value: unknown): string {
  return createHmac("sha256", key).update(canonicalJson(value), "utf8").digest("hex");
}

function parseJson(bytes: Buffer, label: string): unknown {
  try {
    return JSON.parse(bytes.toString("utf8")) as unknown;
  } catch (error) {
    throw new Error(`${label} is malformed`, { cause: error });
  }
}

function parseSignature(value: unknown, changesetId: string): ChangesetSignature {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Changeset signature is malformed");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== 4 || keys[0] !== "algorithm" || keys[1] !== "changesetId" || keys[2] !== "mac" || keys[3] !== "version" ||
      record.version !== 1 || record.algorithm !== "hmac-sha256" || record.changesetId !== changesetId ||
      typeof record.mac !== "string" || !/^[a-f0-9]{64}$/u.test(record.mac)) {
    throw new Error("Changeset signature is malformed");
  }
  return record as unknown as ChangesetSignature;
}

function parsePersistedChangeset(value: unknown): PersistedChangeset {
  const result = persistedChangesetSchema.safeParse(value);
  if (!result.success) {
    const detail = result.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
    throw new Error(`Persisted changeset is malformed: ${detail}`);
  }
  return result.data;
}

function assertIdentityEqual(expected: SecurePathIdentity, actual: SecurePathIdentity): void {
  if (expected.dev !== actual.dev || expected.ino !== actual.ino || expected.kind !== actual.kind ||
      expected.parentDev !== actual.parentDev || expected.parentIno !== actual.parentIno ||
      !sameFilesystemPath(expected.path, actual.path) || !sameFilesystemPath(expected.parent, actual.parent)) {
    throw new Error("Cache file identity changed or was replaced");
  }
}

async function cacheFileMetadata(
  cache: SecureCacheLayout,
  path: string,
  label: string,
  maxBytes: number
): Promise<CacheFileMetadata> {
  await validateCacheFile(cache, path, false);
  const identity = await captureSecurePathIdentity(cache, path, "file");
  const metadata = await lstat(path, { bigint: true });
  if (metadata.dev !== identity.dev || metadata.ino !== identity.ino || !metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} identity changed during validation`);
  }
  if (metadata.size > BigInt(maxBytes)) throw new Error(`${label} exceeds the limit of ${maxBytes} bytes`);
  const size = Number(metadata.size);
  const mtimeMs = Number(metadata.mtimeMs);
  if (!Number.isSafeInteger(size) || size < 0 || !Number.isFinite(mtimeMs)) {
    throw new Error(`${label} has invalid filesystem metadata`);
  }
  return { path, identity, size, mtimeMs };
}

async function readMetadataFile(
  cache: SecureCacheLayout,
  metadata: CacheFileMetadata,
  label: string,
  beforeFinalValidation: (path: string) => Promise<void> = async () => undefined
): Promise<Buffer> {
  await validateSecurePathIdentity(cache, metadata.identity);
  const handle = await open(metadata.path, "r");
  try {
    const before = await handle.stat({ bigint: true });
    assertSecureOwnerFileMetadata(before, metadata.path, 1n);
    if (before.dev !== metadata.identity.dev || before.ino !== metadata.identity.ino ||
        !before.isFile() || before.isSymbolicLink() || before.size !== BigInt(metadata.size)) {
      throw new Error(`${label} identity or byte length changed before bounded read`);
    }
    const bytes = Buffer.allocUnsafe(metadata.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const result = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
      if (result.bytesRead === 0) throw new Error(`${label} ended during bounded read`);
      offset += result.bytesRead;
    }
    const overflowProbe = Buffer.allocUnsafe(1);
    if ((await handle.read(overflowProbe, 0, 1, metadata.size)).bytesRead !== 0) {
      throw new Error(`${label} exceeded its validated byte length during bounded read`);
    }
    await beforeFinalValidation(metadata.path);
    const after = await handle.stat({ bigint: true });
    assertSecureOwnerFileMetadata(after, metadata.path, 1n);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size) {
      throw new Error(`${label} identity or byte length changed during bounded read`);
    }
    await validateSecurePathIdentity(cache, metadata.identity);
    await validateCacheFile(cache, metadata.path, false);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function optionalAuthenticationKey(
  cache: SecureCacheLayout,
  beforeFinalValidation?: (path: string) => Promise<void>
): Promise<Buffer | undefined> {
  const path = join(cache.root, "changeset-hmac.key");
  try {
    await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  const metadata = await cacheFileMetadata(cache, path, "Persistent HMAC key", 32);
  if (metadata.size !== 32) throw new Error("Persistent HMAC key is invalid");
  return readMetadataFile(cache, metadata, "Persistent HMAC key", beforeFinalValidation);
}

async function cacheContainsEvidence(cache: SecureCacheLayout): Promise<boolean> {
  const directory = await opendir(cache.changesets);
  try {
    return await directory.read() !== null;
  } finally {
    await directory.close().catch(() => undefined);
  }
}

async function authenticationKey(
  cache: SecureCacheLayout,
  beforeFinalValidation?: (path: string) => Promise<void>
): Promise<Buffer> {
  const existing = await optionalAuthenticationKey(cache, beforeFinalValidation);
  if (existing) return existing;
  if (await cacheContainsEvidence(cache)) {
    throw new Error("Persistent authentication key is missing while changeset cache evidence remains");
  }
  const path = join(cache.root, "changeset-hmac.key");
  try {
    await publishExclusiveFile(cache, path, randomBytes(32));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  const created = await optionalAuthenticationKey(cache, beforeFinalValidation);
  if (!created) throw new Error("Persistent HMAC key could not be created");
  return created;
}

interface AuthenticatePairOptions {
  expectedRoot?: string;
  allowExpired: boolean;
  now: number;
}

interface AuthenticatedPairContents {
  raw: unknown;
  changesetBytes: Buffer;
  signatureBytes: Buffer;
}

async function readAuthenticatedPair(
  cache: SecureCacheLayout,
  changesetId: string,
  changesetMetadata: CacheFileMetadata,
  signatureMetadata: CacheFileMetadata,
  beforeFinalValidation?: (path: string) => Promise<void>
): Promise<AuthenticatedPairContents> {
  const [changesetBytes, signatureBytes, key] = await Promise.all([
    readMetadataFile(cache, changesetMetadata, "Persisted changeset", beforeFinalValidation),
    readMetadataFile(cache, signatureMetadata, "Changeset signature", beforeFinalValidation),
    optionalAuthenticationKey(cache, beforeFinalValidation)
  ]);
  if (!key) throw new Error("Persistent HMAC key is missing");
  const raw = parseJson(changesetBytes, "Persisted changeset");
  const signature = parseSignature(parseJson(signatureBytes, "Changeset signature"), changesetId);
  const actual = Buffer.from(changesetMac(key, raw), "hex");
  const expected = Buffer.from(signature.mac, "hex");
  if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) {
    throw new Error("Changeset signature authentication failed; cached data may have been tampered with");
  }
  return { raw, changesetBytes, signatureBytes };
}

function parseAuthenticatedVersionTwo(
  cache: SecureCacheLayout,
  changesetId: string,
  changesetMetadata: CacheFileMetadata,
  signatureMetadata: CacheFileMetadata,
  authenticated: AuthenticatedPairContents,
  options: AuthenticatePairOptions
): LoadedAuthenticatedChangeset {
  const { raw, changesetBytes, signatureBytes } = authenticated;
  if (raw && typeof raw === "object" && !Array.isArray(raw) && (raw as Record<string, unknown>).version === 1) {
    throw new Error(`Changeset ${changesetId} uses an expired format; preview the update again`);
  }
  const changeset = parsePersistedChangeset(raw);
  if (changeset.changesetId !== changesetId) throw new Error("Persisted changeset ID does not match its filename");
  if (!options.allowExpired && options.now >= changeset.expiresAt) throw new Error(`Changeset ${changesetId} has expired`);
  if (options.expectedRoot !== undefined && changeset.root !== options.expectedRoot) {
    throw new Error("Changeset root does not match the requested project root");
  }
  if (persistedDiffDigest(changeset.changes, changeset.semanticDecisionIds) !== changeset.diffDigest) {
    throw new Error("Persisted changeset diff digest does not match its authenticated changes");
  }
  return {
    changeset,
    cache,
    changesetPath: changesetMetadata.path,
    signaturePath: signatureMetadata.path,
    changesetBytes,
    signatureBytes,
    changesetIdentity: changesetMetadata.identity,
    signatureIdentity: signatureMetadata.identity
  };
}

async function authenticatePair(
  cache: SecureCacheLayout,
  changesetId: string,
  changesetMetadata: CacheFileMetadata,
  signatureMetadata: CacheFileMetadata,
  options: AuthenticatePairOptions,
  beforeFinalValidation?: (path: string) => Promise<void>
): Promise<LoadedAuthenticatedChangeset> {
  return parseAuthenticatedVersionTwo(
    cache,
    changesetId,
    changesetMetadata,
    signatureMetadata,
    await readAuthenticatedPair(cache, changesetId, changesetMetadata, signatureMetadata, beforeFinalValidation),
    options
  );
}

async function validatePairIdentities(cache: SecureCacheLayout, loaded: LoadedAuthenticatedChangeset): Promise<void> {
  await validateSecurePathIdentity(cache, loaded.changesetIdentity);
  await validateSecurePathIdentity(cache, loaded.signatureIdentity);
}

async function pathPresent(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function removeExactPair(
  cache: SecureCacheLayout,
  changesetIdentity: SecurePathIdentity,
  signatureIdentity: SecurePathIdentity,
  removeExactFile: ChangesetStoreIo["removeExactFile"]
): Promise<void> {
  await validateSecurePathIdentity(cache, changesetIdentity);
  await validateSecurePathIdentity(cache, signatureIdentity);
  await removeExactFile(cache, changesetIdentity);
  try {
    await removeExactFile(cache, signatureIdentity);
  } catch (error) {
    throw new Error("Changeset primary half was removed but exact signature cleanup failed", { cause: error });
  }
}

function quotaError(label: string, limit: number): Error {
  return new Error(`${label} quota of ${limit} live pairs would be exceeded; live changesets are never evicted`);
}

export function createChangesetStore(options: ChangesetStoreOptions = {}): ChangesetStore {
  const now = options.now ?? (() => Date.now());
  const limits = resolveKeeperLimits(options.limits);
  const io: ChangesetStoreIo = {
    publishFile: options.io?.publishFile ?? publishExclusiveFile,
    removeExactFile: options.io?.removeExactFile ?? safeRemoveExactCacheFile,
    beforePairPublication: options.io?.beforePairPublication ?? (async () => undefined),
    afterInventoryClaimReconciliation: options.io?.afterInventoryClaimReconciliation ?? (async () => undefined),
    beforeBoundedReadFinalValidation: options.io?.beforeBoundedReadFinalValidation ?? (async () => undefined)
  };
  const preparedStates = new WeakMap<PreparedChangesetPublication, PreparedState>();

  const secureCache = (root: string) => prepareSecureCache({
    cacheDirectory: options.cacheDirectory,
    environment: options.environment,
    homeDirectory: options.homeDirectory
  }, root);

  async function readBoundedDirectoryEntries(cache: SecureCacheLayout): Promise<Array<{ name: string; isFile: boolean }>> {
    const directoryEntries: Array<{ name: string; isFile: boolean }> = [];
    const directory = await opendir(cache.changesets);
    try {
      for await (const entry of directory) {
        if (directoryEntries.length >= maximumInventoryEntries) {
          throw new Error(`Changeset cache contains more than ${maximumInventoryEntries} bounded entries`);
        }
        directoryEntries.push({ name: entry.name, isFile: entry.isFile() });
      }
    } finally {
      await directory.close().catch(() => undefined);
    }
    return directoryEntries;
  }

  async function inventoryAndCollect(cache: SecureCacheLayout): Promise<StoreInventory> {
    // Exact-unlink intents are the Windows recovery log for directory metadata that
    // Node cannot fsync. Reconcile them under the same process-global store lock
    // before trusting or charging the final-file inventory.
    const removalRecoveryUsage = await reconcileExactRemovalIntents(cache);
    const pairs = new Map<string, PairMetadata>();
    let directoryEntries: Array<{ name: string; isFile: boolean }>;
    let previousClaimCount: number | undefined;
    let reconciliationBudget = maximumInventoryEntries;
    for (;;) {
      directoryEntries = await readBoundedDirectoryEntries(cache);
      const claims = directoryEntries
        .map((entry) => ({ entry, targetName: publicationClaimTargetName(entry.name) }))
        .filter((candidate): candidate is { entry: { name: string; isFile: boolean }; targetName: string } =>
          candidate.targetName !== undefined)
        .sort((left, right) => left.entry.name.localeCompare(right.entry.name, "en-US"));
      if (claims.length === 0) break;
      if (previousClaimCount !== undefined && claims.length >= previousClaimCount) {
        throw new Error("Changeset publication residue did not stabilize during bounded reconciliation churn");
      }
      if (claims.length > reconciliationBudget) {
        throw new Error("Changeset publication residue exceeded its bounded reconciliation budget");
      }
      previousClaimCount = claims.length;
      for (const { entry, targetName } of claims) {
        if (!entry.isFile) throw new Error(`Changeset publication claim is not an ordinary file: ${entry.name}`);
        const result = await reconcileCacheFilePublication(cache, join(cache.changesets, targetName));
        if (result.state === "active") {
          throw new Error("Changeset cache publication is still owned by an active process");
        }
        reconciliationBudget -= 1;
        await io.afterInventoryClaimReconciliation();
      }
    }

    let artifactBytes = removalRecoveryUsage.retainedBytes;
    let artifactEntries = 0;
    for (const entry of directoryEntries) {
      const path = join(cache.changesets, entry.name);
      const isPublicationTemporary = publicationTemporaryEntryPattern.test(entry.name);
      const isClaimInitialization = claimInitializationEntryPattern.test(entry.name);
      const isReleasedClaim = isReleasedClaimEntry(entry.name);
      if (isPublicationTemporary || isClaimInitialization || isReleasedClaim) {
        if (!entry.isFile) throw new Error(`Changeset publication artifact is not an ordinary file: ${entry.name}`);
        const metadata = await cacheFileMetadata(
          cache,
          path,
          "Changeset publication artifact",
          isPublicationTemporary ? limits.changesets.maxChangesetBytes : limits.changesets.maxSignatureBytes
        );
        artifactBytes += metadata.size;
        artifactEntries += 1;
        continue;
      }

      const parsedEntry = parseChangesetEntryName(entry.name);
      if (!parsedEntry || !entry.isFile) {
        throw new Error(`Changeset cache entry is malformed or not an ordinary final file: ${entry.name}`);
      }
      const { id, kind } = parsedEntry;
      const metadata = await cacheFileMetadata(
        cache,
        path,
        kind === "signature" ? "Changeset signature" : "Persisted changeset",
        kind === "signature" ? limits.changesets.maxSignatureBytes : limits.changesets.maxChangesetBytes
      );
      const pair = pairs.get(id) ?? {};
      if (pair[kind]) throw new Error(`Changeset cache contains a duplicate ${kind} half`);
      pair[kind] = metadata;
      pairs.set(id, pair);
    }

    const inventory: StoreInventory = {
      livePairs: 0,
      projectPairs: new Map(),
      retainedBytes: artifactBytes,
      retainedEntries: artifactEntries
    };
    for (const [id, pair] of [...pairs.entries()].sort(([left], [right]) => left.localeCompare(right, "en-US"))) {
      if (pair.changeset && pair.signature) {
        const authenticated = await readAuthenticatedPair(
          cache,
          id,
          pair.changeset,
          pair.signature,
          io.beforeBoundedReadFinalValidation
        );
        if (authenticated.raw && typeof authenticated.raw === "object" && !Array.isArray(authenticated.raw) &&
            (authenticated.raw as Record<string, unknown>).version === 1) {
          const legacy = expiredPersistedChangesetV1Schema.safeParse(authenticated.raw);
          if (!legacy.success) {
            const detail = legacy.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
            throw new Error(`Persisted version-one changeset is malformed: ${detail}`);
          }
          if (legacy.data.changesetId !== id) {
            throw new Error("Persisted version-one changeset ID does not match its filename");
          }
          if (now() >= legacy.data.expiresAt) {
            await removeExactPair(cache, pair.changeset.identity, pair.signature.identity, io.removeExactFile);
          } else {
            inventory.retainedBytes += pair.changeset.size + pair.signature.size;
            inventory.retainedEntries += 2;
          }
          continue;
        }
        const loaded = parseAuthenticatedVersionTwo(cache, id, pair.changeset, pair.signature, authenticated, {
          allowExpired: true,
          now: now()
        });
        if (now() >= loaded.changeset.expiresAt) {
          await removeExactPair(cache, loaded.changesetIdentity, loaded.signatureIdentity, io.removeExactFile);
          continue;
        }
        const digest = projectDigest(loaded.changeset.root);
        inventory.livePairs += 1;
        inventory.projectPairs.set(digest, (inventory.projectPairs.get(digest) ?? 0) + 1);
        inventory.retainedBytes += pair.changeset.size + pair.signature.size;
        inventory.retainedEntries += 2;
        continue;
      }
      const orphan = pair.changeset ?? pair.signature!;
      if (now() - orphan.mtimeMs >= changesetLifetimeMs) {
        await io.removeExactFile(cache, orphan.identity);
        continue;
      }
      inventory.retainedBytes += orphan.size;
      inventory.retainedEntries += 1;
    }
    return inventory;
  }

  function preparedState(prepared: PreparedChangesetPublication): PreparedState {
    const state = preparedStates.get(prepared);
    if (!state) throw new Error("Changeset publication was not prepared by this store");
    if (bytesDigest(prepared.changesetBytes) !== state.changesetDigest ||
        bytesDigest(prepared.signatureBytes) !== state.signatureDigest ||
        prepared.changesetBytes.byteLength + prepared.signatureBytes.byteLength !== state.pairBytes ||
        prepared.changesetId !== state.changesetId || prepared.projectDigest !== state.projectDigest ||
        prepared.expiresAt !== state.expiresAt ||
        !sameFilesystemPath(prepared.changesetPath, changesetPath(state.cache, state.changesetId)) ||
        !sameFilesystemPath(prepared.signaturePath, signaturePath(state.cache, state.changesetId))) {
      throw new Error("Prepared changeset publication bytes or bindings changed before publication");
    }
    return state;
  }

  function assertQuota(inventory: StoreInventory, state: PreparedState): void {
    if (inventory.retainedEntries + pairPublicationEntryHeadroom > maximumInventoryEntries) {
      throw new Error(
        `Changeset cache entry inventory cannot reserve publication headroom within ${maximumInventoryEntries} entries`
      );
    }
    const projectPairs = inventory.projectPairs.get(state.projectDigest) ?? 0;
    if (projectPairs + 1 > limits.changesets.maxPairsPerProject) {
      throw quotaError("Per-project changeset", limits.changesets.maxPairsPerProject);
    }
    if (inventory.livePairs + 1 > limits.changesets.maxPairsGlobal) {
      throw quotaError("Global changeset", limits.changesets.maxPairsGlobal);
    }
    if (inventory.retainedBytes + state.pairBytes > limits.changesets.maxTotalBytes) {
      throw new Error(`Changeset cache bytes exceed the aggregate limit of ${limits.changesets.maxTotalBytes} bytes`);
    }
  }

  async function publishHalf(
    cache: SecureCacheLayout,
    path: string,
    bytes: Buffer,
    recordIdentity: (identity: SecurePathIdentity) => void
  ): Promise<SecurePathIdentity> {
    let publishedIdentity: SecurePathIdentity | undefined;
    await io.publishFile(cache, path, bytes, {
      afterPublishedIdentity: async (identity) => {
        publishedIdentity = identity;
        recordIdentity(identity);
      }
    });
    if (!publishedIdentity) throw new Error("Cache publication completed without an exact published identity");
    return publishedIdentity;
  }

  async function cleanupPublicationFailure(
    cache: SecureCacheLayout,
    primary: unknown,
    identities: Array<SecurePathIdentity | undefined>
  ): Promise<never> {
    const cleanupErrors: unknown[] = [];
    for (const identity of identities) {
      if (!identity) continue;
      try {
        await io.removeExactFile(cache, identity);
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [primary, ...cleanupErrors],
        "Changeset pair publication failed and exact cleanup was ambiguous",
        { cause: primary }
      );
    }
    throw primary;
  }

  async function preparePublication(changeset: PersistedChangeset): Promise<PreparedChangesetPublication> {
    const parsed = parsePersistedChangeset(changeset);
    if (persistedDiffDigest(parsed.changes, parsed.semanticDecisionIds) !== parsed.diffDigest) {
      throw new Error("Persisted changeset diff digest does not match its authenticated changes");
    }
    if (now() >= parsed.expiresAt) throw new Error(`Changeset ${parsed.changesetId} has expired`);
    const changesetBytes = Buffer.from(`${JSON.stringify(parsed, null, 2)}\n`, "utf8");
    if (changesetBytes.byteLength > limits.changesets.maxChangesetBytes) {
      throw new Error(`Persisted changeset exceeds the limit of ${limits.changesets.maxChangesetBytes} bytes`);
    }
    const cache = await secureCache(parsed.root);
    const key = await authenticationKey(cache, io.beforeBoundedReadFinalValidation);
    const signature: ChangesetSignature = {
      version: 1,
      algorithm: "hmac-sha256",
      changesetId: parsed.changesetId,
      mac: changesetMac(key, parsed)
    };
    const signatureBytes = Buffer.from(`${JSON.stringify(signature, null, 2)}\n`, "utf8");
    if (signatureBytes.byteLength > limits.changesets.maxSignatureBytes) {
      throw new Error(`Changeset signature exceeds the limit of ${limits.changesets.maxSignatureBytes} bytes`);
    }
    const digest = projectDigest(parsed.root);
    const prepared: PreparedChangesetPublication = Object.freeze({
      changesetId: parsed.changesetId,
      changesetPath: changesetPath(cache, parsed.changesetId),
      signaturePath: signaturePath(cache, parsed.changesetId),
      changesetBytes,
      signatureBytes,
      projectDigest: digest,
      expiresAt: parsed.expiresAt
    });
    preparedStates.set(prepared, {
      cache,
      changesetId: parsed.changesetId,
      root: parsed.root,
      projectDigest: digest,
      expiresAt: parsed.expiresAt,
      changesetBytes: Buffer.from(changesetBytes),
      signatureBytes: Buffer.from(signatureBytes),
      changesetDigest: bytesDigest(changesetBytes),
      signatureDigest: bytesDigest(signatureBytes),
      pairBytes: changesetBytes.byteLength + signatureBytes.byteLength
    });
    return prepared;
  }

  async function publishPair(prepared: PreparedChangesetPublication): Promise<void> {
    const initialState = preparedState(prepared);
    await withCacheStoreLock(initialState.cache.root, async () => {
      let state = preparedState(prepared);
      if (now() >= state.expiresAt) throw new Error(`Changeset ${state.changesetId} has expired before publication`);
      assertQuota(await inventoryAndCollect(state.cache), state);
      await io.beforePairPublication(prepared);
      state = preparedState(prepared);
      if (now() >= state.expiresAt) throw new Error(`Changeset ${state.changesetId} has expired before publication`);
      assertQuota(await inventoryAndCollect(state.cache), state);

      let changesetIdentity: SecurePathIdentity | undefined;
      let signatureIdentity: SecurePathIdentity | undefined;
      try {
        changesetIdentity = await publishHalf(
          state.cache,
          prepared.changesetPath,
          state.changesetBytes,
          (identity) => { changesetIdentity = identity; }
        );
        state = preparedState(prepared);
      } catch (error) {
        await cleanupPublicationFailure(state.cache, error, [changesetIdentity]);
      }
      try {
        signatureIdentity = await publishHalf(
          state.cache,
          prepared.signaturePath,
          state.signatureBytes,
          (identity) => { signatureIdentity = identity; }
        );
        state = preparedState(prepared);
      } catch (error) {
        await cleanupPublicationFailure(state.cache, error, [signatureIdentity, changesetIdentity]);
      }

      try {
        const changesetMetadata = await cacheFileMetadata(
          state.cache,
          prepared.changesetPath,
          "Persisted changeset",
          limits.changesets.maxChangesetBytes
        );
        const signatureMetadata = await cacheFileMetadata(
          state.cache,
          prepared.signaturePath,
          "Changeset signature",
          limits.changesets.maxSignatureBytes
        );
        assertIdentityEqual(changesetIdentity!, changesetMetadata.identity);
        assertIdentityEqual(signatureIdentity!, signatureMetadata.identity);
        const loaded = await authenticatePair(state.cache, state.changesetId, changesetMetadata, signatureMetadata, {
          expectedRoot: state.root,
          allowExpired: false,
          now: now()
        }, io.beforeBoundedReadFinalValidation);
        if (!loaded.changesetBytes.equals(state.changesetBytes) || !loaded.signatureBytes.equals(state.signatureBytes)) {
          throw new Error("Published changeset pair bytes do not match the prepared pair");
        }
      } catch (error) {
        await cleanupPublicationFailure(state.cache, error, [signatureIdentity, changesetIdentity]);
      }
    });
  }

  async function loadAuthenticated(root: string, changesetId: string): Promise<LoadedAuthenticatedChangeset> {
    const cache = await secureCache(root);
    return withCacheStoreLock(cache.root, async () => {
      await reconcileExactRemovalIntents(cache);
      const primaryPath = changesetPath(cache, changesetId);
      const macPath = signaturePath(cache, changesetId);
      let changesetMetadata: CacheFileMetadata;
      try {
        changesetMetadata = await cacheFileMetadata(cache, primaryPath, "Persisted changeset", limits.changesets.maxChangesetBytes);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") {
          throw new Error(`Changeset ${changesetId} is missing or not found`);
        }
        throw error;
      }
      let signatureMetadata: CacheFileMetadata;
      try {
        signatureMetadata = await cacheFileMetadata(cache, macPath, "Changeset signature", limits.changesets.maxSignatureBytes);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new Error("Changeset signature is missing");
        throw error;
      }
      return authenticatePair(cache, changesetId, changesetMetadata, signatureMetadata, {
        expectedRoot: root,
        allowExpired: false,
        now: now()
      }, io.beforeBoundedReadFinalValidation);
    });
  }

  async function consumePair(loaded: LoadedAuthenticatedChangeset): Promise<void> {
    await withCacheStoreLock(loaded.cache.root, async () => {
      const [changesetPresent, signaturePresent] = await Promise.all([
        pathPresent(loaded.changesetPath),
        pathPresent(loaded.signaturePath)
      ]);
      if (!changesetPresent && !signaturePresent) return;
      if (!changesetPresent || !signaturePresent) {
        throw new Error("Authenticated changeset pair became incomplete before exact consumption");
      }
      await validatePairIdentities(loaded.cache, loaded);
      const currentChangeset = await cacheFileMetadata(
        loaded.cache,
        loaded.changesetPath,
        "Persisted changeset",
        limits.changesets.maxChangesetBytes
      );
      const currentSignature = await cacheFileMetadata(
        loaded.cache,
        loaded.signaturePath,
        "Changeset signature",
        limits.changesets.maxSignatureBytes
      );
      assertIdentityEqual(loaded.changesetIdentity, currentChangeset.identity);
      assertIdentityEqual(loaded.signatureIdentity, currentSignature.identity);
      const reloaded = await authenticatePair(
        loaded.cache,
        loaded.changeset.changesetId,
        currentChangeset,
        currentSignature,
        {
          expectedRoot: loaded.changeset.root,
          allowExpired: true,
          now: now()
        },
        io.beforeBoundedReadFinalValidation
      );
      if (!reloaded.changesetBytes.equals(loaded.changesetBytes) || !reloaded.signatureBytes.equals(loaded.signatureBytes)) {
        throw new Error("Changeset pair bytes changed before exact consumption");
      }
      await removeExactPair(loaded.cache, loaded.changesetIdentity, loaded.signatureIdentity, io.removeExactFile);
    });
  }

  async function collectGarbage(root: string): Promise<void> {
    const cache = await secureCache(root);
    await withCacheStoreLock(cache.root, async () => {
      await inventoryAndCollect(cache);
    });
  }

  return { loadAuthenticated, preparePublication, publishPair, consumePair, collectGarbage };
}
