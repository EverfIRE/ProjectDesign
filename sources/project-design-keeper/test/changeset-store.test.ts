import { createHash, createHmac, randomUUID } from "node:crypto";
import { chmod, chown, link, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import {
  createChangesetStore,
  persistedDiffDigest,
  type PreparedChangesetPublication
} from "../src/changesets/store.js";
import {
  captureSecurePathIdentity,
  prepareSecureCache,
  publishExclusiveFile,
  safeRemoveExactCacheFile
} from "../src/security/cache.js";
import { createPublicationClaimOwner, PUBLICATION_CLAIM_LEASE_MS } from "../src/security/publication-claim.js";
import { changesetLifetimeMs, type PersistedChange, type PersistedChangeset } from "../src/types/schema.js";
import {
  createProjectFixture,
  removeProjectFixture,
  type ProjectFixture
} from "./fixtures.js";

let fixture: ProjectFixture | undefined;
let cacheDirectory: string | undefined;
let clock = 0;

beforeEach(async () => {
  fixture = await createProjectFixture();
  cacheDirectory = await mkdtemp(join(tmpdir(), "project-design-changeset-store-"));
  clock = Date.now();
});

afterEach(async () => {
  await removeProjectFixture(fixture);
  if (cacheDirectory) await rm(cacheDirectory, { recursive: true, force: true });
  fixture = undefined;
  cacheDirectory = undefined;
});

function project(): ProjectFixture {
  if (!fixture) throw new Error("fixture was not created");
  return fixture;
}

function cache(): string {
  if (!cacheDirectory) throw new Error("cache was not created");
  return cacheDirectory;
}

function hash(content: string): string {
  return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
}

function canonicalJson(value: unknown): string {
  const normalize = (candidate: unknown): unknown => {
    if (Array.isArray(candidate)) return candidate.map(normalize);
    if (candidate && typeof candidate === "object") {
      return Object.fromEntries(Object.entries(candidate as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right, "en-US"))
        .map(([key, nested]) => [key, normalize(nested)]));
    }
    return candidate;
  };
  return JSON.stringify(normalize(value));
}

function block(recordId: string, content: string): string {
  return `<!-- project-design-keeper:managed record-id="${recordId}" content-hash="${hash(content)}" -->${content}<!-- /project-design-keeper:managed -->`;
}

function candidate(root = project().repository, overrides: Partial<PersistedChangeset> = {}): PersistedChangeset {
  const changes: PersistedChange[] = overrides.changes ?? [{
    path: `.agents/skills/project-design-context/${randomUUID()}.md`,
    content: block("store-record", "bounded store content"),
    previousHash: null
  }];
  const semanticDecisionIds = overrides.semanticDecisionIds ?? [];
  const createdAt = overrides.createdAt ?? clock;
  return {
    version: 2,
    changesetId: overrides.changesetId ?? randomUUID(),
    root,
    createdAt,
    expiresAt: overrides.expiresAt ?? createdAt + changesetLifetimeMs,
    diffDigest: overrides.diffDigest ?? persistedDiffDigest(changes, semanticDecisionIds),
    archiveActions: overrides.archiveActions ?? { archivedRecordIds: [], tombstonedRecordIds: [] },
    semanticDecisionIds,
    historyFiles: overrides.historyFiles ?? {},
    changes,
    manifestHash: overrides.manifestHash ?? null,
    sourceScope: overrides.sourceScope ?? { root },
    ...(overrides.sourcePaths ? { sourcePaths: overrides.sourcePaths } : {}),
    sourceFiles: overrides.sourceFiles ?? {}
  };
}

function store(options: Record<string, unknown> = {}) {
  return createChangesetStore({ cacheDirectory: cache(), now: () => clock, ...options });
}

async function cacheEntries(): Promise<string[]> {
  try {
    return (await readdir(join(cache(), "changesets"))).sort();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}

async function expectMissing(path: string): Promise<void> {
  await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
}

async function writeYoungOrphans(count: number): Promise<void> {
  const directory = join(cache(), "changesets");
  for (let offset = 0; offset < count; offset += 64) {
    await Promise.all(Array.from({ length: Math.min(64, count - offset) }, async () => {
      await writeFile(join(directory, `${randomUUID()}.json`), "{}", { mode: 0o600 });
    }));
  }
}

async function writeDeadPublicationClaim(targetName: string): Promise<string> {
  const initializationName = `.claim-${randomUUID()}.tmp`;
  const publicationName = `.${randomUUID()}.tmp`;
  const owner = createPublicationClaimOwner(
    targetName,
    initializationName,
    publicationName,
    clock - PUBLICATION_CLAIM_LEASE_MS - 1_000
  );
  owner.pid = 2_147_483_647;
  const claimPath = join(cache(), "changesets", `.publish-${targetName}`);
  await writeFile(claimPath, `${JSON.stringify(owner)}\n`, { mode: 0o600 });
  return claimPath;
}

async function rewriteAsAuthenticatedVersionOne(prepared: PreparedChangesetPublication): Promise<void> {
  const value = JSON.parse(await readFile(prepared.changesetPath, "utf8")) as Record<string, unknown>;
  value.version = 1;
  delete value.diffDigest;
  delete value.archiveActions;
  delete value.semanticDecisionIds;
  delete value.historyFiles;
  const key = await readFile(join(cache(), "changeset-hmac.key"));
  const mac = createHmac("sha256", key).update(canonicalJson(value), "utf8").digest("hex");
  await writeFile(prepared.changesetPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await writeFile(prepared.signaturePath, `${JSON.stringify({
    version: 1,
    algorithm: "hmac-sha256",
    changesetId: prepared.changesetId,
    mac
  }, null, 2)}\n`, { mode: 0o600 });
}

describe("bounded changeset preparation and quotas", () => {
  test("prepares bounded changeset and signature buffers without publishing them", async () => {
    const changesetStore = store();

    const prepared = await changesetStore.preparePublication(candidate());

    expect(Buffer.isBuffer(prepared.changesetBytes)).toBe(true);
    expect(Buffer.isBuffer(prepared.signatureBytes)).toBe(true);
    expect(prepared.changesetBytes.byteLength).toBeGreaterThan(0);
    expect(prepared.signatureBytes.byteLength).toBeGreaterThan(0);
    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("rejects changeset and signature buffers at their configured in-memory byte bounds", async () => {
    await expect(store({ limits: { changesets: { maxChangesetBytes: 64 } } })
      .preparePublication(candidate())).rejects.toThrow(/changeset.*64.*bytes/i);
    await expect(store({ limits: { changesets: { maxSignatureBytes: 64 } } })
      .preparePublication(candidate())).rejects.toThrow(/signature.*64.*bytes/i);
    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("rejects a noncanonical UUID before preparing an inventory-invisible filename", async () => {
    const noncanonical = randomUUID().toUpperCase();

    await expect(store().preparePublication(candidate(project().repository, { changesetId: noncanonical })))
      .rejects.toThrow(/changesetId|canonical.*uuid|invalid/i);

    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("rejects an oversized cached half from metadata before bounded authentication", async () => {
    const publishingStore = store();
    const prepared = await publishingStore.preparePublication(candidate());
    await publishingStore.publishPair(prepared);
    const changesetBefore = await readFile(prepared.changesetPath);
    const signatureBefore = await readFile(prepared.signaturePath);
    const constrained = store({
      limits: { changesets: { maxChangesetBytes: prepared.changesetBytes.byteLength - 1 } }
    });

    await expect(constrained.collectGarbage(project().repository)).rejects.toThrow(/changeset.*exceeds.*bytes/i);

    await expect(readFile(prepared.changesetPath)).resolves.toEqual(changesetBefore);
    await expect(readFile(prepared.signaturePath)).resolves.toEqual(signatureBefore);
  });

  test("does not recreate a missing authentication key while final cache evidence remains", async () => {
    const originalStore = store();
    const published = await originalStore.preparePublication(candidate());
    await originalStore.publishPair(published);
    await rm(published.signaturePath);
    await rm(join(cache(), "changeset-hmac.key"));
    const orphanBefore = await readFile(published.changesetPath);

    await expect(store().preparePublication(candidate())).rejects.toThrow(/authentication key.*missing.*evidence|evidence.*key/i);

    await expect(readFile(published.changesetPath)).resolves.toEqual(orphanBefore);
    await expectMissing(join(cache(), "changeset-hmac.key"));
  });

  test("charges both exact pair halves to the aggregate byte quota", async () => {
    const unconstrained = store();
    const measured = await unconstrained.preparePublication(candidate());
    const exactBytes = measured.changesetBytes.byteLength + measured.signatureBytes.byteLength;
    const constrained = store({ limits: { changesets: { maxTotalBytes: exactBytes - 1 } } });
    const prepared = await constrained.preparePublication(candidate());

    await expect(constrained.publishPair(prepared)).rejects.toThrow(/changeset cache bytes|aggregate.*bytes/i);
    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("enforces the per-project pair quota without evicting a live pair", async () => {
    const changesetStore = store({ limits: { changesets: { maxPairsPerProject: 1 } } });
    const first = await changesetStore.preparePublication(candidate());
    const second = await changesetStore.preparePublication(candidate());
    await changesetStore.publishPair(first);
    const before = await Promise.all((await cacheEntries()).map(async (name) => [name, await readFile(join(cache(), "changesets", name), "utf8")]));

    await expect(changesetStore.publishPair(second)).rejects.toThrow(/project.*changeset.*quota|64|pair/i);

    expect(await Promise.all((await cacheEntries()).map(async (name) => [name, await readFile(join(cache(), "changesets", name), "utf8")])))
      .toEqual(before);
  });

  test("enforces the global pair quota across canonical projects", async () => {
    const changesetStore = store({ limits: { changesets: { maxPairsGlobal: 1 } } });
    const first = await changesetStore.preparePublication(candidate(project().repository));
    const second = await changesetStore.preparePublication(candidate(project().nonGitDirectory));
    await changesetStore.publishPair(first);

    await expect(changesetStore.publishPair(second)).rejects.toThrow(/global.*changeset.*quota|pair/i);
    expect(await cacheEntries()).toHaveLength(2);
  });

  test("serializes concurrent publishers through quota recheck", async () => {
    let enter!: () => void;
    let release!: () => void;
    const entered = new Promise<void>((resolve) => { enter = resolve; });
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let pause = true;
    const firstStore = store({
      limits: { changesets: { maxPairsPerProject: 1 } },
      io: {
        beforePairPublication: async () => {
          if (!pause) return;
          pause = false;
          enter();
          await gate;
        }
      }
    });
    const secondStore = store({ limits: { changesets: { maxPairsPerProject: 1 } } });
    const first = await firstStore.preparePublication(candidate());
    const second = await secondStore.preparePublication(candidate());

    const firstPublication = firstStore.publishPair(first);
    await entered;
    const secondPublication = secondStore.publishPair(second);
    release();
    const outcomes = await Promise.allSettled([firstPublication, secondPublication]);

    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    const rejection = outcomes.find((outcome): outcome is PromiseRejectedResult => outcome.status === "rejected");
    expect(String(rejection?.reason)).toMatch(/project.*changeset.*quota|pair/i);
    expect(await cacheEntries()).toHaveLength(2);
  });

  test("reserves publication artifact headroom at the bounded inventory ceiling", async () => {
    const changesetStore = store();
    const allowed = await changesetStore.preparePublication(candidate());
    await writeYoungOrphans(1_020);

    await expect(changesetStore.publishPair(allowed)).resolves.toBeUndefined();
    expect(await cacheEntries()).toHaveLength(1_022);
  }, 30_000);

  test("rejects publication before a near-full inventory can exceed its hard entry bound", async () => {
    const changesetStore = store();
    const prepared = await changesetStore.preparePublication(candidate());
    await writeYoungOrphans(1_021);
    const before = await cacheEntries();

    await expect(changesetStore.publishPair(prepared)).rejects.toThrow(/entry|inventory|1024/i);

    expect(await cacheEntries()).toEqual(before);
  }, 30_000);

  test("serializes concurrent publishers against reserved inventory entry headroom", async () => {
    const firstStore = store();
    const secondStore = store();
    const first = await firstStore.preparePublication(candidate());
    const second = await secondStore.preparePublication(candidate());
    await writeYoungOrphans(1_019);

    const outcomes = await Promise.allSettled([
      firstStore.publishPair(first),
      secondStore.publishPair(second)
    ]);

    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    const rejection = outcomes.find((outcome): outcome is PromiseRejectedResult => outcome.status === "rejected");
    expect(String(rejection?.reason)).toMatch(/entry|inventory|1024/i);
    expect(await cacheEntries()).toHaveLength(1_021);
  }, 30_000);
});

describe("authenticated garbage collection", () => {
  test("reconciles a durable post-unlink removal intent before inventory", async () => {
    const layout = await prepareSecureCache({ cacheDirectory: cache() }, project().repository);
    const target = join(layout.locks, "post-unlink-recovery-target");
    await writeFile(target, "evidence", { mode: 0o600 });
    const identity = await captureSecurePathIdentity(layout, target, "file");
    await expect(safeRemoveExactCacheFile(layout, identity, {
      afterExactRemovalUnlink: async () => { throw new Error("simulated power loss"); }
    })).rejects.toThrow(/power loss/i);
    expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toHaveLength(1);
    expect((await readdir(layout.locks)).filter((name) => name.startsWith(".removed-"))).toHaveLength(1);

    await store().collectGarbage(project().repository);

    expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toEqual([]);
    expect((await readdir(layout.locks)).filter((name) => name.startsWith(".removed-"))).toEqual([]);
  });

  test("fails closed and preserves a replacement plus its durable removal intent", async () => {
    const layout = await prepareSecureCache({ cacheDirectory: cache() }, project().repository);
    const target = join(layout.locks, "post-unlink-replacement-target");
    await writeFile(target, "original", { mode: 0o600 });
    const identity = await captureSecurePathIdentity(layout, target, "file");
    await expect(safeRemoveExactCacheFile(layout, identity, {
      afterExactRemovalUnlink: async () => { throw new Error("simulated power loss"); }
    })).rejects.toThrow(/power loss/i);
    await writeFile(target, "replacement", { mode: 0o600 });

    await expect(store().collectGarbage(project().repository)).rejects.toThrow(/replaced|evidence|ambiguous/i);

    await expect(readFile(target, "utf8")).resolves.toBe("replacement");
    expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toHaveLength(1);
  });

  test("reclaims a synced quarantine whose removal intent directory entry was lost", async () => {
    const layout = await prepareSecureCache({ cacheDirectory: cache() }, project().repository);
    const target = join(layout.locks, "lost-intent-recovery-target");
    await writeFile(target, "original", { mode: 0o600 });
    const identity = await captureSecurePathIdentity(layout, target, "file");
    await expect(safeRemoveExactCacheFile(layout, identity, {
      afterExactRemovalUnlink: async () => { throw new Error("simulated power loss"); }
    })).rejects.toThrow(/power loss/i);
    const entries = await readdir(layout.locks);
    const intent = entries.find((name) => name.startsWith(".remove-"));
    const quarantine = entries.find((name) => name.startsWith(".removed-"));
    expect(intent).toBeDefined();
    expect(quarantine).toBeDefined();
    await rm(join(layout.locks, intent!));

    await store().collectGarbage(project().repository);

    await expectMissing(join(layout.locks, quarantine!));
  });

  test("does not delete a replacement at a quarantine path whose intent entry was lost", async () => {
    const layout = await prepareSecureCache({ cacheDirectory: cache() }, project().repository);
    const target = join(layout.locks, "lost-intent-quarantine-replacement-target");
    await writeFile(target, "original", { mode: 0o600 });
    const identity = await captureSecurePathIdentity(layout, target, "file");
    await expect(safeRemoveExactCacheFile(layout, identity, {
      afterExactRemovalUnlink: async () => { throw new Error("simulated power loss"); }
    })).rejects.toThrow(/power loss/i);
    const entries = await readdir(layout.locks);
    const intent = entries.find((name) => name.startsWith(".remove-") && name.endsWith(".json"));
    const quarantine = entries.find((name) => name.startsWith(".removed-"));
    expect(intent).toBeDefined();
    expect(quarantine).toBeDefined();
    const quarantinePath = join(layout.locks, quarantine!);
    const evidencePath = `${quarantinePath}.evidence`;
    await rm(join(layout.locks, intent!));
    await rename(quarantinePath, evidencePath);
    await writeFile(quarantinePath, "replacement", { mode: 0o600 });

    await expect(store().collectGarbage(project().repository)).rejects.toThrow(/quarantine.*identity|replacement|evidence/i);

    await expect(readFile(quarantinePath, "utf8")).resolves.toBe("replacement");
    await expect(readFile(evidencePath, "utf8")).resolves.toBe("original");
  });

  test("reconciles more than three bounded dead publication claims to a stable inventory", async () => {
    const changesetStore = store();
    await changesetStore.preparePublication(candidate());
    const claims = await Promise.all(Array.from({ length: 5 }, async () =>
      writeDeadPublicationClaim(`${randomUUID()}.json`)));

    await expect(changesetStore.collectGarbage(project().repository)).resolves.toBeUndefined();

    for (const claim of claims) await expectMissing(claim);
    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("fails closed when dead-claim reconciliation churn does not reduce the bounded inventory", async () => {
    let reconciliations = 0;
    const changesetStore = store({
      io: {
        afterInventoryClaimReconciliation: async () => {
          reconciliations += 1;
          await writeDeadPublicationClaim(`${randomUUID()}.json`);
        }
      }
    });
    await changesetStore.preparePublication(candidate());
    await writeDeadPublicationClaim(`${randomUUID()}.json`);

    await expect(changesetStore.collectGarbage(project().repository)).rejects.toThrow(/stabil|churn|progress|bounded/i);

    expect(reconciliations).toBe(1);
    expect((await cacheEntries()).filter((name) => name.startsWith(".publish-"))).toHaveLength(1);
  });

  test("reconciles a dead Task-2 publication claim and charges its validated residual temporary bytes", async () => {
    const measuringStore = store();
    const measured = await measuringStore.preparePublication(candidate());
    const pairBytes = measured.changesetBytes.byteLength + measured.signatureBytes.byteLength;
    const initializationName = `.claim-${randomUUID()}.tmp`;
    const publicationName = `.${randomUUID()}.tmp`;
    const owner = createPublicationClaimOwner(
      basename(measured.changesetPath),
      initializationName,
      publicationName,
      clock - PUBLICATION_CLAIM_LEASE_MS - 1_000
    );
    owner.pid = 2_147_483_647;
    const claimPath = join(cache(), "changesets", `.publish-${basename(measured.changesetPath)}`);
    const temporaryPath = join(cache(), "changesets", publicationName);
    const temporaryBytes = Buffer.from("validated abandoned publication bytes", "utf8");
    await writeFile(claimPath, `${JSON.stringify(owner)}\n`, { mode: 0o600 });
    await writeFile(temporaryPath, temporaryBytes, { mode: 0o600 });

    await expect(measuringStore.collectGarbage(project().repository)).resolves.toBeUndefined();

    await expectMissing(claimPath);
    await expect(readFile(temporaryPath)).resolves.toEqual(temporaryBytes);
    const constrained = store({ limits: { changesets: { maxTotalBytes: temporaryBytes.byteLength + pairBytes - 1 } } });
    const prepared = await constrained.preparePublication(candidate());
    await expect(constrained.publishPair(prepared)).rejects.toThrow(/aggregate.*bytes|cache bytes/i);
    await expect(readFile(temporaryPath)).resolves.toEqual(temporaryBytes);
  });

  test("charges retained exact-removal recovery artifacts against the aggregate byte quota", async () => {
    const measuringStore = store();
    const measured = await measuringStore.preparePublication(candidate());
    const pairBytes = measured.changesetBytes.byteLength + measured.signatureBytes.byteLength;
    const candidatePath = join(
      cache(),
      "locks",
      `.remove-${randomUUID()}.owner-${randomUUID()}.tmp`
    );
    const recoveryBytes = Buffer.from("fresh exact-removal recovery evidence", "utf8");
    await mkdir(join(cache(), "locks"), { recursive: true, mode: 0o700 });
    await writeFile(candidatePath, recoveryBytes, { mode: 0o600 });

    const constrained = store({
      limits: { changesets: { maxTotalBytes: recoveryBytes.byteLength + pairBytes - 1 } }
    });
    const prepared = await constrained.preparePublication(candidate());
    await expect(constrained.publishPair(prepared)).rejects.toThrow(/aggregate.*bytes|cache bytes/i);
    await expect(readFile(candidatePath)).resolves.toEqual(recoveryBytes);
  });

  test("retains a fresh authenticated version-one pair and exactly removes it only after expiry", async () => {
    const changesetStore = store();
    const value = candidate();
    const prepared = await changesetStore.preparePublication(value);
    await changesetStore.publishPair(prepared);
    await rewriteAsAuthenticatedVersionOne(prepared);
    const freshChangeset = await readFile(prepared.changesetPath);
    const freshSignature = await readFile(prepared.signaturePath);

    await expect(changesetStore.collectGarbage(project().repository)).resolves.toBeUndefined();
    await expect(readFile(prepared.changesetPath)).resolves.toEqual(freshChangeset);
    await expect(readFile(prepared.signaturePath)).resolves.toEqual(freshSignature);

    clock = value.expiresAt;
    await expect(changesetStore.collectGarbage(project().repository)).resolves.toBeUndefined();
    await expectMissing(prepared.changesetPath);
    await expectMissing(prepared.signaturePath);
  });

  test("removes an expired authenticated pair at the exact expiry boundary", async () => {
    const changesetStore = store();
    const value = candidate();
    const prepared = await changesetStore.preparePublication(value);
    await changesetStore.publishPair(prepared);
    clock = value.expiresAt;

    await changesetStore.collectGarbage(project().repository);

    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("removes only true orphan halves older than one full changeset lifetime", async () => {
    const changesetStore = store();
    const oldJson = await changesetStore.preparePublication(candidate());
    const freshSignature = await changesetStore.preparePublication(candidate());
    await changesetStore.publishPair(oldJson);
    await changesetStore.publishPair(freshSignature);
    await rm(oldJson.signaturePath);
    await rm(freshSignature.changesetPath);
    const old = new Date(clock - changesetLifetimeMs - 1_000);
    await utimes(oldJson.changesetPath, old, old);

    await changesetStore.collectGarbage(project().repository);

    await expectMissing(oldJson.changesetPath);
    await expect(readFile(freshSignature.signaturePath, "utf8")).resolves.toContain("hmac-sha256");
  });

  test("fails closed and preserves an expired malformed complete pair as tamper evidence", async () => {
    const changesetStore = store();
    const value = candidate();
    const prepared = await changesetStore.preparePublication(value);
    await changesetStore.publishPair(prepared);
    const tampered = JSON.parse(await readFile(prepared.changesetPath, "utf8")) as Record<string, unknown>;
    tampered.root = project().nonGitDirectory;
    const tamperedBytes = Buffer.from(`${JSON.stringify(tampered, null, 2)}\n`, "utf8");
    await writeFile(prepared.changesetPath, tamperedBytes);
    const signatureBefore = await readFile(prepared.signaturePath);
    clock = value.expiresAt;

    await expect(changesetStore.collectGarbage(project().repository))
      .rejects.toThrow(/authentication|tamper|malformed/i);

    await expect(readFile(prepared.changesetPath)).resolves.toEqual(tamperedBytes);
    await expect(readFile(prepared.signaturePath)).resolves.toEqual(signatureBefore);
  });

  test("collects expired pairs before enforcing a full live-pair quota", async () => {
    const changesetStore = store({ limits: { changesets: { maxPairsPerProject: 1 } } });
    const expiredValue = candidate();
    const expired = await changesetStore.preparePublication(expiredValue);
    await changesetStore.publishPair(expired);
    clock = expiredValue.expiresAt;
    const replacement = await changesetStore.preparePublication(candidate());

    await expect(changesetStore.publishPair(replacement)).resolves.toBeUndefined();

    await expectMissing(expired.changesetPath);
    await expectMissing(expired.signaturePath);
    expect(await cacheEntries()).toEqual([
      `${replacement.changesetPath.split(/[\\/]/u).at(-1)}`,
      `${replacement.signaturePath.split(/[\\/]/u).at(-1)}`
    ].sort());
  });
});

describe("bounded authenticated reads", () => {
  test("reconciles a prepared exact-removal intent before trusting a changeset load", async () => {
    const changesetStore = store();
    const prepared = await changesetStore.preparePublication(candidate());
    await changesetStore.publishPair(prepared);
    const layout = await prepareSecureCache({ cacheDirectory: cache() }, project().repository);
    const identity = await captureSecurePathIdentity(layout, prepared.changesetPath, "file");
    const intentId = randomUUID();
    const intentPath = join(layout.locks, `.remove-${intentId}.json`);
    const quarantinePath = join(layout.locks, `.removed-${intentId}.data`);
    await writeFile(intentPath, `${JSON.stringify({
      version: 1,
      targetPath: identity.path,
      targetParent: identity.parent,
      quarantinePath,
      dev: String(identity.dev),
      ino: String(identity.ino),
      parentDev: String(identity.parentDev),
      parentIno: String(identity.parentIno)
    })}\n`, { mode: 0o600 });

    await expect(changesetStore.loadAuthenticated(project().repository, prepared.changesetId))
      .rejects.toThrow(/missing|not found/i);

    await expectMissing(prepared.changesetPath);
    await expect(readFile(prepared.signaturePath)).resolves.toEqual(prepared.signatureBytes);
    await expectMissing(intentPath);
  });

  test.skipIf(process.platform === "win32")("rechecks owner-only mode through the handle and final path", async () => {
    const publishingStore = store();
    const prepared = await publishingStore.preparePublication(candidate());
    await publishingStore.publishPair(prepared);
    let changed = false;
    const readingStore = store({
      io: {
        beforeBoundedReadFinalValidation: async (path: string) => {
          if (changed || path !== prepared.changesetPath) return;
          changed = true;
          await chmod(path, 0o644);
        }
      }
    });

    await expect(readingStore.loadAuthenticated(project().repository, prepared.changesetId))
      .rejects.toThrow(/permission|mode|owner-only/i);
  });

  test("rechecks the hard-link count through the handle and final path", async () => {
    const publishingStore = store();
    const prepared = await publishingStore.preparePublication(candidate());
    await publishingStore.publishPair(prepared);
    let changed = false;
    const readingStore = store({
      io: {
        beforeBoundedReadFinalValidation: async (path: string) => {
          if (changed || path !== prepared.changesetPath) return;
          changed = true;
          await link(path, join(cache(), "external-changeset-link.json"));
        }
      }
    });

    await expect(readingStore.loadAuthenticated(project().repository, prepared.changesetId))
      .rejects.toThrow(/hard.?link|link count/i);
  });

  test.runIf(process.platform !== "win32" && typeof process.getuid === "function" && process.getuid() === 0)(
    "rechecks file ownership through the handle and final path",
    async () => {
      const publishingStore = store();
      const prepared = await publishingStore.preparePublication(candidate());
      await publishingStore.publishPair(prepared);
      let changed = false;
      const readingStore = store({
        io: {
          beforeBoundedReadFinalValidation: async (path: string) => {
            if (changed || path !== prepared.changesetPath) return;
            changed = true;
            await chown(path, 65_534, 65_534);
          }
        }
      });

      await expect(readingStore.loadAuthenticated(project().repository, prepared.changesetId))
        .rejects.toThrow(/ownership|owner/i);
    }
  );
});

describe("paired publication and exact consumption", () => {
  test("rejects prepared-buffer substitution during asynchronous publication without persisting either pair", async () => {
    let prepared!: PreparedChangesetPublication;
    let substituted!: PreparedChangesetPublication;
    let substituteOnce = true;
    const changesetStore = store({
      io: {
        publishFile: async (layout: Parameters<typeof publishExclusiveFile>[0], path: string, bytes: string | Uint8Array, hooks: Parameters<typeof publishExclusiveFile>[3]) => {
          if (substituteOnce && path.endsWith(".json") && !path.endsWith(".sig.json")) {
            substituteOnce = false;
            expect(substituted.changesetBytes.byteLength).toBe(prepared.changesetBytes.byteLength);
            expect(substituted.signatureBytes.byteLength).toBe(prepared.signatureBytes.byteLength);
            substituted.changesetBytes.copy(prepared.changesetBytes);
            substituted.signatureBytes.copy(prepared.signatureBytes);
          }
          await publishExclusiveFile(layout, path, bytes, hooks);
        }
      }
    });
    const changesetId = randomUUID();
    const path = ".agents/skills/project-design-context/prepared-authority.md";
    const originalChanges: PersistedChange[] = [{
      path,
      content: block("prepared-authority", "AAAA"),
      previousHash: null
    }];
    const substitutedChanges: PersistedChange[] = [{
      path,
      content: block("prepared-authority", "BBBB"),
      previousHash: null
    }];
    prepared = await changesetStore.preparePublication(candidate(project().repository, {
      changesetId,
      changes: originalChanges,
      diffDigest: persistedDiffDigest(originalChanges, [])
    }));
    substituted = await changesetStore.preparePublication(candidate(project().repository, {
      changesetId,
      changes: substitutedChanges,
      diffDigest: persistedDiffDigest(substitutedChanges, [])
    }));

    await expect(changesetStore.publishPair(prepared)).rejects.toThrow(/prepared.*changed|bindings changed/i);

    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("removes both exact halves when signature publication throws after linking its target", async () => {
    const primary = new Error("signature publisher failed after linking target");
    const changesetStore = store({
      io: {
        publishFile: async (layout: Parameters<typeof publishExclusiveFile>[0], path: string, bytes: string | Uint8Array, hooks: Parameters<typeof publishExclusiveFile>[3]) => {
          await publishExclusiveFile(layout, path, bytes, hooks);
          if (path.endsWith(".sig.json")) throw primary;
        }
      }
    });
    const prepared = await changesetStore.preparePublication(candidate());

    await expect(changesetStore.publishPair(prepared)).rejects.toBe(primary);

    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("removes both exact halves when signature parent-directory sync fails after linking", async () => {
    const primary = new Error("signature directory sync failed");
    const changesetStore = store({
      io: {
        publishFile: async (layout: Parameters<typeof publishExclusiveFile>[0], path: string, bytes: string | Uint8Array, hooks: Parameters<typeof publishExclusiveFile>[3]) => {
          let directorySyncs = 0;
          await publishExclusiveFile(layout, path, bytes, {
            ...hooks,
            afterParentDirectorySync: async (directory, outcome) => {
              await hooks?.afterParentDirectorySync?.(directory, outcome);
              directorySyncs += 1;
              if (path.endsWith(".sig.json") && directorySyncs === 2) throw primary;
            }
          });
        }
      }
    });
    const prepared = await changesetStore.preparePublication(candidate());

    await expect(changesetStore.publishPair(prepared)).rejects.toBe(primary);

    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("removes the exact first half and preserves the primary error when signature publication fails", async () => {
    const primary = new Error("injected signature publication failure");
    const changesetStore = store({
      io: {
        publishFile: async (layout: Parameters<typeof publishExclusiveFile>[0], path: string, bytes: string | Uint8Array, hooks: Parameters<typeof publishExclusiveFile>[3]) => {
          if (path.endsWith(".sig.json")) throw primary;
          await publishExclusiveFile(layout, path, bytes, hooks);
        }
      }
    });
    const prepared = await changesetStore.preparePublication(candidate());

    await expect(changesetStore.publishPair(prepared)).rejects.toBe(primary);

    await expect(cacheEntries()).resolves.toEqual([]);
  });

  test("preserves primary and durable cleanup evidence when rollback directory sync fails", async () => {
    const primary = new Error("injected signature publication failure");
    const cleanup = Object.assign(new Error("changeset directory sync denied"), { code: "EACCES" });
    const changesetStore = store({
      io: {
        publishFile: async (layout: Parameters<typeof publishExclusiveFile>[0], path: string, bytes: string | Uint8Array, hooks: Parameters<typeof publishExclusiveFile>[3]) => {
          if (path.endsWith(".sig.json")) throw primary;
          await publishExclusiveFile(layout, path, bytes, hooks);
        },
        removeExactFile: async (
          layout: Parameters<typeof safeRemoveExactCacheFile>[0],
          identity: Parameters<typeof safeRemoveExactCacheFile>[1]
        ) => safeRemoveExactCacheFile(layout, identity, {
          beforeParentDirectoryOpen: async (directory) => {
            if (directory === identity.parent) throw cleanup;
          }
        })
      }
    });
    const prepared = await changesetStore.preparePublication(candidate());

    const failure = await changesetStore.publishPair(prepared).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).errors[0]).toBe(primary);
    expect(String((failure as AggregateError).errors[1])).toMatch(/directory sync denied|cleanup/i);
    await expectMissing(prepared.changesetPath);
    await expectMissing(prepared.signaturePath);
    expect((await readdir(join(cache(), "locks"))).filter((name) => name.startsWith(".remove-"))).toHaveLength(1);
  });

  test("rejects an ID collision without mixing or replacing either winner half", async () => {
    const changesetStore = store();
    const id = randomUUID();
    const winner = await changesetStore.preparePublication(candidate(project().repository, { changesetId: id }));
    const conflictingChanges: PersistedChange[] = [{
      path: ".agents/skills/project-design-context/collision.md",
      content: block("collision", "different authenticated bytes"),
      previousHash: null
    }];
    const collision = await changesetStore.preparePublication(candidate(project().repository, {
      changesetId: id,
      changes: conflictingChanges,
      diffDigest: persistedDiffDigest(conflictingChanges, [])
    }));
    await changesetStore.publishPair(winner);
    const winnerJson = await readFile(winner.changesetPath);
    const winnerSignature = await readFile(winner.signaturePath);

    await expect(changesetStore.publishPair(collision)).rejects.toThrow(/collision|already exists|EEXIST/i);

    await expect(readFile(winner.changesetPath)).resolves.toEqual(winnerJson);
    await expect(readFile(winner.signaturePath)).resolves.toEqual(winnerSignature);
  });

  test("consumes both identities from an unchanged authenticated load", async () => {
    const changesetStore = store();
    const prepared = await changesetStore.preparePublication(candidate());
    await changesetStore.publishPair(prepared);
    const loaded = await changesetStore.loadAuthenticated(project().repository, prepared.changesetId);

    await changesetStore.consumePair(loaded);

    await expectMissing(prepared.changesetPath);
    await expectMissing(prepared.signaturePath);
  });

  test.each(["changeset", "signature"] as const)("does not delete a raced %s replacement during exact consume", async (half) => {
    const changesetStore = store();
    const prepared = await changesetStore.preparePublication(candidate());
    await changesetStore.publishPair(prepared);
    const loaded = await changesetStore.loadAuthenticated(project().repository, prepared.changesetId);
    const target = half === "changeset" ? prepared.changesetPath : prepared.signaturePath;
    const moved = `${target}.evidence`;
    const replacement = Buffer.from(`replacement-${half}`, "utf8");
    await rename(target, moved);
    await writeFile(target, replacement, { mode: 0o600 });

    await expect(changesetStore.consumePair(loaded)).rejects.toThrow(/identity|changed|replacement/i);

    await expect(readFile(target)).resolves.toEqual(replacement);
    await expect(readFile(moved)).resolves.toEqual(half === "changeset" ? prepared.changesetBytes : prepared.signatureBytes);
    const other = half === "changeset" ? prepared.signaturePath : prepared.changesetPath;
    await expect(readFile(other)).resolves.toEqual(half === "changeset" ? prepared.signatureBytes : prepared.changesetBytes);
  });

  test("reports cleanup ambiguity without deleting a replacement after partial publication", async () => {
    const primary = new Error("signature refused");
    let moved = "";
    const replacement = Buffer.from("raced replacement", "utf8");
    const changesetStore = store({
      io: {
        publishFile: async (layout: Parameters<typeof publishExclusiveFile>[0], path: string, bytes: string | Uint8Array, hooks: Parameters<typeof publishExclusiveFile>[3]) => {
          if (path.endsWith(".sig.json")) throw primary;
          await publishExclusiveFile(layout, path, bytes, hooks);
          moved = `${path}.evidence`;
          await rename(path, moved);
          await writeFile(path, replacement, { mode: 0o600 });
        }
      }
    });
    const prepared = await changesetStore.preparePublication(candidate());

    await expect(changesetStore.publishPair(prepared)).rejects.toThrow(/publication.*cleanup|signature refused|ambiguous/i);

    await expect(readFile(prepared.changesetPath)).resolves.toEqual(replacement);
    await expect(readFile(moved)).resolves.toEqual(prepared.changesetBytes);
  });
});
