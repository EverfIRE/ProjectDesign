import { randomUUID } from "node:crypto";
import { statSync } from "node:fs";
import { chmod, chown, link, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { afterEach, expect, test } from "vitest";
import {
  assertSecureOwnerFileMetadata,
  captureOwnedSnapshotPublicationClaim,
  createOwnedBuildDirectory,
  createSecureCacheDirectory,
  claimOwnedSnapshotDirectory,
  captureSecurePathIdentity,
  observeOwnedSnapshotPublicationClaim,
  prepareSecureCache,
  publicationClaimLiveness,
  publishExclusiveFile,
  publishOwnedBuildDirectory,
  reconcileCacheFilePublication,
  reconcileExactRemovalIntents,
  resolveCacheDirectory,
  safeRemoveCacheFile,
  safeRemoveExactCacheFile,
  safeRemoveOwnedBuildDirectory,
  safeRemoveOwnedPublicationClaim,
  safeRemoveOwnedSnapshotDirectory,
  samePublicationClaimEpoch,
  validateCacheFile,
  validateCacheFiles,
  validateSecurePathIdentity
} from "../src/security/cache.js";
import {
  createPublicationClaimOwner,
  parsePublicationClaimOwner
} from "../src/security/publication-claim.js";
import { changesetRemovalRecoveryLimits } from "../src/security/limits.js";

// Keep eight MiB of aggregate headroom so the 7/9 MiB race fixtures still
// cross the current boundary without allocating their sparse file contents.
const recoveryFixtureArtifactBytes = Math.floor((changesetRemovalRecoveryLimits.maxBytes - 8 * 1024 * 1024) / 10);

const roots: string[] = [];

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((accept, decline) => {
    resolve = accept;
    reject = decline;
  });
  return { promise, resolve, reject };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixtureRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "keeper-secure-cache-"));
  roots.push(root);
  await Promise.all([
    mkdir(join(root, "project"), { recursive: true }),
    mkdir(join(root, "outside"), { recursive: true })
  ]);
  return root;
}

async function claimMetadataPath(claim: { path: string }): Promise<string> {
  const metadata = await lstat(claim.path, { bigint: true });
  return metadata.isDirectory() ? join(claim.path, "owner.json") : claim.path;
}

async function expireClaimOwner(claim: { path: string }): Promise<void> {
  const path = await claimMetadataPath(claim);
  const owner = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  await writeFile(path, `${JSON.stringify({
    ...owner,
    pid: 2_147_483_647,
    createdAtMs: 1,
    expiresAtMs: 30_001
  })}\n`, { encoding: "utf8", mode: 0o600 });
}

type OwnedSnapshotPublicationClaim = Awaited<ReturnType<typeof claimOwnedSnapshotDirectory>>;

async function retainClaimGenerationBeforeUnlink(
  claim: OwnedSnapshotPublicationClaim,
  retainedPaths: string[]
): Promise<string> {
  const retainedPath = join(dirname(claim.path), `.claim-retained-${randomUUID()}.tmp`);
  retainedPaths.push(retainedPath);
  await link(claim.path, retainedPath);
  const [visible, retained] = await Promise.all([
    lstat(claim.path, { bigint: true }),
    lstat(retainedPath, { bigint: true })
  ]);
  expect(visible.dev).toBe(claim.dev);
  expect(visible.ino).toBe(claim.ino);
  expect(retained.dev).toBe(claim.dev);
  expect(retained.ino).toBe(claim.ino);
  expect(visible.nlink).toBe(2n);
  expect(retained.nlink).toBe(2n);

  await rm(claim.path);
  await expect(lstat(claim.path)).rejects.toMatchObject({ code: "ENOENT" });
  const preserved = await lstat(retainedPath, { bigint: true });
  expect(preserved.dev).toBe(claim.dev);
  expect(preserved.ino).toBe(claim.ino);
  expect(preserved.nlink).toBe(1n);
  return retainedPath;
}

async function removeRetainedClaimGenerations(retainedPaths: string[]): Promise<void> {
  for (const retainedPath of retainedPaths.splice(0)) {
    await rm(retainedPath, { force: true });
  }
}

async function expectClaimPathGeneration(
  claimPath: string,
  current: OwnedSnapshotPublicationClaim,
  retainedPath: string,
  previous: OwnedSnapshotPublicationClaim
): Promise<void> {
  const [visible, retained] = await Promise.all([
    lstat(claimPath, { bigint: true }),
    lstat(retainedPath, { bigint: true })
  ]);
  expect(visible.dev).toBe(current.dev);
  expect(visible.ino).toBe(current.ino);
  expect(retained.dev).toBe(previous.dev);
  expect(retained.ino).toBe(previous.ino);
  expect(visible.dev === retained.dev && visible.ino === retained.ino).toBe(false);
}

function exactRemovalIntentRecord(
  layout: Awaited<ReturnType<typeof prepareSecureCache>>,
  identity: Awaited<ReturnType<typeof captureSecurePathIdentity>>,
  intentId: string
): Record<string, unknown> {
  return {
    version: 1,
    targetPath: identity.path,
    targetParent: identity.parent,
    quarantinePath: join(layout.locks, `.removed-${intentId}-${identity.dev}-${identity.ino}.data`),
    dev: String(identity.dev),
    ino: String(identity.ino),
    parentDev: String(identity.parentDev),
    parentIno: String(identity.parentIno)
  };
}

test("resolves cache-directory configuration in explicit security precedence order", () => {
  const environment = {
    PLUGIN_DATA: "plugin-data",
    LOCALAPPDATA: "local-data",
    XDG_CACHE_HOME: "xdg-data"
  };
  expect(resolveCacheDirectory({ cacheDirectory: "explicit" }, environment, "home"))
    .toBe(resolve("explicit"));
  expect(resolveCacheDirectory({}, environment, "home")).toBe(resolve("plugin-data"));
  expect(resolveCacheDirectory({}, { ...environment, PLUGIN_DATA: undefined }, "home"))
    .toBe(resolve("local-data", "project-design-keeper"));
  expect(resolveCacheDirectory({}, { XDG_CACHE_HOME: "xdg-data" }, "home"))
    .toBe(resolve("xdg-data", "project-design-keeper"));
  expect(resolveCacheDirectory({}, {}, "home"))
    .toBe(resolve("home", ".cache", "project-design-keeper"));
});

test("validates one-parent cache batches and removes only ordinary owned files", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const first = join(layout.changesets, "first.json");
  const second = join(layout.changesets, "second.json");
  const nested = await createSecureCacheDirectory(layout, join(layout.changesets, "nested"));
  const third = join(nested, "third.json");
  const directoryEntry = join(layout.changesets, "directory-entry");
  await Promise.all([
    writeFile(first, "first", { mode: 0o600 }),
    writeFile(second, "second", { mode: 0o600 }),
    writeFile(third, "third", { mode: 0o600 }),
    mkdir(directoryEntry)
  ]);

  await expect(validateCacheFiles(layout, [])).resolves.toBeUndefined();
  await expect(validateCacheFiles(layout, [first, second])).resolves.toBeUndefined();
  await expect(validateCacheFiles(layout, [first, third])).rejects.toThrow(/one shared parent/i);
  await expect(validateCacheFiles(layout, [directoryEntry])).rejects.toThrow(/ordinary regular file/i);

  await expect(safeRemoveCacheFile(layout, first)).resolves.toBeUndefined();
  await expect(lstat(first)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(safeRemoveCacheFile(layout, first)).resolves.toBeUndefined();
  await expect(safeRemoveCacheFile(layout, directoryEntry)).rejects.toThrow(/ordinary regular file/i);
  await expect(safeRemoveCacheFile(layout, join(root, "outside", "escape.json")))
    .rejects.toThrow(/escapes the cache root/i);
});

test("compares every identity and owner field in a publication-claim epoch", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "d".repeat(64));
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const exact = { ...claim, owner: { ...claim.owner } };
  expect(samePublicationClaimEpoch(claim, exact)).toBe(true);

  const changed = [
    { ...exact, dev: (exact.dev as bigint) + 1n },
    { ...exact, ino: (exact.ino as bigint) + 1n },
    { ...exact, path: `${exact.path}.other` },
    { ...exact, parent: `${exact.parent}.other` },
    { ...exact, parentDev: (exact.parentDev as bigint) + 1n },
    { ...exact, parentIno: (exact.parentIno as bigint) + 1n },
    { ...exact, owner: { ...exact.owner, version: 2 as 1 } },
    { ...exact, owner: { ...exact.owner, pid: exact.owner.pid + 1 } },
    { ...exact, owner: { ...exact.owner, nonce: "0".repeat(32) } },
    { ...exact, owner: { ...exact.owner, createdAtMs: exact.owner.createdAtMs + 1 } },
    { ...exact, owner: { ...exact.owner, expiresAtMs: exact.owner.expiresAtMs + 1 } },
    { ...exact, owner: { ...exact.owner, targetName: `${exact.owner.targetName}.other` } },
    { ...exact, owner: { ...exact.owner, initializationName: `${exact.owner.initializationName}.other` } },
    { ...exact, owner: { ...exact.owner, publicationName: `${exact.owner.publicationName}.other` } }
  ];
  expect(changed.map((candidate) => samePublicationClaimEpoch(claim, candidate))).toEqual(Array(14).fill(false));

  expect(publicationClaimLiveness(claim, claim.owner.expiresAtMs - 1)).toBe("alive");
  expect(publicationClaimLiveness({ ...claim, owner: { ...claim.owner, pid: 0 } }, claim.owner.expiresAtMs))
    .toBe("ambiguous");
});

test("enforces regular-file and exact-link metadata at the exported cache boundary", async () => {
  const root = await fixtureRoot();
  const file = join(root, "outside", "metadata.bin");
  await writeFile(file, "metadata", { mode: 0o600 });
  const fileMetadata = await lstat(file, { bigint: true });
  const directoryMetadata = await lstat(join(root, "outside"), { bigint: true });

  expect(() => assertSecureOwnerFileMetadata(fileMetadata, file)).not.toThrow();
  expect(() => assertSecureOwnerFileMetadata(fileMetadata, file, 1n)).not.toThrow();
  expect(() => assertSecureOwnerFileMetadata(fileMetadata, file, 2n)).toThrow(/hard-link count/i);
  expect(() => assertSecureOwnerFileMetadata(directoryMetadata, join(root, "outside")))
    .toThrow(/ordinary regular file/i);
});

test("rejects a cache that overlaps the project", async () => {
  const root = await fixtureRoot();

  await expect(prepareSecureCache(
    { cacheDirectory: join(root, "project", ".cache") },
    join(root, "project")
  )).rejects.toThrow(/cache.*project.*disjoint/i);
});

test("rejects a lexical project alias below the cache even when its canonical target is elsewhere", async () => {
  const root = await fixtureRoot();
  const cache = join(root, "cache");
  const alias = join(cache, "project-alias");
  await mkdir(cache);
  await symlink(join(root, "project"), alias, process.platform === "win32" ? "junction" : "dir");

  await expect(prepareSecureCache({ cacheDirectory: cache }, alias))
    .rejects.toThrow(/canonical|alias|cache.*project.*disjoint/i);
});

test("rejects a non-canonical project alias even when both spellings are disjoint from the cache", async () => {
  const root = await fixtureRoot();
  const alias = join(root, "project-alias");
  await symlink(join(root, "project"), alias, process.platform === "win32" ? "junction" : "dir");

  await expect(prepareSecureCache({ cacheDirectory: join(root, "cache") }, alias))
    .rejects.toThrow(/canonical|alias/i);
});

test("rejects a project alias whose canonical target is below the cache", async () => {
  const root = await fixtureRoot();
  const cache = join(root, "cache");
  const projectTarget = join(cache, "project-target");
  const alias = join(root, "project-alias");
  await mkdir(projectTarget, { recursive: true });
  await symlink(projectTarget, alias, process.platform === "win32" ? "junction" : "dir");

  await expect(prepareSecureCache({ cacheDirectory: cache }, alias))
    .rejects.toThrow(/canonical|alias|cache.*project.*disjoint/i);
});

test("rejects a project alias whose canonical target contains the cache", async () => {
  const root = await fixtureRoot();
  const projectTarget = join(root, "actual-project");
  const cache = join(projectTarget, "cache");
  const alias = join(root, "project-alias");
  await mkdir(projectTarget);
  await symlink(projectTarget, alias, process.platform === "win32" ? "junction" : "dir");

  await expect(prepareSecureCache({ cacheDirectory: cache }, alias))
    .rejects.toThrow(/canonical|alias|cache.*project.*disjoint/i);
});

test.runIf(process.platform === "win32")("rejects a junction in index ancestry", async () => {
  const root = await fixtureRoot();
  await mkdir(join(root, "cache"), { recursive: true });
  await symlink(join(root, "outside"), join(root, "cache", "indexes"), "junction");

  await expect(prepareSecureCache(
    { cacheDirectory: join(root, "cache") },
    join(root, "project")
  )).rejects.toThrow(/junction|reparse|symbolic/i);
});

test("refuses recursive cleanup after build-directory identity changes", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache(
    { cacheDirectory: join(root, "cache") },
    join(root, "project")
  );
  const build = await createOwnedBuildDirectory(layout, layout.indexes);
  await rename(build.path, `${build.path}.moved`);
  await mkdir(build.path, { mode: 0o700 });

  await expect(safeRemoveOwnedBuildDirectory(layout, build)).rejects.toThrow(/identity/i);
});

test("records and compares cache identities as bigint values", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const build = await createOwnedBuildDirectory(layout, layout.indexes);

  expect(typeof build.dev).toBe("bigint");
  expect(typeof build.ino).toBe("bigint");
  await expect(validateSecurePathIdentity(layout, {
    ...build,
    ino: (build.ino as bigint) + (1n << 60n)
  })).rejects.toThrow(/identity/i);
});

test("captures and observes only exact owned snapshot publication claims", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "a".repeat(64));
  const absentTarget = join(layout.indexes, "b".repeat(64));
  const outsideIndexes = join(layout.snapshots, "c".repeat(64));
  const invalidName = join(layout.indexes, "not-a-snapshot-digest");

  await expect(claimOwnedSnapshotDirectory(layout, outsideIndexes))
    .rejects.toThrow(/owned index snapshot target/i);
  await expect(claimOwnedSnapshotDirectory(layout, invalidName))
    .rejects.toThrow(/owned index snapshot target/i);
  await expect(captureOwnedSnapshotPublicationClaim(layout, outsideIndexes))
    .rejects.toThrow(/publication target is invalid/i);
  await expect(captureOwnedSnapshotPublicationClaim(layout, invalidName))
    .rejects.toThrow(/publication target is invalid/i);
  await expect(observeOwnedSnapshotPublicationClaim(layout, outsideIndexes))
    .rejects.toThrow(/publication target is invalid/i);
  await expect(observeOwnedSnapshotPublicationClaim(layout, invalidName))
    .rejects.toThrow(/publication target is invalid/i);
  await expect(observeOwnedSnapshotPublicationClaim(layout, absentTarget))
    .resolves.toEqual({ state: "absent" });

  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const captured = await captureOwnedSnapshotPublicationClaim(layout, target);
  expect(samePublicationClaimEpoch(claim, captured)).toBe(true);
  await expect(observeOwnedSnapshotPublicationClaim(layout, target)).resolves.toMatchObject({
    state: "owned",
    claim: { path: claim.path, owner: claim.owner }
  });
  await safeRemoveOwnedPublicationClaim(layout, claim);
});

test("rejects snapshot publication identity mutations before rename", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "d".repeat(64));
  const build = await createOwnedBuildDirectory(layout, layout.indexes);
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const increment = (value: bigint | number) => BigInt(value) + 1n;

  await expect(publishOwnedBuildDirectory(layout, {
    ...build,
    kind: "file"
  }, target, claim)).rejects.toThrow(/invalid types/i);
  await expect(publishOwnedBuildDirectory(layout, build, target, {
    ...claim,
    kind: "directory"
  } as unknown as typeof claim)).rejects.toThrow(/invalid types/i);
  await expect(publishOwnedBuildDirectory(layout, build, join(layout.snapshots, "e".repeat(64)), claim))
    .rejects.toThrow(/publication target is invalid/i);
  await expect(publishOwnedBuildDirectory(layout, build, join(layout.indexes, "not-a-snapshot-digest"), claim))
    .rejects.toThrow(/publication target is invalid/i);
  await expect(publishOwnedBuildDirectory(layout, build, target, {
    ...claim,
    path: `${claim.path}.other`
  })).rejects.toThrow(/claim path is invalid/i);
  await expect(publishOwnedBuildDirectory(layout, {
    ...build,
    parent: layout.snapshots
  }, target, claim)).rejects.toThrow(/do not share the target parent/i);
  await expect(publishOwnedBuildDirectory(layout, build, target, {
    ...claim,
    parent: layout.snapshots
  })).rejects.toThrow(/do not share the target parent/i);

  await mkdir(target);
  await expect(publishOwnedBuildDirectory(layout, build, target, claim))
    .rejects.toMatchObject({ code: "EEXIST" });
  await rm(target, { recursive: true });

  const parentMutations = [
    { ...build, parentDev: increment(build.parentDev) },
    { ...build, parentIno: increment(build.parentIno) }
  ];
  for (const mutatedBuild of parentMutations) {
    await expect(publishOwnedBuildDirectory(layout, mutatedBuild, target, claim))
      .rejects.toThrow(/parent identity changed/i);
  }
  const claimParentMutations = [
    { ...claim, parentDev: increment(claim.parentDev) },
    { ...claim, parentIno: increment(claim.parentIno) }
  ];
  for (const mutatedClaim of claimParentMutations) {
    await expect(publishOwnedBuildDirectory(layout, build, target, mutatedClaim))
      .rejects.toThrow(/parent identity changed/i);
  }
  await expect(publishOwnedBuildDirectory(layout, {
    ...build,
    dev: increment(build.dev)
  }, target, claim)).rejects.toThrow(/identity changed/i);
  await expect(publishOwnedBuildDirectory(layout, build, target, {
    ...claim,
    dev: increment(claim.dev)
  })).rejects.toThrow(/identity|owner metadata changed/i);

  await expect(lstat(build.path)).resolves.toSatisfy((metadata) => metadata.isDirectory());
  await expect(lstat(claim.path)).resolves.toSatisfy((metadata) => metadata.isFile());
  await safeRemoveOwnedBuildDirectory(layout, build);
  await safeRemoveOwnedPublicationClaim(layout, claim);
});

test("publishes and removes only the captured snapshot directory identity", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "e".repeat(64));
  const build = await createOwnedBuildDirectory(layout, layout.indexes);
  const marker = join(build.path, "marker.txt");
  await writeFile(marker, "authenticated snapshot", { encoding: "utf8", mode: 0o600 });
  const claim = await claimOwnedSnapshotDirectory(layout, target);

  await expect(safeRemoveOwnedBuildDirectory(layout, {
    ...build,
    kind: "file"
  })).rejects.toThrow(/must describe a directory/i);
  await expect(safeRemoveOwnedBuildDirectory(layout, {
    ...build,
    path: join(layout.indexes, "not-an-owned-build")
  })).rejects.toThrow(/invalid build-directory name/i);

  const published = await publishOwnedBuildDirectory(layout, build, target, claim);
  expect(published.path).toBe(target);
  await expect(readFile(join(target, "marker.txt"), "utf8")).resolves.toBe("authenticated snapshot");
  await expect(captureOwnedSnapshotPublicationClaim(layout, target)).resolves.toSatisfy((current) =>
    samePublicationClaimEpoch(claim, current)
  );

  await expect(safeRemoveOwnedSnapshotDirectory(layout, {
    ...published,
    kind: "file"
  })).rejects.toThrow(/must describe a directory/i);
  await expect(safeRemoveOwnedSnapshotDirectory(layout, {
    ...published,
    path: join(layout.indexes, "not-a-snapshot-digest")
  })).rejects.toThrow(/invalid snapshot-directory path/i);
  await safeRemoveOwnedPublicationClaim(layout, claim);
  await safeRemoveOwnedSnapshotDirectory(layout, published, true);
  await expect(lstat(target)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(safeRemoveOwnedSnapshotDirectory(layout, published)).resolves.toBeUndefined();
  await expect(safeRemoveOwnedSnapshotDirectory(layout, published, true))
    .rejects.toThrow(/disappeared before exact cleanup/i);
  await expect(safeRemoveOwnedBuildDirectory(layout, build)).resolves.toBeUndefined();
});

test("validates every reachable secure path identity component", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const build = await createOwnedBuildDirectory(layout, layout.indexes);
  const rootIdentity = await captureSecurePathIdentity(layout, layout.root, "directory");
  await expect(validateSecurePathIdentity(layout, rootIdentity)).resolves.toBeUndefined();
  await expect(captureSecurePathIdentity(layout, build.path, "file"))
    .rejects.toThrow(/not an ordinary file/i);

  const increment = (value: bigint | number) => BigInt(value) + 1n;
  await expect(validateSecurePathIdentity(layout, {
    ...build,
    parent: layout.snapshots
  })).rejects.toThrow(/unexpected parent/i);
  for (const mutation of [
    { dev: increment(build.dev) },
    { ino: increment(build.ino) },
    { parentDev: increment(build.parentDev) },
    { parentIno: increment(build.parentIno) }
  ]) {
    await expect(validateSecurePathIdentity(layout, { ...build, ...mutation }))
      .rejects.toThrow(/identity changed/i);
  }
  await expect(validateSecurePathIdentity(layout, build)).resolves.toBeUndefined();
  await safeRemoveOwnedBuildDirectory(layout, build);
});

test.each(["missing", "replacement"] as const)(
  "retains exact build evidence when post-mkdir cleanup sees a %s pathname",
  async (outcome) => {
    const root = await fixtureRoot();
    const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
    let created = "";
    let moved = "";
    const primary = new Error(`post-mkdir ${outcome} fault`);

    await expect(createOwnedBuildDirectory(layout, layout.indexes, {
      afterMkdir: async (identity) => {
        created = identity.path;
        moved = `${identity.path}.retained`;
        await rename(identity.path, moved);
        if (outcome === "replacement") await mkdir(identity.path);
        throw primary;
      }
    })).rejects.toSatisfy((error: unknown) =>
      error instanceof AggregateError && error.cause === primary && error.errors[0] === primary
    );
    await expect(lstat(moved)).resolves.toSatisfy((metadata) => metadata.isDirectory());
    if (outcome === "replacement") {
      await expect(lstat(created)).resolves.toSatisfy((metadata) => metadata.isDirectory());
    } else {
      await expect(lstat(created)).rejects.toMatchObject({ code: "ENOENT" });
    }
  }
);

test("retains both snapshot directory identities after an ambiguous post-rename failure", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "f".repeat(64));
  const moved = `${target}.retained`;
  const build = await createOwnedBuildDirectory(layout, layout.indexes);
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const primary = new Error("post-rename publication fault");

  await expect(publishOwnedBuildDirectory(layout, build, target, claim, {
    afterRename: async () => {
      await rename(target, moved);
      await mkdir(target);
      throw primary;
    }
  })).rejects.toSatisfy((error: unknown) =>
    error instanceof AggregateError && error.cause === primary && error.errors[0] === primary
  );
  await expect(lstat(moved)).resolves.toSatisfy((metadata) => metadata.isDirectory());
  await expect(lstat(target)).resolves.toSatisfy((metadata) => metadata.isDirectory());
  await safeRemoveOwnedPublicationClaim(layout, claim);
});

test("rejects a replacement inode before a publication-claim owner becomes authoritative", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "1".repeat(64));
  let candidate = "";
  let moved = "";

  const failure = await claimOwnedSnapshotDirectory(layout, target, {
    beforeClaimOwnerIdentityCapture: async (path) => {
      candidate = path;
      moved = `${path}.original`;
      const bytes = await readFile(path);
      await rename(path, moved);
      await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
    }
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(AggregateError);
  expect(String((failure as AggregateError).cause)).toMatch(/owner identity changed during creation/i);
  await expect(lstat(candidate)).resolves.toSatisfy((metadata) => metadata.isFile());
  await expect(lstat(moved)).resolves.toSatisfy((metadata) => metadata.isFile());
  await expect(lstat(join(layout.indexes, `.publish-${"1".repeat(64)}`)))
    .rejects.toMatchObject({ code: "ENOENT" });
});

test("rejects valid-looking owner bytes rewritten on the created claim inode", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "2".repeat(64));
  let candidate = "";

  await expect(claimOwnedSnapshotDirectory(layout, target, {
    beforeClaimOwnerIdentityCapture: async (path) => {
      candidate = path;
      const owner = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
      owner.nonce = owner.nonce === "0".repeat(32) ? "1".repeat(32) : "0".repeat(32);
      await writeFile(path, `${JSON.stringify(owner)}\n`, { encoding: "utf8", mode: 0o600 });
    }
  })).rejects.toThrow(/owner bytes changed during creation/i);

  await expect(lstat(candidate)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(lstat(join(layout.indexes, `.publish-${"2".repeat(64)}`)))
    .rejects.toMatchObject({ code: "ENOENT" });
});

test("retains a linked claim whose valid owner bytes change before atomic verification", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "3".repeat(64));
  let deterministic = "";

  const failure = await claimOwnedSnapshotDirectory(layout, target, {
    afterClaimLink: async (temporary, published) => {
      deterministic = published;
      const owner = JSON.parse(await readFile(temporary, "utf8")) as Record<string, unknown>;
      owner.nonce = owner.nonce === "a".repeat(32) ? "b".repeat(32) : "a".repeat(32);
      await writeFile(temporary, `${JSON.stringify(owner)}\n`, { encoding: "utf8", mode: 0o600 });
    }
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(AggregateError);
  expect((failure as AggregateError).errors.map((error) => String((error as Error).message)))
    .toEqual([
      expect.stringMatching(/not atomically published/i),
      expect.stringMatching(/changed before failed-creation cleanup/i)
    ]);
  await expect(lstat(deterministic)).resolves.toSatisfy((metadata) => metadata.nlink === 1);
  const retained = await captureOwnedSnapshotPublicationClaim(layout, target);
  await safeRemoveOwnedPublicationClaim(layout, retained);
});

test("never overwrites a pre-existing publication-claim release path", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "4".repeat(64));
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const released = `${claim.path}.release-${claim.owner.nonce}`;
  await writeFile(released, "collision evidence", { flag: "wx", mode: 0o600 });

  await expect(safeRemoveOwnedPublicationClaim(layout, claim))
    .rejects.toThrow(/release path already exists/i);
  await expect(readFile(released, "utf8")).resolves.toBe("collision evidence");
  await expect(lstat(claim.path)).resolves.toSatisfy((metadata) => metadata.isFile());

  await rm(released);
  await safeRemoveOwnedPublicationClaim(layout, claim);
});

test("retains both release-path inodes when claim cleanup sees a replacement", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "5".repeat(64));
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  let released = "";
  let moved = "";

  await expect(safeRemoveOwnedPublicationClaim(layout, claim, {
    afterRename: async (path) => {
      released = path;
      moved = `${path}.original`;
      const bytes = await readFile(path);
      await rename(path, moved);
      await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
    }
  })).rejects.toThrow(/released publication claim identity changed/i);

  await expect(lstat(claim.path)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(lstat(released)).resolves.toSatisfy((metadata) => metadata.isFile());
  await expect(lstat(moved)).resolves.toSatisfy((metadata) => metadata.isFile());
});

test("classifies absent and present file-publication targets without inventing a claim", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const ordinaryTarget = join(layout.changesets, "reconcile-state.json");
  await expect(reconcileCacheFilePublication(layout, ordinaryTarget))
    .resolves.toEqual({ state: "absent" });
  await writeFile(ordinaryTarget, "present", { mode: 0o600 });
  await expect(reconcileCacheFilePublication(layout, ordinaryTarget))
    .resolves.toEqual({ state: "present" });
});

test("rejects an unowned temporary hard-link name during publication proof", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.root, "unowned-publication-link.bin");
  const linked = deferred<void>();
  const release = deferred<void>();
  let ownedTemporary = "";
  let alternateTemporary = "";
  let decoyDirectory = "";
  const publication = publishExclusiveFile(layout, target, "owned", {
    afterLink: async (temporary) => {
      ownedTemporary = temporary;
      alternateTemporary = join(dirname(temporary), `.${randomUUID()}.tmp`);
      decoyDirectory = join(dirname(temporary), `.${randomUUID()}.tmp`);
      await rename(temporary, alternateTemporary);
      await mkdir(decoyDirectory);
      linked.resolve();
      await release.promise;
      await rm(decoyDirectory, { recursive: true });
      await rename(alternateTemporary, ownedTemporary);
    }
  });
  void publication.catch(() => undefined);
  await linked.promise;

  await expect(validateCacheFile(layout, target, false))
    .rejects.toThrow(/external or unowned hard link/i);
  await expect(lstat(alternateTemporary)).resolves.toSatisfy((metadata) => metadata.nlink === 2);
  release.resolve();
  await expect(publication).resolves.toBeUndefined();
  await expect(readFile(target, "utf8")).resolves.toBe("owned");
});

test("rejects injected exact-removal I/O counts outside the bounded contract", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "invalid-writer-count.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");

  await expect(safeRemoveExactCacheFile(layout, identity, {
    writeRemovalIntentChunk: async () => Number.NaN
  })).rejects.toThrow(/invalid bounded byte count/i);
  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toEqual([]);
});

test("rejects invalid and zero-progress bounded removal-intent reads", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "invalid-reader-count.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  await writeFile(intentPath, `${JSON.stringify(exactRemovalIntentRecord(layout, identity, intentId))}\n`, {
    mode: 0o600
  });

  await expect(reconcileExactRemovalIntents(layout, {
    readRemovalIntentChunk: async () => Number.NaN
  })).rejects.toThrow(/invalid bounded byte count/i);
  await expect(reconcileExactRemovalIntents(layout, {
    readRemovalIntentChunk: async () => 0
  })).rejects.toThrow(/ended before its exact metadata length/i);
  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  await expect(lstat(intentPath)).resolves.toSatisfy((metadata) => metadata.isFile());
});

test("rejects removal intents that escape their parent or quarantine binding", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "malicious-intent-binding.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  const record = exactRemovalIntentRecord(layout, identity, intentId);

  await writeFile(intentPath, `${JSON.stringify({ ...record, targetParent: layout.snapshots })}\n`, { mode: 0o600 });
  await expect(reconcileExactRemovalIntents(layout)).rejects.toThrow(/unexpected parent/i);
  await writeFile(intentPath, `${JSON.stringify({
    ...record,
    quarantinePath: join(layout.locks, `.removed-${randomUUID()}-${identity.dev}-${identity.ino}.data`)
  })}\n`, { mode: 0o600 });
  await expect(reconcileExactRemovalIntents(layout)).rejects.toThrow(/invalid quarantine path/i);

  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  await expect(lstat(intentPath)).resolves.toSatisfy((metadata) => metadata.isFile());
});

test("rejects directory and over-linked removal journal artifacts without mutation", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const directoryIntent = join(layout.locks, `.remove-${randomUUID()}.json`);
  await mkdir(directoryIntent);
  await expect(reconcileExactRemovalIntents(layout)).rejects.toThrow(/ordinary file/i);
  await rm(directoryIntent, { recursive: true });

  const intent = join(layout.locks, `.remove-${randomUUID()}.json`);
  const second = join(root, "outside", "intent-link-two");
  const third = join(root, "outside", "intent-link-three");
  await writeFile(intent, "{}\n", { mode: 0o600 });
  await link(intent, second);
  await link(intent, third);
  await expect(reconcileExactRemovalIntents(layout)).rejects.toThrow(/hard-link count|link count/i);
  await expect(lstat(intent)).resolves.toSatisfy((metadata) => metadata.nlink === 3);
});

test("rejects forged cleanup identity kinds and publication-claim paths", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "7".repeat(64));
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const build = await createOwnedBuildDirectory(layout, layout.indexes);

  await expect(safeRemoveOwnedPublicationClaim(layout, {
    ...claim,
    kind: "directory"
  } as unknown as typeof claim)).rejects.toThrow(/must describe a file/i);
  await expect(safeRemoveOwnedPublicationClaim(layout, {
    ...claim,
    path: join(layout.locks, "forged-claim.json")
  })).rejects.toThrow(/invalid path/i);
  await expect(safeRemoveExactCacheFile(layout, build as unknown as Parameters<typeof safeRemoveExactCacheFile>[1]))
    .rejects.toThrow(/must describe a file/i);

  await safeRemoveOwnedBuildDirectory(layout, build);
  await safeRemoveOwnedPublicationClaim(layout, claim);
});

test("rejects non-directory ancestors and directory leaves at the file boundary", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const nonDirectoryParent = join(layout.changesets, "ordinary-file-parent");
  const directoryLeaf = await createSecureCacheDirectory(layout, join(layout.changesets, "directory-leaf"));
  await writeFile(nonDirectoryParent, "not a directory", { mode: 0o600 });

  await expect(validateCacheFile(layout, join(nonDirectoryParent, "child.json"), false))
    .rejects.toThrow(/component is not a directory/i);
  await expect(validateCacheFile(layout, directoryLeaf, false))
    .rejects.toThrow(/not an ordinary regular file/i);
});

test("rejects distinct malicious removal-intent JSON shapes before recovery", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "malicious-intent-shapes.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  const record = exactRemovalIntentRecord(layout, identity, intentId);
  const cases = [
    { value: [], message: /not an object/i },
    { value: { ...record, unexpected: true }, message: /unexpected schema/i },
    { value: { ...record, dev: "-1" }, message: /invalid dev/i },
    { value: { ...record, targetPath: 42 }, message: /invalid target path/i }
  ];

  for (const entry of cases) {
    await writeFile(intentPath, `${JSON.stringify(entry.value)}\n`, { mode: 0o600 });
    await expect(reconcileExactRemovalIntents(layout)).rejects.toThrow(entry.message);
    await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  }
});

test("rejects occupied initialization names and three-link snapshot claims", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "8".repeat(64));
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const initialization = join(claim.parent, claim.owner.initializationName);
  await writeFile(initialization, "occupied initialization", { flag: "wx", mode: 0o600 });
  await expect(captureOwnedSnapshotPublicationClaim(layout, target))
    .rejects.toThrow(/initialization path is ambiguous/i);
  await rm(initialization);

  const second = join(root, "outside", "claim-link-two");
  const third = join(root, "outside", "claim-link-three");
  await link(claim.path, second);
  await link(claim.path, third);
  await expect(captureOwnedSnapshotPublicationClaim(layout, target))
    .rejects.toThrow(/unexpected hard-link count/i);
  await rm(second);
  await rm(third);
  await safeRemoveOwnedPublicationClaim(layout, claim);
});

test("rejects a three-link cache target before publication-window inspection", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.root, "three-link-window.bin");
  const outside = join(root, "outside", "three-link-window.bin");
  const reached = deferred<void>();
  const release = deferred<void>();
  const publication = publishExclusiveFile(layout, target, "owned", {
    afterLink: async () => {
      await link(target, outside);
      reached.resolve();
      await release.promise;
    }
  });
  void publication.catch(() => undefined);
  await reached.promise;

  await expect(validateCacheFile(layout, target, false))
    .rejects.toThrow(/unexpected hard-link count/i);
  await rm(outside);
  release.resolve();
  await expect(publication).resolves.toBeUndefined();
});

test("inspects a directory decoy before accepting the exact publication temporary", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.root, "directory-decoy-window.bin");
  const decoy = join(layout.root, ".00000000-0000-4000-8000-000000000000.tmp");
  const reached = deferred<void>();
  const release = deferred<void>();
  const publication = publishExclusiveFile(layout, target, "owned", {
    afterLink: async () => {
      await mkdir(decoy);
      reached.resolve();
      await release.promise;
    }
  });
  void publication.catch(() => undefined);
  await reached.promise;

  let inspectedDecoy = false;
  const validation = validateCacheFile(layout, target, false, {
    beforeEnumeratedTemporaryStat: async (path) => {
      if (path !== decoy) return;
      inspectedDecoy = true;
      release.resolve();
    }
  });
  await expect(Promise.all([publication, validation])).resolves.toEqual([undefined, undefined]);
  expect(inspectedDecoy).toBe(true);
  await expect(lstat(decoy)).resolves.toSatisfy((metadata) => metadata.isDirectory());
  await rm(decoy, { recursive: true });
});

test("detects build replacement after a successful post-mkdir hook", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  let created = "";
  let moved = "";

  const failure = await createOwnedBuildDirectory(layout, layout.indexes, {
    afterMkdir: async (identity) => {
      created = identity.path;
      moved = `${identity.path}.original`;
      await rename(identity.path, moved);
      await mkdir(identity.path);
    }
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(AggregateError);
  expect(String((failure as AggregateError).cause)).toMatch(/identity changed after creation/i);
  await expect(lstat(created)).resolves.toSatisfy((metadata) => metadata.isDirectory());
  await expect(lstat(moved)).resolves.toSatisfy((metadata) => metadata.isDirectory());
});

test("retains both temporary inodes after post-write publication replacement", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "temporary-replacement.json");
  let temporary = "";
  let moved = "";

  const failure = await publishExclusiveFile(layout, target, "owned", {
    afterTemporaryCreate: async (path) => {
      temporary = path;
      moved = `${path}.original`;
      await rename(path, moved);
      await writeFile(path, "replacement", { flag: "wx", mode: 0o600 });
    }
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(AggregateError);
  expect(String((failure as AggregateError).cause)).toMatch(/identity changed/i);
  await expect(readFile(temporary, "utf8")).resolves.toBe("replacement");
  await expect(readFile(moved, "utf8")).resolves.toBe("owned");
  await expect(lstat(target)).rejects.toMatchObject({ code: "ENOENT" });
});

test("rejects a third hard link introduced immediately after cache publication", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "post-link-third-link.json");
  const outside = join(root, "outside", "post-link-third-link.json");

  await expect(publishExclusiveFile(layout, target, "owned", {
    afterLink: async (temporary) => { await link(temporary, outside); }
  })).rejects.toThrow(/unexpected hard-link count/i);
  await expect(lstat(target)).resolves.toSatisfy((metadata) => metadata.nlink === 2);
  await expect(readFile(outside, "utf8")).resolves.toBe("owned");
});

test("preserves a completed publication when temporary cleanup itself faults", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "temporary-cleanup-fault.json");
  const primary = new Error("temporary cleanup inspection fault");
  let temporary = "";

  await expect(publishExclusiveFile(layout, target, "owned", {
    afterTemporaryCreate: async (path) => { temporary = path; },
    beforeTemporaryCleanup: async () => { throw primary; }
  })).rejects.toBe(primary);
  await expect(readFile(target, "utf8")).resolves.toBe("owned");
  await expect(readFile(temporary, "utf8")).resolves.toBe("owned");
  await expect(lstat(target)).resolves.toSatisfy((metadata) => metadata.nlink === 2);
});

test("does not remove a pre-existing file that wins the temporary-name race", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "exclusive.json");
  let temporary = "";

  await expect(publishExclusiveFile(layout, target, "new", {
    beforeTemporaryCreate: async (path) => {
      temporary = path;
      await writeFile(path, "pre-existing", { flag: "wx", mode: 0o600 });
    }
  })).rejects.toMatchObject({ code: "EEXIST" });
  await expect(readFile(temporary, "utf8")).resolves.toBe("pre-existing");
});

test("rejects a target swapped after the hard-link publication syscall", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "swapped.json");

  await expect(publishExclusiveFile(layout, target, "owned", {
    afterLink: async (_temporary, published) => {
      await rename(published, `${published}.moved`);
      await writeFile(published, "replacement", { flag: "wx", mode: 0o600 });
    }
  })).rejects.toThrow(/identity|changed|published/i);
});

test("preserves the primary publication error when exact temporary cleanup also fails", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "cleanup-error.json");
  const primary = new Error("primary publication failure");

  const result = publishExclusiveFile(layout, target, "owned", {
    beforeLink: async () => { throw primary; },
    beforeTemporaryCleanup: async (temporary) => {
      await rename(temporary, `${temporary}.moved`);
      await writeFile(temporary, "replacement", { flag: "wx", mode: 0o600 });
    }
  });
  await expect(result).rejects.toSatisfy((error: unknown) =>
    error instanceof AggregateError && error.errors[0] === primary && error.errors.length === 2
  );
});

test.skipIf(process.platform === "win32")("rejects an existing cache file with non-owner-only permissions", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "public.json");
  await writeFile(target, "{}", { mode: 0o600 });
  await chmod(target, 0o644);

  await expect(validateCacheFile(layout, target, false)).rejects.toThrow(/owner|permission|mode/i);
});

test("rejects a cache file with an unexpected external hard link", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "linked.json");
  await writeFile(target, "{}", { mode: 0o600 });
  await link(target, join(root, "outside", "linked.json"));

  await expect(validateCacheFile(layout, target, false)).rejects.toThrow(/hard.?link|link count/i);
});

test("exact removal refuses a last-moment hard-link count change", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "exact-link-change.json");
  const outside = join(root, "outside", "exact-link-change.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const hooks = {
    beforeExactRemovalUnlink: async () => { await link(target, outside); }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    beforeExactRemovalUnlink(path: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/hard.?link|link count/i);
  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  await expect(readFile(outside, "utf8")).resolves.toBe("evidence");
});

test.skipIf(process.platform === "win32")("exact removal refuses a last-moment mode change", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "exact-mode-change.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const hooks = {
    beforeExactRemovalUnlink: async () => { await chmod(target, 0o644); }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    beforeExactRemovalUnlink(path: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/owner|permission|mode/i);
  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
});

test.runIf(process.platform !== "win32" && typeof process.getuid === "function" && process.getuid() === 0)(
  "exact removal refuses a last-moment owner change",
  async () => {
    const root = await fixtureRoot();
    const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
    const target = join(layout.changesets, "exact-owner-change.json");
    await writeFile(target, "evidence", { mode: 0o600 });
    const identity = await captureSecurePathIdentity(layout, target, "file");
    const hooks = {
      beforeExactRemovalUnlink: async () => { await chown(target, 65_534, 65_534); }
    } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
      beforeExactRemovalUnlink(path: string): Promise<void>;
    };

    await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/ownership|owner/i);
    await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  }
);

test("retains durable exact-removal evidence when a post-unlink fault occurs", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "exact-removal-fault.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const primary = new Error("simulated power loss after unlink");
  const hooks = {
    afterExactRemovalUnlink: async () => { throw primary; }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    afterExactRemovalUnlink(path: string, intentPath: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toBe(primary);
  await expect(stat(target)).rejects.toMatchObject({ code: "ENOENT" });
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toHaveLength(1);
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".removed-"))).toHaveLength(1);
});

test("syncs an exact-removal intent before and after unlink", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "exact-removal-order.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const phases: string[] = [];
  const hooks = {
    afterRemovalIntentFileSync: async (_intent: string, phase: string) => { phases.push(phase); }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    afterRemovalIntentFileSync(intentPath: string, phase: string): Promise<void>;
  };

  await safeRemoveExactCacheFile(layout, identity, hooks);

  expect(phases).toEqual(["prepared", "unlinked"]);
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toEqual([]);
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".removed-"))).toEqual([]);
});

test("does not expose a final removal intent while candidate bytes are partial", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "partial-intent-target.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const primary = new Error("crash during candidate write");
  let finalPath = "";
  const hooks = {
    duringRemovalIntentCandidateWrite: async (_candidate: string, published: string) => {
      finalPath = published;
      await expect(stat(published)).rejects.toMatchObject({ code: "ENOENT" });
      throw primary;
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    duringRemovalIntentCandidateWrite(candidatePath: string, finalPath: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toBe(primary);

  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  await expect(stat(finalPath)).rejects.toMatchObject({ code: "ENOENT" });
});

test("publishes a complete parseable removal intent at first final-name visibility", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "atomic-intent-target.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const primary = new Error("crash after atomic intent publication");
  let observed = false;
  const hooks = {
    afterRemovalIntentLink: async (candidate: string, published: string) => {
      const [candidateBytes, finalBytes, candidateMetadata, finalMetadata] = await Promise.all([
        readFile(candidate),
        readFile(published),
        stat(candidate),
        stat(published)
      ]);
      expect(JSON.parse(finalBytes.toString("utf8"))).toMatchObject({ targetPath: target });
      expect(finalBytes).toEqual(candidateBytes);
      expect(finalMetadata.ino).toBe(candidateMetadata.ino);
      expect(finalMetadata.nlink).toBe(2);
      observed = true;
      throw primary;
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    afterRemovalIntentLink(candidatePath: string, finalPath: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toBe(primary);

  expect(observed).toBe(true);
  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-") && name.endsWith(".json"))).toHaveLength(1);
});

test("loops over one-byte candidate writes before publishing an exact removal intent", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "one-byte-write-target.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  let writes = 0;
  const hooks = {
    writeRemovalIntentChunk: async (
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ) => {
      writes += 1;
      return (await handle.write(buffer, offset, Math.min(length, 1), position)).bytesWritten;
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    writeRemovalIntentChunk(
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ): Promise<number>;
  };

  await safeRemoveExactCacheFile(layout, identity, hooks);

  expect(writes).toBeGreaterThan(2);
  await expect(stat(target)).rejects.toMatchObject({ code: "ENOENT" });
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove"))).toEqual([]);
});

test("fails a zero-byte candidate write before final intent publication", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "zero-write-target.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const hooks = {
    writeRemovalIntentChunk: async () => 0
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    writeRemovalIntentChunk(
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ): Promise<number>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/zero|write|progress/i);

  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  expect((await readdir(layout.locks)).filter((name) => name.endsWith(".json"))).toEqual([]);
});

test("cleans a partially written candidate after a later write fault without publishing final intent", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "partial-second-write-target.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const primary = new Error("candidate write fault");
  let writes = 0;
  const hooks = {
    writeRemovalIntentChunk: async (
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ) => {
      writes += 1;
      if (writes === 3) throw primary;
      const boundedLength = writes === 2 ? 1 : length;
      return (await handle.write(buffer, offset, boundedLength, position)).bytesWritten;
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    writeRemovalIntentChunk(
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ): Promise<number>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toBe(primary);

  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove"))).toEqual([]);
});

test("rescans exact physical-byte headroom after a candidate write mutation before writing the remainder", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const maximumJournalBytes = changesetRemovalRecoveryLimits.maxBytes;
  const fixedArtifactBytes = 10 * recoveryFixtureArtifactBytes;
  for (let index = 0; index < 10; index += 1) {
    const path = join(layout.locks, `.removed-${randomUUID()}.data`);
    const artifact = await open(path, "wx", 0o600);
    try { await artifact.truncate(recoveryFixtureArtifactBytes); } finally { await artifact.close(); }
  }
  const growerPath = join(layout.locks, `.removed-${randomUUID()}.data`);
  const grower = await open(growerPath, "wx", 0o600);
  try { await grower.truncate(7 * 1024 * 1024); } finally { await grower.close(); }
  const target = join(layout.changesets, "candidate-midwrite-byte-headroom-target.json");
  await writeFile(target, "x", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const overLimitWrite = new Error("remaining candidate bytes became visible above the journal limit");
  let candidatePath = "";
  let bytesAtMutationReturn = 0;
  let maximumVisibleBytes = 0;
  let writerCalls = 0;
  const hooks = {
    writeRemovalIntentChunk: async (
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ) => {
      writerCalls += 1;
      return (await handle.write(buffer, offset, length, position)).bytesWritten;
    },
    duringRemovalIntentCandidateWrite: async (candidate: string) => {
      candidatePath = candidate;
      const partialBytes = (await stat(candidate)).size;
      const exactGrowerBytes = maximumJournalBytes - fixedArtifactBytes - partialBytes;
      const artifact = await open(growerPath, "r+");
      try { await artifact.truncate(exactGrowerBytes); } finally { await artifact.close(); }
      bytesAtMutationReturn = fixedArtifactBytes + exactGrowerBytes + partialBytes;
      maximumVisibleBytes = bytesAtMutationReturn;
    },
    removalRecoveryNow: () => {
      if (candidatePath) {
        const visibleBytes = fixedArtifactBytes + statSync(growerPath).size + statSync(candidatePath).size;
        maximumVisibleBytes = Math.max(maximumVisibleBytes, visibleBytes);
        if (visibleBytes > maximumJournalBytes) throw overLimitWrite;
      }
      return 0;
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    writeRemovalIntentChunk(
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ): Promise<number>;
    duringRemovalIntentCandidateWrite(candidatePath: string, finalPath: string): Promise<void>;
  };

  let failure: unknown;
  try {
    await safeRemoveExactCacheFile(layout, identity, hooks);
  } catch (error) {
    failure = error;
  }

  expect(bytesAtMutationReturn).toBe(maximumJournalBytes);
  expect(maximumVisibleBytes).toBe(maximumJournalBytes);
  expect(writerCalls).toBe(1);
  expect(failure).toBeInstanceOf(Error);
  expect((failure as Error).message).toMatch(/headroom|bytes|limit/i);
  const candidate = await stat(candidatePath);
  expect(candidate.size).toBeGreaterThan(0);
  expect(candidate.size).toBeLessThan(4 * 1024);
  await expect(readFile(target, "utf8")).resolves.toBe("x");
  expect((await readdir(layout.locks)).filter((name) => /^\.remove-.*\.json$/u.test(name))).toEqual([]);
});

test("moves short-write completion into the callback-free window after the candidate mutation hook", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "candidate-short-write-final-window-target.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  let callbackWrites = 0;
  let callbackWritesAtMutation = 0;
  const hooks = {
    writeRemovalIntentChunk: async (
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ) => {
      callbackWrites += 1;
      return (await handle.write(buffer, offset, Math.min(length, 1), position)).bytesWritten;
    },
    duringRemovalIntentCandidateWrite: async () => {
      callbackWritesAtMutation = callbackWrites;
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    writeRemovalIntentChunk(
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ): Promise<number>;
    duringRemovalIntentCandidateWrite(candidatePath: string, finalPath: string): Promise<void>;
  };

  await safeRemoveExactCacheFile(layout, identity, hooks);

  expect(callbackWritesAtMutation).toBeGreaterThan(2);
  expect(callbackWrites).toBe(callbackWritesAtMutation);
  await expect(stat(target)).rejects.toMatchObject({ code: "ENOENT" });
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove"))).toEqual([]);
});

test("keeps a concurrent removal behind callback-free short-write completion", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const firstTarget = join(layout.changesets, "candidate-short-write-concurrent-first.json");
  const secondTarget = join(layout.changesets, "candidate-short-write-concurrent-second.json");
  await Promise.all([
    writeFile(firstTarget, "first", { mode: 0o600 }),
    writeFile(secondTarget, "second", { mode: 0o600 })
  ]);
  const [firstIdentity, secondIdentity] = await Promise.all([
    captureSecurePathIdentity(layout, firstTarget, "file"),
    captureSecurePathIdentity(layout, secondTarget, "file")
  ]);
  const mutationEntered = deferred<void>();
  const releaseMutation = deferred<void>();
  let firstCallbackWrites = 0;
  let writesAtMutation = 0;
  let secondEntered = false;
  const first = safeRemoveExactCacheFile(layout, firstIdentity, {
    writeRemovalIntentChunk: async (handle, buffer, offset, length, position) => {
      firstCallbackWrites += 1;
      return (await handle.write(buffer, offset, Math.min(length, 1), position)).bytesWritten;
    },
    duringRemovalIntentCandidateWrite: async () => {
      writesAtMutation = firstCallbackWrites;
      mutationEntered.resolve();
      await releaseMutation.promise;
    }
  });
  await mutationEntered.promise;
  const second = safeRemoveExactCacheFile(layout, secondIdentity, {
    duringRemovalIntentCandidateWrite: async () => { secondEntered = true; }
  });
  await new Promise((resolve) => setTimeout(resolve, 25));
  expect(secondEntered).toBe(false);
  releaseMutation.resolve();

  await expect(Promise.all([first, second])).resolves.toEqual([undefined, undefined]);

  expect(firstCallbackWrites).toBe(writesAtMutation);
  expect(secondEntered).toBe(true);
  await expect(stat(firstTarget)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(stat(secondTarget)).rejects.toMatchObject({ code: "ENOENT" });
});

test("preserves a malformed hard-linked candidate and final marker before recovery parsing", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const removalId = randomUUID();
  const candidate = join(layout.locks, `.remove-${removalId}.owner-${randomUUID()}.tmp`);
  const intent = join(layout.locks, `.remove-${removalId}.json`);
  await writeFile(candidate, "{malformed", { mode: 0o600 });
  await link(candidate, intent);

  await expect(reconcileExactRemovalIntents(layout)).rejects.toThrow(/valid JSON|intent|malformed/i);

  await expect(readFile(candidate, "utf8")).resolves.toBe("{malformed");
  await expect(readFile(intent, "utf8")).resolves.toBe("{malformed");
  await expect(stat(candidate)).resolves.toMatchObject({ nlink: 2 });
});

test.each([
  { label: "growth", mutate: async (path: string) => {
    const handle = await open(path, "r+");
    try { await handle.truncate(4_097); } finally { await handle.close(); }
  } },
  { label: "truncation", mutate: async (path: string) => {
    const handle = await open(path, "r+");
    try { await handle.truncate(1); } finally { await handle.close(); }
  } }
])("preserves candidate and final evidence after same-inode $label before final use", async ({ mutate }) => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "paired-final-mutation-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const removalId = randomUUID();
  const candidate = join(layout.locks, `.remove-${removalId}.owner-${randomUUID()}.tmp`);
  const intent = join(layout.locks, `.remove-${removalId}.json`);
  await writeFile(candidate, `${JSON.stringify({
    version: 1,
    targetPath: identity.path,
    targetParent: identity.parent,
    quarantinePath: join(layout.locks, `.removed-${removalId}-${identity.dev}-${identity.ino}.data`),
    dev: String(identity.dev),
    ino: String(identity.ino),
    parentDev: String(identity.parentDev),
    parentIno: String(identity.parentIno)
  })}\n`, { mode: 0o600 });
  await link(candidate, intent);
  let mutated = false;
  const hooks = {
    beforeRemovalArtifactUse: async (path: string, kind: string) => {
      if (!mutated && path === intent && kind === "intent") {
        mutated = true;
        await mutate(path);
      }
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    beforeRemovalArtifactUse(path: string, kind: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/intent|bytes|size|JSON|changed|limit/i);

  await expect(stat(candidate)).resolves.toMatchObject({ nlink: 2 });
  await expect(stat(intent)).resolves.toMatchObject({ nlink: 2 });
  await expect(readFile(target, "utf8")).resolves.toBe("original");
});

test("retains a fresh pre-link removal candidate and exactly cleans it after one changeset lifetime", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const candidate = join(layout.locks, `.remove-${randomUUID()}.owner-${randomUUID()}.tmp`);
  await writeFile(candidate, "partial", { mode: 0o600 });

  await reconcileExactRemovalIntents(layout);
  await expect(readFile(candidate, "utf8")).resolves.toBe("partial");

  const old = new Date(Date.now() - 30 * 60 * 1000 - 1);
  await utimes(candidate, old, old);
  await reconcileExactRemovalIntents(layout);
  await expect(stat(candidate)).rejects.toMatchObject({ code: "ENOENT" });
});

test("reserves two lock-directory entries before publishing removal journal names", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  for (let offset = 0; offset < 1_023; offset += 64) {
    await Promise.all(Array.from({ length: Math.min(64, 1_023 - offset) }, async (_, index) => {
      await writeFile(join(layout.locks, `task8-headroom-${offset + index}.lock`), "owned", { mode: 0o600 });
    }));
  }
  const before = (await readdir(layout.locks)).sort();
  const target = join(layout.changesets, "entry-headroom-target.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");

  await expect(safeRemoveExactCacheFile(layout, identity)).rejects.toThrow(/headroom|entr|1024|limit/i);

  expect((await readdir(layout.locks)).sort()).toEqual(before);
  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
});

test("reserves physical journal bytes before moving a maximum-sized target", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const evidence: string[] = [];
  for (let index = 0; index < 10; index += 1) {
    const path = join(layout.locks, `.removed-${randomUUID()}.data`);
    const handle = await open(path, "wx", 0o600);
    try { await handle.truncate(recoveryFixtureArtifactBytes); } finally { await handle.close(); }
    evidence.push(path);
  }
  const target = join(layout.changesets, "byte-headroom-target.json");
  const targetHandle = await open(target, "wx", 0o600);
  try { await targetHandle.truncate(changesetRemovalRecoveryLimits.maxArtifactBytes); } finally { await targetHandle.close(); }
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const before = (await readdir(layout.locks)).sort();

  await expect(safeRemoveExactCacheFile(layout, identity)).rejects.toThrow(/headroom|bytes|limit/i);

  expect((await readdir(layout.locks)).sort()).toEqual(before);
  await expect(stat(target)).resolves.toMatchObject({ size: changesetRemovalRecoveryLimits.maxArtifactBytes });
  await expect(stat(evidence[0]!)).resolves.toMatchObject({ size: recoveryFixtureArtifactBytes });
});

test("serializes concurrent removal journal headroom reservations and preserves the refused target", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  for (let offset = 0; offset < 1_022; offset += 64) {
    await Promise.all(Array.from({ length: Math.min(64, 1_022 - offset) }, async (_, index) => {
      await writeFile(join(layout.locks, `task8-concurrent-${offset + index}.lock`), "owned", { mode: 0o600 });
    }));
  }
  const firstTarget = join(layout.changesets, "concurrent-headroom-first.json");
  const secondTarget = join(layout.changesets, "concurrent-headroom-second.json");
  await writeFile(firstTarget, "first", { mode: 0o600 });
  await writeFile(secondTarget, "second", { mode: 0o600 });
  const firstIdentity = await captureSecurePathIdentity(layout, firstTarget, "file");
  const secondIdentity = await captureSecurePathIdentity(layout, secondTarget, "file");
  const primary = new Error("pause with published journal evidence");
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  let published!: () => void;
  const visible = new Promise<void>((resolve) => { published = resolve; });
  const first = safeRemoveExactCacheFile(layout, firstIdentity, {
    afterRemovalIntentLink: async () => {
      published();
      await held;
      throw primary;
    }
  });
  await visible;
  let secondVisibleEntries = 0;
  const second = safeRemoveExactCacheFile(layout, secondIdentity, {
    afterRemovalIntentLink: async () => {
      secondVisibleEntries = (await readdir(layout.locks)).length;
    }
  });
  const releaseTimer = setTimeout(release, 25);

  await expect(first).rejects.toBe(primary);
  await expect(second).resolves.toBeUndefined();
  clearTimeout(releaseTimer);
  expect(secondVisibleEntries).toBeLessThanOrEqual(1_024);
  await expect(stat(firstTarget)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(stat(secondTarget)).rejects.toMatchObject({ code: "ENOENT" });
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toEqual([]);
});

test("rechecks journal entry headroom after the last pre-link hook", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  for (let offset = 0; offset < 1_022; offset += 64) {
    await Promise.all(Array.from({ length: Math.min(64, 1_022 - offset) }, async (_, index) => {
      await writeFile(join(layout.locks, `task8-prelink-${offset + index}.lock`), "owned", { mode: 0o600 });
    }));
  }
  const target = join(layout.changesets, "prelink-entry-race-target.json");
  await writeFile(target, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const raced = join(layout.locks, "task8-prelink-race.lock");

  await expect(safeRemoveExactCacheFile(layout, identity, {
    beforeRemovalIntentLink: async () => {
      await writeFile(raced, "raced", { flag: "wx", mode: 0o600 });
    }
  })).rejects.toThrow(/headroom|entr|1024|limit/i);

  await expect(readFile(target, "utf8")).resolves.toBe("evidence");
  await expect(readFile(raced, "utf8")).resolves.toBe("raced");
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toEqual([]);
});

test("rechecks target and existing physical bytes after the last pre-link hook", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  for (let index = 0; index < 10; index += 1) {
    const path = join(layout.locks, `.removed-${randomUUID()}.data`);
    const handle = await open(path, "wx", 0o600);
    try { await handle.truncate(recoveryFixtureArtifactBytes); } finally { await handle.close(); }
  }
  const target = join(layout.changesets, "prelink-byte-race-target.json");
  const targetHandle = await open(target, "wx", 0o600);
  try { await targetHandle.truncate(1024 * 1024); } finally { await targetHandle.close(); }
  const identity = await captureSecurePathIdentity(layout, target, "file");

  await expect(safeRemoveExactCacheFile(layout, identity, {
    beforeRemovalIntentLink: async () => {
      const handle = await open(target, "r+");
      try { await handle.truncate(9 * 1024 * 1024); } finally { await handle.close(); }
    }
  })).rejects.toThrow(/headroom|bytes|limit/i);

  await expect(stat(target)).resolves.toMatchObject({ size: 9 * 1024 * 1024 });
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toEqual([]);
});

test("refuses recovery before a full lock directory can expose a quarantine entry", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  for (let offset = 0; offset < 1_023; offset += 64) {
    await Promise.all(Array.from({ length: Math.min(64, 1_023 - offset) }, async (_, index) => {
      await writeFile(join(layout.locks, `task8-recovery-${offset + index}.lock`), "owned", { mode: 0o600 });
    }));
  }
  const target = join(layout.changesets, "full-directory-recovery-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  await writeFile(intentPath, `${JSON.stringify({
    version: 1,
    targetPath: identity.path,
    targetParent: identity.parent,
    quarantinePath: join(layout.locks, `.removed-${intentId}-${identity.dev}-${identity.ino}.data`),
    dev: String(identity.dev),
    ino: String(identity.ino),
    parentDev: String(identity.parentDev),
    parentIno: String(identity.parentIno)
  })}\n`, { mode: 0o600 });
  let visibleEntries = 0;

  await expect(reconcileExactRemovalIntents(layout, {
    afterExactRemovalUnlink: async () => {
      visibleEntries = Math.max(visibleEntries, (await readdir(layout.locks)).length);
    }
  })).rejects.toThrow(/headroom|entr|1024|limit/i);

  expect(visibleEntries).toBeLessThanOrEqual(1_024);
  await expect(readFile(target, "utf8")).resolves.toBe("original");
  await expect(stat(intentPath)).resolves.toMatchObject({ size: expect.any(Number) });
});

test("reobserves an absent target when a replacement appears before removal recovery", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "recovery-resample-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  await rm(target);
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  await writeFile(intentPath, `${JSON.stringify({
    version: 1,
    targetPath: identity.path,
    targetParent: identity.parent,
    quarantinePath: join(layout.locks, `.removed-${intentId}.data`),
    dev: String(identity.dev),
    ino: String(identity.ino),
    parentDev: String(identity.parentDev),
    parentIno: String(identity.parentIno)
  })}\n`, { mode: 0o600 });
  const hooks = {
    beforeExactRemovalRecovery: async () => {
      await writeFile(target, "replacement", { flag: "wx", mode: 0o600 });
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    beforeExactRemovalRecovery(intentPath: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/replacement|identity|evidence/i);

  await expect(readFile(target, "utf8")).resolves.toBe("replacement");
  expect(JSON.parse(await readFile(intentPath, "utf8"))).toMatchObject({ targetPath: identity.path });
});

test("reobserves target and evidence immediately before clearing a completed intent", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "completion-resample-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  await writeFile(intentPath, `${JSON.stringify({
    version: 1,
    targetPath: identity.path,
    targetParent: identity.parent,
    quarantinePath: join(layout.locks, `.removed-${intentId}.data`),
    dev: String(identity.dev),
    ino: String(identity.ino),
    parentDev: String(identity.parentDev),
    parentIno: String(identity.parentIno)
  })}\n`, { mode: 0o600 });
  const hooks = {
    beforeExactRemovalCompletion: async () => {
      await writeFile(target, "replacement", { flag: "wx", mode: 0o600 });
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    beforeExactRemovalCompletion(intentPath: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/replacement|identity|evidence/i);

  await expect(readFile(target, "utf8")).resolves.toBe("replacement");
  expect(JSON.parse(await readFile(intentPath, "utf8"))).toMatchObject({ targetPath: identity.path });
});

test("bounds lock-directory enumeration without misclassifying Task-8 lock files", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  for (let offset = 0; offset < 1_025; offset += 64) {
    await Promise.all(Array.from({ length: Math.min(64, 1_025 - offset) }, async (_, index) => {
      await writeFile(join(layout.locks, `task8-${offset + index}.lock`), "owned", { mode: 0o600 });
    }));
  }

  await expect(reconcileExactRemovalIntents(layout)).rejects.toThrow(/lock.*entr|recovery.*entr|1024|limit/i);

  await expect(readFile(join(layout.locks, "task8-0.lock"), "utf8")).resolves.toBe("owned");
  await expect(readFile(join(layout.locks, "task8-1024.lock"), "utf8")).resolves.toBe("owned");
});

test("charges retained fresh removal candidates without deleting unrelated lock files", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const candidate = join(layout.locks, `.remove-${randomUUID()}.owner-${randomUUID()}.tmp`);
  const candidateBytes = Buffer.from("fresh candidate", "utf8");
  await writeFile(candidate, candidateBytes, { mode: 0o600 });
  const unrelated = join(layout.locks, "task8-project.lock");
  await writeFile(unrelated, "owned", { mode: 0o600 });

  const usage = await reconcileExactRemovalIntents(layout);

  expect(usage).toEqual({ retainedEntries: 1, retainedBytes: candidateBytes.byteLength });
  await expect(readFile(candidate)).resolves.toEqual(candidateBytes);
  await expect(readFile(unrelated, "utf8")).resolves.toBe("owned");
});

test("bounds aggregate removal-recovery artifact bytes independently of entry count", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const artifacts: string[] = [];
  for (let index = 0; index < 11; index += 1) {
    const path = join(layout.locks, `.removed-${randomUUID()}.data`);
    const handle = await open(path, "wx", 0o600);
    try {
      await handle.truncate(recoveryFixtureArtifactBytes);
    } finally {
      await handle.close();
    }
    artifacts.push(path);
  }

  await expect(reconcileExactRemovalIntents(layout)).rejects.toThrow(/recovery bytes|limit/i);

  await expect(stat(artifacts[0]!)).resolves.toMatchObject({ size: recoveryFixtureArtifactBytes });
  await expect(stat(artifacts.at(-1)!)).resolves.toMatchObject({ size: recoveryFixtureArtifactBytes });
});

test("enforces a monotonic deadline while preserving fresh removal residue", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const candidate = join(layout.locks, `.remove-${randomUUID()}.owner-${randomUUID()}.tmp`);
  await writeFile(candidate, "fresh", { mode: 0o600 });
  let monotonicMs = 0;
  const hooks = {
    removalRecoveryNow: () => {
      monotonicMs += 20_000;
      return monotonicMs;
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & { removalRecoveryNow(): number };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/deadline|milliseconds/i);
  await expect(readFile(candidate, "utf8")).resolves.toBe("fresh");
});

test("loops over legal short reads and verifies exact EOF for a removal intent", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "short-read-intent-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  await writeFile(intentPath, `${JSON.stringify({
    version: 1,
    targetPath: identity.path,
    targetParent: identity.parent,
    quarantinePath: join(layout.locks, `.removed-${intentId}.data`),
    dev: String(identity.dev),
    ino: String(identity.ino),
    parentDev: String(identity.parentDev),
    parentIno: String(identity.parentIno)
  })}\n`, { mode: 0o600 });
  let reads = 0;
  const hooks = {
    readRemovalIntentChunk: async (
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ) => {
      reads += 1;
      return (await handle.read(buffer, offset, Math.min(length, 7), position)).bytesRead;
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    readRemovalIntentChunk(
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ): Promise<number>;
  };

  await reconcileExactRemovalIntents(layout, hooks);

  expect(reads).toBeGreaterThan(1);
  await expect(stat(target)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(stat(intentPath)).rejects.toMatchObject({ code: "ENOENT" });
});

test("charges each one-byte intent read to the reachable shared recovery work limit", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "work-limit-intent-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  const serialized = JSON.stringify({
    version: 1,
    targetPath: identity.path,
    targetParent: identity.parent,
    quarantinePath: join(layout.locks, `.removed-${intentId}.data`),
    dev: String(identity.dev),
    ino: String(identity.ino),
    parentDev: String(identity.parentDev),
    parentIno: String(identity.parentIno)
  });
  await writeFile(intentPath, `${serialized}${" ".repeat(4_096 - serialized.length)}`, { mode: 0o600 });
  let reads = 0;
  const hooks = {
    readRemovalIntentChunk: async (
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      _length: number,
      position: number
    ) => {
      reads += 1;
      return (await handle.read(buffer, offset, 1, position)).bytesRead;
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    readRemovalIntentChunk(
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ): Promise<number>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/work|4096|limit/i);

  expect(reads).toBeLessThanOrEqual(4_096);
  await expect(readFile(target, "utf8")).resolves.toBe("original");
  await expect(stat(intentPath)).resolves.toMatchObject({ size: 4_096 });
});

test("checks the shared deadline after a final artifact read before recovery mutation", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "deadline-after-read-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  await writeFile(intentPath, `${JSON.stringify({
    version: 1,
    targetPath: identity.path,
    targetParent: identity.parent,
    quarantinePath: join(layout.locks, `.removed-${intentId}.data`),
    dev: String(identity.dev),
    ino: String(identity.ino),
    parentDev: String(identity.parentDev),
    parentIno: String(identity.parentIno)
  })}\n`, { mode: 0o600 });
  let expired = false;
  const hooks = {
    removalRecoveryNow: () => expired ? 30_001 : 0,
    readRemovalIntentChunk: async (
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ) => {
      const result = await handle.read(buffer, offset, length, position);
      expired = true;
      return result.bytesRead;
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    readRemovalIntentChunk(
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ): Promise<number>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/deadline|30000|milliseconds/i);

  await expect(readFile(target, "utf8")).resolves.toBe("original");
  await expect(stat(intentPath)).resolves.toMatchObject({ size: expect.any(Number) });
});

test("revalidates and charges a fresh candidate size changed between scan and use", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const candidate = join(layout.locks, `.remove-${randomUUID()}.owner-${randomUUID()}.tmp`);
  await writeFile(candidate, "x", { mode: 0o600 });
  let changed = false;
  const hooks = {
    beforeRemovalArtifactUse: async (path: string, kind: string) => {
      if (!changed && path === candidate && kind === "candidate") {
        changed = true;
        await writeFile(path, "x".repeat(100), { mode: 0o600 });
      }
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    beforeRemovalArtifactUse(path: string, kind: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).resolves.toEqual({ retainedEntries: 1, retainedBytes: 100 });
  await expect(stat(candidate)).resolves.toMatchObject({ size: 100 });
});

test("rejects a quarantine grown above its artifact limit before syncing or deleting it", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const provisional = join(layout.locks, "quarantine-growth-provisional");
  await writeFile(provisional, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, provisional, "file");
  const quarantine = join(layout.locks, `.removed-${randomUUID()}-${identity.dev}-${identity.ino}.data`);
  await rename(provisional, quarantine);
  const hooks = {
    beforeRemovalArtifactUse: async (path: string, kind: string) => {
      if (path === quarantine && kind === "quarantine") {
        const handle = await open(path, "r+");
        try { await handle.truncate(changesetRemovalRecoveryLimits.maxArtifactBytes + 1); } finally { await handle.close(); }
      }
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    beforeRemovalArtifactUse(path: string, kind: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/quarantine|artifact|bytes|limit/i);

  await expect(stat(quarantine)).resolves.toMatchObject({ size: changesetRemovalRecoveryLimits.maxArtifactBytes + 1 });
});

test("revalidates aggregate bytes after a retained artifact grows between scan and use", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  for (let index = 0; index < 10; index += 1) {
    const path = join(layout.locks, `.removed-${randomUUID()}.data`);
    const handle = await open(path, "wx", 0o600);
    try { await handle.truncate(recoveryFixtureArtifactBytes); } finally { await handle.close(); }
  }
  const growing = join(layout.locks, `.removed-${randomUUID()}.data`);
  await writeFile(growing, "x", { mode: 0o600 });
  const hooks = {
    beforeRemovalArtifactUse: async (path: string, kind: string) => {
      if (path === growing && kind === "legacy-quarantine") {
        const handle = await open(path, "r+");
        try { await handle.truncate(9 * 1024 * 1024); } finally { await handle.close(); }
      }
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    beforeRemovalArtifactUse(path: string, kind: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/recovery bytes|limit/i);

  await expect(stat(growing)).resolves.toMatchObject({ size: 9 * 1024 * 1024 });
});

test.each(["malformed", "different-valid"] as const)(
  "refuses to publish a $mode durable intent mutated by the last pre-link hook",
  async (mode) => {
    const root = await fixtureRoot();
    const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
    const target = join(layout.changesets, `pre-link-${mode}-target.json`);
    const alternate = join(layout.changesets, `pre-link-${mode}-alternate.json`);
    await writeFile(target, "original", { mode: 0o600 });
    await writeFile(alternate, "alternate", { mode: 0o600 });
    const identity = await captureSecurePathIdentity(layout, target, "file");
    const alternateIdentity = await captureSecurePathIdentity(layout, alternate, "file");
    let candidatePath = "";
    let intentPath = "";
    const hooks = {
      beforeRemovalIntentLink: async (candidate: string, intent: string) => {
        candidatePath = candidate;
        intentPath = intent;
        if (mode === "malformed") {
          await writeFile(candidate, "{malformed", { mode: 0o600 });
          return;
        }
        const removalId = basename(intent).slice(".remove-".length, -".json".length);
        await writeFile(candidate, `${JSON.stringify({
          version: 1,
          targetPath: alternateIdentity.path,
          targetParent: alternateIdentity.parent,
          quarantinePath: join(layout.locks, `.removed-${removalId}-${alternateIdentity.dev}-${alternateIdentity.ino}.data`),
          dev: String(alternateIdentity.dev),
          ino: String(alternateIdentity.ino),
          parentDev: String(alternateIdentity.parentDev),
          parentIno: String(alternateIdentity.parentIno)
        })}\n`, { mode: 0o600 });
      }
    } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
      beforeRemovalIntentLink(candidatePath: string, finalPath: string): Promise<void>;
    };

    await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/intent|expected|bytes|changed/i);

    await expect(readFile(target, "utf8")).resolves.toBe("original");
    await expect(readFile(alternate, "utf8")).resolves.toBe("alternate");
    await expect(readFile(candidatePath, "utf8")).resolves.toBeTruthy();
    await expect(stat(intentPath)).rejects.toMatchObject({ code: "ENOENT" });
  }
);

test("preserves both names when a post-link hook substitutes another valid intent", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "post-link-authoritative-target.json");
  const alternate = join(layout.changesets, "post-link-authoritative-alternate.json");
  await writeFile(target, "original", { mode: 0o600 });
  await writeFile(alternate, "alternate", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const alternateIdentity = await captureSecurePathIdentity(layout, alternate, "file");
  let candidatePath = "";
  let intentPath = "";
  const hooks = {
    afterRemovalIntentLink: async (candidate: string, intent: string) => {
      candidatePath = candidate;
      intentPath = intent;
      const removalId = basename(intent).slice(".remove-".length, -".json".length);
      await writeFile(intent, `${JSON.stringify({
        version: 1,
        targetPath: alternateIdentity.path,
        targetParent: alternateIdentity.parent,
        quarantinePath: join(layout.locks, `.removed-${removalId}-${alternateIdentity.dev}-${alternateIdentity.ino}.data`),
        dev: String(alternateIdentity.dev),
        ino: String(alternateIdentity.ino),
        parentDev: String(alternateIdentity.parentDev),
        parentIno: String(alternateIdentity.parentIno)
      })}\n`, { mode: 0o600 });
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    afterRemovalIntentLink(candidatePath: string, finalPath: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/intent|expected|semantic|changed/i);

  await expect(readFile(target, "utf8")).resolves.toBe("original");
  await expect(readFile(alternate, "utf8")).resolves.toBe("alternate");
  await expect(stat(candidatePath)).resolves.toMatchObject({ nlink: 2 });
  await expect(stat(intentPath)).resolves.toMatchObject({ nlink: 2 });
});

test("revalidates authoritative intent bytes after a directory-sync mutation hook", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "directory-sync-intent-mutation-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  let mutatedIntent = "";
  const hooks = {
    afterParentDirectorySync: async () => {
      if (mutatedIntent) return;
      const names = await readdir(layout.locks);
      const intentName = names.find((name) => name.startsWith(".remove-") && name.endsWith(".json"));
      const quarantineName = names.find((name) => name.startsWith(".removed-") && name.endsWith(".data"));
      if (!intentName || !quarantineName) return;
      try {
        await stat(target);
        return;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      mutatedIntent = join(layout.locks, intentName);
      await writeFile(mutatedIntent, "{mutated-after-directory-sync", { mode: 0o600 });
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    afterParentDirectorySync(directory: string, outcome: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/intent|expected|bytes|JSON/i);

  expect(mutatedIntent).not.toBe("");
  await expect(stat(mutatedIntent)).resolves.toMatchObject({ size: expect.any(Number) });
  expect((await readdir(layout.locks)).some((name) => name.startsWith(".removed-"))).toBe(true);
});

test("performs a hook-free authoritative intent read after a close hook mutates equal-length bytes", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "close-hook-intent-mutation-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  let mutatedIntent = "";
  let eligibleCloses = 0;
  const hooks = {
    closeExactRemovalResource: async (
      resource: { close(): Promise<void> },
      path: string,
      kind: string
    ) => {
      await resource.close();
      if (mutatedIntent || kind !== "file" || !path.endsWith(".json")) return;
      try {
        await stat(target);
        return;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      if ((await readdir(layout.locks)).some((name) => name.startsWith(".removed-"))) return;
      eligibleCloses += 1;
      if (eligibleCloses !== 2) return;
      const size = (await stat(path)).size;
      mutatedIntent = path;
      await writeFile(path, "{".padEnd(size, " "), { mode: 0o600 });
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    closeExactRemovalResource(resource: { close(): Promise<void> }, path: string, kind: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/intent|expected|bytes|JSON/i);

  expect(mutatedIntent).not.toBe("");
  await expect(stat(mutatedIntent)).resolves.toMatchObject({ size: expect.any(Number) });
});

test.each(["directory", "file"] as const)(
  "closes a newly acquired $kind resource outside the budget and preserves deadline plus close failures",
  async (kind) => {
    const root = await fixtureRoot();
    const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
    const target = join(layout.changesets, `post-acquire-${kind}-deadline.json`);
    await writeFile(target, "original", { mode: 0o600 });
    const identity = await captureSecurePathIdentity(layout, target, "file");
    const closeFailure = new Error(`${kind} close failure`);
    let expired = false;
    let closeInjected = false;
    const hooks = {
      removalRecoveryNow: () => expired ? 30_001 : 0,
      afterExactRemovalResourceAcquire: async (path: string, acquiredKind: string) => {
        if ((kind === "directory" && acquiredKind === "directory" && path === layout.locks) ||
            (kind === "file" && acquiredKind === "file" && path.includes(".owner-"))) {
          expired = true;
        }
      },
      closeExactRemovalResource: async (
        resource: { close(): Promise<void> },
        path: string,
        acquiredKind: string
      ) => {
        await resource.close();
        if (!closeInjected && ((kind === "directory" && acquiredKind === "directory" && path === layout.locks) ||
            (kind === "file" && acquiredKind === "file" && path.includes(".owner-")))) {
          closeInjected = true;
          throw closeFailure;
        }
      }
    } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
      afterExactRemovalResourceAcquire(path: string, kind: string): Promise<void>;
      closeExactRemovalResource(resource: { close(): Promise<void> }, path: string, kind: string): Promise<void>;
    };

    const operation = kind === "directory"
      ? reconcileExactRemovalIntents(layout, hooks)
      : safeRemoveExactCacheFile(layout, identity, hooks);
    if (kind === "directory") {
      await expect(operation).rejects.toSatisfy((error: unknown) =>
        error instanceof AggregateError &&
        error.errors.some((item) => item === closeFailure) &&
        error.errors.some((item) => item instanceof Error && /deadline|30000/i.test(item.message))
      );
    } else {
      // Candidate creation is now in a native FinalContext. The injectable
      // after-acquire callback cannot run there, so only the later hookful
      // close failure is observable and no synthetic deadline is created.
      await expect(operation).rejects.toBe(closeFailure);
      expect(expired).toBe(false);
    }

    expect(closeInjected).toBe(true);
    await expect(readFile(target, "utf8")).resolves.toBe("original");
  }
);

test("preserves a post-read deadline and close failure without leaking or deleting recovery evidence", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "post-read-close-failure-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const intentId = randomUUID();
  const intentPath = join(layout.locks, `.remove-${intentId}.json`);
  await writeFile(intentPath, `${JSON.stringify({
    version: 1,
    targetPath: identity.path,
    targetParent: identity.parent,
    quarantinePath: join(layout.locks, `.removed-${intentId}-${identity.dev}-${identity.ino}.data`),
    dev: String(identity.dev),
    ino: String(identity.ino),
    parentDev: String(identity.parentDev),
    parentIno: String(identity.parentIno)
  })}\n`, { mode: 0o600 });
  const closeFailure = new Error("intent close failure");
  let expired = false;
  const hooks = {
    removalRecoveryNow: () => expired ? 30_001 : 0,
    readRemovalIntentChunk: async (
      handle: Awaited<ReturnType<typeof open>>,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ) => {
      const result = await handle.read(buffer, offset, length, position);
      expired = true;
      return result.bytesRead;
    },
    closeExactRemovalResource: async (resource: { close(): Promise<void> }, path: string) => {
      await resource.close();
      if (path === intentPath && expired) throw closeFailure;
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    closeExactRemovalResource(resource: { close(): Promise<void> }, path: string, kind: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toSatisfy((error: unknown) =>
    error instanceof AggregateError &&
    error.errors.some((item) => item === closeFailure) &&
    error.errors.some((item) => item instanceof Error && /deadline|30000/i.test(item.message))
  );
  await expect(readFile(target, "utf8")).resolves.toBe("original");
  await expect(stat(intentPath)).resolves.toMatchObject({ size: expect.any(Number) });
});

test("rechecks journal headroom after the pre-quarantine mutation hook", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "pre-quarantine-entry-growth-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const hooks = {
    beforeExactRemovalUnlink: async () => {
      for (let offset = 0; offset < 1_023; offset += 64) {
        await Promise.all(Array.from({ length: Math.min(64, 1_023 - offset) }, async (_, index) => {
          await writeFile(join(layout.locks, `task8-pre-quarantine-${offset + index}.lock`), "owned", { mode: 0o600 });
        }));
      }
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    beforeExactRemovalUnlink(path: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/headroom|entr|1024|limit/i);

  await expect(readFile(target, "utf8")).resolves.toBe("original");
  expect((await readdir(layout.locks)).length).toBe(1_024);
});

test("recovers an exclusive two-link quarantine claim left before target unlink", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "quarantine-claim-recovery-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const primary = new Error("fault after exclusive quarantine claim");
  let quarantinePath = "";
  const hooks = {
    afterExactRemovalQuarantineClaim: async (_target: string, quarantine: string) => {
      quarantinePath = quarantine;
      throw primary;
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    afterExactRemovalQuarantineClaim(targetPath: string, quarantinePath: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toBe(primary);

  const [targetMetadata, quarantineMetadata] = await Promise.all([stat(target), stat(quarantinePath)]);
  expect(targetMetadata.ino).toBe(quarantineMetadata.ino);
  expect(targetMetadata.nlink).toBe(2);
  expect(quarantineMetadata.nlink).toBe(2);
  await reconcileExactRemovalIntents(layout);
  await expect(stat(target)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(stat(quarantinePath)).rejects.toMatchObject({ code: "ENOENT" });
});

test("never exposes a candidate mutated by a reservation hook after the final candidate validation", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "final-no-hook-window-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  let candidatePath = "";
  let intentPath = "";
  let armed = false;
  let mutated = false;
  const hooks = {
    beforeRemovalIntentLink: async (candidate: string, intent: string) => {
      candidatePath = candidate;
      intentPath = intent;
      armed = true;
    },
    afterExactRemovalResourceAcquire: async (path: string, kind: string) => {
      if (!armed || mutated || path !== layout.locks || kind !== "directory") return;
      mutated = true;
      const exactSize = (await stat(candidatePath)).size;
      await writeFile(candidatePath, "{".padEnd(exactSize, " "), { mode: 0o600 });
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    beforeRemovalIntentLink(candidatePath: string, finalPath: string): Promise<void>;
    afterExactRemovalResourceAcquire(path: string, kind: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/candidate|intent|bytes|JSON|changed/i);

  expect(mutated).toBe(true);
  await expect(readFile(target, "utf8")).resolves.toBe("original");
  await expect(stat(candidatePath)).resolves.toMatchObject({ size: expect.any(Number) });
  await expect(stat(intentPath)).rejects.toMatchObject({ code: "ENOENT" });
});

test("rebuilds exact entry headroom after reservation resource hooks before publishing an intent", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "final-entry-reservation-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  for (let offset = 0; offset < 1_022; offset += 64) {
    await Promise.all(Array.from({ length: Math.min(64, 1_022 - offset) }, async (_, index) => {
      await writeFile(join(layout.locks, `task8-final-entry-${offset + index}.lock`), "owned", { mode: 0o600 });
    }));
  }
  let armed = false;
  let injected = false;
  let candidatePath = "";
  let intentPath = "";
  const injectedPath = join(layout.locks, "task8-final-entry-injected.lock");
  const hooks = {
    beforeRemovalIntentLink: async (candidate: string, intent: string) => {
      candidatePath = candidate;
      intentPath = intent;
      armed = true;
    },
    closeExactRemovalResource: async (resource: { close(): Promise<void> }, path: string, kind: string) => {
      try {
        await resource.close();
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ERR_DIR_CLOSED") throw error;
      }
      if (!armed || injected || path !== layout.locks || kind !== "directory") return;
      injected = true;
      await writeFile(injectedPath, "owned", { mode: 0o600 });
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    beforeRemovalIntentLink(candidatePath: string, finalPath: string): Promise<void>;
    closeExactRemovalResource(resource: { close(): Promise<void> }, path: string, kind: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/headroom|entr|1024|limit/i);

  expect(injected).toBe(true);
  await expect(readFile(target, "utf8")).resolves.toBe("original");
  await expect(stat(intentPath)).rejects.toMatchObject({ code: "ENOENT" });
  // Reservation fails before the post-hook authoritative candidate check, so
  // the untrusted candidate is retained as evidence instead of being deleted.
  expect((await readdir(layout.locks)).length).toBe(1_024);
  await expect(stat(candidatePath)).resolves.toMatchObject({ size: expect.any(Number) });
});

test("rebuilds physical-byte headroom after all pre-quarantine resource hooks", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "final-byte-reservation-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  for (let index = 0; index < 10; index += 1) {
    const path = join(layout.locks, `.removed-00000000-0000-4000-8000-${String(index + 10).padStart(12, "0")}.data`);
    const handle = await open(path, "wx", 0o600);
    try { await handle.truncate(recoveryFixtureArtifactBytes); } finally { await handle.close(); }
  }
  const growing = join(layout.locks, ".removed-00000000-0000-4000-8000-000000000001.data");
  const trigger = join(layout.locks, ".removed-ffffffff-ffff-4fff-bfff-ffffffffffff.data");
  await writeFile(growing, "x", { mode: 0o600 });
  await writeFile(trigger, "y", { mode: 0o600 });
  let armed = false;
  let grown = false;
  const hooks = {
    beforeExactRemovalUnlink: async () => { armed = true; },
    closeExactRemovalResource: async (resource: { close(): Promise<void> }, path: string, kind: string) => {
      await resource.close();
      if (!armed || grown || path !== trigger || kind !== "file") return;
      grown = true;
      const handle = await open(growing, "r+");
      try { await handle.truncate(9 * 1024 * 1024); } finally { await handle.close(); }
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    beforeExactRemovalUnlink(path: string): Promise<void>;
    closeExactRemovalResource(resource: { close(): Promise<void> }, path: string, kind: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/headroom|bytes|limit/i);

  expect(grown).toBe(true);
  await expect(readFile(target, "utf8")).resolves.toBe("original");
  await expect(stat(growing)).resolves.toMatchObject({ size: 9 * 1024 * 1024 });
});

test("recovers a filename-bound two-link quarantine after its intent is lost", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "lost-intent-two-link-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const crash = new Error("crash after quarantine claim");
  let quarantinePath = "";
  await expect(safeRemoveExactCacheFile(layout, identity, {
    afterExactRemovalQuarantineClaim: async (_target, quarantine) => {
      quarantinePath = quarantine;
      throw crash;
    }
  })).rejects.toBe(crash);
  const intentName = (await readdir(layout.locks)).find((name) => /^\.remove-.*\.json$/u.test(name));
  expect(intentName).toBeDefined();
  await rm(join(layout.locks, intentName!));

  await reconcileExactRemovalIntents(layout);

  await expect(stat(target)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(stat(quarantinePath)).rejects.toMatchObject({ code: "ENOENT" });
});

test("preserves a lost-intent quarantine when an extra hard link makes its identity ambiguous", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "lost-intent-extra-link-target.json");
  const extra = join(layout.changesets, "lost-intent-extra-link-copy.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const crash = new Error("crash after quarantine claim");
  let quarantinePath = "";
  await expect(safeRemoveExactCacheFile(layout, identity, {
    afterExactRemovalQuarantineClaim: async (_target, quarantine) => {
      quarantinePath = quarantine;
      throw crash;
    }
  })).rejects.toBe(crash);
  const intentName = (await readdir(layout.locks)).find((name) => /^\.remove-.*\.json$/u.test(name));
  await rm(join(layout.locks, intentName!));
  await link(target, extra);

  await expect(reconcileExactRemovalIntents(layout)).rejects.toThrow(/hard.?link|ambiguous|identity|evidence/i);

  await expect(readFile(target, "utf8")).resolves.toBe("original");
  await expect(readFile(extra, "utf8")).resolves.toBe("original");
  await expect(readFile(quarantinePath, "utf8")).resolves.toBe("original");
});

test("rescans hook-free reservation headroom immediately before exclusive candidate creation", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "candidate-create-final-reservation-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  for (let offset = 0; offset < 1_022; offset += 64) {
    await Promise.all(Array.from({ length: Math.min(64, 1_022 - offset) }, async (_, index) => {
      await writeFile(join(layout.locks, `task8-candidate-create-${offset + index}.lock`), "owned", { mode: 0o600 });
    }));
  }
  let injected = false;
  let maximumVisibleEntries = 1_022;
  const hooks = {
    afterExactRemovalResourceAcquire: async (path: string, kind: string) => {
      if (!injected && path === target && kind === "file") {
        injected = true;
        await Promise.all([
          writeFile(join(layout.locks, "task8-candidate-create-late-a.lock"), "owned", { mode: 0o600 }),
          writeFile(join(layout.locks, "task8-candidate-create-late-b.lock"), "owned", { mode: 0o600 })
        ]);
      }
      maximumVisibleEntries = Math.max(maximumVisibleEntries, (await readdir(layout.locks)).length);
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2] & {
    afterExactRemovalResourceAcquire(path: string, kind: string): Promise<void>;
  };

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toThrow(/headroom|entr|1024|limit/i);

  expect(injected).toBe(true);
  expect(maximumVisibleEntries).toBe(1_024);
  expect((await readdir(layout.locks)).filter((name) => name.startsWith(".remove-"))).toEqual([]);
  await expect(readFile(target, "utf8")).resolves.toBe("original");
});

test("does not access hook option getters inside the final candidate validation window", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "final-window-hook-getter-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const stop = new Error("stop after observing first-visible intent");
  let getterReads = 0;
  let readsBeforeWindow = -1;
  let readsAtFirstVisibility = -1;
  const hooks = {
    get removalRecoveryNow() {
      getterReads += 1;
      return () => 0;
    },
    beforeRemovalIntentLink: async () => { readsBeforeWindow = getterReads; },
    afterRemovalIntentLink: async () => {
      readsAtFirstVisibility = getterReads;
      throw stop;
    }
  } as Parameters<typeof safeRemoveExactCacheFile>[2];

  await expect(safeRemoveExactCacheFile(layout, identity, hooks)).rejects.toBe(stop);

  expect(readsBeforeWindow).toBeGreaterThanOrEqual(1);
  expect(readsAtFirstVisibility).toBe(readsBeforeWindow);
});

test("keeps lost-intent quarantine settlement and deletion in one injected-clock-free window", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "lost-intent-no-callback-delete-target.json");
  await writeFile(target, "original", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, target, "file");
  const crash = new Error("crash after quarantine claim");
  let quarantinePath = "";
  await expect(safeRemoveExactCacheFile(layout, identity, {
    afterExactRemovalQuarantineClaim: async (_target, quarantine) => {
      quarantinePath = quarantine;
      throw crash;
    }
  })).rejects.toBe(crash);
  const intentName = (await readdir(layout.locks)).find((name) => /^\.remove-.*\.json$/u.test(name));
  await rm(join(layout.locks, intentName!));
  let callbacksDuringSettledEvidence = 0;
  const hooks = {
    removalRecoveryNow: () => {
      try {
        statSync(target);
        return 0;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      try {
        statSync(quarantinePath);
        callbacksDuringSettledEvidence += 1;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      return 0;
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1];

  await reconcileExactRemovalIntents(layout, hooks);

  expect(callbacksDuringSettledEvidence).toBe(0);
  await expect(stat(target)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(stat(quarantinePath)).rejects.toMatchObject({ code: "ENOENT" });
});

test.each([
  { label: "growth", initial: "x", changed: "x".repeat(100), expectedBytes: 101 },
  { label: "truncation", initial: "x".repeat(100), changed: "x", expectedBytes: 2 }
])("reports retained bytes after late same-inode $label", async ({ initial, changed, expectedBytes }) => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const candidate = join(layout.locks, `.remove-${randomUUID()}.owner-${randomUUID()}.tmp`);
  const later = join(layout.locks, `.removed-${randomUUID()}.data`);
  await writeFile(candidate, initial, { mode: 0o600 });
  await writeFile(later, "y", { mode: 0o600 });
  let laterUses = 0;
  const hooks = {
    beforeRemovalArtifactUse: async (path: string, kind: string) => {
      if (path === later && kind === "legacy-quarantine") {
        laterUses += 1;
        if (laterUses === 2) await writeFile(candidate, changed, { mode: 0o600 });
      }
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    beforeRemovalArtifactUse(path: string, kind: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks))
    .resolves.toEqual({ retainedEntries: 2, retainedBytes: expectedBytes });
});

test("rejects aggregate retained-byte growth introduced after an artifact was retained", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  for (let index = 0; index < 10; index += 1) {
    const path = join(layout.locks, `.removed-${randomUUID()}.data`);
    const handle = await open(path, "wx", 0o600);
    try { await handle.truncate(recoveryFixtureArtifactBytes); } finally { await handle.close(); }
  }
  const growing = join(layout.locks, ".removed-00000000-0000-4000-8000-000000000001.data");
  const trigger = join(layout.locks, ".removed-00000000-0000-4000-8000-000000000002.data");
  await writeFile(growing, "x", { mode: 0o600 });
  await writeFile(trigger, "y", { mode: 0o600 });
  let triggerUses = 0;
  const hooks = {
    beforeRemovalArtifactUse: async (path: string, kind: string) => {
      if (path === trigger && kind === "legacy-quarantine") {
        triggerUses += 1;
        if (triggerUses === 2) {
          const handle = await open(growing, "r+");
          try { await handle.truncate(9 * 1024 * 1024); } finally { await handle.close(); }
        }
      }
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    beforeRemovalArtifactUse(path: string, kind: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/recovery bytes|limit/i);
  await expect(stat(growing)).resolves.toMatchObject({ size: 9 * 1024 * 1024 });
});

test("revalidates and charges a bound quarantine mutated immediately after file sync", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const provisional = join(layout.locks, "post-sync-quarantine-provisional");
  await writeFile(provisional, "evidence", { mode: 0o600 });
  const identity = await captureSecurePathIdentity(layout, provisional, "file");
  const quarantine = join(layout.locks, `.removed-${randomUUID()}-${identity.dev}-${identity.ino}.data`);
  await rename(provisional, quarantine);
  const hooks = {
    afterExactRemovalArtifactSync: async (path: string) => {
      if (path === quarantine) {
        const handle = await open(path, "r+");
        try { await handle.truncate(changesetRemovalRecoveryLimits.maxArtifactBytes + 1); } finally { await handle.close(); }
      }
    }
  } as Parameters<typeof reconcileExactRemovalIntents>[1] & {
    afterExactRemovalArtifactSync(path: string): Promise<void>;
  };

  await expect(reconcileExactRemovalIntents(layout, hooks)).rejects.toThrow(/artifact|bytes|limit|sync/i);
  await expect(stat(quarantine)).resolves.toMatchObject({ size: changesetRemovalRecoveryLimits.maxArtifactBytes + 1 });
});

test.runIf(process.platform !== "win32" && typeof process.getuid === "function" && process.getuid() === 0)(
  "rejects a cache file owned by another POSIX user",
  async () => {
    const root = await fixtureRoot();
    const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
    const target = join(layout.changesets, "wrong-owner.json");
    await writeFile(target, "{}", { mode: 0o600 });
    await chown(target, 65_534, 65_534);

    await expect(validateCacheFile(layout, target, false)).rejects.toThrow(/ownership|owner/i);
  }
);

test("exclusive publication removes its temporary hard link and leaves one target link", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "single-link.json");

  await publishExclusiveFile(layout, target, "owned");

  expect((await stat(target)).nlink).toBe(1);
  await expect(readFile(target, "utf8")).resolves.toBe("owned");
});

test("syncs publication bytes and reports the explicit parent-directory durability policy", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "durable.json");
  const fileSyncs: string[] = [];
  const directorySyncs: string[] = [];
  const hooks = {
    afterTemporaryFileSync: async (temporary: string) => { fileSyncs.push(temporary); },
    afterParentDirectorySync: async (_directory: string, outcome: string) => { directorySyncs.push(outcome); }
  } as Parameters<typeof publishExclusiveFile>[3] & {
    afterTemporaryFileSync(temporary: string): Promise<void>;
    afterParentDirectorySync(directory: string, outcome: string): Promise<void>;
  };

  await publishExclusiveFile(layout, target, "durable", hooks);

  expect(fileSyncs).toHaveLength(1);
  expect(directorySyncs.length).toBeGreaterThanOrEqual(3);
  expect(new Set(directorySyncs)).toEqual(new Set([process.platform === "win32" ? "unsupported" : "synced"]));
  await expect(readFile(target, "utf8")).resolves.toBe("durable");
});

test("does not misclassify a Windows directory-open ACL failure as unsupported sync", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "directory-open-error.json");
  const primary = Object.assign(new Error("directory open denied"), { code: "EPERM" });
  const hooks = {
    beforeParentDirectoryOpen: async () => { throw primary; }
  } as Parameters<typeof publishExclusiveFile>[3] & {
    beforeParentDirectoryOpen(directory: string): Promise<void>;
  };

  const failure = await publishExclusiveFile(layout, target, "owned", hooks).catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(AggregateError);
  expect((failure as AggregateError).errors).toEqual([primary, primary]);
  await expect(stat(target)).rejects.toMatchObject({ code: "ENOENT" });
});

test("syncs and identity-validates the final target after link and temporary unlink", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "final-handle-sync.json");
  const observedLinks: number[] = [];
  const hooks = {
    afterFinalTargetFileSync: async (_path: string, links: number) => { observedLinks.push(links); }
  } as Parameters<typeof publishExclusiveFile>[3] & {
    afterFinalTargetFileSync(path: string, links: number): Promise<void>;
  };

  await publishExclusiveFile(layout, target, "owned", hooks);

  expect(observedLinks).toEqual([2, 1]);
  await expect(readFile(target, "utf8")).resolves.toBe("owned");
});

test("syncs the publication-claim recovery record at both final names", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "claim-final-handle-sync.json");
  const observedLinks: number[] = [];
  const hooks = {
    afterClaimFinalFileSync: async (_path: string, links: number) => { observedLinks.push(links); }
  } as Parameters<typeof publishExclusiveFile>[3] & {
    afterClaimFinalFileSync(path: string, links: number): Promise<void>;
  };

  await publishExclusiveFile(layout, target, "owned", hooks);

  expect(observedLinks).toEqual([2, 1]);
});

test("rejects a replacement introduced before final-target handle sync", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "final-sync-swap.json");
  let swapped = false;
  const hooks = {
    beforeFinalTargetFileSync: async (path: string, links: number) => {
      if (swapped || links !== 2) return;
      swapped = true;
      await rename(path, `${path}.moved`);
      await writeFile(path, "replacement", { flag: "wx", mode: 0o600 });
    }
  } as Parameters<typeof publishExclusiveFile>[3] & {
    beforeFinalTargetFileSync(path: string, links: number): Promise<void>;
  };

  const failure = await publishExclusiveFile(layout, target, "owned", hooks).catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(AggregateError);
  expect((failure as AggregateError).errors.map((error) => String((error as Error).message)))
    .toEqual([expect.stringMatching(/identity|replaced|changed/i), expect.stringMatching(/identity|replaced|changed/i)]);

  await expect(readFile(target, "utf8")).resolves.toBe("replacement");
});

test("waits for an identity-bound in-progress HMAC publication during concurrent cache initialization", async () => {
  const root = await fixtureRoot();
  const options = { cacheDirectory: join(root, "cache") };
  const project = join(root, "project");
  const layout = await prepareSecureCache(options, project);
  const target = join(layout.root, "changeset-hmac.key");
  const linked = deferred<void>();
  const release = deferred<void>();
  const publication = publishExclusiveFile(layout, target, Buffer.alloc(32, 7), {
    afterLink: async () => {
      linked.resolve();
      await release.promise;
    }
  });
  await linked.promise;

  const validation = prepareSecureCache(options, project);
  await expect(Promise.race([
    validation.then(() => "validated"),
    new Promise<"held">((accept) => setTimeout(() => accept("held"), 50))
  ])).resolves.toBe("held");
  release.resolve();

  await expect(Promise.all([publication, validation])).resolves.toEqual([undefined, expect.objectContaining({ root: layout.root })]);
  expect((await stat(target)).nlink).toBe(1);
});

test("publishes a complete owner-only claim token atomically", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "d".repeat(64));
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const [owner, metadata] = await Promise.all([
    readFile(claim.path, "utf8").then((contents) => JSON.parse(contents) as Record<string, unknown>),
    lstat(claim.path, { bigint: true })
  ]);

  expect(Object.keys(owner).sort()).toEqual([
    "createdAtMs",
    "expiresAtMs",
    "initializationName",
    "nonce",
    "pid",
    "publicationName",
    "targetName",
    "version"
  ]);
  expect(owner).toEqual(expect.objectContaining({
    version: 1,
    pid: process.pid,
    targetName: "d".repeat(64)
  }));
  expect(owner.nonce).toMatch(/^[a-f0-9]{32}$/u);
  expect(owner.initializationName).toMatch(/^\.claim-[a-f0-9-]{36}\.tmp$/u);
  expect(Number(owner.expiresAtMs) - Number(owner.createdAtMs)).toBe(30_000);
  expect(metadata.isFile()).toBe(true);
  expect(metadata.nlink).toBe(1n);
  if (process.platform !== "win32") expect(metadata.mode & 0o777n).toBe(0o600n);

  await safeRemoveOwnedPublicationClaim(layout, claim);
  await expect(lstat(claim.path)).rejects.toMatchObject({ code: "ENOENT" });
});

test("accepts only the exact publication-owner schema and lease policy", () => {
  const owner = createPublicationClaimOwner(
    "target.bin",
    ".claim-00000000-0000-4000-8000-000000000000.tmp",
    ".00000000-0000-4000-8000-000000000001.tmp",
    1_000
  );

  expect(() => parsePublicationClaimOwner({ ...owner, projectDigest: "forged" }, "target.bin"))
    .toThrow(/metadata.*invalid|unknown|field/i);
  expect(() => parsePublicationClaimOwner({ ...owner, renewedAtMs: 1_500 }, "target.bin"))
    .toThrow(/metadata.*invalid|unknown|field/i);
  const { nonce: _nonce, ...missingNonce } = owner;
  expect(() => parsePublicationClaimOwner(missingNonce, "target.bin"))
    .toThrow(/metadata.*invalid|missing|field/i);
  expect(() => parsePublicationClaimOwner(owner, "different.bin"))
    .toThrow(/target|metadata.*invalid/i);
  for (const invalidTarget of ["", ".", "..", "nested/name", "nested\\name"]) {
    expect(() => parsePublicationClaimOwner({ ...owner, targetName: invalidTarget }, invalidTarget))
      .toThrow(/target|metadata.*invalid/i);
  }
  expect(() => parsePublicationClaimOwner({
    ...owner,
    initializationName: `.claim-${"-".repeat(36)}.tmp`
  }, "target.bin")).toThrow(/initialization|uuid|metadata.*invalid/i);
  expect(() => parsePublicationClaimOwner({
    ...owner,
    publicationName: `.${"-".repeat(36)}.tmp`
  }, "target.bin")).toThrow(/temporary|uuid|metadata.*invalid/i);
  expect(() => parsePublicationClaimOwner({ ...owner, expiresAtMs: owner.expiresAtMs + 1 }, "target.bin"))
    .toThrow(/lease|duration|metadata.*invalid/i);
  expect(parsePublicationClaimOwner(owner, "target.bin")).toEqual(owner);
});

for (const hookName of [
  "beforeClaimOwnerCreate",
  "duringClaimOwnerWrite",
  "beforeClaimOwnerIdentityCapture"
] as const) {
  test(`leaves no deterministic blocker when ${hookName} fails`, async () => {
    const root = await fixtureRoot();
    const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
    const target = join(layout.indexes, "f".repeat(64));
    const deterministicClaim = join(layout.indexes, `.publish-${"f".repeat(64)}`);
    const fault = new Error(`${hookName} crash`);
    const claim = claimOwnedSnapshotDirectory as unknown as (
      layout: Parameters<typeof claimOwnedSnapshotDirectory>[0],
      target: string,
      hooks: Record<typeof hookName, () => Promise<void>>
    ) => Promise<unknown>;

    await expect(claim(layout, target, { [hookName]: async () => { throw fault; } } as unknown as Record<typeof hookName, () => Promise<void>>))
      .rejects.toBe(fault);
    await expect(lstat(deterministicClaim)).rejects.toMatchObject({ code: "ENOENT" });
  });
}

for (const hookName of [
  "beforeClaimOwnerCreate",
  "duringClaimOwnerWrite",
  "beforeClaimOwnerIdentityCapture"
] as const) {
  test(`allows a winner while another claim is paused at ${hookName}`, async () => {
    const root = await fixtureRoot();
    const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
    const target = join(layout.indexes, "2".repeat(64));
    const deterministicClaim = join(layout.indexes, `.publish-${"2".repeat(64)}`);
    const reached = deferred<void>();
    const release = deferred<void>();
    const claim = claimOwnedSnapshotDirectory as unknown as (
      layout: Parameters<typeof claimOwnedSnapshotDirectory>[0],
      target: string,
      hooks: Record<typeof hookName, () => Promise<void>>
    ) => ReturnType<typeof claimOwnedSnapshotDirectory>;
    const paused = claim(layout, target, {
      [hookName]: async () => {
        reached.resolve();
        await release.promise;
      }
    } as unknown as Record<typeof hookName, () => Promise<void>>);
    void paused.catch(() => undefined);
    await reached.promise;

    await expect(lstat(deterministicClaim)).rejects.toMatchObject({ code: "ENOENT" });
    const winner = await claimOwnedSnapshotDirectory(layout, target);
    release.resolve();
    const [pausedResult] = await Promise.allSettled([paused]);

    expect(pausedResult).toMatchObject({ status: "rejected", reason: expect.objectContaining({ code: "EEXIST" }) });
    await safeRemoveOwnedPublicationClaim(layout, winner);
  });
}

test("the deterministic claim is complete and identity-bound at first visibility", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "1".repeat(64));
  let inspected = false;
  const claim = claimOwnedSnapshotDirectory as unknown as (
    layout: Parameters<typeof claimOwnedSnapshotDirectory>[0],
    target: string,
    hooks: { afterClaimLink: (temporary: string, deterministic: string) => Promise<void> }
  ) => ReturnType<typeof claimOwnedSnapshotDirectory>;

  const owned = await claim(layout, target, {
    afterClaimLink: async (temporary, deterministic) => {
      const [temporaryMetadata, deterministicMetadata, owner] = await Promise.all([
        lstat(temporary, { bigint: true }),
        lstat(deterministic, { bigint: true }),
        readFile(deterministic, "utf8").then((bytes) => JSON.parse(bytes) as Record<string, unknown>)
      ]);
      expect(temporaryMetadata.dev).toBe(deterministicMetadata.dev);
      expect(temporaryMetadata.ino).toBe(deterministicMetadata.ino);
      expect(temporaryMetadata.nlink).toBe(2n);
      expect(deterministicMetadata.nlink).toBe(2n);
      expect(owner).toEqual(expect.objectContaining({ pid: process.pid, targetName: "1".repeat(64) }));
      inspected = true;
    }
  });

  expect(inspected).toBe(true);
  expect((await lstat(owned.path, { bigint: true })).nlink).toBe(1n);
  await safeRemoveOwnedPublicationClaim(layout, owned);
});

test("retries a claim capture after a completed link settlement advances ctime", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "2".repeat(64));
  const owned = await claimOwnedSnapshotDirectory(layout, target);
  const transientLink = join(layout.indexes, `.claim-settlement-${randomUUID()}.tmp`);
  let advanced = false;
  let captures = 0;

  const observed = await observeOwnedSnapshotPublicationClaim(layout, target, {
    afterClaimMetadataCapture: async (path) => {
      captures += 1;
      if (advanced) return;
      advanced = true;
      await link(path, transientLink);
      await rm(transientLink);
    }
  });

  expect(advanced).toBe(true);
  expect(captures).toBeGreaterThanOrEqual(2);
  expect(observed.state).toBe("owned");
  if (observed.state === "owned") expect(samePublicationClaimEpoch(observed.claim, owned)).toBe(true);
  await safeRemoveOwnedPublicationClaim(layout, owned);
});

test("observes a valid replacement claim created after initial generation capture", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "5".repeat(64));
  const original = await claimOwnedSnapshotDirectory(layout, target);
  const retainedPaths: string[] = [];
  let replacement: Awaited<ReturnType<typeof claimOwnedSnapshotDirectory>> | undefined;
  let replaced = false;

  try {
    const observed = await observeOwnedSnapshotPublicationClaim(layout, target, {
      afterClaimMetadataCapture: async (path, metadata) => {
        if (replaced) return;
        replaced = true;
        expect(path).toBe(original.path);
        expect(metadata.dev).toBe(original.dev);
        expect(metadata.ino).toBe(original.ino);
        const retainedPath = await retainClaimGenerationBeforeUnlink(original, retainedPaths);
        replacement = await claimOwnedSnapshotDirectory(layout, target);
        await expectClaimPathGeneration(path, replacement, retainedPath, original);
      }
    });

    expect(replaced).toBe(true);
    expect(replacement).toBeDefined();
    expect(observed.state).toBe("owned");
    if (observed.state === "owned") expect(samePublicationClaimEpoch(observed.claim, replacement!)).toBe(true);
    await safeRemoveOwnedPublicationClaim(layout, replacement!);
  } finally {
    await removeRetainedClaimGenerations(retainedPaths);
  }
});

test("fails closed when an unlinked claim path is relinked with the same dev and ino", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "9".repeat(64));
  const owned = await claimOwnedSnapshotDirectory(layout, target);
  const originalBytes = await readFile(owned.path, "utf8");
  const retainedPaths: string[] = [];
  let relinked = false;
  let captures = 0;

  try {
    const failure = await observeOwnedSnapshotPublicationClaim(layout, target, {
      afterClaimMetadataCapture: async (path, metadata) => {
        captures += 1;
        if (relinked) return;
        const retainedPath = await retainClaimGenerationBeforeUnlink(owned, retainedPaths);
        await link(retainedPath, path);
        await rm(retainedPath);
        const reused = await lstat(path, { bigint: true });
        expect(reused.dev).toBe(metadata.dev);
        expect(reused.ino).toBe(metadata.ino);
        expect(reused.nlink).toBe(1n);
        await writeFile(path, "{malformed", { encoding: "utf8", mode: 0o600 });
        relinked = true;
      }
    }).catch((error: unknown) => error);

    expect(relinked).toBe(true);
    expect(captures).toBe(1);
    expect(failure).toBeInstanceOf(Error);
    expect(String((failure as Error).message)).toMatch(/malformed|ambiguous/iu);
    expect((failure as Error).cause).toBeInstanceOf(Error);
    const current = await lstat(owned.path, { bigint: true });
    expect(current.dev).toBe(owned.dev);
    expect(current.ino).toBe(owned.ino);

    await removeRetainedClaimGenerations(retainedPaths);
    await writeFile(owned.path, originalBytes, { encoding: "utf8", mode: 0o600 });
    const restored = await captureOwnedSnapshotPublicationClaim(layout, target);
    await safeRemoveOwnedPublicationClaim(layout, restored);
  } finally {
    await removeRetainedClaimGenerations(retainedPaths);
  }
});

test("bounds valid replacement-claim churn and preserves the last generation", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "6".repeat(64));
  let current = await claimOwnedSnapshotDirectory(layout, target);
  const retainedPaths: string[] = [];
  let captures = 0;

  try {
    const failure = await observeOwnedSnapshotPublicationClaim(layout, target, {
      afterClaimMetadataCapture: async (path) => {
        captures += 1;
        const previous = current;
        const retainedPath = await retainClaimGenerationBeforeUnlink(previous, retainedPaths);
        current = await claimOwnedSnapshotDirectory(layout, target);
        await expectClaimPathGeneration(path, current, retainedPath, previous);
      }
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(Error);
    expect(String((failure as Error).message)).toMatch(/publication claim|replacement|stabili[sz]/iu);
    expect(captures).toBe(4);
    await expect(captureOwnedSnapshotPublicationClaim(layout, target)).resolves.toSatisfy((claim) =>
      samePublicationClaimEpoch(claim, current)
    );
    await safeRemoveOwnedPublicationClaim(layout, current);
  } finally {
    await removeRetainedClaimGenerations(retainedPaths);
  }
});

test("file publication acquisition continues through a valid replacement claim", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "7".repeat(64));
  let original = await claimOwnedSnapshotDirectory(layout, target);
  await expireClaimOwner(original);
  original = await captureOwnedSnapshotPublicationClaim(layout, target);
  const retainedPaths: string[] = [];
  let replacement: Awaited<ReturnType<typeof claimOwnedSnapshotDirectory>> | undefined;

  try {
    await publishExclusiveFile(layout, target, "published", {
      afterClaimMetadataCapture: async (path, metadata) => {
        if (replacement) return;
        expect(path).toBe(original.path);
        expect(metadata.dev).toBe(original.dev);
        expect(metadata.ino).toBe(original.ino);
        const retainedPath = await retainClaimGenerationBeforeUnlink(original, retainedPaths);
        replacement = await claimOwnedSnapshotDirectory(layout, target);
        await expectClaimPathGeneration(path, replacement, retainedPath, original);
        await expireClaimOwner(replacement);
      }
    });

    expect(replacement).toBeDefined();
    await expect(lstat(replacement!.path)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(target, "utf8")).resolves.toBe("published");
  } finally {
    await removeRetainedClaimGenerations(retainedPaths);
  }
});

test("rejects same-generation malformed claim bytes without spending replacement retries", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "8".repeat(64));
  const owned = await claimOwnedSnapshotDirectory(layout, target);
  const originalBytes = await readFile(owned.path, "utf8");
  let captures = 0;

  const failure = await observeOwnedSnapshotPublicationClaim(layout, target, {
    afterClaimMetadataCapture: async (path) => {
      captures += 1;
      await writeFile(path, "{malformed", { encoding: "utf8", mode: 0o600 });
    }
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(Error);
  expect(captures).toBe(1);
  expect((failure as Error).cause).toBeInstanceOf(Error);
  await writeFile(owned.path, originalBytes, { encoding: "utf8", mode: 0o600 });
  const restored = await captureOwnedSnapshotPublicationClaim(layout, target);
  await safeRemoveOwnedPublicationClaim(layout, restored);
});

test("rejects a third hard link introduced during claim capture", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "3".repeat(64));
  const owned = await claimOwnedSnapshotDirectory(layout, target);
  const firstLink = join(layout.indexes, `.claim-external-${randomUUID()}.tmp`);
  const secondLink = join(layout.indexes, `.claim-external-${randomUUID()}.tmp`);
  let injected = false;
  let captures = 0;

  try {
    const failure = await observeOwnedSnapshotPublicationClaim(layout, target, {
      afterClaimMetadataCapture: async (path) => {
        captures += 1;
        if (injected) return;
        injected = true;
        await link(path, firstLink);
        await link(path, secondLink);
      }
    }).catch((error: unknown) => error);

    expect(injected).toBe(true);
    expect(captures).toBe(1);
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).cause).toSatisfy((cause: unknown) =>
      cause instanceof Error && /identity or metadata changed before bounded read/i.test(cause.message)
    );
    expect((await lstat(owned.path, { bigint: true })).nlink).toBe(3n);
  } finally {
    await rm(firstLink, { force: true });
    await rm(secondLink, { force: true });
    await safeRemoveOwnedPublicationClaim(layout, owned);
  }
});

test("rejects an owner rewrite hidden behind consecutive settlement retries", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "4".repeat(64));
  const owned = await claimOwnedSnapshotDirectory(layout, target);
  const fixedTime = new Date("2025-01-01T00:00:00.000Z");
  await utimes(owned.path, fixedTime, fixedTime);
  const transientLink = join(layout.indexes, `.claim-settlement-${randomUUID()}.tmp`);
  let attempt = 0;

  await expect(observeOwnedSnapshotPublicationClaim(layout, target, {
    afterClaimMetadataCapture: async (path) => {
      attempt += 1;
      if (attempt === 1) {
        await link(path, transientLink);
        return;
      }
      if (attempt === 2) {
        const owner = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
        owner.nonce = owner.nonce === "0".repeat(32) ? "1".repeat(32) : "0".repeat(32);
        await writeFile(path, `${JSON.stringify(owner)}\n`, { encoding: "utf8", mode: 0o600 });
        await utimes(path, fixedTime, fixedTime);
        await rm(transientLink);
      }
    }
  })).rejects.toSatisfy((error: unknown) =>
    error instanceof Error && error.cause instanceof Error &&
    /identity or owner metadata changed while initialization settled/i.test(error.cause.message)
  );

  expect(attempt).toBe(2);
  const rewritten = await captureOwnedSnapshotPublicationClaim(layout, target);
  await safeRemoveOwnedPublicationClaim(layout, rewritten);
});

test("never reports an occupied malformed deterministic claim as absent", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "3".repeat(64));
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const externalLink = join(root, "outside", "claim-link");
  await link(claim.path, externalLink);

  await expect(observeOwnedSnapshotPublicationClaim(layout, target))
    .rejects.toThrow(/initialization|hard.?link|link count|ambiguous/i);
  await expect(lstat(claim.path)).resolves.toSatisfy((metadata) => metadata.nlink === 2);

  await rm(externalLink);
  await safeRemoveOwnedPublicationClaim(layout, claim);
});

test("waits for a live owner paused after atomic claim visibility", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "slow-claim.json");
  const reached = deferred<void>();
  const release = deferred<void>();
  const first = publishExclusiveFile(layout, target, "owned", {
    afterClaimLink: async () => {
      reached.resolve();
      await release.promise;
    }
  });
  await reached.promise;
  const second = publishExclusiveFile(layout, target, "loser");
  const remainedBlocked = await Promise.race([
    second.then(() => false, () => false),
    new Promise<true>((accept) => setTimeout(() => accept(true), 50))
  ]);
  release.resolve();

  expect(remainedBlocked).toBe(true);
  await expect(first).resolves.toBeUndefined();
  await expect(second).rejects.toMatchObject({ code: "EEXIST" });
  await expect(readFile(target, "utf8")).resolves.toBe("owned");
});

test("reclaims a dead owner paused immediately after atomic claim visibility", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "dead-claim-initialization.json");
  const reached = deferred<void>();
  const release = deferred<void>();
  const first = publishExclusiveFile(layout, target, "abandoned", {
    afterClaimLink: async (_temporary, deterministic) => {
      await expireClaimOwner({ path: deterministic });
      reached.resolve();
      await release.promise;
    }
  });
  void first.catch(() => undefined);
  await reached.promise;

  await expect(publishExclusiveFile(layout, target, "winner")).resolves.toBeUndefined();
  release.resolve();
  await Promise.allSettled([first]);

  expect((await lstat(target, { bigint: true })).nlink).toBe(1n);
  await expect(readFile(target, "utf8")).resolves.toBe("winner");
});

test("reclaims an expired dead ordinary publisher before link and retries", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "dead-before-link.json");
  const reached = deferred<void>();
  const release = deferred<void>();
  let claim: { path: string } | undefined;
  const first = publishExclusiveFile(layout, target, "abandoned", {
    afterClaimAcquire: async (owned) => { claim = owned; },
    beforeLink: async () => {
      await expireClaimOwner(claim!);
      reached.resolve();
      await release.promise;
    }
  });
  void first.catch(() => undefined);
  await reached.promise;

  await expect(publishExclusiveFile(layout, target, "winner")).resolves.toBeUndefined();
  release.resolve();
  await Promise.allSettled([first]);

  await expect(readFile(target, "utf8")).resolves.toBe("winner");
  expect((await lstat(target, { bigint: true })).nlink).toBe(1n);
});

test("recovers an expired dead ordinary publisher after link before releasing its proof", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "dead-after-link.json");
  const reached = deferred<void>();
  const release = deferred<void>();
  let claim: { path: string } | undefined;
  const first = publishExclusiveFile(layout, target, "owned", {
    afterClaimAcquire: async (owned) => { claim = owned; },
    afterLink: async () => {
      await expireClaimOwner(claim!);
      reached.resolve();
      await release.promise;
    }
  });
  void first.catch(() => undefined);
  await reached.promise;

  await expect(publishExclusiveFile(layout, target, "loser")).rejects.toMatchObject({ code: "EEXIST" });
  const recoveredBeforeOriginalResumed = await lstat(target, { bigint: true });
  release.resolve();
  await Promise.allSettled([first]);

  expect(recoveredBeforeOriginalResumed.nlink).toBe(1n);
  await expect(validateCacheFile(layout, target, false)).resolves.toBeUndefined();
  await expect(readFile(target, "utf8")).resolves.toBe("owned");
});

test("retains the claim and a replacement when the exact dead-publisher temporary changes before cleanup", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "dead-temp-replacement.json");
  const reached = deferred<void>();
  const release = deferred<void>();
  let claim: { path: string } | undefined;
  let replacement = "";
  let movedOwnedTemporary = "";
  const first = publishExclusiveFile(layout, target, "owned", {
    afterClaimAcquire: async (owned) => { claim = owned; },
    afterLink: async () => {
      await expireClaimOwner(claim!);
      reached.resolve();
      await release.promise;
    }
  });
  void first.catch(() => undefined);
  await reached.promise;
  const contenderHooks = {
    beforeDeadTemporaryCleanup: async (temporary: string) => {
      replacement = temporary;
      movedOwnedTemporary = `${temporary}.owned-moved`;
      await rename(temporary, movedOwnedTemporary);
      await writeFile(temporary, "replacement", { encoding: "utf8", mode: 0o600 });
    }
  } as Parameters<typeof publishExclusiveFile>[3] & {
    beforeDeadTemporaryCleanup: (temporary: string, target: string) => Promise<void>;
  };

  await expect(publishExclusiveFile(layout, target, "loser", contenderHooks)).rejects.toThrow(/identity|changed|ambiguous|external|unowned/i);
  await expect(readFile(replacement, "utf8")).resolves.toBe("replacement");
  await expect(lstat(movedOwnedTemporary, { bigint: true })).resolves.toSatisfy((metadata) => metadata.nlink === 2n);
  await expect(lstat(claim!.path)).resolves.toSatisfy((metadata) => metadata.isFile());
  release.resolve();
  await Promise.allSettled([first]);
});

test("does not release dead-publisher proof when a third hard link makes recovery ambiguous", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "dead-external-link.json");
  const outside = join(root, "outside", "external-link.json");
  const reached = deferred<void>();
  const release = deferred<void>();
  let claim: { path: string } | undefined;
  const first = publishExclusiveFile(layout, target, "owned", {
    afterClaimAcquire: async (owned) => { claim = owned; },
    afterLink: async () => {
      await expireClaimOwner(claim!);
      await link(target, outside);
      reached.resolve();
      await release.promise;
    }
  });
  void first.catch(() => undefined);
  await reached.promise;

  await expect(publishExclusiveFile(layout, target, "loser")).rejects.toThrow(/hard-link|link count|ambiguous/i);
  await expect(lstat(claim!.path)).resolves.toSatisfy((metadata) => metadata.isFile());
  expect((await lstat(target, { bigint: true })).nlink).toBe(3n);
  await rm(outside);
  release.resolve();
  await Promise.allSettled([first]);
});

test("reclaims an expired dead ordinary publisher after temporary cleanup", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.changesets, "dead-after-cleanup.json");
  const reached = deferred<void>();
  const release = deferred<void>();
  let claim: { path: string } | undefined;
  const publish = publishExclusiveFile as unknown as (
    layout: Parameters<typeof publishExclusiveFile>[0],
    target: string,
    bytes: string,
    hooks: Parameters<typeof publishExclusiveFile>[3] & { afterTemporaryCleanup: () => Promise<void> }
  ) => Promise<void>;
  const first = publish(layout, target, "owned", {
    afterClaimAcquire: async (owned) => { claim = owned; },
    afterTemporaryCleanup: async () => {
      await expireClaimOwner(claim!);
      reached.resolve();
      await release.promise;
    }
  });
  void first.catch(() => undefined);
  const paused = await Promise.race([reached.promise.then(() => true), first.then(() => false)]);
  if (!paused) {
    expect(paused).toBe(true);
    return;
  }

  await expect(publishExclusiveFile(layout, target, "loser")).rejects.toMatchObject({ code: "EEXIST" });
  expect((await lstat(target, { bigint: true })).nlink).toBe(1n);
  release.resolve();
  await Promise.allSettled([first]);
  await expect(readFile(target, "utf8")).resolves.toBe("owned");
});

test("recovers an expired dead HMAC-key publisher in the two-link window", async () => {
  const root = await fixtureRoot();
  const options = { cacheDirectory: join(root, "cache") };
  const project = join(root, "project");
  const layout = await prepareSecureCache(options, project);
  const target = join(layout.root, "changeset-hmac.key");
  const reached = deferred<void>();
  const release = deferred<void>();
  let claim: { path: string } | undefined;
  const first = publishExclusiveFile(layout, target, Buffer.alloc(32, 9), {
    afterClaimAcquire: async (owned) => { claim = owned; },
    afterLink: async () => {
      await expireClaimOwner(claim!);
      reached.resolve();
      await release.promise;
    }
  });
  void first.catch(() => undefined);
  await reached.promise;

  const validation = prepareSecureCache(options, project);
  const recovered = await Promise.race([
    validation.then(() => true),
    new Promise<false>((accept) => setTimeout(() => accept(false), 200))
  ]);
  release.resolve();
  await Promise.allSettled([first, validation]);

  expect(recovered).toBe(true);
  expect((await lstat(target, { bigint: true })).nlink).toBe(1n);
  await expect(readFile(target)).resolves.toEqual(Buffer.alloc(32, 9));
});

test("lets concurrent readers converge one exact dead two-link publication", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.root, "concurrent-dead-read.bin");
  const publisherReached = deferred<void>();
  const releasePublisher = deferred<void>();
  const recoverersReached = deferred<void>();
  const releaseRecoverers = deferred<void>();
  let claim: { path: string } | undefined;
  let recovererCount = 0;
  const publication = publishExclusiveFile(layout, target, "owned", {
    afterClaimAcquire: async (owned) => { claim = owned; },
    afterLink: async () => {
      await expireClaimOwner(claim!);
      publisherReached.resolve();
      await releasePublisher.promise;
    }
  });
  void publication.catch(() => undefined);
  await publisherReached.promise;
  const recoveryHooks = {
    beforeDeadTemporaryCleanup: async () => {
      recovererCount += 1;
      if (recovererCount === 2) recoverersReached.resolve();
      await releaseRecoverers.promise;
    }
  };
  const readers = [
    validateCacheFile(layout, target, false, recoveryHooks),
    validateCacheFile(layout, target, false, recoveryHooks)
  ];
  await recoverersReached.promise;
  releaseRecoverers.resolve();

  await expect(Promise.all(readers)).resolves.toEqual([undefined, undefined]);
  expect((await lstat(target, { bigint: true })).nlink).toBe(1n);
  releasePublisher.resolve();
  await Promise.allSettled([publication]);
});

test("reads a dead HMAC-key publication after exact temporary cleanup and reclaims its claim on collision", async () => {
  const root = await fixtureRoot();
  const options = { cacheDirectory: join(root, "cache") };
  const project = join(root, "project");
  const layout = await prepareSecureCache(options, project);
  const target = join(layout.root, "changeset-hmac.key");
  const reached = deferred<void>();
  const release = deferred<void>();
  let claim: { path: string } | undefined;
  const publish = publishExclusiveFile as unknown as (
    layout: Parameters<typeof publishExclusiveFile>[0],
    target: string,
    bytes: Uint8Array,
    hooks: Parameters<typeof publishExclusiveFile>[3] & { afterTemporaryCleanup: () => Promise<void> }
  ) => Promise<void>;
  const first = publish(layout, target, Buffer.alloc(32, 5), {
    afterClaimAcquire: async (owned) => { claim = owned; },
    afterTemporaryCleanup: async () => {
      await expireClaimOwner(claim!);
      reached.resolve();
      await release.promise;
    }
  });
  void first.catch(() => undefined);
  const paused = await Promise.race([reached.promise.then(() => true), first.then(() => false)]);
  if (!paused) {
    expect(paused).toBe(true);
    return;
  }

  await expect(prepareSecureCache(options, project)).resolves.toEqual(expect.objectContaining({ root: layout.root }));
  await expect(publishExclusiveFile(layout, target, Buffer.alloc(32, 1))).rejects.toMatchObject({ code: "EEXIST" });
  release.resolve();
  await Promise.allSettled([first]);

  expect((await lstat(target, { bigint: true })).nlink).toBe(1n);
  await expect(readFile(target)).resolves.toEqual(Buffer.alloc(32, 5));
});

test("moves a released claim out of the deterministic path before fallible cleanup", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "e".repeat(64));
  const claim = await claimOwnedSnapshotDirectory(layout, target);
  const cleanupFault = new Error("post-release cleanup fault");
  const remove = safeRemoveOwnedPublicationClaim as unknown as (
    layout: Parameters<typeof safeRemoveOwnedPublicationClaim>[0],
    claim: Parameters<typeof safeRemoveOwnedPublicationClaim>[1],
    hooks: { afterRename: (releasedPath: string) => Promise<void> }
  ) => Promise<void>;

  await expect(remove(layout, claim, { afterRename: async () => { throw cleanupFault; } })).rejects.toBe(cleanupFault);
  await expect(lstat(claim.path)).rejects.toMatchObject({ code: "ENOENT" });
  const next = await claimOwnedSnapshotDirectory(layout, target);
  await safeRemoveOwnedPublicationClaim(layout, next);
});

test("accepts an owned temporary that disappears between enumeration and stat only after target convergence", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.root, "owned-churn.bin");
  const linked = deferred<void>();
  const release = deferred<void>();
  let ownedTemporary = "";
  let observed = false;
  const publication = publishExclusiveFile(layout, target, "payload", {
    afterLink: async (temporary) => {
      ownedTemporary = temporary;
      linked.resolve();
      await release.promise;
    }
  });
  await linked.promise;
  const fallback = setTimeout(() => release.resolve(), 500);
  const validationHooks = {
    beforeEnumeratedTemporaryStat: async (temporary: string) => {
      if (temporary !== ownedTemporary || observed) return;
      observed = true;
      release.resolve();
      for (;;) {
        const missing = await lstat(temporary).then(() => false, (error: NodeJS.ErrnoException) => error.code === "ENOENT");
        if (missing) break;
        await new Promise<void>((accept) => setTimeout(accept, 5));
      }
    }
  } as Parameters<typeof validateCacheFile>[3] & {
    beforeEnumeratedTemporaryStat: (temporary: string, target: string) => Promise<void>;
  };
  try {
    await expect(Promise.all([
      publication,
      validateCacheFile(layout, target, false, validationHooks)
    ])).resolves.toEqual([undefined, undefined]);
  } finally {
    clearTimeout(fallback);
    release.resolve();
  }
  expect(observed).toBe(true);
  expect((await lstat(target, { bigint: true })).nlink).toBe(1n);
});

test("retries complete publication proof when an unrelated enumerated temporary disappears", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.root, "unrelated-churn.bin");
  const unrelated = join(layout.root, `.${randomUUID()}.tmp`);
  const linked = deferred<void>();
  const release = deferred<void>();
  const churnObserved = deferred<void>();
  let observed = false;
  await writeFile(unrelated, "unrelated", { mode: 0o600 });
  const publication = publishExclusiveFile(layout, target, "payload", {
    afterLink: async () => {
      linked.resolve();
      await release.promise;
    }
  });
  await linked.promise;
  const validationHooks = {
    beforeEnumeratedTemporaryStat: async (temporary: string) => {
      if (temporary !== unrelated || observed) return;
      observed = true;
      await rm(unrelated);
      churnObserved.resolve();
    }
  } as Parameters<typeof validateCacheFile>[3] & {
    beforeEnumeratedTemporaryStat: (temporary: string, target: string) => Promise<void>;
  };
  const validation = validateCacheFile(layout, target, false, validationHooks);
  const sawChurn = await Promise.race([
    churnObserved.promise.then(() => true),
    new Promise<false>((accept) => setTimeout(() => accept(false), 500))
  ]);
  release.resolve();

  await expect(Promise.all([publication, validation])).resolves.toEqual([undefined, undefined]);
  expect(sawChurn).toBe(true);
  expect((await lstat(target, { bigint: true })).nlink).toBe(1n);
});

test("guards exact claim cleanup when the parent changes immediately after file claim acquisition", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "parent-capture.bin");
  const movedParent = `${layout.indexes}.owned-moved`;
  const movedClaim = join(movedParent, ".publish-parent-capture.bin");
  const hooks = {
    afterClaimAcquire: async () => {
      await rename(layout.indexes, movedParent);
      await mkdir(layout.indexes, { mode: 0o700 });
    }
  } as Parameters<typeof publishExclusiveFile>[3] & { afterClaimAcquire: () => Promise<void> };

  await expect(publishExclusiveFile(layout, target, "payload", hooks)).rejects.toSatisfy((error: unknown) =>
    error instanceof AggregateError && error.errors.length >= 2
  );
  await expect(lstat(movedClaim)).resolves.toSatisfy((metadata) => metadata.isFile());
  await expect(lstat(target)).rejects.toMatchObject({ code: "ENOENT" });
});

test("cleans an exact snapshot claim candidate when a pre-link fault occurs", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "a".repeat(64));
  const claim = join(layout.indexes, `.publish-${"a".repeat(64)}`);
  const create = claimOwnedSnapshotDirectory as unknown as (
    layout: Parameters<typeof claimOwnedSnapshotDirectory>[0],
    path: string,
    hooks: { beforeClaimLink: () => Promise<void> }
  ) => Promise<unknown>;

  await expect(create(layout, target, { beforeClaimLink: async () => { throw new Error("claim pre-link fault"); } }))
    .rejects.toThrow(/claim pre-link fault/i);
  await expect(lstat(claim)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(lstat(target)).rejects.toMatchObject({ code: "ENOENT" });
});

test("does not remove a replacement at a failed snapshot claim candidate path", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "b".repeat(64));
  let candidate = "";
  let movedCandidate = "";
  const create = claimOwnedSnapshotDirectory as unknown as (
    layout: Parameters<typeof claimOwnedSnapshotDirectory>[0],
    path: string,
    hooks: { beforeClaimLink: (candidate: string) => Promise<void> }
  ) => Promise<unknown>;

  await expect(create(layout, target, {
    beforeClaimLink: async (path) => {
      candidate = path;
      movedCandidate = `${path}.owned-moved`;
      await rename(path, movedCandidate);
      await writeFile(path, "replacement", { encoding: "utf8", mode: 0o600 });
      throw new Error("claim parent swap fault");
    }
  })).rejects.toSatisfy((error: unknown) =>
    error instanceof AggregateError && /claim parent swap fault/i.test(String(error.errors[0]))
  );
  await expect(readFile(candidate, "utf8")).resolves.toBe("replacement");
  await expect(lstat(movedCandidate)).resolves.toSatisfy((metadata) => metadata.isFile());
});

test("reports the exact retained claim candidate when its parent is swapped before link", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.indexes, "c".repeat(64));
  const movedParent = `${layout.indexes}.owned-moved`;
  let movedCandidate = "";
  const replacementMarker = join(layout.indexes, "replacement.txt");

  await expect(claimOwnedSnapshotDirectory(layout, target, {
    beforeClaimLink: async (candidate) => {
      movedCandidate = join(movedParent, basename(candidate));
      await rename(layout.indexes, movedParent);
      await mkdir(layout.indexes);
      await writeFile(replacementMarker, "replacement", "utf8");
      throw new Error("claim parent changed");
    }
  })).rejects.toSatisfy((error: unknown) =>
    error instanceof AggregateError &&
    /claim parent changed/i.test(String(error.errors[0])) &&
    /retained|exact path|cleanup/i.test(String(error.errors[1]))
  );
  await expect(lstat(movedCandidate)).resolves.toSatisfy((metadata) => metadata.isFile());
  await expect(readFile(replacementMarker, "utf8")).resolves.toBe("replacement");
});

test("cleans an exact random build directory when post-mkdir setup fails", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  let created = "";
  const create = createOwnedBuildDirectory as unknown as (
    layout: Parameters<typeof createOwnedBuildDirectory>[0],
    parent: string,
    hooks: { afterMkdir: (identity: { path: string }) => Promise<void> }
  ) => Promise<unknown>;

  await expect(create(layout, layout.indexes, {
    afterMkdir: async (identity) => {
      created = identity.path;
      throw new Error("build post-mkdir fault");
    }
  })).rejects.toThrow(/build post-mkdir fault/i);
  await expect(lstat(created)).rejects.toMatchObject({ code: "ENOENT" });
});

test.skipIf(process.platform === "win32")("rejects replacement during HMAC permission repair without chmodding it", async () => {
  const root = await fixtureRoot();
  const layout = await prepareSecureCache({ cacheDirectory: join(root, "cache") }, join(root, "project"));
  const target = join(layout.root, "changeset-hmac.key");
  const moved = `${target}.moved`;
  await writeFile(target, Buffer.alloc(32), { mode: 0o644 });
  const validate = validateCacheFile as unknown as (
    layout: Parameters<typeof validateCacheFile>[0],
    path: string,
    allowMissing: boolean,
    hooks: { beforeFileModeRepair: () => Promise<void> }
  ) => Promise<void>;

  await expect(validate(layout, target, false, {
    beforeFileModeRepair: async () => {
      await rename(target, moved);
      await writeFile(target, Buffer.alloc(32, 1), { mode: 0o644 });
    }
  })).rejects.toThrow(/identity|changed|replacement/i);
  expect((await stat(target)).mode & 0o777).toBe(0o644);
});

test.runIf(process.platform !== "win32" && typeof process.getuid === "function" && process.getuid() === 0)(
  "rejects a wrong-owner cache directory without changing its mode",
  async () => {
    const root = await fixtureRoot();
    const cache = join(root, "wrong-owner-cache");
    await mkdir(cache, { mode: 0o755 });
    await chown(cache, 65_534, 65_534);

    await expect(prepareSecureCache({ cacheDirectory: cache }, join(root, "project"))).rejects.toThrow(/owner/i);
    expect((await stat(cache)).mode & 0o777).toBe(0o755);
  }
);
