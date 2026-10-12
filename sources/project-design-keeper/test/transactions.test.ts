import { createHash, randomUUID } from "node:crypto";
import { appendFile, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import {
  createProjectFixture,
  removeProjectFixture,
  type ProjectFixture
} from "./fixtures.js";
import { writeCanonicalPackFixture } from "./canonical-pack-fixture.js";
import { createTrustedTestKeeper } from "./keeper.js";
import { persistedChangesetSchema } from "../src/types/schema.js";

type KeeperModule = typeof import("../src/index.js");
type Keeper = KeeperModule["projectDesignKeeper"];

let fixture: ProjectFixture | undefined;
let cacheDirectory: string | undefined;

beforeEach(async () => {
  fixture = await createProjectFixture();
  cacheDirectory = await mkdtemp(join(tmpdir(), "project-design-keeper-cache-"));
});

afterEach(async () => {
  vi.useRealTimers();
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
  if (!cacheDirectory) throw new Error("cache directory was not created");
  return cacheDirectory;
}

async function module(): Promise<KeeperModule> {
  return import("../src/index.js");
}

async function keeper(options: Record<string, unknown> = {}): Promise<Keeper> {
  return createTrustedTestKeeper({ cacheDirectory: cache(), ...options }) as Keeper;
}

async function expectChangesetPairPresent(changesetId: unknown): Promise<void> {
  const id = String(changesetId);
  await expect(readFile(join(cache(), "changesets", `${id}.json`), "utf8")).resolves.toContain(id);
  await expect(readFile(join(cache(), "changesets", `${id}.sig.json`), "utf8")).resolves.toContain("hmac-sha256");
}

function hash(content: string): string {
  return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
}

function managedBlock(recordId: string, content: string, contentHash = hash(content)): string {
  return `<!-- project-design-keeper:managed record-id="${recordId}" content-hash="${contentHash}" -->${content}<!-- /project-design-keeper:managed -->`;
}

function ownedJson(value: unknown): string {
  return `${JSON.stringify({ managedBy: "project-design-keeper", schemaVersion: "1.0", value }, null, 2)}\n`;
}

function canonicalPack(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const requiredDocuments = [
    "index.md",
    "intent.md",
    "principles.md",
    "architecture.md",
    "conventions.md",
    "decisions.md",
    "open-questions.md",
    "evidence-map.md"
  ].map((name) => ({ id: name.replace(/\.md$/u, ""), path: `docs/project-design/${name}` }));
  return {
    managedBy: "project-design-keeper",
    schemaVersion: "1.0",
    scope: { root: ".", paths: ["Source"] },
    sourceRevision: { kind: "snapshot", files: { "Source/game.ts": hash("source line\n") } },
    documents: [...requiredDocuments, { id: "design-overview", path: "docs/project-design/overview.md" }],
    records: [{
      id: "combat.damage-model",
      domain: "combat",
      scope: "damage",
      statement: "Damage is resolved on the authority.",
      evidence: ["Source/game.ts:1"],
      impact: ["Networked damage calculations"],
      status: "declared",
      strength: "required",
      approval: "confirmed",
      confidence: "high"
    }],
    ...overrides
  };
}

async function writeCanonicalPackFiles(): Promise<void> {
  await mkdir(join(project().repository, "docs", "project-design"), { recursive: true });
  await mkdir(join(project().repository, "Source"), { recursive: true });
  await writeFile(join(project().repository, "Source", "game.ts"), "source line\n", "utf8");
  for (const name of ["index.md", "intent.md", "principles.md", "architecture.md", "conventions.md", "decisions.md", "open-questions.md", "evidence-map.md"]) {
    await writeFile(join(project().repository, "docs", "project-design", name), "", "utf8");
  }
  await writeFile(join(project().repository, "docs", "project-design", "overview.md"), managedBlock("combat.damage-model", "record"), "utf8");
}

async function persistedJsonFiles(root: string): Promise<string[]> {
  const found: string[] = [];
  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.name.endsWith(".json")) found.push(path);
    }
  }
  await visit(root);
  return found;
}

describe("knowledge-pack schema", () => {
  test("accepts the canonical metadata, documents, and stable knowledge record shape", async () => {
    const api = await keeper();
    await writeCanonicalPackFiles();

    await expect(api.validatePack({ root: project().repository, pack: canonicalPack() }))
      .resolves.toMatchObject({ valid: true });
  });

  test("rejects a canonical pack missing required metadata or record fields", async () => {
    const api = await keeper();
    const pack = canonicalPack({ schemaVersion: undefined });
    const [record] = pack.records as Array<Record<string, unknown>>;
    delete record.statement;

    await expect(api.validatePack({ root: project().repository, pack }))
      .resolves.toMatchObject({ valid: false, errors: expect.any(Array) });
  });

  test("rejects unsupported knowledge-record enum values", async () => {
    const api = await keeper();
    const pack = canonicalPack();
    (pack.records as Array<Record<string, unknown>>)[0].status = "accepted";

    await expect(api.validatePack({ root: project().repository, pack }))
      .resolves.toMatchObject({ valid: false });
  });

  test("allows required or preferred strength only for user-confirmed records", async () => {
    const api = await keeper();
    const pack = canonicalPack();
    (pack.records as Array<Record<string, unknown>>)[0].approval = "pending";

    await expect(api.validatePack({ root: project().repository, pack }))
      .resolves.toMatchObject({ valid: false, errors: expect.arrayContaining([expect.objectContaining({ message: expect.stringMatching(/confirmed/i) })]) });
  });
});

describe("preview persistence and path safety", () => {
  test("bounds a candidate pack before preview reads or candidate helpers", async () => {
    const pack = await writeCanonicalPackFixture(project()) as Record<string, unknown>;
    const baselineBytes = Buffer.byteLength(JSON.stringify(pack), "utf8");
    pack.untrustedExtension = "x".repeat(2_048);
    const maximumBytes = baselineBytes + 128;
    let currentManifestReads = 0;
    const api = await keeper({
      limits: { mcpArgumentBytes: maximumBytes },
      afterCurrentManifestRead: async () => { currentManifestReads += 1; }
    });

    await expect(api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: "docs/project-design/manifest.json",
        content: `${JSON.stringify(pack, null, 2)}\n`
      }]
    })).rejects.toThrow(new RegExp(`pack validation input.*${maximumBytes} bytes`, "i"));
    expect(currentManifestReads).toBe(0);
  });

  test("binds service scan limits to preview candidate validation", async () => {
    const pack = await writeCanonicalPackFixture(project()) as Record<string, unknown>;
    await appendFile(
      join(project().repository, "docs", "project-design", "intent.md"),
      `\n${"x".repeat(2_048)}`,
      "utf8"
    );
    const api = await keeper({ limits: { scan: { maxFileBytes: 1_024 } } });

    await expect(api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: "docs/project-design/manifest.json",
        content: `${JSON.stringify(pack, null, 2)}\n`
      }]
    })).rejects.toThrow(/pack validation file.*1[ ,]?024 bytes/i);
  });

  test("binds service validation identity hooks to preview candidate validation", async () => {
    const pack = await writeCanonicalPackFixture(project()) as Record<string, unknown>;
    const sourcePath = "docs/设计 evidence.txt";
    let hookCalls = 0;
    const api = await keeper({
      validationIo: {
        afterProjectFileOpen: async (path: string) => {
          if (path !== sourcePath || hookCalls > 0) return;
          hookCalls += 1;
          await writeFile(project().trackedText, "Keeper evidence: sun--garden\n", "utf8");
        }
      }
    });

    await expect(api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: "docs/project-design/manifest.json",
        content: `${JSON.stringify(pack, null, 2)}\n`
      }]
    })).rejects.toThrow(/pack validation file.*identity.*changed/i);
    expect(hookCalls).toBe(1);
  });

  test("shares one aggregate budget across preview reads and candidate validation", async () => {
    const pack = await writeCanonicalPackFixture(project()) as Record<string, any>;
    const manifestContent = `${JSON.stringify(pack, null, 2)}\n`;
    const documentBytes = (await Promise.all((pack.documents as Array<{ path: string }>).map(async (document) =>
      (await readFile(join(project().repository, ...document.path.split("/")))).byteLength)))
      .reduce((total, bytes) => total + bytes, 0);
    const maximumBytes = Buffer.byteLength(manifestContent, "utf8") + documentBytes + 1_024;
    const api = await keeper({ limits: { preview: { maxAggregateBytes: maximumBytes } } });

    await expect(api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{ path: "docs/project-design/manifest.json", content: manifestContent }]
    })).rejects.toThrow(new RegExp(`preview file reads.*${maximumBytes} bytes`, "i"));
  });

  test("bounds the project-design output inventory when project-design outputs are in scope", async () => {
    const api = await keeper({ limits: { scan: { maxFiles: 4 } } });
    const pack = await writeCanonicalPackFixture(project());
    const existingIndex = await readFile(join(project().repository, "docs", "project-design", "index.md"), "utf8");

    await expect(api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: "docs/project-design/index.md",
        content: existingIndex
      }]
    })).rejects.toThrow(/project-design output inventory.*limit/i);

    await expect(readdir(join(cache(), "changesets"))).resolves.toEqual([]);
  });

  test("bounds project-design output inventory depth and the shared scan deadline", async () => {
    const pack = await writeCanonicalPackFixture(project());
    const outputRoot = join(project().repository, "docs", "project-design");
    const deep = Array.from({ length: 17 }, (_, index) => `level-${index}`).reduce(
      (parent, segment) => join(parent, segment),
      outputRoot
    );
    await mkdir(deep, { recursive: true });
    await writeFile(join(deep, "owned.md"), managedBlock("deep", "deep"), "utf8");

    const depthBounded = await keeper();
    await expect(depthBounded.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: "docs/project-design/index.md",
        content: await readFile(join(outputRoot, "index.md"), "utf8")
      }]
    })).rejects.toThrow(/project-design output inventory.*depth/i);

    await rm(outputRoot, { recursive: true, force: true });
    await mkdir(outputRoot, { recursive: true });
    const deadlineBounded = await keeper({ limits: { scan: { deadlineMs: 0 } } });
    await expect(deadlineBounded.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: "docs/project-design/index.md",
        content: managedBlock("deadline", "bounded\n")
      }]
    })).rejects.toThrow(/pack validation.*deadline/i);
  });

  test("bounds existing target reads by per-file and aggregate preview bytes", async () => {
    const target = join(project().repository, ".agents", "skills", "project-design-context", "bounded-target.json");
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, ownedJson("x".repeat(256)), "utf8");
    const api = await keeper({ limits: { preview: { maxFileBytes: 64, maxAggregateBytes: 64 } } });

    await expect(api.previewUpdate({
      root: project().repository,
      changes: [{
        path: ".agents/skills/project-design-context/bounded-target.json",
        content: ownedJson("replacement")
      }]
    })).rejects.toThrow(/preview file reads.*limit|bounded preview read/i);

    await expect(readdir(join(cache(), "changesets"))).resolves.toEqual([]);
  });

  test("persists a generated diff above 768 KiB and returns a bounded first page", async () => {
    const api = await keeper();

    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{
        path: ".agents/skills/project-design-context/oversized-diff.md",
        content: managedBlock("oversized-diff", "x".repeat(800 * 1024))
      }]
    });
    expect(preview.applicable).toBe(true);
    expect(preview.complete).toBe(false);
    expect(preview.nextCursor).toEqual(expect.any(String));
    expect(Buffer.byteLength(JSON.stringify(preview))).toBeLessThan(1024 * 1024);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("omits repeated content when the complete preview would exceed the result budget", async () => {
    const api = await keeper();

    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{
        path: ".agents/skills/project-design-context/oversized-result.md",
        content: managedBlock("oversized-result", "y".repeat(600 * 1024))
      }]
    });
    expect(preview.applicable).toBe(true);
    expect(preview.complete).toBe(false);
    expect(preview.changes).toEqual([expect.objectContaining({ contentOmitted: true })]);
    expect(Buffer.byteLength(JSON.stringify(preview))).toBeLessThan(1024 * 1024);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("persists a full changeset while returning a human-readable summary without project writes", async () => {
    const api = await keeper();
    const target = ".agents/skills/project-design-context/new.md";

    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: target, content: managedBlock("new-design", "new design\n") }]
    });

    expect(preview).toMatchObject({
      changesetId: expect.any(String),
      summary: expect.stringContaining(target),
      changes: [{ path: target }]
    });
    await expect(readFile(join(project().repository, target), "utf8")).rejects.toThrow();
    const files = await persistedJsonFiles(cache());
    const stored = JSON.parse(await readFile(files.find((path) => path.includes("changesets"))!, "utf8"));
    expect(stored).toMatchObject({ root: project().repository, changes: [{ path: target, content: managedBlock("new-design", "new design\n") }] });
  });

  test("rejects traversal, absolute, and alternate managed-root spellings", async () => {
    const api = await keeper();
    const invalid = [
      "docs/project-design/../../outside.md",
      join(project().repository, "docs", "project-design", "absolute.md"),
      "docs/project-design-other/not-allowed.md"
    ];

    for (const path of invalid) {
      await expect(api.previewUpdate({ root: project().repository, changes: [{ path, content: "x" }] }))
        .rejects.toThrow(/path|managed|relative/i);
    }
  });

  test("rejects a managed-path parent symlink that escapes the repository", async () => {
    const api = await keeper();
    const link = join(project().repository, "docs", "project-design");
    try {
      await symlink(project().nonGitDirectory, link, "dir");
    } catch {
      return;
    }

    await expect(api.previewUpdate({
      root: project().repository,
      pack: canonicalPack(),
      changes: [{ path: "docs/project-design/escape.md", content: "x" }]
    })).rejects.toThrow(/escape|outside|symbolic-link|reparse|managed root/i);
  });

  test("cache-directory precedence honors service, PLUGIN_DATA, LOCALAPPDATA, XDG, then home", async () => {
    const { resolveCacheDirectory } = await module();
    const cases = [
      [{ cacheDirectory: "explicit" }, { PLUGIN_DATA: "plugin", LOCALAPPDATA: "local", XDG_CACHE_HOME: "xdg" }, "home", resolve("explicit")],
      [{}, { PLUGIN_DATA: "plugin", LOCALAPPDATA: "local", XDG_CACHE_HOME: "xdg" }, "home", resolve("plugin")],
      [{}, { LOCALAPPDATA: "local", XDG_CACHE_HOME: "xdg" }, "home", resolve("local", "project-design-keeper")],
      [{}, { XDG_CACHE_HOME: "xdg" }, "home", resolve("xdg", "project-design-keeper")],
      [{}, {}, "home", resolve("home", ".cache", "project-design-keeper")]
    ] as const;

    for (const [options, environment, home, expected] of cases) {
      expect(resolveCacheDirectory(options, environment, home)).toBe(expected);
    }
  });

  test("expires a changeset at exactly thirty minutes and reloads by id", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-06T00:00:00.000Z"));
    const api = await keeper();
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: ".agents/skills/project-design-context/expires.md", content: managedBlock("expires", "x") }]
    });
    vi.advanceTimersByTime(30 * 60 * 1000);

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/expired/i);
  });

  test("removes both authenticated changeset halves after a successful apply", async () => {
    const api = await keeper();
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{
        path: ".agents/skills/project-design-context/consumed.md",
        content: managedBlock("consumed", "applied")
      }]
    });
    const changeset = join(cache(), "changesets", `${String(preview.changesetId)}.json`);
    const signature = join(cache(), "changesets", `${String(preview.changesetId)}.sig.json`);

    await api.applyUpdate({ root: project().repository, changesetId: preview.changesetId });

    await expect(lstat(changeset)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(signature)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("retains a failed pair for retry and consumes it only after the retry commits", async () => {
    let failOnce = true;
    const api = await keeper({
      beforeStageWrite: async () => {
        if (!failOnce) return;
        failOnce = false;
        throw new Error("injected pre-commit failure");
      }
    });
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{
        path: ".agents/skills/project-design-context/retry-consume.md",
        content: managedBlock("retry-consume", "applied on retry")
      }]
    });
    const changeset = join(cache(), "changesets", `${String(preview.changesetId)}.json`);
    const signature = join(cache(), "changesets", `${String(preview.changesetId)}.sig.json`);

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/injected pre-commit failure/i);
    await expect(lstat(changeset)).resolves.toMatchObject({ size: expect.any(Number) });
    await expect(lstat(signature)).resolves.toMatchObject({ size: expect.any(Number) });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .resolves.toMatchObject({ applied: true });
    await expect(lstat(changeset)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(signature)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("reports a post-commit consume race while preserving the applied project and replacement evidence", async () => {
    let changeset = "";
    let signature = "";
    const replacement = Buffer.from("raced replacement", "utf8");
    const api = await keeper({
      beforeChangesetConsume: async (_root: string, changesetId: string) => {
        changeset = join(cache(), "changesets", `${changesetId}.json`);
        signature = join(cache(), "changesets", `${changesetId}.sig.json`);
        await rename(signature, `${signature}.evidence`);
        await writeFile(signature, replacement, { mode: 0o600 });
      }
    });
    const target = join(project().repository, ".agents", "skills", "project-design-context", "consume-race.md");
    const content = managedBlock("consume-race", "applied before consume race");
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: ".agents/skills/project-design-context/consume-race.md", content }]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/committed successfully.*could not be consumed|files remain applied/i);

    await expect(readFile(target, "utf8")).resolves.toBe(content);
    await expect(readFile(changeset, "utf8")).resolves.toContain(String(preview.changesetId));
    await expect(readFile(signature)).resolves.toEqual(replacement);
    await expect(readFile(`${signature}.evidence`, "utf8")).resolves.toContain("hmac-sha256");
  });

  test("treats an exact pair already removed by concurrent garbage collection as consumed after commit", async () => {
    const api = await keeper({
      beforeChangesetConsume: async (_root: string, changesetId: string) => {
        await rm(join(cache(), "changesets", `${changesetId}.json`));
        await rm(join(cache(), "changesets", `${changesetId}.sig.json`));
      }
    });
    const target = join(project().repository, ".agents", "skills", "project-design-context", "consume-gc.md");
    const content = managedBlock("consume-gc", "applied before concurrent collection");
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: ".agents/skills/project-design-context/consume-gc.md", content }]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .resolves.toMatchObject({ applied: true });

    await expect(readFile(target, "utf8")).resolves.toBe(content);
  });
});

describe("optimistic concurrency", () => {
  test("rejects missing changesets and root mismatches", async () => {
    const api = await keeper();
    await expect(api.applyUpdate({ root: project().repository, changesetId: "00000000-0000-4000-8000-000000000000" }))
      .rejects.toThrow(/missing|not found/i);

    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: ".agents/skills/project-design-context/root.md", content: managedBlock("root", "x") }]
    });
    await expect(api.applyUpdate({ root: project().nonGitDirectory, changesetId: preview.changesetId }))
      .rejects.toThrow(/root/i);
  });

  test("rejects a manifest changed after preview even when it is not a target", async () => {
    const api = await keeper();
    const manifest = join(project().repository, "docs", "project-design", "manifest.json");
    await mkdir(join(project().repository, "docs", "project-design"), { recursive: true });
    await writeFile(manifest, `${JSON.stringify({ managedBy: "project-design-keeper", schemaVersion: "1.0" })}\n`, "utf8");
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: ".agents/skills/project-design-context/manifest-stale.md", content: managedBlock("manifest-stale", "x") }]
    });
    await writeFile(manifest, "{\"changed\":true}\n", "utf8");

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/manifest.*stale|stale.*manifest/i);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("rejects a selected source changed after preview", async () => {
    const api = await keeper();
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: ".agents/skills/project-design-context/source-stale.md", content: managedBlock("source-stale", "x") }]
    });
    await writeFile(project().trackedText, "changed source\n", "utf8");

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/source.*stale|stale.*source/i);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("rechecks every candidate-pack source even when preview path is narrower", async () => {
    const api = await keeper({
      afterCandidateValidation: async () => {
        await writeFile(project().trackedText, "changed between validation and persistence\n", "utf8");
      }
    });
    const pack = await writeCanonicalPackFixture(project());
    await writeFile(
      join(project().repository, "docs/project-design/manifest.json"),
      `${JSON.stringify(pack, null, 2)}\n`,
      "utf8"
    );
    await mkdir(join(project().repository, "Other"), { recursive: true });
    await writeFile(join(project().repository, "Other", "placeholder.txt"), "unrelated\n", "utf8");
    const preview = await api.previewUpdate({
      root: project().repository,
      path: "Other",
      pack,
      changes: [{ path: ".agents/skills/project-design-context/pack-source-stale.md", content: managedBlock("pack-source-stale", "x") }]
    });
    expect(preview).toMatchObject({ applicable: true, changesetId: expect.any(String) });
    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/source.*stale|stale.*source/i);
  });

  test("bounds exact candidate-pack source reads during apply", async () => {
    const api = await keeper({ limits: { scan: { maxFileBytes: 256, maxAggregateBytes: 4_096 } } });
    const pack = await writeCanonicalPackFixture(project());
    await writeFile(
      join(project().repository, "docs/project-design/manifest.json"),
      `${JSON.stringify(pack, null, 2)}\n`,
      "utf8"
    );
    const preview = await api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: ".agents/skills/project-design-context/bounded-source.md",
        content: managedBlock("bounded-source", "bounded\n")
      }]
    });
    await writeFile(project().trackedText, "x".repeat(300), "utf8");

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/source file reads.*limit|bounded source read/i);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("fails closed when apply source revalidation exhausts the scan deadline", async () => {
    let applying = false;
    const api = await keeper({
      limits: { scan: { deadlineMs: 1_000 } },
      scopeIo: {
        beforeGitCommand: async (args: readonly string[]) => {
          if (applying && args.includes("--show-toplevel")) await delay(2_000);
        }
      }
    });
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: Array.from({ length: 8 }, (_, index) => ({
        path: `.agents/skills/project-design-context/apply-budget-${index}.md`,
        content: managedBlock(`apply-budget-${index}`, `bounded ${index}\n`)
      }))
    });
    applying = true;

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/(?:apply|cold scan).*deadline|selected source snapshot is stale/i);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("rejects a declared pack document changed after preview validation", async () => {
    const api = await keeper();
    const pack = await writeCanonicalPackFixture(project()) as Record<string, any>;
    await writeFile(
      join(project().repository, "docs", "project-design", "manifest.json"),
      `${JSON.stringify(pack, null, 2)}\n`,
      "utf8"
    );
    const preview = await api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: ".agents/skills/project-design-context/validated-dependency.md",
        content: managedBlock("validated-dependency", "bounded\n")
      }]
    });
    expect(preview).toMatchObject({ applicable: true, changesetId: expect.any(String) });
    const documentPath = (pack.documents as Array<{ path: string }>)[0].path;
    await appendFile(join(project().repository, ...documentPath.split("/")), "late document drift\n", "utf8");

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/validation dependenc|candidate pack.*stale|pack validation/i);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("rejects an independently valid declared document rewrite after preview validation", async () => {
    const api = await keeper();
    const pack = await writeCanonicalPackFixture(project()) as Record<string, any>;
    await writeFile(
      join(project().repository, "docs", "project-design", "manifest.json"),
      `${JSON.stringify(pack, null, 2)}\n`,
      "utf8"
    );
    const preview = await api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: ".agents/skills/project-design-context/validated-content.md",
        content: managedBlock("validated-content", "bounded\n")
      }]
    });
    expect(preview).toMatchObject({ applicable: true, changesetId: expect.any(String) });
    const documentPath = (pack.documents as Array<{ path: string }>)[0].path;
    await writeFile(
      join(project().repository, ...documentPath.split("/")),
      managedBlock("record.1", "independently valid drift\n"),
      "utf8"
    );
    await expect(api.validatePack({ root: project().repository, pack }))
      .resolves.toMatchObject({ valid: true });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/validation dependenc|candidate pack.*stale/i);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("rejects a managed-tree inventory change after preview validation", async () => {
    const api = await keeper();
    const pack = await writeCanonicalPackFixture(project());
    await writeFile(
      join(project().repository, "docs", "project-design", "manifest.json"),
      `${JSON.stringify(pack, null, 2)}\n`,
      "utf8"
    );
    const preview = await api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: ".agents/skills/project-design-context/validated-inventory.md",
        content: managedBlock("validated-inventory", "bounded\n")
      }]
    });
    expect(preview).toMatchObject({ applicable: true, changesetId: expect.any(String) });
    await writeFile(
      join(project().repository, "docs", "project-design", "unmapped-after-preview.md"),
      "unmapped after preview\n",
      "utf8"
    );

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/validation dependenc|candidate pack.*stale|pack validation/i);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("authenticates validation dependencies across a fresh service instance", async () => {
    const first = await keeper();
    const pack = await writeCanonicalPackFixture(project());
    await writeFile(
      join(project().repository, "docs", "project-design", "manifest.json"),
      `${JSON.stringify(pack, null, 2)}\n`,
      "utf8"
    );
    const preview = await first.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: ".agents/skills/project-design-context/restarted-validation.md",
        content: managedBlock("restarted-validation", "bounded\n")
      }]
    });
    const stored = JSON.parse(await readFile(
      join(cache(), "changesets", `${String(preview.changesetId)}.json`),
      "utf8"
    )) as Record<string, unknown>;
    expect(stored).toMatchObject({
      validatedPack: expect.any(Object),
      validationDependencyDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u)
    });
    expect(persistedChangesetSchema.safeParse({ ...stored, validatedPack: undefined }).success).toBe(false);
    expect(persistedChangesetSchema.safeParse({ ...stored, validationDependencyDigest: undefined }).success).toBe(false);
    expect(persistedChangesetSchema.safeParse({
      ...stored,
      validatedPack: undefined,
      validationDependencyDigest: undefined
    }).success).toBe(true);

    const restarted = await keeper();
    await expect(restarted.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .resolves.toMatchObject({ applied: true });
  });

  test("persists the exact candidate object that produced the validation dependency digest", async () => {
    const pack = await writeCanonicalPackFixture(project()) as Record<string, any>;
    const originalStatement = (pack.records as Array<Record<string, unknown>>)[0].statement;
    await writeFile(
      join(project().repository, "docs", "project-design", "manifest.json"),
      `${JSON.stringify(pack, null, 2)}\n`,
      "utf8"
    );
    const api = await keeper({
      afterCandidateValidation: async () => {
        (pack.records as Array<Record<string, unknown>>)[0].statement = "mutated after validation";
      }
    });
    const preview = await api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: ".agents/skills/project-design-context/candidate-snapshot.md",
        content: managedBlock("candidate-snapshot", "bounded\n")
      }]
    });
    const stored = JSON.parse(await readFile(
      join(cache(), "changesets", `${String(preview.changesetId)}.json`),
      "utf8"
    )) as Record<string, any>;

    expect(stored.validatedPack.records[0].statement).toBe(originalStatement);
  });

  test("shares candidate-validation work across repeated pre-mutation checks", async () => {
    const pack = await writeCanonicalPackFixture(project());
    await writeFile(
      join(project().repository, "docs", "project-design", "manifest.json"),
      `${JSON.stringify(pack, null, 2)}\n`,
      "utf8"
    );
    const api = await keeper({ limits: { scan: { maxEvidence: 500 } } });
    const preview = await api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: ".agents/skills/project-design-context/shared-validation-work.md",
        content: managedBlock("shared-validation-work", "bounded\n")
      }]
    });
    expect(preview).toMatchObject({ applicable: true, changesetId: expect.any(String) });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/apply candidate validation work.*500 items/i);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("shares candidate-validation analysis bytes across repeated pre-mutation checks", async () => {
    const pack = await writeCanonicalPackFixture(project());
    await writeFile(
      join(project().repository, "docs", "project-design", "manifest.json"),
      `${JSON.stringify(pack, null, 2)}\n`,
      "utf8"
    );
    const api = await keeper({ limits: { scan: { maxAggregateBytes: 25 * 1_024 } } });
    const preview = await api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: "docs/project-design/index.md",
        managedBlock: { recordId: "record.1", content: `${"x".repeat(10 * 1_024)}\n` }
      }]
    });
    expect(preview).toMatchObject({ applicable: true, conflicts: [], changesetId: expect.any(String) });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/apply candidate validation analysis.*25[ ,]?600 bytes/i);
    await expectChangesetPairPresent(preview.changesetId);
  });

  test("source concurrency ignores both generated output roots", async () => {
    const api = await keeper();
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: ".agents/skills/project-design-context/source-stable.md", content: managedBlock("source-stable", "x") }]
    });
    await mkdir(join(project().repository, ".agents", "skills", "project-design-context"), { recursive: true });
    await writeFile(join(project().repository, ".agents", "skills", "project-design-context", "other.md"), "human change\n", "utf8");

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .resolves.toMatchObject({ applied: true });
  });
});

describe("managed merges and output conflicts", () => {
  test("returns a non-applicable conflict when a managed marker hash is corrupt", async () => {
    const api = await keeper();
    const directory = join(project().repository, ".agents", "skills", "project-design-context");
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, "managed.md"), `intro\n${managedBlock("record", "old", hash("different"))}\noutro\n`, "utf8");

    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: ".agents/skills/project-design-context/managed.md", managedBlock: { recordId: "record", content: "new" } }]
    });

    expect(preview).toMatchObject({ applicable: false, conflicts: [expect.stringMatching(/hash/i)] });
    expect(preview).not.toHaveProperty("changesetId");
  });

  test("returns a non-applicable conflict when an expected managed hash differs", async () => {
    const api = await keeper();
    const directory = join(project().repository, ".agents", "skills", "project-design-context");
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, "managed.md"), managedBlock("record", "old"), "utf8");

    const preview = await api.previewUpdate({
      root: project().repository,
      expectedContentHash: hash("unexpected"),
      changes: [{ path: ".agents/skills/project-design-context/managed.md", managedBlock: { recordId: "record", content: "new" } }]
    });

    expect(preview).toMatchObject({ applicable: false, conflicts: [expect.any(String)] });
    expect(preview).not.toHaveProperty("changesetId");
  });

  test("reports an initialization conflict for unrelated unmanaged project-design files", async () => {
    const api = await keeper();
    const directory = join(project().repository, "docs", "project-design");
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, "human-notes.md"), "do not overwrite\n", "utf8");

    const preview = await api.previewUpdate({
      root: project().repository,
      pack: {},
      changes: [{ path: "docs/project-design/generated.md", content: "generated\n" }]
    });

    expect(preview).toMatchObject({ applicable: false, conflicts: [expect.stringMatching(/unmanaged/i)] });
    expect(preview).not.toHaveProperty("changesetId");
  });

  test("fails closed when a nested output disappears after an earlier unmanaged conflict was found", async () => {
    const pack = await writeCanonicalPackFixture(project());
    const directory = join(project().repository, "docs", "project-design");
    const vanishing = join(directory, "z-vanishing");
    await mkdir(vanishing, { recursive: true });
    await writeFile(join(directory, "a-human-notes.md"), "do not overwrite\n", "utf8");
    await writeFile(join(vanishing, "transient.md"), "transient\n", "utf8");
    const api = await keeper({
      beforeProjectDesignOutputEntry: async (path: string, kind: "file" | "directory") => {
        if (kind === "directory" && path === vanishing) await rm(path, { recursive: true });
      }
    });

    await expect(api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{ path: "docs/project-design/generated.md", content: managedBlock("generated", "generated\n") }]
    })).rejects.toMatchObject({ code: "ENOENT" });

    await expect(readdir(join(cache(), "changesets"))).resolves.toEqual([]);
  });
});

describe("atomic apply and recovery snapshots", () => {
  test("applies a complete pack when the manifest is followed by the project context Skill", async () => {
    const api = await keeper();
    const pack = await writeCanonicalPackFixture(project());
    const manifestPath = "docs/project-design/manifest.json";
    const skillPath = ".agents/skills/project-design-context/SKILL.md";
    const skill = [
      "---",
      "name: project-design-context",
      "description: \"Use when planning work with a Project Design Keeper knowledge pack.\"",
      "metadata:",
      "  managed-by: project-design-keeper",
      "---",
      managedBlock("skill.project-design-context.workflow", "# Project Design Context\n"),
      ""
    ].join("\n");
    const manifest = `${JSON.stringify(pack, null, 2)}\n`;
    const preview = await api.previewUpdate({
      root: project().repository,
      pack,
      changes: [
        { path: manifestPath, content: manifest },
        { path: skillPath, content: skill }
      ]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .resolves.toMatchObject({ applied: true });
    await expect(readFile(join(project().repository, manifestPath), "utf8")).resolves.toBe(manifest);
    await expect(readFile(join(project().repository, skillPath), "utf8")).resolves.toBe(skill);
  });

  test("writes no staged output when a later pre-stage hook fails", async () => {
    const api = await keeper({
      beforeStageWrite: async (_path: string, index: number) => {
        if (index === 1) throw new Error("injected staging failure");
      }
    });
    const directory = join(project().repository, ".agents", "skills", "project-design-context");
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [
        { path: ".agents/skills/project-design-context/one.md", content: managedBlock("one", "one\n") },
        { path: ".agents/skills/project-design-context/two.md", content: managedBlock("two", "two\n") }
      ]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/staging failure/i);
    await expect(readFile(join(directory, "one.md"), "utf8")).rejects.toThrow();
    await expect(readFile(join(directory, "two.md"), "utf8")).rejects.toThrow();
    await expect(readdir(directory)).rejects.toThrow();
  });

  test("creates nested output directories with the platform-exact parent link-count transition", async () => {
    const api = await keeper();
    const relativePath = ".agents/skills/project-design-context/posix/deep/created.json";
    const content = ownedJson("nested");
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: relativePath, content }]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .resolves.toMatchObject({ applied: true });
    await expect(readFile(join(project().repository, ...relativePath.split("/")), "utf8")).resolves.toBe(content);
  });

  test("cleans nested output directories with the platform-exact parent link-count transition", async () => {
    const relativePath = ".agents/skills/project-design-context/posix-cleanup/deep/created.json";
    const parent = join(project().repository, ".agents", "skills", "project-design-context", "posix-cleanup");
    const api = await keeper({ beforeCommit: async () => { throw new Error("injected nested cleanup fault"); } });
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: relativePath, content: ownedJson("nested") }]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/injected nested cleanup fault/i);
    await expect(lstat(parent)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("leaves every target unchanged when a later pre-stage hook fails", async () => {
    const api = await keeper({
      beforeStageWrite: async (_path: string, index: number) => {
        if (index === 1) throw new Error("injected rename failure");
      }
    });
    const directory = join(project().repository, ".agents", "skills", "project-design-context");
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, "one.json"), ownedJson("one before"), "utf8");
    await writeFile(join(directory, "two.json"), ownedJson("two before"), "utf8");
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [
        { path: ".agents/skills/project-design-context/one.json", content: ownedJson("one after") },
        { path: ".agents/skills/project-design-context/two.json", content: ownedJson("two after") }
      ]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/rename failure/i);
    await expect(readFile(join(directory, "one.json"), "utf8")).resolves.toBe(ownedJson("one before"));
    await expect(readFile(join(directory, "two.json"), "utf8")).resolves.toBe(ownedJson("two before"));
    expect((await readdir(directory)).every((name) => !name.includes(".project-design-keeper-"))).toBe(true);
  });

  test("stores restorable overwritten and deleted files and retains only ten newest snapshots", async () => {
    let recoveryNow = 10_000;
    const api = await keeper({ now: () => recoveryNow });
    const directory = join(project().repository, ".agents", "skills", "project-design-context");
    await mkdir(directory, { recursive: true });
    const target = join(directory, "history.json");
    await writeFile(target, ownedJson(0), "utf8");

    for (let version = 1; version <= 10; version += 1) {
      recoveryNow = 10_000 + version;
      const preview = await api.previewUpdate({
        root: project().repository,
        changes: [{ path: ".agents/skills/project-design-context/history.json", content: ownedJson(version) }]
      });
      await api.applyUpdate({ root: project().repository, changesetId: preview.changesetId });
    }
    recoveryNow = 5_000;
    const deletion = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: ".agents/skills/project-design-context/history.json", delete: true }]
    });
    await api.applyUpdate({ root: project().repository, changesetId: deletion.changesetId });

    const snapshotFiles = (await persistedJsonFiles(join(cache(), "snapshots"))).sort();
    expect(snapshotFiles).toHaveLength(10);
    expect(snapshotFiles.every((path) => /^[0-9]+-[0-9a-f-]+-[0-9a-f-]+\.json$/u.test(path.split(/[\\/]/u).at(-1)!))).toBe(true);
    const snapshots = await Promise.all(snapshotFiles.map(async (path) => JSON.parse(await readFile(path, "utf8"))));
    expect(snapshots.some((snapshot) => snapshot.changesetId === deletion.changesetId)).toBe(true);
    expect(snapshots.some((snapshot) => snapshot.files[".agents/skills/project-design-context/history.json"]?.content === ownedJson(10)))
      .toBe(true);
    await expect(readFile(target, "utf8")).rejects.toThrow();
  }, 20_000);

  test("does not publish duplicate recovery snapshots when one active changeset is retried", async () => {
    const relativePath = ".agents/skills/project-design-context/retry.json";
    const target = join(project().repository, ...relativePath.split("/"));
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, ownedJson("before"), "utf8");
    const api = await keeper({
      beforeCommit: async () => { throw new Error("retryable precommit fault"); }
    });
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: relativePath, content: ownedJson("after") }]
    });

    for (let attempt = 0; attempt < 12; attempt += 1) {
      await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
        .rejects.toThrow(/retryable precommit fault/i);
    }

    const snapshots = await Promise.all((await persistedJsonFiles(join(cache(), "snapshots")))
      .map(async (path) => JSON.parse(await readFile(path, "utf8"))));
    expect(snapshots.filter((snapshot) => snapshot.changesetId === preview.changesetId)).toHaveLength(1);
    await expect(readFile(target, "utf8")).resolves.toBe(ownedJson("before"));
  }, 20_000);

  test.each([
    {
      label: "a partial active record",
      tamper: async (path: string, snapshot: Record<string, unknown>) => {
        await writeFile(path, `${JSON.stringify({
          createdAt: snapshot.createdAt,
          changesetId: snapshot.changesetId
        })}\n`, "utf8");
      }
    },
    {
      label: "an extra top-level field",
      tamper: async (path: string, snapshot: Record<string, unknown>) => {
        await writeFile(path, `${JSON.stringify({ ...snapshot, unexpected: true })}\n`, "utf8");
      }
    },
    {
      label: "a mismatched canonical root",
      tamper: async (path: string, snapshot: Record<string, unknown>) => {
        await writeFile(path, `${JSON.stringify({ ...snapshot, root: join(project().repository, "other") })}\n`, "utf8");
      }
    },
    {
      label: "a missing changed-file record",
      tamper: async (path: string, snapshot: Record<string, unknown>) => {
        await writeFile(path, `${JSON.stringify({ ...snapshot, files: {} })}\n`, "utf8");
      }
    },
    {
      label: "a filename epoch mismatch",
      tamper: async (path: string, snapshot: Record<string, unknown>) => {
        await rename(path, join(path, "..", `9999-${String(snapshot.changesetId)}-${randomUUID()}.json`));
      }
    },
    {
      label: "a filename changeset mismatch",
      tamper: async (path: string, snapshot: Record<string, unknown>) => {
        await rename(path, join(path, "..", `${String(snapshot.createdAt)}-${randomUUID()}-${randomUUID()}.json`));
      }
    },
    {
      label: "valid-looking recovery contents for a different previousHash",
      tamper: async (path: string, snapshot: Record<string, unknown>) => {
        const files = snapshot.files as Record<string, Record<string, unknown>>;
        const record = Object.values(files)[0]!;
        const replacement = Buffer.from(ownedJson("other!"), "utf8");
        record.content = replacement.toString("utf8");
        record.contentBase64 = replacement.toString("base64");
        record.hash = hash(replacement.toString("utf8"));
        record.previousHash = record.hash;
        await writeFile(path, `${JSON.stringify(snapshot)}\n`, "utf8");
      }
    }
  ])("rejects $label instead of accepting it as the active recovery snapshot", async ({ tamper }) => {
    let recoveryNow = 30_000;
    const relativePath = ".agents/skills/project-design-context/strict-recovery.json";
    const target = join(project().repository, ...relativePath.split("/"));
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, ownedJson("before"), "utf8");
    const api = await keeper({
      now: () => recoveryNow,
      beforeCommit: async () => { throw new Error("retryable strict recovery fault"); }
    });
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: relativePath, content: ownedJson("after") }]
    });
    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/strict recovery fault/i);

    const [snapshotPath] = await persistedJsonFiles(join(cache(), "snapshots"));
    const snapshot = JSON.parse(await readFile(snapshotPath!, "utf8")) as Record<string, unknown>;
    await tamper(snapshotPath!, snapshot);
    recoveryNow += 1;

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/recovery snapshot metadata is invalid/i);
    await expect(readFile(target, "utf8")).resolves.toBe(ownedJson("before"));
  });

  test("converges eleven strict active duplicates to one authoritative recovery snapshot", async () => {
    let recoveryNow = 40_000;
    const relativePath = ".agents/skills/project-design-context/duplicate-recovery.json";
    const target = join(project().repository, ...relativePath.split("/"));
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, ownedJson("before"), "utf8");
    const api = await keeper({
      now: () => recoveryNow,
      beforeCommit: async () => { throw new Error("retryable duplicate recovery fault"); }
    });
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: relativePath, content: ownedJson("after") }]
    });
    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/duplicate recovery fault/i);

    const [originalPath] = await persistedJsonFiles(join(cache(), "snapshots"));
    const duplicate = JSON.parse(await readFile(originalPath!, "utf8")) as Record<string, unknown>;
    for (let duplicateIndex = 1; duplicateIndex <= 10; duplicateIndex += 1) {
      recoveryNow += 1;
      duplicate.createdAt = recoveryNow;
      const duplicatePath = join(
        originalPath!,
        "..",
        `${recoveryNow}-${String(preview.changesetId)}-${randomUUID()}.json`
      );
      await writeFile(duplicatePath, `${JSON.stringify(duplicate, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    }
    const expectedAuthoritativeCreatedAt = recoveryNow;
    recoveryNow += 1;

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/duplicate recovery fault/i);
    const activeSnapshots = await Promise.all((await persistedJsonFiles(join(cache(), "snapshots")))
      .map(async (path) => JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>));
    expect(activeSnapshots.filter((snapshot) => snapshot.changesetId === preview.changesetId)).toHaveLength(1);
    expect(activeSnapshots).toHaveLength(1);
    expect(activeSnapshots[0]!.createdAt).toBe(expectedAuthoritativeCreatedAt);
  });

  test.each([
    {
      label: "a same-length rewrite before opening the target",
      hooks: (replacement: string) => ({
        beforeRecoveryTargetOpen: async (path: string) => { await writeFile(path, replacement, "utf8"); }
      })
    },
    {
      label: "a pathname replacement after opening the target",
      hooks: (replacement: string) => ({
        afterRecoveryTargetOpen: async (path: string) => {
          await rename(path, `${path}.recovery-race`);
          await writeFile(path, replacement, "utf8");
        }
      })
    },
    {
      label: "a short read after opening the target",
      hooks: () => ({
        afterRecoveryTargetOpen: async (path: string) => { await truncate(path, 0); }
      })
    },
    {
      label: "growth after the exact recovery read",
      hooks: () => ({
        afterRecoveryTargetRead: async (path: string) => { await appendFile(path, "growth", "utf8"); }
      })
    }
  ])("fails closed on $label while capturing recovery evidence", async ({ hooks }) => {
    const relativePath = ".agents/skills/project-design-context/recovery-race.json";
    const before = ownedJson("before");
    const replacement = ownedJson("attack");
    expect(Buffer.byteLength(replacement)).toBe(Buffer.byteLength(before));
    const target = join(project().repository, ...relativePath.split("/"));
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, before, "utf8");
    const api = await keeper(hooks(replacement));
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: relativePath, content: ownedJson("after") }]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/recovery snapshot.*(?:identity|content|read|size|stale)/i);
  });

  test("binds the nearest existing ancestor when a missing recovery target parent is created concurrently", async () => {
    const relativePath = ".agents/skills/project-design-context/missing/created.json";
    let hookRan = false;
    const api = await keeper({
      beforeRecoveryTargetOpen: async (path: string) => {
        hookRan = true;
        await mkdir(join(path, ".."), { recursive: true });
        await writeFile(path, ownedJson("attacker"), "utf8");
      }
    });
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: relativePath, content: ownedJson("created") }]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/recovery snapshot.*missing.*changed/i);
    expect(hookRan).toBe(true);
    await expect(readFile(join(project().repository, ...relativePath.split("/")), "utf8"))
      .resolves.toBe(ownedJson("attacker"));
  });

  test("revalidates captured target evidence immediately before exclusive recovery publication", async () => {
    const relativePath = ".agents/skills/project-design-context/recovery-publish-race.json";
    const target = join(project().repository, ...relativePath.split("/"));
    const before = ownedJson("before");
    const attacker = ownedJson("attack");
    expect(Buffer.byteLength(attacker)).toBe(Buffer.byteLength(before));
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, before, "utf8");
    const api = await keeper({
      beforeRecoverySnapshotPublish: async () => { await writeFile(target, attacker, "utf8"); }
    });
    const preview = await api.previewUpdate({
      root: project().repository,
      changes: [{ path: relativePath, content: ownedJson("after") }]
    });

    await expect(api.applyUpdate({ root: project().repository, changesetId: preview.changesetId }))
      .rejects.toThrow(/recovery snapshot.*evidence.*changed/i);
    await expect(readFile(target, "utf8")).resolves.toBe(attacker);
  });
});
