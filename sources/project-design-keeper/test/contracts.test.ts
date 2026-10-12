import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { writeCanonicalPackFixture } from "./canonical-pack-fixture.js";
import { createTrustedTestKeeper } from "./keeper.js";
import {
  createProjectFixture,
  removeProjectFixture,
  type ProjectFixture
} from "./fixtures.js";

type ToolResult = Record<string, unknown>;

interface KeeperApi {
  scanScope(input: Record<string, unknown>): Promise<ToolResult>;
  snapshot(input: Record<string, unknown>): Promise<ToolResult>;
  searchEvidence(input: Record<string, unknown>): Promise<ToolResult>;
  detectDrift(input: Record<string, unknown>): Promise<ToolResult>;
  queryContext(input: Record<string, unknown>): Promise<ToolResult>;
  validatePack(input: Record<string, unknown>): Promise<ToolResult>;
  previewUpdate(input: Record<string, unknown>): Promise<ToolResult>;
  applyUpdate(input: Record<string, unknown>): Promise<ToolResult>;
  createMcpServer(): Promise<{
    connect(transport: InMemoryTransport): Promise<void>;
    close(): Promise<void>;
  }>;
}

async function keeper(): Promise<KeeperApi> {
  if (!cacheDirectory) throw new Error("test cache was not created");
  return createTrustedTestKeeper({ cacheDirectory }) as unknown as KeeperApi;
}

let fixture: ProjectFixture | undefined;
let cacheDirectory: string | undefined;

beforeEach(async () => {
  fixture = await createProjectFixture();
  cacheDirectory = await mkdtemp(join(tmpdir(), "project-design-contract-cache-"));
});

afterEach(async () => {
  await removeProjectFixture(fixture);
  if (cacheDirectory) await rm(cacheDirectory, { recursive: true, force: true });
  fixture = undefined;
  cacheDirectory = undefined;
});

function currentFixture(): ProjectFixture {
  if (!fixture) throw new Error("fixture was not created");
  return fixture;
}

function contentHash(content: string): string {
  return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
}

function managedBlock(recordId: string, content: string): string {
  return `<!-- project-design-keeper:managed record-id="${recordId}" content-hash="${contentHash(content)}" -->${content}<!-- /project-design-keeper:managed -->`;
}

describe("Project Design Keeper public contracts", () => {
  test("scan_scope resolves a Git scope but refuses parent traversal and symlink escapes", async () => {
    const project = currentFixture();
    const api = await keeper();

    await expect(api.scanScope({ path: project.repository })).resolves.toMatchObject({
      schemaVersion: 2,
      scope: { root: project.repository, paths: [project.repository] },
      repository: { root: project.repository }
    });
    await expect(api.scanScope({ path: "../outside.txt", root: project.repository })).rejects.toThrow();
    if (project.symlinkEscape) {
      await expect(api.scanScope({ path: project.symlinkEscape, root: project.repository })).rejects.toThrow();
    }
  });

  test("scan_scope resolves a non-Git directory as a non-repository scope", async () => {
    const project = currentFixture();
    const api = await keeper();

    await expect(api.scanScope({ path: project.nonGitDirectory })).resolves.toMatchObject({
      schemaVersion: 2,
      scope: { root: project.nonGitDirectory, paths: [project.nonGitDirectory] }
    });
  });

  test("scan_scope scans tracked UTF-8 text while excluding binary and ignored generated content", async () => {
    const project = currentFixture();
    const api = await keeper();

    const result = await api.scanScope({ path: project.repository, view: "files" });
    expect(result.items).toContainEqual(expect.objectContaining({ path: relative(project.repository, project.trackedText).replaceAll("\\", "/") }));
    expect(result.items).not.toContainEqual(expect.objectContaining({ path: relative(project.repository, project.binaryFile).replaceAll("\\", "/") }));
    expect(result.items).not.toContainEqual(expect.objectContaining({ path: relative(project.repository, project.ignoredFile).replaceAll("\\", "/") }));
  });

  test("finds evidence in a tracked Unicode path with a one-based line number", async () => {
    const project = currentFixture();
    const api = await keeper();

    const result = await api.searchEvidence({ root: project.repository, query: "moon-garden" });
    expect(result.matches).toContainEqual({
      path: relative(project.repository, project.trackedText).replaceAll("\\", "/"),
      line: 1,
      text: "Keeper evidence: moon-garden"
    });
  });

  test("query_context returns matching project design context for tracked evidence", async () => {
    const project = currentFixture();
    const api = await keeper();

    const result = await api.queryContext({ root: project.repository, query: "moon-garden" });
    expect(result.context).toContainEqual(expect.objectContaining({
      path: relative(project.repository, project.trackedText).replaceAll("\\", "/"),
      text: "Keeper evidence: moon-garden"
    }));
  });

  test("reports drift when a required design evidence item is absent", async () => {
    const project = currentFixture();
    const api = await keeper();

    const result = await api.detectDrift({
      root: project.repository,
      pack: { requiredEvidence: ["moon-garden", "sun-garden"] },
      view: "details"
    });
    expect(result.items).toContainEqual(expect.objectContaining({ evidence: "sun-garden" }));
  });

  test("rejects a malformed design pack before previewing changes", async () => {
    const project = currentFixture();
    const api = await keeper();

    await expect(api.validatePack({ root: project.repository, pack: { requiredEvidence: 42 } })).resolves.toMatchObject({
      valid: false
    });
  });

  test("accepts a valid canonical design pack with tracked evidence", async () => {
    const project = currentFixture();
    const api = await keeper();
    const pack = await writeCanonicalPackFixture(project);

    await expect(api.validatePack({
      root: project.repository,
      pack
    })).resolves.toMatchObject({ valid: true });
  });

  test("preview_update does not write and apply_update writes only an approved project design change", async () => {
    const project = currentFixture();
    const api = await keeper();
    const relativeTarget = ".agents/skills/project-design-context/generated-design.md";

    const preview = await api.previewUpdate({
      root: project.repository,
      changes: [{ path: relativeTarget, managedBlock: { recordId: "generated-design", content: "# Generated design\n" } }]
    });
    expect(preview).toMatchObject({ changes: [expect.objectContaining({ path: relativeTarget })] });
    await expect(readFile(`${project.repository}/${relativeTarget}`, "utf8")).rejects.toThrow();

    await api.applyUpdate({ root: project.repository, changeset: preview });
    await expect(readFile(`${project.repository}/${relativeTarget}`, "utf8")).resolves.toBe(managedBlock("generated-design", "# Generated design\n"));
  });

  test("preview_update and apply_update accept a project design context skill path", async () => {
    const project = currentFixture();
    const api = await keeper();
    const relativeTarget = ".agents/skills/project-design-context/context.md";

    const preview = await api.previewUpdate({
      root: project.repository,
      changes: [{ path: relativeTarget, managedBlock: { recordId: "project-design-context", content: "# Project design context\n" } }]
    });
    expect(preview).toMatchObject({ changes: [expect.objectContaining({ path: relativeTarget })] });
    await expect(readFile(`${project.repository}/${relativeTarget}`, "utf8")).rejects.toThrow();

    await api.applyUpdate({ root: project.repository, changeset: preview });
    await expect(readFile(`${project.repository}/${relativeTarget}`, "utf8")).resolves.toBe(managedBlock("project-design-context", "# Project design context\n"));
  });

  test("preview_update rejects edits outside managed project design locations", async () => {
    const project = currentFixture();
    const api = await keeper();

    await expect(api.previewUpdate({
      root: project.repository,
      changes: [{ path: "docs/not-project-design.md", content: "not allowed\n" }]
    })).rejects.toThrow();
  });

  test("preserves human text around a record-keyed, content-hashed managed block and reports conflicts", async () => {
    const project = currentFixture();
    const api = await keeper();
    const recordId = "design-overview";
    const target = `${project.repository}/.agents/skills/project-design-context/managed.md`;
    await mkdir(`${project.repository}/.agents/skills/project-design-context`, { recursive: true });
    await writeFile(target, `Human intro\n${managedBlock(recordId, "old")}\nHuman outro\n`, "utf8");

    const preview = await api.previewUpdate({
      root: project.repository,
      changes: [{ path: ".agents/skills/project-design-context/managed.md", managedBlock: { recordId, content: "new" } }]
    });
    await api.applyUpdate({ root: project.repository, changeset: preview });
    await expect(readFile(target, "utf8")).resolves.toBe(
      `Human intro\n${managedBlock(recordId, "new")}\nHuman outro\n`
    );

    await expect(api.previewUpdate({
      root: project.repository,
      changes: [{ path: ".agents/skills/project-design-context/managed.md", managedBlock: { recordId, content: "another" } }],
      expectedContentHash: contentHash("old")
    })).resolves.toMatchObject({ conflicts: [expect.anything()] });
  });

  test("rejects an apply request whose preview changeset is stale", async () => {
    const project = currentFixture();
    const api = await keeper();
    const target = `${project.repository}/.agents/skills/project-design-context/stale.md`;
    await mkdir(`${project.repository}/.agents/skills/project-design-context`, { recursive: true });
    await writeFile(target, managedBlock("stale-record", "before"), "utf8");

    const preview = await api.previewUpdate({
      root: project.repository,
      changes: [{ path: ".agents/skills/project-design-context/stale.md", managedBlock: { recordId: "stale-record", content: "after" } }]
    });
    await writeFile(target, managedBlock("stale-record", "changed after preview"), "utf8");

    await expect(api.applyUpdate({ root: project.repository, changeset: preview })).rejects.toThrow(/stale/i);
  });

  test("rejects an apply request more than thirty minutes after its preview", async () => {
    const project = currentFixture();
    const api = await keeper();
    const relativeTarget = ".agents/skills/project-design-context/expired.md";
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-06T00:00:00.000Z"));

    try {
      const preview = await api.previewUpdate({
        root: project.repository,
        changes: [{ path: relativeTarget, managedBlock: { recordId: "expired", content: "expired\n" } }]
      });
      vi.advanceTimersByTime(30 * 60 * 1000 + 1);

      await expect(api.applyUpdate({ root: project.repository, changeset: preview })).rejects.toThrow(/expired/i);
    } finally {
      vi.useRealTimers();
    }
  });

  test("scan_scope returns a stable snapshot that reports the changed tracked file", async () => {
    const project = currentFixture();
    const api = await keeper();
    const before = await api.snapshot({ path: project.repository });
    await writeFile(project.trackedText, "Keeper evidence: moon-garden\nchanged\n", "utf8");

    const after = await api.snapshot({ path: project.repository, previousSnapshot: before });
    expect(after).toMatchObject({ changed: [relative(project.repository, project.trackedText).replaceAll("\\", "/")] });
  });

  test("exposes the public contract through an SDK MCP client tool list request", async () => {
    const api = await keeper();
    const server = await api.createMcpServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "project-design-keeper-contract-test", version: "0.1.0" });

    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const names = (await client.listTools()).tools.map((tool) => tool.name).sort();
      expect(names).toEqual([
        "analyze_redundancy",
        "apply_update",
        "detect_drift",
        "get_settings",
        "open_settings",
        "preview_update",
        "query_context",
        "query_history",
        "read_preview",
        "scan_scope",
        "search_evidence",
        "validate_pack"
      ]);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
