import { chmod, lstat, open, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { ByteBudget, CounterBudget, DeadlineBudget } from "../src/security/limits.js";
import { createProjectDesignKeeper } from "../src/index.js";
import { resolveScope } from "../src/scope/index.js";
import { readIndexedFile, type ScopeReaderIo } from "../src/scope/reader.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function projectFixture(prefix = "keeper-scope-budget-") {
  const root = await mkdtemp(join(tmpdir(), prefix));
  roots.push(root);
  const projectRoot = join(root, "project");
  const cacheDirectory = join(root, "cache");
  await mkdir(projectRoot, { recursive: true });
  return { root, projectRoot, cacheDirectory };
}

function readerInput(absolutePath: string, outputPath: string, overrides: {
  maxFileBytes?: number;
  maxAggregateBytes?: number;
  maxEvidence?: number;
  deadline?: DeadlineBudget;
} = {}) {
  return {
    absolutePath,
    outputPath,
    bytes: new ByteBudget("scan aggregate bytes", overrides.maxAggregateBytes ?? 64 * 1024 * 1024),
    evidence: new CounterBudget("scan evidence", overrides.maxEvidence ?? 100_000),
    deadline: overrides.deadline ?? new DeadlineBudget("cold scan", 60_000),
    maxFileBytes: overrides.maxFileBytes ?? 8 * 1024 * 1024
  };
}

describe("bounded scope file reading", () => {
  test("stats an oversized explicit file before any content read", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "oversized.txt");
    const handle = await open(path, "w");
    try {
      await handle.truncate(8 * 1024 * 1024 + 1);
    } finally {
      await handle.close();
    }
    let contentReads = 0;
    const io: ScopeReaderIo = {
      beforeOpen: async () => { contentReads += 1; }
    };

    const result = await readIndexedFile(readerInput(path, "oversized.txt"), io);

    expect(result).toEqual({
      evidence: [],
      omission: { path: "oversized.txt", reason: "file-bytes", size: 8 * 1024 * 1024 + 1 }
    });
    expect(contentReads).toBe(0);
  });

  test("uses fatal UTF-8 decoding and omits invalid bytes", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "invalid.txt");
    await writeFile(path, Buffer.from([0x66, 0x6f, 0x80, 0x6f]));

    const result = await readIndexedFile(readerInput(path, "invalid.txt"));

    expect(result).toEqual({
      evidence: [],
      omission: { path: "invalid.txt", reason: "binary", size: 4 }
    });
  });

  test("streams a huge line into a 16 KiB prefix with exact original bytes", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "huge-line.txt");
    const line = "界".repeat(6_000);
    await writeFile(path, `${line}\n`, "utf8");

    const result = await readIndexedFile(readerInput(path, "huge-line.txt"));

    expect(result.file).toMatchObject({ path: "huge-line.txt", size: 18_001, lineCount: 1 });
    expect(result.file).not.toHaveProperty("text");
    expect(result.evidence).toEqual([{
      path: "huge-line.txt",
      line: 1,
      text: expect.any(String),
      truncated: true,
      textBytes: 18_000
    }]);
    expect(Buffer.byteLength(result.evidence[0]!.text, "utf8")).toBeLessThanOrEqual(16 * 1024);
  });

  test("counts and preserves a UTF-8 BOM at the 16 KiB line-prefix boundary", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "bom-line.txt");
    await writeFile(path, Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.alloc(16 * 1024, 0x61),
      Buffer.from("\n")
    ]));

    const result = await readIndexedFile(readerInput(path, "bom-line.txt"));

    expect(result.evidence).toEqual([{
      path: "bom-line.txt",
      line: 1,
      text: expect.stringMatching(/^\uFEFFa+$/u),
      truncated: true,
      textBytes: 16 * 1024 + 3
    }]);
    expect(Buffer.byteLength(result.evidence[0]!.text, "utf8")).toBe(16 * 1024);
  });

  test("strips a CR that lands at the end of a stream chunk before a split LF", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "split-crlf.txt");
    await writeFile(path, `${"a".repeat(65_535)}\r\nnext\n`, "utf8");

    const result = await readIndexedFile(readerInput(path, "split-crlf.txt"));

    expect(result.file).toMatchObject({ lineCount: 2 });
    expect(result.evidence[0]).toMatchObject({ truncated: true, textBytes: 65_535 });
    expect(result.evidence[1]).toEqual({ path: "split-crlf.txt", line: 2, text: "next" });
  });

  test("stops an evidence-heavy file at the evidence budget", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "many-lines.txt");
    await writeFile(path, "one\ntwo\nthree\n", "utf8");

    const result = await readIndexedFile(readerInput(path, "many-lines.txt", { maxEvidence: 2 }));

    expect(result.file).toBeUndefined();
    expect(result.evidence).toEqual([]);
    expect(result.omission).toEqual({ path: "many-lines.txt", reason: "evidence-limit", size: 14 });
  });

  test("checks the deadline before opening repository content", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "deadline.txt");
    await writeFile(path, "content\n", "utf8");
    let contentReads = 0;
    const io: ScopeReaderIo = { beforeOpen: async () => { contentReads += 1; } };
    const deadline = new DeadlineBudget("cold scan", 1, (() => {
      let now = 0;
      return () => now++;
    })());

    const result = await readIndexedFile(readerInput(path, "deadline.txt", { deadline }), io);

    expect(result).toEqual({ evidence: [], omission: { path: "deadline.txt", reason: "deadline" } });
    expect(contentReads).toBe(0);
  });

  test("rechecks the deadline after a zero-byte file open hook", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "empty.txt");
    await writeFile(path, "", "utf8");
    let clock = 0;
    const deadline = new DeadlineBudget("cold scan", 10, () => clock);

    const result = await readIndexedFile(readerInput(path, "empty.txt", { deadline }), {
      beforeOpen: async () => { clock = 10; }
    });

    expect(result).toEqual({ evidence: [], omission: { path: "empty.txt", reason: "deadline", size: 0 } });
  });

  test("rechecks the deadline after the final streamed chunk hook", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "last-chunk.txt");
    await writeFile(path, "last\n", "utf8");
    let clock = 0;
    const deadline = new DeadlineBudget("cold scan", 10, () => clock);

    const result = await readIndexedFile(readerInput(path, "last-chunk.txt", { deadline }), {
      onChunkRead: async () => { clock = 10; }
    });

    expect(result).toEqual({ evidence: [], omission: { path: "last-chunk.txt", reason: "deadline", size: 5 } });
  });

  test("rejects a junction escape before opening its file", async () => {
    const { root, projectRoot } = await projectFixture();
    const outside = join(root, "outside");
    const linked = join(projectRoot, "linked");
    await mkdir(outside);
    await writeFile(join(outside, "secret.txt"), "secret\n", "utf8");
    await symlink(outside, linked, process.platform === "win32" ? "junction" : "dir");
    let contentReads = 0;
    const io: ScopeReaderIo = { beforeOpen: async () => { contentReads += 1; } };

    const result = await readIndexedFile(readerInput(join(linked, "secret.txt"), "linked/secret.txt"), io);

    expect(result).toEqual({
      evidence: [],
      omission: { path: "linked/secret.txt", reason: "unsafe", size: 7 }
    });
    expect(contentReads).toBe(0);
  });

  test("discards bytes when the regular-file identity is replaced after streaming", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "replace.txt");
    const moved = join(projectRoot, "replace-original.txt");
    await writeFile(path, "original\n", "utf8");
    const io: ScopeReaderIo = {
      beforeFinalIdentityCheck: async () => {
        await rename(path, moved);
        await writeFile(path, "attacker\n", "utf8");
      }
    };

    const result = await readIndexedFile(readerInput(path, "replace.txt"), io);

    expect(await readFile(path, "utf8")).toBe("attacker\n");
    expect(result).toEqual({
      evidence: [],
      omission: { path: "replace.txt", reason: "unsafe", size: 9 }
    });
  });

  test("never reads growth beyond the identity-checked pre-stat length", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "growing.txt");
    await writeFile(path, "first\n", "utf8");
    let streamedBytes = 0;
    const io: ScopeReaderIo = {
      afterOpenIdentityCheck: async () => {
        const append = await open(path, "a");
        try {
          await append.write("x".repeat(1024 * 1024));
        } finally {
          await append.close();
        }
      },
      onChunkRead: async (_path, bytes) => { streamedBytes += bytes; }
    };

    const result = await readIndexedFile(readerInput(path, "growing.txt"), io);

    expect(streamedBytes).toBe(6);
    expect(result).toEqual({ evidence: [], omission: { path: "growing.txt", reason: "unsafe", size: 6 } });
  });

  test("rejects a same-inode same-length rewrite after an earlier streamed chunk", async () => {
    const { projectRoot } = await projectFixture();
    const path = join(projectRoot, "same-inode.txt");
    await writeFile(path, Buffer.alloc(128 * 1024, 0x61));
    let chunks = 0;

    const result = await readIndexedFile(readerInput(path, "same-inode.txt"), {
      onChunkRead: async (_path, _bytes, totalBytes) => {
        chunks += 1;
        if (totalBytes !== 64 * 1024) return;
        const writer = await open(path, "r+");
        try {
          const replacement = Buffer.alloc(64 * 1024, 0x62);
          await writer.write(replacement, 0, replacement.byteLength, 64 * 1024);
          await writer.sync();
          await writer.utimes(new Date(0), new Date("2030-01-01T00:00:00.000Z"));
        } finally {
          await writer.close();
        }
      }
    });

    expect(chunks).toBe(2);
    expect(result).toEqual({
      evidence: [],
      omission: { path: "same-inode.txt", reason: "unsafe", size: 128 * 1024 }
    });
  });
});

describe("cold scan budgets", () => {
  test("indexes filtered evidence references once and scans indexed chunks once", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    const sourcePath = join(projectRoot, "Source", "selector.txt");
    await mkdir(join(projectRoot, "Source"), { recursive: true });
    await writeFile(sourcePath, "needle one\nneedle two\nneedle three\n", "utf8");
    await mkdir(join(projectRoot, "docs", "project-design"), { recursive: true });
    await writeFile(join(projectRoot, "docs", "project-design", "manifest.json"), JSON.stringify({
      records: ["one", "two"].map((id) => ({
        id,
        domain: "technical",
        status: "observed",
        statement: `needle ${id}`,
        evidence: ["Source/selector.txt:1", "Source/selector.txt:2"]
      }))
    }), "utf8");
    const selectorWork = { references: 0, chunks: 0 };
    const api = createProjectDesignKeeper({
      cacheDirectory,
      scopeIo: {
        onSelectorWork: (kind) => {
          if (kind === "reference-index") selectorWork.references += 1;
          if (kind === "chunk-filter") selectorWork.chunks += 1;
        }
      }
    });

    const result = await api.searchEvidence({ root: projectRoot, query: "needle", domain: "technical" });

    expect(result.matches).toHaveLength(2);
    expect(selectorWork).toEqual({ references: 4, chunks: 3 });
  });

  test("bounds Git discovery by the cold-scan deadline", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    let commands = 0;
    const options = {
      cacheDirectory,
      limits: { scan: { deadlineMs: 10 } },
      scopeIo: {
        beforeGitCommand: async () => {
          commands += 1;
          await new Promise<void>((accept) => setTimeout(accept, 100));
        }
      }
    };
    const startedAt = performance.now();

    const result = await resolveScope({ root: projectRoot }, options);

    expect(performance.now() - startedAt).toBeLessThan(75);
    expect(commands).toBe(1);
    expect(result).toMatchObject({ root: projectRoot, isGitRepository: false });
  });

  test("bounds a repository content hook that never resolves", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    await writeFile(join(projectRoot, "blocked.txt"), "blocked\n", "utf8");
    const api = createProjectDesignKeeper({
      cacheDirectory,
      limits: { scan: { deadlineMs: 200 } },
      scopeIo: {
        beforeRepositoryContentRead: async () => await new Promise<void>(() => undefined)
      }
    });

    const outcome = await Promise.race([
      api.scanScope({ root: projectRoot, view: "files" }),
      new Promise<"timed-out">((accept) => setTimeout(() => accept("timed-out"), 1_500))
    ]);

    expect(outcome).not.toBe("timed-out");
    expect(outcome).toMatchObject({ items: [], totals: { files: 0, omitted: expect.any(Number) } });
  }, 3_000);

  test("stops before a second reader batch after the first batch reaches the deadline", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    await Promise.all(Array.from({ length: 9 }, (_, index) =>
      writeFile(join(projectRoot, `${index}.txt`), `${index}\n`, "utf8")
    ));
    let contentReads = 0;
    let readerStats = 0;
    const options = {
      cacheDirectory,
      limits: { scan: { deadlineMs: 200 } },
      scopeIo: {
        beforeRepositoryFileStat: async () => { readerStats += 1; },
        beforeRepositoryContentRead: async () => {
          contentReads += 1;
          await new Promise<void>((accept) => setTimeout(accept, 250));
        }
      }
    };
    const api = createProjectDesignKeeper(options as Parameters<typeof createProjectDesignKeeper>[0] & {
      scopeIo: { beforeRepositoryFileStat: () => Promise<void> };
    });

    const result = await api.scanScope({ root: projectRoot, view: "files" });

    expect(result.items).toEqual([]);
    expect(contentReads).toBe(8);
    expect(readerStats).toBe(8);
  }, 3_000);

  test("rejects selected pack paths before fanning out Git subprocesses", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    await Promise.all(["One", "Two", "Three"].map(async (name) => {
      const directory = join(projectRoot, name);
      await mkdir(directory);
      await writeFile(join(directory, `${name}.txt`), `${name}\n`, "utf8");
    }));
    let commands = 0;
    const api = createProjectDesignKeeper({
      cacheDirectory,
      limits: { scan: { maxFiles: 2 } },
      scopeIo: { beforeGitCommand: async () => { commands += 1; } }
    });

    await expect(api.detectDrift({
      root: projectRoot,
      pack: { scope: { paths: ["One", "Two", "Three"] }, sourceRevision: { files: {} } }
    })).rejects.toThrow(/selected scope paths|file.*limit/iu);

    expect(commands).toBeLessThanOrEqual(1);
  });

  test("rejects a manifest whose mode changes between path stat and handle stat", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    const packRoot = join(projectRoot, "docs", "project-design");
    const manifestPath = join(packRoot, "manifest.json");
    await Promise.all([
      mkdir(join(projectRoot, "Source"), { recursive: true }),
      writeFile(join(projectRoot, "outside.txt"), "outside\n", "utf8")
    ]);
    await writeFile(join(projectRoot, "Source", "inside.txt"), "inside\n", "utf8");
    await mkdir(packRoot, { recursive: true });
    await writeFile(manifestPath, `${JSON.stringify({
      scope: { root: ".", paths: ["Source"] },
      sourceRevision: { kind: "working-tree", files: {} },
      records: [],
      documents: []
    })}\n`, "utf8");
    let modeChanged = false;
    const api = createProjectDesignKeeper({
      cacheDirectory,
      scopeIo: {
        beforeRepositoryContentRead: async (path) => {
          if (path !== manifestPath || modeChanged) return;
          const before = await lstat(path, { bigint: true });
          await chmod(path, 0o400);
          const after = await lstat(path, { bigint: true });
          modeChanged = before.mode !== after.mode;
        }
      }
    });

    const result = await api.detectDrift({ root: projectRoot });

    expect(modeChanged).toBe(true);
    expect(result).toMatchObject({ counts: { new: 2 } });
  });

  test("rejects direct drift packs that exceed record or per-record evidence limits", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    await writeFile(join(projectRoot, "source.txt"), "source\n", "utf8");
    const api = createProjectDesignKeeper({
      cacheDirectory,
      limits: { pack: { maxRecords: 2, maxEvidencePerRecord: 2 } }
    });
    const sourceRevision = { files: { "source.txt": `sha256:${"0".repeat(64)}` } };
    const scope = { paths: ["source.txt"] };

    await expect(api.detectDrift({
      root: projectRoot,
      pack: { scope, sourceRevision, records: [{ id: "one" }, { id: "two" }, { id: "three" }] }
    })).rejects.toThrow(/pack.*records|records.*limit/iu);
    await expect(api.detectDrift({
      root: projectRoot,
      pack: { scope, sourceRevision, records: [{ id: "one", evidence: [{}, {}, {}] }] }
    })).rejects.toThrow(/record.*evidence|evidence.*limit/iu);
    await expect(api.detectDrift({
      root: projectRoot,
      pack: { scope, sourceRevision, records: [{
        id: "one",
        evidence: [{ path: "source.txt", startLine: 1, endLine: "invalid", excerptHash: `sha256:${"0".repeat(64)}` }]
      }] }
    })).rejects.toThrow(/evidence.*range|endLine|invalid/iu);
  });

  test("rejects an out-of-file typed evidence range before allocating its span", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    await writeFile(join(projectRoot, "source.txt"), "source\n", "utf8");
    const api = createProjectDesignKeeper({ cacheDirectory });

    const result = await api.detectDrift({
      root: projectRoot,
      pack: {
        scope: { paths: ["source.txt"] },
        sourceRevision: { files: { "source.txt": `sha256:${"0".repeat(64)}` } },
        records: [{
          id: "range",
          evidence: [{
            path: "source.txt",
            startLine: 1,
            endLine: 10_000_000_000,
            excerptHash: `sha256:${"0".repeat(64)}`
          }]
        }]
      }
    });

    expect(result.relocationCandidates).toEqual([]);
    expect(result).toMatchObject({ counts: { invalidated: 1 } });
  });

  test("stats an oversized pack manifest before any repository content read", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    const packRoot = join(projectRoot, "docs", "project-design");
    await mkdir(packRoot, { recursive: true });
    const manifestPath = join(packRoot, "manifest.json");
    const handle = await open(manifestPath, "w");
    try {
      await handle.truncate(64 * 1024 * 1024 + 1);
    } finally {
      await handle.close();
    }
    let contentReads = 0;
    const api = createProjectDesignKeeper({
      cacheDirectory,
      scopeIo: { beforeRepositoryContentRead: async () => { contentReads += 1; } }
    });

    await expect(api.queryContext({ root: projectRoot, query: "needle" })).rejects.toThrow(/file.*bytes|64.*MiB|limit/iu);
    expect(contentReads).toBe(0);
  });

  test("reads routed pack documents with at most eight concurrent readers", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    const packRoot = join(projectRoot, "docs", "project-design");
    await mkdir(packRoot, { recursive: true });
    const documents = Array.from({ length: 9 }, (_, index) => ({
      id: `needle-document-${index}`,
      path: `docs/project-design/document-${index}.md`
    }));
    await writeFile(join(packRoot, "manifest.json"), `${JSON.stringify({ documents, records: [] })}\n`, "utf8");
    await Promise.all(documents.map((document) => writeFile(join(projectRoot, document.path), "# Managed\n", "utf8")));
    let active = 0;
    let maximumActive = 0;
    const api = createProjectDesignKeeper({
      cacheDirectory,
      scopeIo: {
        beforeRepositoryContentRead: async (path) => {
          if (!path.endsWith(".md")) return;
          active += 1;
          maximumActive = Math.max(maximumActive, active);
          await new Promise<void>((accept) => setTimeout(accept, 10));
          active -= 1;
        }
      }
    });

    const result = await api.queryContext({ root: projectRoot, query: "needle" });

    expect(result.documents).toHaveLength(9);
    expect(maximumActive).toBe(8);
  });

  test("enforces aggregate bytes in deterministic path order", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    await writeFile(join(projectRoot, "A.txt"), "aaaa\n", "utf8");
    await writeFile(join(projectRoot, "B.txt"), "bbbb\n", "utf8");
    const api = createProjectDesignKeeper({ cacheDirectory, limits: { scan: { maxAggregateBytes: 5 } } });

    const result = await api.scanScope({ root: projectRoot, view: "files" });

    expect(result.items).toEqual([expect.objectContaining({ path: "A.txt" })]);
    expect(result.totals).toEqual({ files: 1, evidence: 1, omitted: 1 });
  });

  test("stops discovery at the file limit and records one bounded omission", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    await Promise.all(["A.txt", "B.txt", "C.txt"].map((name) => writeFile(join(projectRoot, name), `${name}\n`, "utf8")));
    const api = createProjectDesignKeeper({ cacheDirectory, limits: { scan: { maxFiles: 2 } } });

    const result = await api.scanScope({ root: projectRoot, view: "files" });

    expect((result.items as Array<{ path: string }>).map((item) => item.path)).toEqual(["A.txt", "B.txt"]);
    expect(result.totals).toEqual({ files: 2, evidence: 2, omitted: 1 });
  });

  test("bounds aggregate evidence and omits the file that crosses the ceiling", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    await writeFile(join(projectRoot, "evidence.txt"), "one\ntwo\nthree\n", "utf8");
    const api = createProjectDesignKeeper({ cacheDirectory, limits: { scan: { maxEvidence: 2 } } });

    const result = await api.scanScope({ root: projectRoot, view: "evidence" });

    expect(result.totals.evidence).toBeLessThanOrEqual(2);
    expect(result.totals.omitted).toBe(1);
  });

  test("honors an already exhausted cold-scan deadline without opening files", async () => {
    const { projectRoot, cacheDirectory } = await projectFixture();
    await writeFile(join(projectRoot, "deadline.txt"), "content\n", "utf8");
    const api = createProjectDesignKeeper({ cacheDirectory, limits: { scan: { deadlineMs: 0 } } });

    const result = await api.scanScope({ root: projectRoot, view: "files" });

    expect(result.items).toEqual([]);
    expect(result.totals.files).toBe(0);
    expect(result.totals.omitted).toBeGreaterThan(0);
  });
});
