import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";
import { build } from "esbuild";
import vitestConfig from "../vitest.config.js";

const pluginRoot = resolve(import.meta.dirname, "..");
const execFile = promisify(execFileCallback);

async function json(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
}

describe("release metadata and read-only acceptance contract", () => {
  test("publishes the approved ProjectDesignKeeper invocation name", async () => {
    const manifest = await json(resolve(pluginRoot, ".codex-plugin/plugin.json"));
    expect(manifest).toMatchObject({
      name: "project-design-keeper",
      version: "1.0.2",
      author: { name: "EverfIRE" },
      skills: "./skills/",
      mcpServers: "./.mcp.json",
      interface: {
        displayName: "ProjectDesignKeeper",
        developerName: "EverfIRE",
        category: "Developer Tools",
        capabilities: ["Read", "Write"]
      }
    });

    const searchable = JSON.stringify(manifest);
    expect(searchable).toContain("$distill-project-design");
    expect(searchable).toMatch(/local[^\"]*evidence|evidence[^\"]*local/i);
    expect(searchable).toMatch(/preview/i);
    expect(searchable).toMatch(/apply/i);
    expect(searchable).toMatch(/reusable[^\"]*project[^\"]*context|project[^\"]*context[^\"]*reusable/i);
    expect(manifest).not.toHaveProperty("websiteURL");
    expect(manifest).not.toHaveProperty("privacyPolicyURL");
    expect(manifest).not.toHaveProperty("termsOfServiceURL");
  });

  test("publishes matching package metadata and executable quality gates", async () => {
    const packageManifest = await json(resolve(pluginRoot, "package.json"));
    expect(packageManifest).toMatchObject({
      version: "1.0.2",
      scripts: {
        "test:coverage": expect.any(String),
        "test:perf": expect.any(String),
        "package:verify": expect.any(String),
        "smoke:installed": "node scripts/smoke-installed-plugin.mjs"
      }
    });
    expect((packageManifest.scripts as Record<string, string>)["test:perf"]).toContain("--scenario full");
  });

  test("runs clean-checkout CI without host-local release acceptance", async () => {
    const packageManifest = await json(resolve(pluginRoot, "package.json"));
    const scripts = packageManifest.scripts as Record<string, string>;
    const workflow = await readFile(resolve(pluginRoot, ".github/workflows/ci.yml"), "utf8");
    const defaultReleaseSuite = await readFile(resolve(pluginRoot, "test/release.test.ts"), "utf8");
    const localConfig = await readFile(resolve(pluginRoot, "vitest.task10-local.config.ts"), "utf8");
    const localAcceptance = await readFile(resolve(pluginRoot, "test/task10-local.acceptance.ts"), "utf8");
    const legacyGatePrefix = ["KEEPER", "RUN"].join("_") + "_";
    const hostUserPrefix = ["C:", "Users"].join("/") + "/";
    expect(scripts["test:ci"]).toBe("vitest run --maxWorkers=1 --testTimeout=120000");
    expect(scripts["test:task10-local"]).toMatch(/^npm run test:ci && vitest run --config vitest\.task10-local\.config\.ts$/u);
    expect(scripts["test:coverage"]).toContain("--testTimeout=120000");
    expect(vitestConfig.test?.testTimeout).toBe(10_000);
    expect(vitestConfig.test?.include).toEqual(["test/**/*.test.ts"]);
    expect(workflow).toMatch(/npm run test:ci/u);
    expect(workflow).not.toContain(legacyGatePrefix);
    expect(defaultReleaseSuite).not.toContain(hostUserPrefix);
    expect(defaultReleaseSuite).not.toContain(legacyGatePrefix);
    expect(localConfig).toContain('include: ["test/task10-local.acceptance.ts"]');
    expect(localAcceptance).not.toMatch(/\.runIf\(|\.skipIf\(|\.skip\(/u);
  });

  test("keeps every coverage override truthful and all critical modules at 90/90/85", () => {
    const coverage = vitestConfig.test?.coverage as { thresholds?: Record<string, unknown> } | undefined;
    const thresholds = coverage?.thresholds ?? {};
    const global = {
      lines: Number(thresholds.lines),
      statements: Number(thresholds.statements),
      branches: Number(thresholds.branches)
    };
    for (const [path, value] of Object.entries(thresholds)) {
      if (["lines", "statements", "branches", "functions"].includes(path)) continue;
      const override = value as Record<string, number>;
      expect(override.lines, `${path} lines`).toBeGreaterThanOrEqual(global.lines);
      expect(override.statements, `${path} statements`).toBeGreaterThanOrEqual(global.statements);
      expect(override.branches, `${path} branches`).toBeGreaterThanOrEqual(global.branches);
    }
    const critical = [
      "src/security/approval.ts",
      "src/security/cache.ts",
      "src/security/cursor.ts",
      "src/security/limits.ts",
      "src/security/process-liveness.ts",
      "src/security/process-lock.ts",
      "src/security/publication-claim.ts",
      "src/scope/store.ts",
      "src/knowledge/history-integrity.ts"
    ];
    for (const path of critical) {
      const override = thresholds[path] as Record<string, number> | undefined;
      expect(override, `${path} explicit coverage threshold`).toBeDefined();
      expect(override?.lines, `${path} lines`).toBeGreaterThanOrEqual(90);
      expect(override?.statements, `${path} statements`).toBeGreaterThanOrEqual(90);
      expect(override?.branches, `${path} branches`).toBeGreaterThanOrEqual(85);
    }
  });

  test("runs installed smoke against an explicit temporary CI fixture after package verification", async () => {
    const workflow = await readFile(resolve(pluginRoot, ".github/workflows/ci.yml"), "utf8");
    const packaged = workflow.indexOf("npm run package:verify");
    const fixture = workflow.indexOf("keeper-installed-smoke");
    const smoke = workflow.indexOf("npm run smoke:installed");
    expect(packaged).toBeGreaterThanOrEqual(0);
    expect(fixture).toBeGreaterThan(packaged);
    expect(smoke).toBeGreaterThan(fixture);
    expect(workflow).toMatch(/npm run smoke:installed -- .*\.package[/\\]project-design-keeper/iu);
    expect(workflow.slice(fixture, smoke)).not.toMatch(/Set-Content[^\n]*\$fixture/iu);
  });

  test("preserves failed smoke evidence and only deletes a verified empty CI fixture non-recursively", async () => {
    const workflow = await readFile(resolve(pluginRoot, ".github/workflows/ci.yml"), "utf8");
    const finallyIndex = workflow.indexOf("finally {");
    const successIndex = workflow.indexOf("$smokeSucceeded");
    const boundedEmptyIndex = workflow.indexOf("EnumerateFileSystemEntries($fixture)", finallyIndex);
    const firstEntryIndex = workflow.indexOf("MoveNext()", boundedEmptyIndex);
    const cleanupIndex = workflow.indexOf("[IO.Directory]::Delete($fixture, $false)");
    const rootRecheckIndex = workflow.indexOf("GetDirectoryIdentity($runnerTemp)", finallyIndex);
    const fixtureRecheckIndex = workflow.indexOf("GetDirectoryIdentity($fixture)", finallyIndex);
    const componentRecheckIndex = workflow.indexOf(
      "Assert-NoReparsePathComponents -Label 'CI installed smoke fixture' -Path $fixture",
      finallyIndex
    );

    expect(workflow).toMatch(/Set-StrictMode -Version Latest/u);
    expect(workflow).toMatch(/\$ErrorActionPreference\s*=\s*['"]Stop['"]/u);
    expect(workflow).toMatch(/GetFileInformationByHandle/u);
    expect(workflow).toMatch(/FILE_FLAG_BACKUP_SEMANTICS/u);
    expect(workflow).toMatch(/FILE_FLAG_OPEN_REPARSE_POINT/u);
    expect(workflow).toMatch(/\$runnerTempIdentity\s*=.*GetDirectoryIdentity\(\$runnerTemp\)/u);
    expect(workflow).toMatch(/\$fixtureIdentity\s*=.*GetDirectoryIdentity\(\$fixture\)/u);
    expect(workflow).toMatch(/smoke failed[^\n]*preserving[^\n]*\$fixture/iu);
    expect(workflow).not.toMatch(/Remove-Item[^\n]*\$fixture[^\n]*-Recurse/iu);
    expect(workflow).not.toMatch(/Assert-NoReparseFixtureTree/u);
    expect(finallyIndex).toBeGreaterThanOrEqual(0);
    expect(successIndex).toBeGreaterThanOrEqual(0);
    expect(componentRecheckIndex).toBeGreaterThan(finallyIndex);
    expect(rootRecheckIndex).toBeGreaterThan(finallyIndex);
    expect(fixtureRecheckIndex).toBeGreaterThan(finallyIndex);
    expect(fixtureRecheckIndex).toBeGreaterThan(componentRecheckIndex);
    expect(boundedEmptyIndex).toBeGreaterThan(fixtureRecheckIndex);
    expect(firstEntryIndex).toBeGreaterThan(boundedEmptyIndex);
    expect(cleanupIndex).toBeGreaterThan(firstEntryIndex);
  });

  test("emits a machine-readable 20-sample scope-cache performance gate", async () => {
    const temporary = await mkdtemp(join(tmpdir(), "keeper-release-perf-runtime-"));
    try {
      const runtime = join(temporary, "index.js");
      await build({
        entryPoints: [resolve(pluginRoot, "src/index.ts")],
        bundle: true,
        platform: "node",
        format: "esm",
        target: "node20",
        outfile: runtime,
        logLevel: "silent"
      });
      const result = await execFile(process.execPath, [
        resolve(pluginRoot, "test/performance.mjs"), "--scenario", "scope-cache-smoke"
      ], {
        cwd: pluginRoot,
        env: { ...process.env, KEEPER_PERF_RUNTIME: runtime },
        maxBuffer: 8 * 1024 * 1024
      });
      const output = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(output).toMatchObject({
        scenario: "scope-cache-smoke",
        fixture: { schemaVersion: "3.0", files: 1000 },
        samples: { cursor: 20 },
        p95Ms: { cursor: expect.any(Number) },
        repositoryReadsDuringHotQueries: 0
      });
      expect(((output.p95Ms as Record<string, number>).cursor)).toBeLessThanOrEqual(2_000);
    } finally {
      await rm(temporary, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
    }
  }, 90_000);

  test("ships a generic acceptance runner that cannot apply changes", async () => {
    const runner = await readFile(resolve(pluginRoot, "test/read-only-acceptance.mjs"), "utf8");
    expect(runner).toContain("scanScope");
    expect(runner).toContain("searchEvidence");
    expect(runner).toContain("previewUpdate");
    expect(runner).toContain("git status --porcelain=v1 -uall");
    expect(runner).toContain("trackedDiffHash");
    expect(runner).toContain("workingPathHashes");
    expect(runner).toContain('replaceAll("\\\\", "/")');
    expect(runner).not.toMatch(/applyUpdate\s*\(|apply_update/u);
  });

  test("ships the bundled stdio runtime as a tracked publishable file", async () => {
    await expect(readFile(resolve(pluginRoot, "dist/index.js"))).resolves.toBeInstanceOf(Buffer);
    await expect(execFile("git", ["-C", pluginRoot, "check-ignore", "--quiet", "dist/index.js"]))
      .rejects.toMatchObject({ code: 1 });
    await expect(execFile("git", ["-C", pluginRoot, "ls-files", "--error-unmatch", "dist/index.js"]))
      .resolves.toMatchObject({ stdout: expect.stringContaining("dist/index.js") });
  });
});
