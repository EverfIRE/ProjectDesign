import { createHash, randomUUID } from "node:crypto";
import { execFile as execFileCallback, spawn } from "node:child_process";
import { once } from "node:events";
import {
  cp,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile
} from "node:fs/promises";
import { rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";
import { build } from "esbuild";

const execFile = promisify(execFileCallback);
const pluginRoot = resolve(import.meta.dirname, "..");
const activationScript = join(pluginRoot, "scripts", "activate-installed-plugin.ps1");
const installedSmoke = join(pluginRoot, "scripts", "smoke-installed-plugin.mjs");
const demoRoot = process.env.KEEPER_ACTIVATION_DEMO_ROOT;
const exactPackageFiles = [
  ".codex-plugin/plugin.json",
  ".mcp.json",
  "dist/index.js",
  "package.json",
  "skills/distill-project-design/agents/openai.yaml",
  "skills/distill-project-design/assets/knowledge-pack/architecture.md.template",
  "skills/distill-project-design/assets/knowledge-pack/archive-index.md.template",
  "skills/distill-project-design/assets/knowledge-pack/conventions.md.template",
  "skills/distill-project-design/assets/knowledge-pack/decisions.md.template",
  "skills/distill-project-design/assets/knowledge-pack/evidence-map.md.template",
  "skills/distill-project-design/assets/knowledge-pack/index.md.template",
  "skills/distill-project-design/assets/knowledge-pack/intent.md.template",
  "skills/distill-project-design/assets/knowledge-pack/manifest.json",
  "skills/distill-project-design/assets/knowledge-pack/module.md.template",
  "skills/distill-project-design/assets/knowledge-pack/open-questions.md.template",
  "skills/distill-project-design/assets/knowledge-pack/principles.md.template",
  "skills/distill-project-design/assets/knowledge-pack/tuning.md.template",
  "skills/distill-project-design/assets/knowledge-pack/verification.md.template",
  "skills/distill-project-design/assets/project-design-context/agents/openai.yaml",
  "skills/distill-project-design/assets/project-design-context/SKILL.md",
  "skills/distill-project-design/references/document-contract.md",
  "skills/distill-project-design/references/knowledge-model.md",
  "skills/distill-project-design/references/mcp-tools.md",
  "skills/distill-project-design/references/workflow.md",
  "skills/distill-project-design/SKILL.md"
] as const;

interface ActivationLayout {
  packageParent: string;
  packageRoot: string;
  installParent: string;
  installRoot: string;
  projectParent: string;
  projectRoot: string;
  processFixture: string;
}

interface CommandResult {
  exitCode: number;
  output: string;
}

const temporaryParents: string[] = [];
let bundledRuntime = "";
let runtimeParent = "";
let keeperDiffBefore = "";
let demoDiffBefore: string | undefined;

function isStrictlyInside(parent: string, candidate: string): boolean {
  const nested = relative(parent, candidate);
  return nested !== "" && nested !== ".." && !nested.startsWith(`..${sep}`) && !isAbsolute(nested);
}

async function verifiedTemporaryParent(prefix: string): Promise<string> {
  const systemTemporary = await realpath(tmpdir());
  const created = await mkdtemp(join(systemTemporary, prefix));
  const canonical = await realpath(created);
  if (!isStrictlyInside(systemTemporary, canonical)) {
    throw new Error(`Temporary parent escaped the system temporary directory: ${canonical}`);
  }
  temporaryParents.push(canonical);
  return canonical;
}

async function trackedDiff(root: string): Promise<string> {
  try {
    if (!(await lstat(root)).isDirectory()) return "";
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw error;
  }
  try {
    return (await execFile("git", [
      "-C", root, "diff", "--no-ext-diff", "--binary", "--", ".", ":(exclude).plugin-eval/**"
    ], {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024
    })).stdout;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw error;
  }
}

async function makeLayout(): Promise<ActivationLayout> {
  const [packageParent, installParent, projectParent] = await Promise.all([
    verifiedTemporaryParent("keeper-activation-package-parent-"),
    verifiedTemporaryParent("keeper-activation-install-parent-"),
    verifiedTemporaryParent("keeper-activation-project-parent-")
  ]);
  const packageRoot = join(packageParent, `package-${randomUUID()}`);
  const installRoot = join(installParent, "1.0.2");
  const projectRoot = join(projectParent, `project-${randomUUID()}`);
  await Promise.all([
    mkdir(packageRoot, { recursive: false }),
    mkdir(installRoot, { recursive: false }),
    mkdir(projectRoot, { recursive: false })
  ]);
  const processFixture = join(installParent, `processes-${randomUUID()}.json`);
  await writeFile(processFixture, "[]\n", "utf8");
  return { packageParent, packageRoot, installParent, installRoot, projectParent, projectRoot, processFixture };
}

async function writePackage(
  root: string,
  options: { runtime?: "current" | "broken" | "wrong-tools" | "stderr-flood"; previous?: boolean; marker?: string } = {}
): Promise<void> {
  for (const relativePath of exactPackageFiles) {
    const target = join(root, ...relativePath.split("/"));
    await mkdir(dirname(target), { recursive: true });
    await cp(join(pluginRoot, ...relativePath.split("/")), target);
  }
  if (options.runtime === "broken") {
    await writeFile(join(root, "dist", "index.js"), "process.stderr.write('injected installed smoke failure\\n'); process.exit(17);\n", "utf8");
  } else {
    await cp(bundledRuntime, join(root, "dist", "index.js"), { force: true });
    if (options.runtime === "wrong-tools") {
      const runtime = await readFile(join(root, "dist", "index.js"), "utf8");
      const changed = runtime.replace(
        'registerTool(server, "validate_pack"',
        'registerTool(server, "validate_pack_wrong"'
      );
      if (changed === runtime) throw new Error("Bundled runtime did not contain the validate_pack registration");
      await writeFile(join(root, "dist", "index.js"), changed, "utf8");
    } else if (options.runtime === "stderr-flood") {
      const runtime = await readFile(join(root, "dist", "index.js"), "utf8");
      await writeFile(
        join(root, "dist", "index.js"),
        `process.stderr.write("x".repeat(2 * 1024 * 1024));\n${runtime}`,
        "utf8"
      );
    }
  }
  if (options.previous) {
    const manifestPath = join(root, "package.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Record<string, unknown>;
    manifest.activationFixture = "previous-install";
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  }
  if (options.marker) {
    const workflow = join(root, "skills", "distill-project-design", "references", "workflow.md");
    await writeFile(workflow, `${await readFile(workflow, "utf8")}\n<!-- ${options.marker} -->\n`, "utf8");
  }
}

async function addStubbornStdioDescendant(root: string, pidControl?: string): Promise<void> {
  const runtimePath = join(root, "dist", "index.js");
  const runtime = await readFile(runtimePath, "utf8");
  await writeFile(runtimePath, [
    'import { spawn as keeperSmokeTestSpawn } from "node:child_process";',
    'import { writeFileSync as keeperSmokeTestWriteFileSync } from "node:fs";',
    'const keeperSmokeTestDetached = Boolean(process.env.KEEPER_SMOKE_TEST_DESCENDANT_PID);',
    'const keeperSmokeTestDescendantSource = keeperSmokeTestDetached ? "setInterval(() => {}, 1000)" : "setTimeout(() => {}, 12000)";',
    'const keeperSmokeTestDescendant = keeperSmokeTestSpawn(process.execPath, ["-e", keeperSmokeTestDescendantSource], {',
    '  detached: keeperSmokeTestDetached,',
    '  stdio: keeperSmokeTestDetached ? ["ignore", "ignore", "ignore"] : ["ignore", "inherit", "inherit"],',
    '  windowsHide: true',
    '});',
    'if (process.env.KEEPER_SMOKE_TEST_DESCENDANT_PID) {',
    '  keeperSmokeTestWriteFileSync(process.env.KEEPER_SMOKE_TEST_DESCENDANT_PID, String(keeperSmokeTestDescendant.pid), { flag: "wx" });',
    '}',
    'keeperSmokeTestDescendant.unref();',
    runtime
  ].join("\n"), "utf8");
  if (pidControl) await rm(pidControl, { force: true });
}

async function hashTree(root: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en-US"))) {
      const path = join(directory, entry.name);
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) throw new Error(`Unexpected link in hash fixture: ${path}`);
      if (metadata.isDirectory()) {
        await visit(path);
      } else if (metadata.isFile()) {
        const key = relative(root, path).replaceAll("\\", "/");
        result[key] = createHash("sha256").update(await readFile(path)).digest("hex");
      } else {
        throw new Error(`Unexpected fixture entry: ${path}`);
      }
    }
  }
  await visit(root);
  return result;
}

async function command(file: string, args: string[], env: NodeJS.ProcessEnv = {}): Promise<CommandResult> {
  try {
    const result = await execFile(file, args, {
      cwd: pluginRoot,
      encoding: "utf8",
      env: { ...process.env, ...env },
      maxBuffer: 8 * 1024 * 1024,
      timeout: 60_000,
      windowsHide: true
    });
    return { exitCode: 0, output: `${result.stdout}${result.stderr}` };
  } catch (error) {
    const failure = error as Error & { code?: number | string; stdout?: string; stderr?: string; killed?: boolean };
    if (failure.killed) throw new Error(`Bounded child process timed out: ${file}`);
    return {
      exitCode: typeof failure.code === "number" ? failure.code : 1,
      output: `${failure.stdout ?? ""}${failure.stderr ?? ""}${failure.message ?? ""}`
    };
  }
}

function activationEnvironment(layout: ActivationLayout, overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "test",
    KEEPER_ACTIVATION_TEST_ROOT: layout.installParent,
    KEEPER_ACTIVATION_PROCESS_FIXTURE: layout.processFixture,
    ...overrides
  };
}

async function runActivation(layout: ActivationLayout, overrides: NodeJS.ProcessEnv = {}): Promise<CommandResult> {
  return command("powershell.exe", activationArguments(layout), activationEnvironment(layout, overrides));
}

function activationArguments(layout: ActivationLayout): string[] {
  return [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-File", activationScript,
    "-PackageRoot", layout.packageRoot,
    "-InstallRoot", layout.installRoot,
    "-SmokeProject", layout.projectRoot
  ];
}

function startActivation(
  layout: ActivationLayout,
  overrides: NodeJS.ProcessEnv = {},
  preservePreexistingControls = false
): { child: ReturnType<typeof spawn>; result: Promise<CommandResult> } {
  if (!preservePreexistingControls) {
    for (const [name, value] of Object.entries(overrides)) {
      if (!name.endsWith("_BARRIER") || !value) continue;
      try {
        rmdirSync(value);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "ENOENT" && code !== "ENOTEMPTY") throw error;
      }
    }
  }
  const child = spawn("powershell.exe", activationArguments(layout), {
    cwd: pluginRoot,
    env: { ...process.env, ...activationEnvironment(layout, overrides) },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "";
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => { output += chunk; });
  child.stderr?.on("data", (chunk: string) => { output += chunk; });
  const result = new Promise<CommandResult>((resolveResult, rejectResult) => {
    child.once("error", rejectResult);
    child.once("close", (code) => resolveResult({ exitCode: code ?? 1, output }));
  });
  return { child, result };
}

async function startRenameBlockingLease(
  target: string,
  controlRoot: string
): Promise<{ child: ReturnType<typeof spawn>; result: Promise<CommandResult>; release: string }> {
  const script = join(controlRoot, `hold-rename-${randomUUID()}.ps1`);
  const ready = join(controlRoot, `hold-rename-ready-${randomUUID()}`);
  const release = join(controlRoot, `hold-rename-release-${randomUUID()}`);
  await writeFile(script, [
    "param([string]$Target, [string]$Ready, [string]$Release)",
    "$ErrorActionPreference = 'Stop'",
    "Add-Type -TypeDefinition @'",
    "using System;",
    "using System.ComponentModel;",
    "using System.Runtime.InteropServices;",
    "using Microsoft.Win32.SafeHandles;",
    "public static class KeeperRenameBlocker {",
    "  [DllImport(\"kernel32.dll\", CharSet = CharSet.Unicode, SetLastError = true)]",
    "  private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);",
    "  public static SafeFileHandle OpenDirectory(string path) {",
    "    SafeFileHandle handle = CreateFileW(path, 0x00010000, 0x00000003, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);",
    "    if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), \"Unable to hold directory rename lease\");",
    "    return handle;",
    "  }",
    "}",
    "'@",
    "$stream = [KeeperRenameBlocker]::OpenDirectory($Target)",
    "try {",
    "  [IO.File]::WriteAllText($Ready, 'ready')",
    "  while (-not (Test-Path -LiteralPath $Release)) { Start-Sleep -Milliseconds 25 }",
    "}",
    "finally { $stream.Dispose() }"
  ].join("\n"), "utf8");
  const child = spawn("powershell.exe", [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", script, "-Target", target, "-Ready", ready, "-Release", release
  ], {
    cwd: pluginRoot,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "";
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => { output += chunk; });
  child.stderr?.on("data", (chunk: string) => { output += chunk; });
  const result = new Promise<CommandResult>((resolveResult, rejectResult) => {
    child.once("error", rejectResult);
    child.once("close", (code) => resolveResult({ exitCode: code ?? 1, output }));
  });
  await Promise.race([
    waitForPath(ready),
    result.then((early) => { throw new Error(`Rename blocker exited before acquiring its lease:\n${early.output}`); })
  ]);
  return { child, result, release };
}

async function startWritableFileLease(
  target: string,
  controlRoot: string
): Promise<{ child: ReturnType<typeof spawn>; result: Promise<CommandResult>; release: string }> {
  const script = join(controlRoot, `hold-writable-${randomUUID()}.ps1`);
  const ready = join(controlRoot, `hold-writable-ready-${randomUUID()}`);
  const release = join(controlRoot, `hold-writable-release-${randomUUID()}`);
  await writeFile(script, [
    "param([string]$Target, [string]$Ready, [string]$Release)",
    "$ErrorActionPreference = 'Stop'",
    "$share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete",
    "$stream = [IO.File]::Open($Target, [IO.FileMode]::Open, [IO.FileAccess]::Write, $share)",
    "try {",
    "  [IO.File]::WriteAllText($Ready, 'ready')",
    "  while (-not (Test-Path -LiteralPath $Release)) { Start-Sleep -Milliseconds 25 }",
    "}",
    "finally { $stream.Dispose() }"
  ].join("\n"), "utf8");
  const child = spawn("powershell.exe", [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", script, "-Target", target, "-Ready", ready, "-Release", release
  ], {
    cwd: pluginRoot,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "";
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => { output += chunk; });
  child.stderr?.on("data", (chunk: string) => { output += chunk; });
  const result = new Promise<CommandResult>((resolveResult, rejectResult) => {
    child.once("error", rejectResult);
    child.once("close", (code) => resolveResult({ exitCode: code ?? 1, output }));
  });
  await Promise.race([
    waitForPath(ready),
    result.then((early) => { throw new Error(`Writable lease exited before acquiring its handle:\n${early.output}`); })
  ]);
  return { child, result, release };
}

async function waitForPath(path: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await lstat(path);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await delay(25);
  }
  throw new Error(`Timed out waiting for deterministic activation barrier: ${path}`);
}

function fixturePidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw error;
  }
}

async function waitForFixturePidExit(pid: number, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!fixturePidAlive(pid)) return;
    await delay(25);
  }
  throw new Error(`Owned smoke descendant PID ${pid} remained alive`);
}

async function requireSmokeBarrierBeforeExit(
  entered: string,
  running: ReturnType<typeof startInstalledSmoke>,
  label: string
): Promise<void> {
  const enteredBeforeExit = await Promise.race([
    waitForPath(entered).then(() => true),
    running.result.then(() => false)
  ]);
  if (!enteredBeforeExit) {
    const earlyExit = await running.result;
    throw new Error(`Installed smoke exited before entering the ${label} barrier:\n${earlyExit.output}`);
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function trackNewSmokeTemporaryRoots(before: Set<string>): Promise<string[]> {
  const systemTemporary = await realpath(tmpdir());
  const prefixes = [
    "keeper-installed-smoke-cache-",
    "keeper-installed-smoke-cache-cleanup-"
  ];
  const created = (await readdir(systemTemporary))
    .filter((name) => !before.has(name) && prefixes.some((prefix) => name.startsWith(prefix)))
    .map((name) => join(systemTemporary, name));
  temporaryParents.push(...created);
  return created;
}

async function requireBarrierBeforeExit(
  entered: string,
  running: ReturnType<typeof startActivation>,
  label: string
): Promise<void> {
  const enteredBeforeExit = await Promise.race([
    waitForPath(entered).then(() => true),
    running.result.then(() => false)
  ]);
  if (!enteredBeforeExit) {
    const earlyExit = await running.result;
    throw new Error(`Activation exited before entering the ${label} barrier:\n${earlyExit.output}`);
  }
}

async function runInstalledSmoke(args: string[], env: NodeJS.ProcessEnv = {}): Promise<CommandResult> {
  return command(process.execPath, [installedSmoke, ...args], env);
}

function startInstalledSmoke(args: string[], env: NodeJS.ProcessEnv = {}): { result: Promise<CommandResult> } {
  const child = spawn(process.execPath, [installedSmoke, ...args], {
    cwd: pluginRoot,
    env: { ...process.env, ...env },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "";
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => { output += chunk; });
  child.stderr?.on("data", (chunk: string) => { output += chunk; });
  const result = new Promise<CommandResult>((resolveResult, rejectResult) => {
    child.once("error", rejectResult);
    child.once("close", (code) => resolveResult({ exitCode: code ?? 1, output }));
  });
  return { result };
}

async function waitForCanonicalFixtureFile(
  projectRoot: string,
  relativePath: string,
  running: { result: Promise<CommandResult> },
  timeoutMs = 10_000
): Promise<string> {
  const expiresAt = Date.now() + timeoutMs;
  while (Date.now() < expiresAt) {
    const fixtureName = (await readdir(projectRoot)).find((name) => name.startsWith("keeper-canonical-schema3-"));
    if (fixtureName) {
      const path = join(projectRoot, fixtureName, ...relativePath.split("/"));
      try {
        await lstat(path);
        return path;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    const ended = await Promise.race([
      delay(10).then(() => undefined),
      running.result.then((result) => result)
    ]);
    if (ended) throw new Error(`Installed smoke exited before publishing its canonical fixture:\n${ended.output}`);
  }
  throw new Error(`Timed out waiting for canonical fixture file ${relativePath}`);
}

async function swapArtifacts(layout: ActivationLayout): Promise<string[]> {
  const leaf = basename(layout.installRoot);
  return (await readdir(layout.installParent))
    .filter((name) => name.startsWith(`${leaf}.backup-`) || name.startsWith(`${leaf}.staging-`) || name.startsWith(`${leaf}.failed-`))
    .sort();
}

beforeAll(async () => {
  keeperDiffBefore = await trackedDiff(pluginRoot);
  if (demoRoot) demoDiffBefore = await trackedDiff(demoRoot);
  runtimeParent = await verifiedTemporaryParent("keeper-activation-runtime-");
  temporaryParents.splice(temporaryParents.indexOf(runtimeParent), 1);
  bundledRuntime = join(runtimeParent, "index.js");
  await build({
    entryPoints: [join(pluginRoot, "src", "index.ts")],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    outfile: bundledRuntime,
    logLevel: "silent"
  });
});

afterEach(async () => {
  const roots = temporaryParents.splice(0);
  await Promise.all(roots.map(async (root) => {
    const canonicalTemporary = await realpath(tmpdir());
    if (!isStrictlyInside(canonicalTemporary, root)) throw new Error(`Refusing unsafe fixture cleanup: ${root}`);
    await rm(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  }));
});

afterAll(async () => {
  expect(await trackedDiff(pluginRoot)).toBe(keeperDiffBefore);
  if (demoRoot && demoDiffBefore !== undefined) {
    expect(await trackedDiff(demoRoot)).toBe(demoDiffBefore);
  }
  if (runtimeParent) await rm(runtimeParent, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
});

const windowsTest = test.runIf(process.platform === "win32");

describe("installed plugin smoke contract", () => {
  windowsTest("builds validates and removes a canonical Schema 3 fixture inside an empty disposable project", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await expect(readdir(layout.projectRoot)).resolves.toEqual([]);

    const result = await runInstalledSmoke([layout.packageRoot, layout.projectRoot]);

    expect(result.exitCode).toBe(0);
    expect(result.output).toMatch(/canonical Schema 3.*validated/i);
    expect(result.output).toMatch(/installed smoke passed/i);
    await expect(readdir(layout.projectRoot)).resolves.toEqual([]);
  }, 90_000);

  windowsTest("rejects an oversized installed JSON manifest before publishing a fixture", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    const packageManifest = JSON.parse(await readFile(join(layout.packageRoot, "package.json"), "utf8")) as Record<string, unknown>;
    packageManifest.padding = "x".repeat(256 * 1024);
    await writeFile(join(layout.packageRoot, "package.json"), `${JSON.stringify(packageManifest)}\n`, "utf8");

    const result = await runInstalledSmoke([layout.packageRoot, layout.projectRoot]);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/installed package JSON.*(?:bytes|size).*limit/i);
    await expect(readdir(layout.projectRoot)).resolves.toEqual([]);
  }, 90_000);

  windowsTest("bounds aggregate MCP stderr without retaining an unbounded diagnostic stream", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot, { runtime: "stderr-flood" });

    const result = await runInstalledSmoke([layout.packageRoot, layout.projectRoot]);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/MCP stderr.*bounded.*byte.*limit/i);
    expect(result.output.length).toBeLessThan(2 * 1024 * 1024);
  }, 90_000);

  windowsTest("fails closed and preserves the fixture until the stdio child is confirmed closed", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await addStubbornStdioDescendant(layout.packageRoot);
    const systemTemporary = await realpath(tmpdir());
    const temporaryBefore = new Set(await readdir(systemTemporary));
    const closeControl = join(layout.projectParent, `close-confirm-${randomUUID()}`);

    const result = await runInstalledSmoke([layout.packageRoot, layout.projectRoot], {
      NODE_ENV: "test",
      KEEPER_INSTALLED_SMOKE_TEST_ROOT: layout.projectParent,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_CONTROL: closeControl,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_DELAY_MS: "12000"
    });
    const createdTemporary = await trackNewSmokeTemporaryRoots(temporaryBefore);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/MCP.*(?:fully exit|confirmed closed).*preserving/i);
    const [fixtureName] = (await readdir(layout.projectRoot))
      .filter((name) => name.startsWith("keeper-canonical-schema3-"));
    expect(fixtureName).toBeDefined();
    await expect(readFile(join(layout.projectRoot, fixtureName, "README.md"), "utf8"))
      .resolves.toBe("Installed smoke canonical evidence.\n");
    const cacheRoot = createdTemporary.find((path) => basename(path).startsWith("keeper-installed-smoke-cache-") &&
      !basename(path).startsWith("keeper-installed-smoke-cache-cleanup-"));
    expect(cacheRoot).toBeDefined();
    await expect(pathExists(cacheRoot!)).resolves.toBe(true);
    await delay(250);
    await expect(pathExists(join(layout.projectRoot, fixtureName))).resolves.toBe(true);
    await expect(pathExists(cacheRoot!)).resolves.toBe(true);
  }, 90_000);

  windowsTest("rejects a nonempty smoke project without changing user-owned entries", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writeFile(join(layout.projectRoot, "user-owned.txt"), "do not modify\n", "utf8");
    const before = await hashTree(layout.projectRoot);

    const result = await runInstalledSmoke([layout.packageRoot, layout.projectRoot]);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/smoke project.*empty.*disposable|empty disposable.*smoke project/i);
    expect(await hashTree(layout.projectRoot)).toEqual(before);
  }, 90_000);

  windowsTest("fails nonzero and preserves the complete fixture when cleanup identity is ambiguous", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    const running = startInstalledSmoke([layout.packageRoot, layout.projectRoot]);
    const readme = await waitForCanonicalFixtureFile(layout.projectRoot, "README.md", running);
    await writeFile(readme, "replacement evidence must be preserved\n", "utf8");

    const result = await running.result;

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/cleanup is ambiguous.*preserving remaining evidence/i);
    await expect(readFile(readme, "utf8")).resolves.toBe("replacement evidence must be preserved\n");
    const [fixtureName] = await readdir(layout.projectRoot);
    expect(fixtureName).toMatch(/^keeper-canonical-schema3-/u);
    expect(Object.keys(await hashTree(join(layout.projectRoot, fixtureName)))).toContain("docs/project-design/manifest.json");
  }, 90_000);

  windowsTest("quarantines but never deletes a replacement at the fixture root cleanup boundary", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    const barrier = join(layout.projectParent, `fixture-cleanup-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startInstalledSmoke([layout.packageRoot, layout.projectRoot], {
      NODE_ENV: "test",
      KEEPER_INSTALLED_SMOKE_TEST_ROOT: layout.projectParent,
      KEEPER_INSTALLED_SMOKE_TEST_FIXTURE_QUARANTINE_BARRIER: barrier
    });
    try {
      await requireSmokeBarrierBeforeExit(entered, running, "fixture cleanup");
      const fixtureRoot = (await readFile(entered, "utf8")).trim();
      const ownedEvidence = `${fixtureRoot}.owned-evidence`;
      await rename(fixtureRoot, ownedEvidence);
      await mkdir(fixtureRoot);
      await writeFile(join(fixtureRoot, "user-owned.txt"), "preserve replacement\n", "utf8");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/fixture.*identity changed.*preserving|preserving.*fixture.*identity/iu);
      await expect(readFile(join(ownedEvidence, "README.md"), "utf8"))
        .resolves.toBe("Installed smoke canonical evidence.\n");
      const [quarantine] = (await readdir(layout.projectRoot))
        .filter((name) => name.startsWith("keeper-installed-smoke-fixture-cleanup-"));
      expect(quarantine).toBeDefined();
      await expect(readFile(join(layout.projectRoot, quarantine, "payload", "user-owned.txt"), "utf8"))
        .resolves.toBe("preserve replacement\n");
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      await running.result.catch(() => undefined);
    }
  }, 90_000);

  windowsTest("quarantines but never recursively deletes a replacement cache root", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    const barrier = join(layout.projectParent, `cache-cleanup-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const systemTemporary = await realpath(tmpdir());
    const temporaryBefore = new Set(await readdir(systemTemporary));
    const running = startInstalledSmoke([layout.packageRoot, layout.projectRoot], {
      NODE_ENV: "test",
      KEEPER_INSTALLED_SMOKE_TEST_ROOT: layout.projectParent,
      KEEPER_INSTALLED_SMOKE_TEST_CACHE_QUARANTINE_BARRIER: barrier
    });
    try {
      await requireSmokeBarrierBeforeExit(entered, running, "cache cleanup");
      const cacheRoot = (await readFile(entered, "utf8")).trim();
      const ownedEvidence = `${cacheRoot}.owned-evidence-${randomUUID()}`;
      await rename(cacheRoot, ownedEvidence);
      await mkdir(cacheRoot);
      await writeFile(join(cacheRoot, "user-owned.txt"), "preserve cache replacement\n", "utf8");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;
      const createdTemporary = await trackNewSmokeTemporaryRoots(temporaryBefore);

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/cache.*identity changed.*preserving|preserving.*cache.*identity/iu);
      expect(createdTemporary).toContain(ownedEvidence);
      await expect(pathExists(ownedEvidence)).resolves.toBe(true);
      const quarantine = createdTemporary.find((path) => basename(path).startsWith("keeper-installed-smoke-cache-cleanup-"));
      expect(quarantine).toBeDefined();
      await expect(readFile(join(quarantine!, "payload", "user-owned.txt"), "utf8"))
        .resolves.toBe("preserve cache replacement\n");
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      await running.result.catch(() => undefined);
    }
  }, 90_000);

  windowsTest("requires exactly two absolute positional roots", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);

    const missing = await runInstalledSmoke([]);
    const relativeRoot = await runInstalledSmoke(["relative-package", layout.projectRoot]);
    const surplus = await runInstalledSmoke([layout.packageRoot, layout.projectRoot, layout.projectRoot]);

    expect(missing.exitCode).not.toBe(0);
    expect(relativeRoot.exitCode).not.toBe(0);
    expect(surplus.exitCode).not.toBe(0);
    expect(`${missing.output}\n${relativeRoot.output}\n${surplus.output}`).toMatch(/two absolute|absolute.*root|exactly two/i);
  }, 90_000);

  windowsTest("rejects close-confirm test hooks without the strict temporary test context", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    const nestedTestRoot = join(layout.projectParent, `nested-test-root-${randomUUID()}`);
    await mkdir(nestedTestRoot);
    const productionControl = join(layout.projectParent, `production-control-${randomUUID()}`);
    const nestedControl = join(nestedTestRoot, `nested-control-${randomUUID()}`);
    const existingControl = join(layout.projectParent, `existing-control-${randomUUID()}`);
    await writeFile(existingControl, "pre-existing\n", "utf8");

    const production = await runInstalledSmoke([layout.packageRoot, layout.projectRoot], {
      NODE_ENV: "production",
      KEEPER_INSTALLED_SMOKE_TEST_ROOT: layout.projectParent,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_CONTROL: productionControl,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_DELAY_MS: "1"
    });
    const nested = await runInstalledSmoke([layout.packageRoot, layout.projectRoot], {
      NODE_ENV: "test",
      KEEPER_INSTALLED_SMOKE_TEST_ROOT: nestedTestRoot,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_CONTROL: nestedControl,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_DELAY_MS: "1"
    });
    const collision = await runInstalledSmoke([layout.packageRoot, layout.projectRoot], {
      NODE_ENV: "test",
      KEEPER_INSTALLED_SMOKE_TEST_ROOT: layout.projectParent,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_CONTROL: existingControl,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_DELAY_MS: "1"
    });

    expect(production.exitCode).not.toBe(0);
    expect(production.output).toMatch(/restricted to NODE_ENV=test/i);
    expect(nested.exitCode).not.toBe(0);
    expect(nested.output).toMatch(/direct child of system temp/i);
    expect(collision.exitCode).not.toBe(0);
    expect(collision.output).toMatch(/EEXIST|already exists/i);
    await expect(readdir(layout.projectRoot)).resolves.toEqual([]);
  }, 90_000);

  windowsTest("retains the documented zero-positional environment fallback", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);

    const result = await runInstalledSmoke([], {
      KEEPER_INSTALLED_ROOT: layout.packageRoot,
      KEEPER_SMOKE_PROJECT: layout.projectRoot
    });

    expect(result.exitCode).toBe(0);
    expect(result.output).toMatch(/deprecated|compatibility/i);
  }, 90_000);

  windowsTest("rejects a wrong installed package identity", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    const packageManifest = JSON.parse(await readFile(join(layout.packageRoot, "package.json"), "utf8")) as Record<string, unknown>;
    packageManifest.name = "not-project-design-keeper";
    await writeFile(join(layout.packageRoot, "package.json"), `${JSON.stringify(packageManifest)}\n`, "utf8");
    const wrongPackage = await runInstalledSmoke([layout.packageRoot, layout.projectRoot]);

    expect(wrongPackage.exitCode).not.toBe(0);
    expect(wrongPackage.output).toMatch(/wrong installed package identity/i);
  }, 90_000);

  windowsTest("rejects a reparse-point installed root", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    const linkedRoot = join(layout.packageParent, `linked-${randomUUID()}`);
    await symlink(layout.packageRoot, linkedRoot, "junction");

    const linked = await runInstalledSmoke([linkedRoot, layout.projectRoot]);

    expect(linked.exitCode).not.toBe(0);
    expect(linked.output).toMatch(/installed root.*(?:reparse|link)/i);
  }, 90_000);

  windowsTest("rejects any tool catalog other than the exact nine sorted tools", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot, { runtime: "wrong-tools" });

    const result = await runInstalledSmoke([layout.packageRoot, layout.projectRoot]);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/tool|validate_pack|exact/i);
  }, 90_000);
});

describe("recoverable installed plugin activation", () => {
  test("never passes a negative remaining deadline to Thread.Sleep", async () => {
    const source = await readFile(activationScript, "utf8");

    expect(source).not.toContain("Thread.Sleep((int)Math.Min(25L, milliseconds - clock.ElapsedMilliseconds))");
    expect(source).not.toContain("Thread.Sleep((int)Math.Min(25L, waitMilliseconds - waitClock.ElapsedMilliseconds))");
    expect(source.match(/remainingMilliseconds <= 0/g)?.length).toBeGreaterThanOrEqual(2);
  });

  windowsTest("refuses a nonempty smoke project before either install rename", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    await writeFile(join(layout.projectRoot, "user-owned.txt"), "do not modify\n", "utf8");
    const beforeInstall = await hashTree(layout.installRoot);
    const beforeProject = await hashTree(layout.projectRoot);

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/smoke project.*empty.*disposable|empty disposable.*smoke project/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await hashTree(layout.projectRoot)).toEqual(beforeProject);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("rejects an oversized activation process fixture before staging", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    await writeFile(layout.processFixture, `[{"padding":"${"x".repeat(256 * 1024)}"}]\n`, "utf8");

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/process fixture.*bounded byte limit/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("fails closed when the activation-wide operation deadline expires", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);

    const result = await runActivation(layout, { KEEPER_ACTIVATION_TEST_DEADLINE_MS: "1" });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/activation.*(?:deadline|time.*limit|timed out)/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("uses a separate recovery deadline when the forward deadline expires after the first rename", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const candidate = await hashTree(layout.packageRoot);

    const result = await runActivation(layout, {
      KEEPER_ACTIVATION_TEST_EXPIRE_AFTER_FIRST_RENAME: "1"
    });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/activation.*deadline|deadline.*expired/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    const [stagingName] = (await swapArtifacts(layout)).filter((name) => name.includes(".staging-"));
    expect(stagingName).toBeDefined();
    expect(await hashTree(join(layout.installParent, stagingName!))).toEqual(candidate);
  }, 120_000);

  windowsTest("uses a separate recovery deadline for an ordinary failure at the forward deadline after mutation", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);

    const result = await runActivation(layout, {
      KEEPER_ACTIVATION_TEST_ORDINARY_FAILURE_AFTER_FIRST_RENAME: "1"
    });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/injected ordinary post-mutation failure/i);
    expect(result.output).toMatch(/independent bounded recovery deadline/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 120_000);

  windowsTest("refuses a live direct Codex MCP child before either rename", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const otherPluginRoot = join(layout.installParent, `other-plugin-${randomUUID()}`);
    await mkdir(otherPluginRoot);
    const cwdProbe = spawn(process.execPath, ["-e", "setInterval(() => undefined, 1000)"], {
      cwd: layout.installRoot,
      windowsHide: true,
      stdio: "ignore"
    });
    await once(cwdProbe, "spawn");
    if (!cwdProbe.pid) throw new Error("CWD probe did not expose a PID");
    try {
      await writeFile(layout.processFixture, `${JSON.stringify([
        { Name: "Codex.exe", ProcessId: 4100, ParentProcessId: 1, CommandLine: "Codex.exe" },
        {
          Name: "node.exe",
          ProcessId: 4101,
          ParentProcessId: 4100,
          CommandLine: `\"C:\\Program Files\\nodejs\\node.exe\" \"${join(layout.installRoot, "dist", "index.js")}\"`
        },
        {
          Name: "node.exe",
          ProcessId: cwdProbe.pid,
          ParentProcessId: 4100,
          CommandLine: "node dist/index.js"
        },
        {
          Name: "node.exe",
          ProcessId: 4103,
          ParentProcessId: 4100,
          CommandLine: "node dist/index.js",
          WorkingDirectory: otherPluginRoot
        }
      ])}\n`, "utf8");

      const result = await runActivation(layout);

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/\b4101\b/u);
      expect(result.output).toContain(String(cwdProbe.pid));
      expect(result.output).not.toMatch(/\b4103\b/u);
      expect(result.output).toMatch(/in use|close.*task|restart Codex/i);
      expect(cwdProbe.exitCode).toBeNull();
      expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
      expect(await swapArtifacts(layout)).toEqual([]);
    } finally {
      if (cwdProbe.exitCode === null) {
        const exited = once(cwdProbe, "exit");
        cwdProbe.kill();
        await exited;
      }
    }
  }, 90_000);

  windowsTest("fails closed with operator guidance when a relative MCP cwd cannot be verified", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    await writeFile(layout.processFixture, `${JSON.stringify([
      { Name: "Codex.exe", ProcessId: 7300, ParentProcessId: 1, CommandLine: "Codex.exe" },
      {
        Name: "node.exe",
        ProcessId: 2_000_000_000,
        ParentProcessId: 7300,
        CommandLine: "node dist/index.js"
      }
    ])}\n`, "utf8");

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/cannot safely (?:determine|verify).*PID\s*2000000000/i);
    expect(result.output).toMatch(/close.*task|restart Codex/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("fails closed when a direct Codex Node command line cannot be inspected", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    await writeFile(layout.processFixture, `${JSON.stringify([
      { Name: "Codex.exe", ProcessId: 7350, ParentProcessId: 1, CommandLine: "Codex.exe" },
      { Name: "node.exe", ProcessId: 7351, ParentProcessId: 7350, CommandLine: null }
    ])}\n`, "utf8");

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/cannot safely (?:inspect|determine).*command line.*PID\s*7351/i);
    expect(result.output).toMatch(/close.*task|restart Codex/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("serializes concurrent activation and releases the lock for the next activation", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot, { marker: "candidate-a" });
    await writePackage(layout.installRoot, { previous: true });
    const secondPackageRoot = join(layout.packageParent, `package-${randomUUID()}`);
    await mkdir(secondPackageRoot);
    await writePackage(secondPackageRoot, { marker: "candidate-b" });
    const secondLayout = { ...layout, packageRoot: secondPackageRoot };
    const barrier = join(layout.installParent, `barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const first = startActivation(layout, { KEEPER_ACTIVATION_TEST_BARRIER: barrier });
    try {
      await waitForPath(entered);

      const contender = await runActivation(secondLayout);

      expect(contender.exitCode).not.toBe(0);
      expect(contender.output).toMatch(/already in progress|activation.*lock|concurrent/i);
      await writeFile(release, "continue\n", "utf8");
      const firstResult = await first.result;
      expect(firstResult.exitCode).toBe(0);
      expect(await hashTree(layout.installRoot)).toEqual(await hashTree(layout.packageRoot));
      expect((await swapArtifacts(layout)).filter((name) => name.includes(".backup-"))).toHaveLength(1);

      const secondResult = await runActivation(secondLayout);

      expect(secondResult.exitCode).toBe(0);
      expect(await hashTree(layout.installRoot)).toEqual(await hashTree(secondPackageRoot));
      const finalArtifacts = await swapArtifacts(layout);
      expect(finalArtifacts.filter((name) => name.includes(".backup-"))).toHaveLength(1);
      expect(finalArtifacts.filter((name) => name.includes(".staging-") || name.includes(".failed-"))).toEqual([]);
      expect(await hashTree(join(layout.installParent, finalArtifacts[0]!))).toEqual(await hashTree(layout.packageRoot));
    } finally {
      if (first.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(first.child, "exit");
        first.child.kill();
        await exited;
      }
      await first.result.catch(() => undefined);
    }
  }, 180_000);

  windowsTest("rechecks live Codex children after staging and before the first rename", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_BARRIER: barrier });
    try {
      await waitForPath(entered);
      expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
      const stagedArtifacts = await swapArtifacts(layout);
      expect(stagedArtifacts.filter((name) => name.includes(".staging-"))).toHaveLength(1);
      expect(stagedArtifacts.filter((name) => name.includes(".backup-") || name.includes(".failed-"))).toEqual([]);
      await writeFile(layout.processFixture, `${JSON.stringify([
        { Name: "Codex.exe", ProcessId: 7200, ParentProcessId: 1, CommandLine: "Codex.exe" },
        {
          Name: "node.exe",
          ProcessId: 7201,
          ParentProcessId: 7200,
          CommandLine: `node \"${join(layout.installRoot, "dist", "index.js")}\"`
        }
      ])}\n`, "utf8");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/PID\s*7201/i);
      expect(result.output).toMatch(/in use|close.*task|restart Codex/i);
      expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
      expect(await swapArtifacts(layout)).toEqual([]);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("refuses to move an active-directory replacement introduced while staged", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_BARRIER: barrier });
    try {
      await waitForPath(entered);
      const [stagingName] = (await swapArtifacts(layout)).filter((name) => name.includes(".staging-"));
      if (!stagingName) throw new Error("Activation did not create its staging evidence before the barrier");
      const stagingPath = join(layout.installParent, stagingName);
      const stagedCandidate = await hashTree(stagingPath);
      const capturedActive = join(layout.installParent, `${basename(layout.installRoot)}.captured-active-${randomUUID()}`);
      await rename(layout.installRoot, capturedActive);
      await mkdir(layout.installRoot);
      await writePackage(layout.installRoot, { marker: "untrusted-active-replacement" });
      const activeReplacement = await hashTree(layout.installRoot);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/active|install.*identity|directory.*changed/i);
      expect(await hashTree(capturedActive)).toEqual(originalActive);
      expect(await hashTree(layout.installRoot)).toEqual(activeReplacement);
      expect(await hashTree(stagingPath)).toEqual(stagedCandidate);
      expect((await swapArtifacts(layout)).filter((name) => name.includes(".backup-") || name.includes(".failed-"))).toEqual([]);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("refuses to move a staging-directory replacement introduced before the first rename", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_BARRIER: barrier });
    try {
      await waitForPath(entered);
      const [stagingName] = (await swapArtifacts(layout)).filter((name) => name.includes(".staging-"));
      if (!stagingName) throw new Error("Activation did not create its staging evidence before the barrier");
      const stagingPath = join(layout.installParent, stagingName);
      const capturedStaging = join(layout.installParent, `${basename(layout.installRoot)}.captured-staging-${randomUUID()}`);
      const stagedCandidate = await hashTree(stagingPath);
      await rename(stagingPath, capturedStaging);
      await mkdir(stagingPath);
      await writePackage(stagingPath, { marker: "untrusted-staging-replacement" });
      const stagingReplacement = await hashTree(stagingPath);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/staging.*identity|directory.*changed/i);
      expect(await hashTree(layout.installRoot)).toEqual(originalActive);
      expect(await hashTree(capturedStaging)).toEqual(stagedCandidate);
      expect(await hashTree(stagingPath)).toEqual(stagingReplacement);
      expect((await swapArtifacts(layout)).filter((name) => name.includes(".backup-") || name.includes(".failed-"))).toEqual([]);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("refuses a real install-parent replacement before acquiring the activation lock", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrierName = `prelock-barrier-${randomUUID()}`;
    const barrier = join(dirname(layout.installParent), barrierName);
    await mkdir(barrier);
    temporaryParents.push(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const capturedParent = join(dirname(layout.installParent), `${basename(layout.installParent)}-captured-${randomUUID()}`);
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_PRELOCK_BARRIER: barrier });
    try {
      const enteredBeforeExit = await Promise.race([
        waitForPath(entered).then(() => true),
        running.result.then(() => false)
      ]);
      if (!enteredBeforeExit) {
        const earlyExit = await running.result;
        throw new Error(`Activation exited before entering the pre-lock barrier:\n${earlyExit.output}`);
      }

      await rename(layout.installParent, capturedParent);
      temporaryParents.push(capturedParent);
      await mkdir(layout.installParent);
      await mkdir(layout.installRoot);
      await writePackage(layout.installRoot, { marker: "untrusted-parent-replacement" });
      const activeReplacement = await hashTree(layout.installRoot);
      await writeFile(layout.processFixture, "[]\n", "utf8");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/install parent.*identity|directory.*changed/i);
      expect(await hashTree(join(capturedParent, basename(layout.installRoot)))).toEqual(originalActive);
      expect(await hashTree(layout.installRoot)).toEqual(activeReplacement);
      expect(await swapArtifacts(layout)).toEqual([]);
      expect(await readdir(layout.installParent)).not.toContain(`.${basename(layout.installRoot)}.project-design-keeper.activation.lock`);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("preserves a staging replacement when rollback cleanup identity is ambiguous", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `rollback-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, {
      KEEPER_ACTIVATION_TEST_FAULT: "first-rename",
      KEEPER_ACTIVATION_TEST_ROLLBACK_BARRIER: barrier
    });
    try {
      await requireBarrierBeforeExit(entered, running, "rollback");
      const [stagingName] = (await swapArtifacts(layout)).filter((name) => name.includes(".staging-"));
      if (!stagingName) throw new Error("Rollback barrier did not retain the staged candidate");
      const stagingPath = join(layout.installParent, stagingName);
      const capturedStaging = join(layout.installParent, `${basename(layout.installRoot)}.captured-rollback-staging-${randomUUID()}`);
      const stagedCandidate = await hashTree(stagingPath);
      await rename(stagingPath, capturedStaging);
      await mkdir(stagingPath);
      await writePackage(stagingPath, { marker: "untrusted-rollback-staging" });
      const stagingReplacement = await hashTree(stagingPath);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/identity.*ambiguous|preserv.*evidence/i);
      expect(await hashTree(layout.installRoot)).toEqual(originalActive);
      expect(await hashTree(capturedStaging)).toEqual(stagedCandidate);
      expect(await hashTree(stagingPath)).toEqual(stagingReplacement);
      expect((await swapArtifacts(layout)).filter((name) => name.includes(".backup-") || name.includes(".failed-"))).toEqual([]);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("preserves a backup replacement when rollback restore identity is ambiguous", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `rollback-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, {
      KEEPER_ACTIVATION_TEST_FAULT: "second-rename",
      KEEPER_ACTIVATION_TEST_ROLLBACK_BARRIER: barrier
    });
    try {
      await requireBarrierBeforeExit(entered, running, "rollback");
      const artifacts = await swapArtifacts(layout);
      const [backupName] = artifacts.filter((name) => name.includes(".backup-"));
      const [stagingName] = artifacts.filter((name) => name.includes(".staging-"));
      if (!backupName || !stagingName) throw new Error("Rollback barrier did not expose backup and staging evidence");
      const backupPath = join(layout.installParent, backupName);
      const stagingPath = join(layout.installParent, stagingName);
      const capturedBackup = join(layout.installParent, `${basename(layout.installRoot)}.captured-rollback-backup-${randomUUID()}`);
      const stagedCandidate = await hashTree(stagingPath);
      await rename(backupPath, capturedBackup);
      await mkdir(backupPath);
      await writePackage(backupPath, { marker: "untrusted-rollback-backup" });
      const backupReplacement = await hashTree(backupPath);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/identity.*ambiguous|preserv.*evidence/i);
      expect(await pathExists(layout.installRoot)).toBe(false);
      expect(await hashTree(capturedBackup)).toEqual(originalActive);
      expect(await hashTree(backupPath)).toEqual(backupReplacement);
      expect(await hashTree(stagingPath)).toEqual(stagedCandidate);
      expect((await swapArtifacts(layout)).filter((name) => name.includes(".failed-"))).toEqual([]);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("preserves an activated replacement instead of moving it to failed evidence", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot, { runtime: "broken" });
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const candidate = await hashTree(layout.packageRoot);
    const barrier = join(layout.installParent, `rollback-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_ROLLBACK_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "rollback");
      const [backupName] = (await swapArtifacts(layout)).filter((name) => name.includes(".backup-"));
      if (!backupName) throw new Error("Rollback barrier did not expose the previous active backup");
      const backupPath = join(layout.installParent, backupName);
      const capturedCandidate = join(layout.installParent, `${basename(layout.installRoot)}.captured-failed-candidate-${randomUUID()}`);
      await rename(layout.installRoot, capturedCandidate);
      await mkdir(layout.installRoot);
      await writePackage(layout.installRoot, { marker: "untrusted-activated-replacement" });
      const activeReplacement = await hashTree(layout.installRoot);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/identity.*ambiguous|preserv.*evidence/i);
      expect(await hashTree(capturedCandidate)).toEqual(candidate);
      expect(await hashTree(layout.installRoot)).toEqual(activeReplacement);
      expect(await hashTree(backupPath)).toEqual(originalActive);
      expect((await swapArtifacts(layout)).filter((name) => name.includes(".failed-") || name.includes(".staging-"))).toEqual([]);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("preserves an old-backup replacement during success cleanup identity ambiguity", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const oldBackup = join(layout.installParent, `${basename(layout.installRoot)}.backup-20000101T000000000Z-old`);
    await mkdir(oldBackup);
    await writePackage(oldBackup, { previous: true });
    const oldBackupContents = await hashTree(oldBackup);
    const barrier = join(layout.installParent, `cleanup-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_CLEANUP_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "success cleanup");
      const capturedOldBackup = join(layout.installParent, `${basename(layout.installRoot)}.captured-old-backup-${randomUUID()}`);
      await rename(oldBackup, capturedOldBackup);
      await mkdir(oldBackup);
      await writePackage(oldBackup, { marker: "untrusted-old-backup-replacement" });
      const oldBackupReplacement = await hashTree(oldBackup);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/identity.*ambiguous|preserv.*evidence/i);
      expect(await hashTree(capturedOldBackup)).toEqual(oldBackupContents);
      expect(await hashTree(oldBackup)).toEqual(oldBackupReplacement);
      expect(await hashTree(layout.installRoot)).toEqual(await hashTree(layout.packageRoot));
      expect((await swapArtifacts(layout)).filter((name) => name.includes(".failed-") || name.includes(".staging-"))).toEqual([]);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 180_000);

  windowsTest("restores the trusted backup and preserves staging changed before the second precheck", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `second-precheck-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_SECOND_PRECHECK_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "second-precheck");
      const artifacts = await swapArtifacts(layout);
      const [backupName] = artifacts.filter((name) => name.includes(".backup-"));
      const [stagingName] = artifacts.filter((name) => name.includes(".staging-"));
      if (!backupName || !stagingName) throw new Error("Second-precheck barrier did not expose trusted backup and staging");
      const stagingPath = join(layout.installParent, stagingName);
      const workflow = join(stagingPath, "skills", "distill-project-design", "references", "workflow.md");
      await writeFile(workflow, `${await readFile(workflow, "utf8")}\n<!-- changed-before-second-precheck -->\n`, "utf8");
      const changedCandidate = await hashTree(stagingPath);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/staging|candidate|manifest|hash|changed/i);
      expect(await hashTree(layout.installRoot)).toEqual(originalActive);
      expect(await hashTree(stagingPath)).toEqual(changedCandidate);
      const finalArtifacts = await swapArtifacts(layout);
      expect(finalArtifacts.filter((name) => name.includes(".staging-"))).toEqual([stagingName]);
      expect(finalArtifacts.filter((name) => name.includes(".backup-") || name.includes(".failed-"))).toEqual([]);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("detects staging changed after the second precheck and preserves it as failed evidence", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `second-rename-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_SECOND_RENAME_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "second-rename");
      const artifacts = await swapArtifacts(layout);
      const [stagingName] = artifacts.filter((name) => name.includes(".staging-"));
      if (!stagingName) throw new Error("Second-rename barrier did not expose staging");
      const stagingPath = join(layout.installParent, stagingName);
      const workflow = join(stagingPath, "skills", "distill-project-design", "references", "workflow.md");
      await writeFile(workflow, `${await readFile(workflow, "utf8")}\n<!-- changed-after-second-precheck -->\n`, "utf8");
      const changedCandidate = await hashTree(stagingPath);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/activated|staging|manifest|hash|changed/i);
      expect(await hashTree(layout.installRoot)).toEqual(originalActive);
      const finalArtifacts = await swapArtifacts(layout);
      const [failedName] = finalArtifacts.filter((name) => name.includes(".failed-"));
      if (!failedName) throw new Error("Changed activated candidate was not preserved as failed evidence");
      expect(await hashTree(join(layout.installParent, failedName))).toEqual(changedCandidate);
      expect(finalArtifacts.filter((name) => name.includes(".backup-") || name.includes(".staging-"))).toEqual([]);
    } finally {
      if (running.child.exitCode === null) {
        await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("rejects activation test hooks unless NODE_ENV is test", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `non-test-barrier-${randomUUID()}`);
    await mkdir(barrier);
    await writeFile(join(barrier, "release"), "continue\n", "utf8");

    const result = await runActivation(layout, {
      NODE_ENV: "production",
      KEEPER_ACTIVATION_TEST_BARRIER: barrier,
      KEEPER_ACTIVATION_TEST_FAULT: "first-rename"
    });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/NODE_ENV.*test|test mode/i);
    expect(await hashTree(layout.installRoot)).toEqual(originalActive);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("rejects test hooks when the install parent is not a direct child of system temp", async () => {
    const base = await makeLayout();
    await writePackage(base.packageRoot);
    const nestedParent = join(base.installParent, `nested-${randomUUID()}`);
    const nestedInstall = join(nestedParent, "1.0.2");
    await mkdir(nestedParent);
    await mkdir(nestedInstall);
    await writePackage(nestedInstall, { previous: true });
    const originalActive = await hashTree(nestedInstall);
    const nestedFixture = join(nestedParent, `processes-${randomUUID()}.json`);
    await writeFile(nestedFixture, "[]\n", "utf8");
    const nested: ActivationLayout = {
      ...base,
      installParent: nestedParent,
      installRoot: nestedInstall,
      processFixture: nestedFixture
    };

    const result = await runActivation(nested, { NODE_ENV: "test" });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/system temp|temporary.*direct child|test root/i);
    expect(await hashTree(nestedInstall)).toEqual(originalActive);
    expect(await swapArtifacts(nested)).toEqual([]);
  }, 90_000);

  windowsTest("does not overwrite a pre-existing activation barrier marker", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `occupied-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    await writeFile(entered, "sentinel-marker", "utf8");
    await writeFile(join(barrier, "release"), "continue\n", "utf8");

    const result = await runActivation(layout, {
      NODE_ENV: "test",
      KEEPER_ACTIVATION_TEST_BARRIER: barrier
    });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/control directory.*pre-existing|marker.*already exists|must not already exist|no-clobber/i);
    expect(await readFile(entered, "utf8")).toBe("sentinel-marker");
    expect(await hashTree(layout.installRoot)).toEqual(originalActive);
  }, 90_000);

  windowsTest("rejects a pre-existing activation control directory before creating markers", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `preexisting-control-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_BARRIER: barrier }, true);
    const enteredBeforeExit = await Promise.race([
      waitForPath(entered).then(() => true),
      running.result.then(() => false)
    ]);
    if (enteredBeforeExit) await writeFile(release, "continue\n", "utf8");

    const result = await running.result;

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/barrier.*(?:control|directory|already exists|pre-existing)/i);
    expect(await pathExists(entered)).toBe(false);
    expect(await hashTree(layout.installRoot)).toEqual(originalActive);
  }, 90_000);

  windowsTest("holds a no-delete lease on an activation control directory until the barrier is released", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const barrier = join(layout.installParent, `leased-control-${randomUUID()}`);
    const captured = join(layout.installParent, `captured-control-${randomUUID()}`);
    const external = join(layout.installParent, `external-control-${randomUUID()}`);
    await Promise.all([mkdir(barrier), mkdir(external)]);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "leased control");
      let replacementBlocked = false;
      try {
        await rename(barrier, captured);
        await symlink(external, barrier, "junction");
      } catch (error) {
        replacementBlocked = (error as NodeJS.ErrnoException).code === "EPERM" ||
          (error as NodeJS.ErrnoException).code === "EBUSY";
        if (!replacementBlocked) throw error;
      }
      expect(replacementBlocked).toBe(true);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;
      expect(result.exitCode).toBe(0);
      expect(await readdir(external)).toEqual([]);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      await writeFile(join(captured, "release"), "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("rejects a hard-linked activation barrier release marker", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const originalActive = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `linked-release-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const externalSignal = join(layout.installParent, `external-release-${randomUUID()}`);
    await writeFile(externalSignal, "continue\n", "utf8");
    const running = startActivation(layout, {
      NODE_ENV: "test",
      KEEPER_ACTIVATION_TEST_BARRIER: barrier
    });
    try {
      await requireBarrierBeforeExit(entered, running, "linked-release");
      await link(externalSignal, release);

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/release.*(?:hard.?link|single-link|regular file)|link count/i);
      expect(await readFile(externalSignal, "utf8")).toBe("continue\n");
      expect(await hashTree(layout.installRoot)).toEqual(originalActive);
    } finally {
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 90_000);

  windowsTest("rejects extra package content before staging", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    await writeFile(join(layout.packageRoot, "skills", "unexpected.txt"), "not allowlisted\n", "utf8");

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/allowlist|unexpected|manifest/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("rejects an oversized package JSON manifest before staging", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const packageManifest = JSON.parse(await readFile(join(layout.packageRoot, "package.json"), "utf8")) as Record<string, unknown>;
    packageManifest.padding = "x".repeat(256 * 1024);
    await writeFile(join(layout.packageRoot, "package.json"), `${JSON.stringify(packageManifest)}\n`, "utf8");

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/activation package JSON.*(?:bytes|size).*limit/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("rejects a package reparse point without following it", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const external = join(layout.packageParent, `external-${randomUUID()}`);
    await mkdir(external);
    for (const name of ["document-contract.md", "knowledge-model.md", "mcp-tools.md", "workflow.md"]) {
      await cp(join(layout.packageRoot, "skills", "distill-project-design", "references", name), join(external, name));
    }
    await rm(join(layout.packageRoot, "skills", "distill-project-design", "references"), { recursive: true });
    await symlink(external, join(layout.packageRoot, "skills", "distill-project-design", "references"), "junction");

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/reparse|link/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("never writes through a staging subdirectory replaced by a junction", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `staging-copy-barrier-${randomUUID()}`);
    const external = join(layout.installParent, `staging-copy-external-${randomUUID()}`);
    await Promise.all([mkdir(barrier), mkdir(external)]);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, {
      KEEPER_ACTIVATION_TEST_STAGING_COPY_BARRIER: barrier
    });
    try {
      await requireBarrierBeforeExit(entered, running, "staging package copy");
      const [stagingName] = (await swapArtifacts(layout)).filter((name) => name.includes(".staging-"));
      if (!stagingName) throw new Error("Staging-copy barrier did not expose staging");
      const stagingReferences = join(
        layout.installParent,
        stagingName,
        "skills",
        "distill-project-design",
        "references"
      );
      let replacementBlocked = false;
      try {
        await rm(stagingReferences, { recursive: true });
        await symlink(external, stagingReferences, "junction");
      } catch (error) {
        replacementBlocked = (error as NodeJS.ErrnoException).code === "EPERM" ||
          (error as NodeJS.ErrnoException).code === "EBUSY";
        if (!replacementBlocked) throw error;
      }
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      if (replacementBlocked) {
        expect(result.exitCode).toBe(0);
      } else {
        expect(result.exitCode).not.toBe(0);
        expect(result.output).toMatch(/staging.*(?:directory|identity|reparse|junction)|identity.*staging/i);
      }
      expect(await readdir(external)).toEqual([]);
      if (!replacementBlocked) expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("rejects a hard-linked package file", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const target = join(layout.packageRoot, ".mcp.json");
    const external = join(layout.packageParent, `hardlink-source-${randomUUID()}.json`);
    await cp(target, external);
    await unlink(target);
    await link(external, target);

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/hard.?link|link count/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("refuses an activation package file held open for concurrent writes", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const writer = await startWritableFileLease(join(layout.packageRoot, ".mcp.json"), layout.packageParent);
    try {
      const result = await runActivation(layout);

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/(?:open|read|identity|bounded).*(?:package|file)|sharing violation/i);
      expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
      expect(await swapArtifacts(layout)).toEqual([]);
    } finally {
      await writeFile(writer.release, "release\n", "utf8").catch(() => undefined);
      await writer.result;
    }
  }, 90_000);

  windowsTest("rejects Win32 device namespace roots before staging", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const device = (path: string): string => `\\\\?\\${path}`;
    const namespaced: ActivationLayout = {
      packageParent: device(layout.packageParent),
      packageRoot: device(layout.packageRoot),
      installParent: device(layout.installParent),
      installRoot: device(layout.installRoot),
      projectParent: device(layout.projectParent),
      projectRoot: device(layout.projectRoot),
      processFixture: device(layout.processFixture)
    };

    const result = await runActivation(namespaced);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/device namespace|unsupported.*namespace/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("rolls back a fault before the first rename without changing active", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);

    const result = await runActivation(layout, { KEEPER_ACTIVATION_TEST_FAULT: "first-rename" });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/first rename|injected/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 90_000);

  windowsTest("restores active after a fault before the second rename", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);

    const result = await runActivation(layout, { KEEPER_ACTIVATION_TEST_FAULT: "second-rename" });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/second rename|injected/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await swapArtifacts(layout)).toEqual([]);

    const retry = await runActivation(layout);

    expect(retry.exitCode).toBe(0);
    expect(await hashTree(layout.installRoot)).toEqual(await hashTree(layout.packageRoot));
    expect((await swapArtifacts(layout)).filter((name) => name.includes(".backup-"))).toHaveLength(1);
  }, 90_000);

  windowsTest("reconciles a real second Move-Item failure and restores the verified backup", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const candidate = await hashTree(layout.packageRoot);
    const previousInstall = await hashTree(layout.installRoot);
    const secondRenameBarrier = join(layout.installParent, `second-rename-os-failure-${randomUUID()}`);
    const failureBarrier = join(layout.installParent, `second-rename-reconcile-${randomUUID()}`);
    await Promise.all([mkdir(secondRenameBarrier), mkdir(failureBarrier)]);
    const secondEntered = join(secondRenameBarrier, "entered");
    const secondRelease = join(secondRenameBarrier, "release");
    const failureEntered = join(failureBarrier, "entered");
    const failureRelease = join(failureBarrier, "release");
    const running = startActivation(layout, {
      KEEPER_ACTIVATION_TEST_SECOND_RENAME_BARRIER: secondRenameBarrier,
      KEEPER_ACTIVATION_TEST_SECOND_MOVE_FAILURE_BARRIER: failureBarrier
    });
    let blocker: Awaited<ReturnType<typeof startRenameBlockingLease>> | undefined;
    try {
      await requireBarrierBeforeExit(secondEntered, running, "second-rename");
      const [stagingName] = (await swapArtifacts(layout)).filter((name) => name.includes(".staging-"));
      if (!stagingName) throw new Error("Second-rename barrier did not expose staging");
      blocker = await startRenameBlockingLease(
        join(layout.installParent, stagingName),
        secondRenameBarrier
      );
      await writeFile(secondRelease, "attempt real rename\n", "utf8");
      await requireBarrierBeforeExit(failureEntered, running, "second Move-Item failure reconciliation");
      expect(await pathExists(layout.installRoot)).toBe(false);
      expect(await hashTree(join(layout.installParent, stagingName))).toEqual(candidate);
      const [backupName] = (await swapArtifacts(layout)).filter((name) => name.includes(".backup-"));
      if (!backupName) throw new Error("Failed second rename did not preserve the previous active backup");
      expect(await hashTree(join(layout.installParent, backupName))).toEqual(previousInstall);
      await writeFile(blocker.release, "release file lease\n", "utf8");
      const blockerResult = await blocker.result;
      expect(blockerResult.exitCode).toBe(0);
      await writeFile(failureRelease, "reconcile\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/second rename|Move-Item|rename.*failed|rollback/i);
      expect(await hashTree(layout.installRoot)).toEqual(previousInstall);
      expect(await swapArtifacts(layout)).toEqual([]);
    } finally {
      await writeFile(secondRelease, "cleanup\n", "utf8").catch(() => undefined);
      await writeFile(failureRelease, "cleanup\n", "utf8").catch(() => undefined);
      if (blocker) {
        await writeFile(blocker.release, "cleanup\n", "utf8").catch(() => undefined);
        if (blocker.child.exitCode === null) {
          const exited = once(blocker.child, "exit");
          blocker.child.kill();
          await exited;
        }
        await blocker.result.catch(() => undefined);
      }
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("performs the final live-process scan after hashing and immediately before the first rename", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const previousInstall = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `final-liveness-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_FINAL_LIVENESS_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "final liveness");
      const staged = await swapArtifacts(layout);
      expect(staged.filter((name) => name.includes(".staging-"))).toHaveLength(1);
      expect(staged.filter((name) => name.includes(".backup-") || name.includes(".failed-"))).toEqual([]);
      expect(await hashTree(layout.installRoot)).toEqual(previousInstall);
      await writeFile(layout.processFixture, `${JSON.stringify([
        { Name: "Codex.exe", ProcessId: 7600, ParentProcessId: 1, CommandLine: "Codex.exe" },
        {
          Name: "node.exe",
          ProcessId: 7601,
          ParentProcessId: 7600,
          CommandLine: `node "${join(layout.installRoot, "dist", "index.js")}"`
        }
      ])}\n`, "utf8");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/PID\s*7601/i);
      expect(result.output).toMatch(/close.*task|restart Codex/i);
      expect(await hashTree(layout.installRoot)).toEqual(previousInstall);
      expect(await swapArtifacts(layout)).toEqual([]);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("refuses a smoke project changed during staging before the first install rename", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const previousInstall = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `final-smoke-project-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_FINAL_LIVENESS_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "final smoke project");
      await writeFile(join(layout.projectRoot, "user-owned.txt"), "do not modify\n", "utf8");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/smoke project.*empty.*disposable|nonempty project/iu);
      expect(await hashTree(layout.installRoot)).toEqual(previousInstall);
      expect(await swapArtifacts(layout)).toEqual([]);
      await expect(readFile(join(layout.projectRoot, "user-owned.txt"), "utf8")).resolves.toBe("do not modify\n");
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("preserves the active candidate and backup when a live MCP appears before rollback", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot, { runtime: "broken" });
    await writePackage(layout.installRoot, { previous: true });
    const candidate = await hashTree(layout.packageRoot);
    const previousInstall = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `rollback-live-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_ROLLBACK_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "rollback live-process");
      const [backupName] = (await swapArtifacts(layout)).filter((name) => name.includes(".backup-"));
      if (!backupName) throw new Error("Rollback barrier did not expose the previous active backup");
      await writeFile(layout.processFixture, `${JSON.stringify([
        { Name: "Codex.exe", ProcessId: 7610, ParentProcessId: 1, CommandLine: "Codex.exe" },
        {
          Name: "node.exe",
          ProcessId: 7611,
          ParentProcessId: 7610,
          CommandLine: `node "${join(layout.installRoot, "dist", "index.js")}"`
        }
      ])}\n`, "utf8");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/PID\s*7611/i);
      expect(result.output).toMatch(/close.*task|restart Codex|preserv.*active/i);
      expect(await hashTree(layout.installRoot)).toEqual(candidate);
      expect(await hashTree(join(layout.installParent, backupName))).toEqual(previousInstall);
      expect((await swapArtifacts(layout)).filter((name) => name.includes(".failed-") || name.includes(".staging-"))).toEqual([]);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("preserves an old backup whose authenticated manifest changes before cleanup", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const oldBackup = join(layout.installParent, `${basename(layout.installRoot)}.backup-20000101T000000000Z-content`);
    await mkdir(oldBackup);
    await writePackage(oldBackup, { previous: true });
    const barrier = join(layout.installParent, `cleanup-manifest-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_CLEANUP_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "old-backup manifest cleanup");
      const workflow = join(oldBackup, "skills", "distill-project-design", "references", "workflow.md");
      await writeFile(workflow, `${await readFile(workflow, "utf8")}\n<!-- changed-before-cleanup -->\n`, "utf8");
      const changedBackup = await hashTree(oldBackup);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/backup.*manifest|content.*changed|preserv.*evidence/i);
      expect(await hashTree(oldBackup)).toEqual(changedBackup);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 180_000);

  windowsTest("hashes an old backup after its final tree scan and preserves a later in-place change", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const oldBackup = join(layout.installParent, `${basename(layout.installRoot)}.backup-x`);
    await mkdir(oldBackup);
    await writePackage(oldBackup, { previous: true });
    const barrier = join(layout.installParent, `pd-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, {
      KEEPER_ACTIVATION_TEST_OLD_BACKUP_PREDELETE_BARRIER: barrier
    });
    try {
      await requireBarrierBeforeExit(entered, running, "old-backup pre-delete manifest");
      const workflow = join(oldBackup, "skills", "distill-project-design", "references", "workflow.md");
      await writeFile(workflow, `${await readFile(workflow, "utf8")}\n<!-- changed-after-tree-scan -->\n`, "utf8");
      const changedBackup = await hashTree(oldBackup);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/backup.*manifest|content.*changed|preserv.*evidence/i);
      expect(await hashTree(oldBackup)).toEqual(changedBackup);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 180_000);

  windowsTest("preserves a late post-authentication entry in a quarantined old backup", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const oldBackup = join(layout.installParent, `${basename(layout.installRoot)}.backup-postauth`);
    await mkdir(oldBackup);
    await writePackage(oldBackup, { previous: true });
    const oldBackupContents = await hashTree(oldBackup);
    const barrier = join(layout.installParent, `postauth-cleanup-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, {
      KEEPER_ACTIVATION_TEST_OLD_BACKUP_POSTAUTH_BARRIER: barrier
    });
    try {
      await requireBarrierBeforeExit(entered, running, "old-backup post-authentication cleanup");
      const [quarantineName] = (await readdir(layout.installParent))
        .filter((name) => name.startsWith(".project-design-keeper.cleanup-"));
      if (!quarantineName) throw new Error("Post-authentication cleanup barrier did not expose a quarantine");
      const quarantine = join(layout.installParent, quarantineName);
      const lateEntry = join(quarantine, "late-user.txt");
      await writeFile(lateEntry, "late user evidence\n", "utf8");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/cleanup.*(?:changed|ambiguous)|preserv.*quarantine|identity/i);
      await expect(readFile(lateEntry, "utf8")).resolves.toBe("late user evidence\n");
      const preserved = await hashTree(quarantine);
      for (const [path, digest] of Object.entries(oldBackupContents)) expect(preserved[path]).toBe(digest);
      expect(await hashTree(layout.installRoot)).toEqual(await hashTree(layout.packageRoot));
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      await running.result.catch(() => undefined);
    }
  }, 180_000);

  windowsTest("starts no cleanup after a late entry appears at the final handle-delete boundary", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const oldBackup = join(layout.installParent, `${basename(layout.installRoot)}.backup-handle-boundary`);
    await mkdir(oldBackup);
    await writePackage(oldBackup, { previous: true });
    const oldBackupContents = await hashTree(oldBackup);
    const barrier = join(layout.installParent, `handle-delete-cleanup-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, {
      KEEPER_ACTIVATION_TEST_OLD_BACKUP_HANDLE_DELETE_BARRIER: barrier
    });
    try {
      await requireBarrierBeforeExit(entered, running, "old-backup final handle-delete");
      const [quarantineName] = (await readdir(layout.installParent))
        .filter((name) => name.startsWith(".project-design-keeper.cleanup-"));
      if (!quarantineName) throw new Error("Handle-delete barrier did not expose a quarantine");
      const quarantine = join(layout.installParent, quarantineName);
      const lateEntry = join(quarantine, "late-at-handle-boundary.txt");
      await writeFile(lateEntry, "late handle-boundary evidence\n", "utf8");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/cleanup.*(?:unexpected|changed|ambiguous)|preserv.*evidence/i);
      await expect(readFile(lateEntry, "utf8")).resolves.toBe("late handle-boundary evidence\n");
      const preserved = await hashTree(quarantine);
      for (const [path, digest] of Object.entries(oldBackupContents)) expect(preserved[path]).toBe(digest);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 180_000);

  windowsTest("preserves staging whose authenticated manifest changes before rollback cleanup", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const previousInstall = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `rollback-manifest-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, {
      KEEPER_ACTIVATION_TEST_FAULT: "first-rename",
      KEEPER_ACTIVATION_TEST_ROLLBACK_BARRIER: barrier
    });
    try {
      await requireBarrierBeforeExit(entered, running, "staging manifest rollback cleanup");
      const [stagingName] = (await swapArtifacts(layout)).filter((name) => name.includes(".staging-"));
      if (!stagingName) throw new Error("Rollback barrier did not expose staging");
      const stagingPath = join(layout.installParent, stagingName);
      const workflow = join(stagingPath, "skills", "distill-project-design", "references", "workflow.md");
      await writeFile(workflow, `${await readFile(workflow, "utf8")}\n<!-- changed-before-rollback-cleanup -->\n`, "utf8");
      const changedStaging = await hashTree(stagingPath);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/staging.*manifest|content.*changed|preserv.*evidence/i);
      expect(await hashTree(layout.installRoot)).toEqual(previousInstall);
      expect(await hashTree(stagingPath)).toEqual(changedStaging);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("fails after smoke and preserves evidence when the active candidate manifest changes", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const previousInstall = await hashTree(layout.installRoot);
    const barrier = join(layout.installParent, `post-smoke-active-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_CLEANUP_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "post-smoke active validation");
      const workflow = join(layout.installRoot, "skills", "distill-project-design", "references", "workflow.md");
      await writeFile(workflow, `${await readFile(workflow, "utf8")}\n<!-- changed-after-smoke -->\n`, "utf8");
      const changedCandidate = await hashTree(layout.installRoot);
      const [backupName] = (await swapArtifacts(layout)).filter((name) => name.includes(".backup-"));
      if (!backupName) throw new Error("Post-smoke barrier did not expose the new backup");
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toMatch(/active|candidate|manifest|changed|preserv.*evidence/i);
      expect(await hashTree(layout.installRoot)).toEqual(changedCandidate);
      expect(await hashTree(join(layout.installParent, backupName))).toEqual(previousInstall);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 180_000);

  windowsTest("revalidates the retained backup immediately before reporting activation success", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const candidate = await hashTree(layout.packageRoot);
    const barrier = join(layout.installParent, `final-success-barrier-${randomUUID()}`);
    await mkdir(barrier);
    const entered = join(barrier, "entered");
    const release = join(barrier, "release");
    const running = startActivation(layout, { KEEPER_ACTIVATION_TEST_FINAL_SUCCESS_BARRIER: barrier });
    try {
      await requireBarrierBeforeExit(entered, running, "final success validation");
      const [backupName] = (await swapArtifacts(layout)).filter((name) => name.includes(".backup-"));
      if (!backupName) throw new Error("Final-success barrier did not expose the retained backup");
      const backupPath = join(layout.installParent, backupName);
      const workflow = join(backupPath, "skills", "distill-project-design", "references", "workflow.md");
      await writeFile(workflow, `${await readFile(workflow, "utf8")}\n<!-- changed-before-success -->\n`, "utf8");
      const changedBackup = await hashTree(backupPath);
      await writeFile(release, "continue\n", "utf8");

      const result = await running.result;

      expect(result.exitCode).not.toBe(0);
      expect(result.output).not.toMatch(/Activated project-design-keeper/i);
      expect(result.output).toMatch(/backup.*manifest|content.*changed|preserv.*evidence/i);
      expect(await hashTree(layout.installRoot)).toEqual(candidate);
      expect(await hashTree(backupPath)).toEqual(changedBackup);
    } finally {
      await writeFile(release, "cleanup\n", "utf8").catch(() => undefined);
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 180_000);

  windowsTest("rejects a package input whose direct-child name is reserved for activation backups", async () => {
    const layout = await makeLayout();
    await writePackage(layout.installRoot, { previous: true });
    const previousInstall = await hashTree(layout.installRoot);
    const reservedPackageRoot = join(
      layout.installParent,
      `${basename(layout.installRoot)}.backup-caller-package-${randomUUID()}`
    );
    await mkdir(reservedPackageRoot);
    await writePackage(reservedPackageRoot);
    const packageContents = await hashTree(reservedPackageRoot);
    const reservedLayout = { ...layout, packageRoot: reservedPackageRoot };

    const result = await runActivation(reservedLayout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/package root|reserved|backup.*name|explicit.*input/i);
    expect(await hashTree(layout.installRoot)).toEqual(previousInstall);
    expect(await hashTree(reservedPackageRoot)).toEqual(packageContents);
    expect(await swapArtifacts(layout)).toEqual([basename(reservedPackageRoot)]);
  }, 120_000);

  windowsTest("rejects an ordinary package input that shares the verified install parent", async () => {
    const layout = await makeLayout();
    await writePackage(layout.installRoot, { previous: true });
    const previousInstall = await hashTree(layout.installRoot);
    const sharedPackageRoot = join(layout.installParent, `ordinary-package-${randomUUID()}`);
    await mkdir(sharedPackageRoot);
    await writePackage(sharedPackageRoot);
    const packageContents = await hashTree(sharedPackageRoot);

    const result = await runActivation({ ...layout, packageRoot: sharedPackageRoot });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/package.*parent|disjoint.*parent|share.*install parent/i);
    expect(await hashTree(layout.installRoot)).toEqual(previousInstall);
    expect(await hashTree(sharedPackageRoot)).toEqual(packageContents);
    expect(await swapArtifacts(layout)).toEqual([]);
  }, 120_000);

  windowsTest("bounds installed smoke by the remaining activation deadline and confirms child exit", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    const descendantPidControl = join(layout.projectParent, `activation-smoke-descendant-${randomUUID()}.pid`);
    await addStubbornStdioDescendant(layout.packageRoot, descendantPidControl);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const closeControl = join(layout.projectParent, `activation-smoke-close-${randomUUID()}`);

    const running = startActivation(layout, {
      KEEPER_ACTIVATION_TEST_SMOKE_TIMEOUT_MS: "5000",
      KEEPER_SMOKE_TEST_DESCENDANT_PID: descendantPidControl,
      KEEPER_INSTALLED_SMOKE_TEST_ROOT: layout.projectParent,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_CONTROL: closeControl,
      KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_DELAY_MS: "12000"
    });
    let descendantPid: number | undefined;
    try {
      await Promise.race([
        waitForPath(descendantPidControl, 30_000),
        running.result.then((early) => { throw new Error(`Activation exited before starting the owned descendant:\n${early.output}`); })
      ]);
      descendantPid = Number.parseInt(await readFile(descendantPidControl, "utf8"), 10);
      expect(Number.isSafeInteger(descendantPid)).toBe(true);
      expect(fixturePidAlive(descendantPid)).toBe(true);

      const result = await running.result;
      expect(result.exitCode).not.toBe(0);
      expect(result.output.replace(/\s+/gu, "")).toMatch(/installedsmoke.*activationdeadline.*ownedchildtree.*ActiveProcesses=0.*exit.*confirmed/i);
      await waitForFixturePidExit(descendantPid);
      expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
      expect((await swapArtifacts(layout)).filter((name) => name.includes(".failed-"))).toHaveLength(1);
    } finally {
      if (descendantPid !== undefined && fixturePidAlive(descendantPid)) {
        process.kill(descendantPid);
        await waitForFixturePidExit(descendantPid).catch(() => undefined);
      }
      if (running.child.exitCode === null) {
        const exited = once(running.child, "exit");
        running.child.kill();
        await exited;
      }
      await running.result.catch(() => undefined);
    }
  }, 120_000);

  windowsTest("rolls back an installed smoke failure and preserves failed-package evidence", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot, { runtime: "broken" });
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/smoke|rollback|restore/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    const artifacts = await swapArtifacts(layout);
    expect(artifacts.filter((name) => name.includes(".backup-"))).toEqual([]);
    expect(artifacts.filter((name) => name.includes(".staging-"))).toEqual([]);
    expect(artifacts.filter((name) => name.includes(".failed-"))).toHaveLength(1);
  }, 90_000);

  windowsTest("preserves a legacy non-package backup without blocking a verified activation", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const previousInstall = await hashTree(layout.installRoot);
    const legacyBackup = join(
      layout.installParent,
      `${basename(layout.installRoot)}.backup-20000101T000000000Z-legacy`
    );
    await mkdir(legacyBackup);
    for (let index = 0; index < 7; index += 1) {
      await writeFile(join(legacyBackup, `development-artifact-${index}.txt`), `legacy-${index}\n`, "utf8");
    }
    const legacyContents = await hashTree(legacyBackup);

    const result = await runActivation(layout);

    expect(result.exitCode).toBe(0);
    expect(result.output).toMatch(/legacy.*backup.*preserv|preserv.*legacy.*backup/i);
    expect(result.output.replace(/\s+/gu, " ")).toMatch(/bounded entry limit/i);
    expect(result.output).not.toMatch(/One or more errors occurred/i);
    expect(await hashTree(legacyBackup)).toEqual(legacyContents);
    expect(await hashTree(layout.installRoot)).toEqual(await hashTree(layout.packageRoot));
    const artifacts = await swapArtifacts(layout);
    expect(artifacts.filter((name) => name.includes(".backup-"))).toHaveLength(2);
    const retainedCurrentBackup = artifacts.find((name) => join(layout.installParent, name) !== legacyBackup);
    expect(retainedCurrentBackup).toBeDefined();
    expect(await hashTree(join(layout.installParent, retainedCurrentBackup!))).toEqual(previousInstall);
    expect(artifacts.filter((name) => name.includes(".staging-") || name.includes(".failed-"))).toEqual([]);
  }, 120_000);

  windowsTest("preserves a stable exact-tree backup with legacy package metadata", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const previousInstall = await hashTree(layout.installRoot);
    const legacyBackup = join(
      layout.installParent,
      `${basename(layout.installRoot)}.backup-20000101T000000000Z-metadata`
    );
    await mkdir(legacyBackup);
    await writePackage(legacyBackup, { previous: true });
    await writeFile(join(legacyBackup, ".codex-plugin", "plugin.json"), "{}\n", "utf8");
    await writeFile(join(legacyBackup, ".mcp.json"), "{}\n", "utf8");
    const legacyContents = await hashTree(legacyBackup);

    const result = await runActivation(layout);

    expect(result.exitCode).toBe(0);
    expect(result.output).toMatch(/legacy.*backup.*preserv|preserv.*legacy.*backup/i);
    expect(result.output).toMatch(/package\s+identity|missing\s+required[\s\S]*(?:name|mcpServers)/i);
    expect(await hashTree(legacyBackup)).toEqual(legacyContents);
    expect(await hashTree(layout.installRoot)).toEqual(await hashTree(layout.packageRoot));
    const artifacts = await swapArtifacts(layout);
    expect(artifacts.filter((name) => name.includes(".backup-"))).toHaveLength(2);
    const retainedCurrentBackup = artifacts.find((name) => join(layout.installParent, name) !== legacyBackup);
    expect(retainedCurrentBackup).toBeDefined();
    expect(await hashTree(join(layout.installParent, retainedCurrentBackup!))).toEqual(previousInstall);
    expect(artifacts.filter((name) => name.includes(".staging-") || name.includes(".failed-"))).toEqual([]);
  }, 120_000);

  windowsTest("does not downgrade an unverified backup identity to legacy content", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const beforeInstall = await hashTree(layout.installRoot);
    const legacyTarget = join(layout.installParent, `legacy-target-${randomUUID()}`);
    await mkdir(legacyTarget);
    await writeFile(join(legacyTarget, "evidence.txt"), "external legacy evidence\n", "utf8");
    const legacyContents = await hashTree(legacyTarget);
    const linkedBackup = join(
      layout.installParent,
      `${basename(layout.installRoot)}.backup-20000101T000000000Z-unverified`
    );
    await symlink(legacyTarget, linkedBackup, "junction");

    const result = await runActivation(layout);

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toMatch(/existing backup.*identity|reparse|symbolic link/i);
    expect(result.output).not.toMatch(/preserving legacy or unrecognized activation backup/i);
    expect(await hashTree(layout.installRoot)).toEqual(beforeInstall);
    expect(await hashTree(legacyTarget)).toEqual(legacyContents);
    expect(await swapArtifacts(layout)).toEqual([basename(linkedBackup)]);
  }, 90_000);

  windowsTest("swaps by rename, passes installed smoke, and retains only the new timestamped backup", async () => {
    const layout = await makeLayout();
    await writePackage(layout.packageRoot);
    await writePackage(layout.installRoot, { previous: true });
    const previousInstall = await hashTree(layout.installRoot);
    const oldBackup = join(layout.installParent, `${basename(layout.installRoot)}.backup-20000101T000000000Z-old`);
    await mkdir(oldBackup);
    await writePackage(oldBackup, { previous: true });

    const result = await runActivation(layout);

    expect(result.exitCode).toBe(0);
    expect(result.output).toMatch(/activated|smoke.*pass/i);
    expect(await hashTree(layout.installRoot)).toEqual(await hashTree(layout.packageRoot));
    const artifacts = await swapArtifacts(layout);
    expect(artifacts.filter((name) => name.includes(".backup-"))).toHaveLength(1);
    expect(artifacts.filter((name) => name.includes(".staging-") || name.includes(".failed-"))).toEqual([]);
    expect(await hashTree(join(layout.installParent, artifacts[0]!))).toEqual(previousInstall);
  }, 120_000);
});
