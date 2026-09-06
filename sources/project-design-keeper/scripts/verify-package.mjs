import { createHash } from "node:crypto";
import { lstat, open, opendir, realpath } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const packageParent = resolve(root, ".package");
const target = resolve(packageParent, "project-design-keeper");
const exactFiles = [
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
].sort();
const textSuffixes = [".js", ".json", ".md", ".md.template", ".yaml", ".yml"];
const maximumFileBytes = 16 * 1024 * 1024;
const maximumJsonBytes = 256 * 1024;
const maximumTotalBytes = 64 * 1024 * 1024;

function samePath(left, right) {
  const normalize = (value) => process.platform === "win32"
    ? resolve(value).toLocaleLowerCase("en-US")
    : resolve(value);
  return normalize(left) === normalize(right);
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.nlink === right.nlink && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

async function assertCanonicalDirectory(path, label) {
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink()) throw new Error(`${label} is a reparse point or symbolic link`);
  if (!metadata.isDirectory()) throw new Error(`${label} must be a directory`);
  if (!samePath(path, await realpath(path))) throw new Error(`${label} resolves through a reparse point or symbolic link`);
}

if (dirname(packageParent) !== root || dirname(target) !== packageParent) {
  throw new Error("Package verification roots are not strict direct children");
}
await assertCanonicalDirectory(root, "Plugin root");
await assertCanonicalDirectory(packageParent, "Package parent");
await assertCanonicalDirectory(target, "Package target");

function expectedDirectories() {
  const directories = new Set();
  for (const file of exactFiles) {
    let directory = dirname(file).replaceAll("\\", "/");
    while (directory !== ".") {
      directories.add(directory);
      directory = dirname(directory).replaceAll("\\", "/");
    }
  }
  return [...directories].sort();
}

function expectedChildren() {
  const directories = expectedDirectories();
  const children = new Map([[".", new Map()]]);
  for (const directory of directories) children.set(directory, new Map());
  for (const directory of directories) {
    const parent = dirname(directory).replaceAll("\\", "/");
    children.get(parent).set(directory.split("/").at(-1), "directory");
  }
  for (const file of exactFiles) {
    const parent = dirname(file).replaceAll("\\", "/");
    children.get(parent).set(file.split("/").at(-1), "file");
  }
  return children;
}

async function enumerateExactPackage(directory) {
  const topology = expectedChildren();
  for (const [relativeDirectory, expected] of topology) {
    const current = relativeDirectory === "."
      ? directory
      : resolve(directory, ...relativeDirectory.split("/"));
    await assertCanonicalDirectory(current, `Package directory ${relativeDirectory}`);
    const observed = new Set();
    const handle = await opendir(current);
    for await (const entry of handle) {
      if (observed.size >= expected.size) {
        throw new Error(`Package directory ${relativeDirectory} has an unexpected extra entry: ${entry.name}`);
      }
      const kind = expected.get(entry.name);
      if (!kind) throw new Error(`Package directory ${relativeDirectory} has an unexpected or case-mismatched entry: ${entry.name}`);
      if (observed.has(entry.name)) throw new Error(`Package directory ${relativeDirectory} repeats an entry: ${entry.name}`);
      const path = resolve(current, entry.name);
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) throw new Error(`Package contains a reparse point or symbolic link: ${relative(directory, path)}`);
      if (kind === "directory" ? !metadata.isDirectory() : !metadata.isFile()) {
        throw new Error(`Package entry has the wrong kind: ${relative(directory, path)}`);
      }
      if (kind === "file" && metadata.nlink !== 1) {
        throw new Error(`Package contains a hard-linked file with link count ${metadata.nlink}: ${relative(directory, path)}`);
      }
      observed.add(entry.name);
    }
    if (observed.size !== expected.size) {
      const missing = [...expected.keys()].filter((name) => !observed.has(name));
      throw new Error(`Package directory ${relativeDirectory} is missing exact allowlist entries: ${JSON.stringify(missing)}`);
    }
  }
  return exactFiles;
}

function normalizedSourceBytes(path, contents) {
  if (!textSuffixes.some((suffix) => path.toLowerCase().endsWith(suffix))) return contents;
  const normalized = contents.toString("utf8").replace(/\r\n?/gu, "\n");
  if (path !== "package.json") return Buffer.from(normalized, "utf8");
  const { scripts: _scripts, devDependencies: _devDependencies, ...runtimeManifest } = JSON.parse(normalized);
  return Buffer.from(`${JSON.stringify(runtimeManifest, null, 2)}\n`, "utf8");
}

function byteBudget(label) {
  let used = 0;
  return {
    consume(bytes) {
      if (used + bytes > maximumTotalBytes) throw new Error(`${label} bytes exceed the aggregate limit of ${maximumTotalBytes}`);
      used += bytes;
    }
  };
}

async function safeRegularFile(path, label, maximumBytes, budget) {
  const beforePath = await lstat(path, { bigint: true });
  if (beforePath.isSymbolicLink()) throw new Error(`${label} is a reparse point or symbolic link: ${path}`);
  if (!beforePath.isFile()) throw new Error(`${label} is not a regular file: ${path}`);
  if (beforePath.nlink !== 1n) throw new Error(`${label} is hard linked with link count ${beforePath.nlink}: ${path}`);
  if (beforePath.size < 0n || beforePath.size > BigInt(maximumBytes)) {
    throw new Error(`${label} bytes exceed the per-file limit of ${maximumBytes}: ${path}`);
  }
  const expected = Number(beforePath.size);
  budget.consume(expected);
  const handle = await open(path, "r");
  let contents;
  try {
    const beforeHandle = await handle.stat({ bigint: true });
    if (!beforeHandle.isFile() || beforeHandle.isSymbolicLink() || !sameFileIdentity(beforePath, beforeHandle)) {
      throw new Error(`${label} changed identity before its bounded read: ${path}`);
    }
    contents = Buffer.alloc(expected);
    let offset = 0;
    while (offset < expected) {
      const read = await handle.read(contents, offset, Math.min(64 * 1024, expected - offset), offset);
      if (read.bytesRead <= 0) throw new Error(`${label} ended during its bounded read: ${path}`);
      offset += read.bytesRead;
    }
    const overflow = Buffer.alloc(1);
    if ((await handle.read(overflow, 0, 1, expected)).bytesRead !== 0) throw new Error(`${label} grew during its bounded read: ${path}`);
    const afterHandle = await handle.stat({ bigint: true });
    if (!sameFileIdentity(beforeHandle, afterHandle)) throw new Error(`${label} changed identity during its bounded read: ${path}`);
  } finally {
    await handle.close();
  }
  const afterPath = await lstat(path, { bigint: true });
  if (afterPath.isSymbolicLink() || !afterPath.isFile() || !sameFileIdentity(beforePath, afterPath)) {
    throw new Error(`${label} changed pathname identity after its bounded read: ${path}`);
  }
  return contents;
}

const packaged = await enumerateExactPackage(target);
const manifest = [];
const installedBytes = new Map();
const sourceBudget = byteBudget("Package source verification");
const packageBudget = byteBudget("Packaged artifact verification");
for (const path of packaged) {
  const sourcePath = resolve(root, ...path.split("/"));
  const packagedPath = resolve(target, ...path.split("/"));
  const json = path.toLowerCase().endsWith(".json");
  const maximumBytes = json ? maximumJsonBytes : maximumFileBytes;
  const source = normalizedSourceBytes(
    path,
    await safeRegularFile(sourcePath, json ? `Package JSON source ${path}` : `Allowlisted source file ${path}`, maximumBytes, sourceBudget)
  );
  const installed = await safeRegularFile(
    packagedPath,
    json ? `Package JSON file ${path}` : `Packaged file ${path}`,
    maximumBytes,
    packageBudget
  );
  installedBytes.set(path, installed);
  const expectedHash = createHash("sha256").update(source).digest("hex");
  const actualHash = createHash("sha256").update(installed).digest("hex");
  if (actualHash !== expectedHash) throw new Error(`Package SHA-256 hash mismatch for ${path}`);
  manifest.push([path, actualHash]);
}

const parseInstalledJson = (path) => JSON.parse(installedBytes.get(path).toString("utf8"));
const pluginManifest = parseInstalledJson(".codex-plugin/plugin.json");
const packageManifest = parseInstalledJson("package.json");
const mcpManifest = parseInstalledJson(".mcp.json");
if (pluginManifest.name !== "project-design-keeper" || packageManifest.name !== "project-design-keeper") {
  throw new Error("Package metadata identity must equal project-design-keeper");
}
if (Object.hasOwn(packageManifest, "scripts") || Object.hasOwn(packageManifest, "devDependencies")) {
  throw new Error("Runtime package metadata must not expose unavailable development scripts or dependencies");
}
if (pluginManifest.version !== "1.0.2" || packageManifest.version !== "1.0.2") {
  throw new Error("Package metadata versions must both equal 1.0.2");
}
if (pluginManifest.skills !== "./skills/" || pluginManifest.mcpServers !== "./.mcp.json") {
  throw new Error("Plugin manifest package roots are invalid");
}
const mcp = mcpManifest.mcpServers?.["project-design-keeper"];
if (JSON.stringify(mcp) !== JSON.stringify({ command: "node", args: ["dist/index.js"], cwd: "." })) {
  throw new Error("Package MCP command must be the exact relocatable dist/index.js command");
}

const digest = createHash("sha256")
  .update(manifest.map(([path, hash]) => `${path}\0${hash}\n`).join(""), "utf8")
  .digest("hex");
process.stdout.write(`Verified ${packaged.length} exact package files (sha256:${digest})\n`);
