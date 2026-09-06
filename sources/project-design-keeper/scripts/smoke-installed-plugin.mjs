import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, mkdtemp, open, opendir, realpath, rename, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

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
].sort();

const exactTools = [
  "analyze_redundancy",
  "apply_update",
  "detect_drift",
  "preview_update",
  "query_context",
  "query_history",
  "scan_scope",
  "search_evidence",
  "validate_pack"
].sort();

const canonicalTemplates = [
  ["index.md.template", "docs/project-design/index.md"],
  ["intent.md.template", "docs/project-design/intent.md"],
  ["principles.md.template", "docs/project-design/principles.md"],
  ["architecture.md.template", "docs/project-design/architecture.md"],
  ["module.md.template", "docs/project-design/modules/example.md"],
  ["conventions.md.template", "docs/project-design/conventions.md"],
  ["decisions.md.template", "docs/project-design/decisions.md"],
  ["tuning.md.template", "docs/project-design/tuning.md"],
  ["verification.md.template", "docs/project-design/verification.md"],
  ["open-questions.md.template", "docs/project-design/open-questions.md"],
  ["evidence-map.md.template", "docs/project-design/evidence-map.md"]
];

const CACHE_CLEANUP_MAX_ENTRIES = 2_048;
const CACHE_CLEANUP_MAX_DEPTH = 12;
const CACHE_CLEANUP_MAX_BYTES = 64 * 1024 * 1024;
const PACKAGE_MAX_FILE_BYTES = 16 * 1024 * 1024;
const PACKAGE_MAX_JSON_BYTES = 256 * 1024;
const PACKAGE_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const MCP_CLOSE_CONFIRM_TIMEOUT_MS = 5_000;
const MCP_STDERR_MAX_BYTES = 1024 * 1024;

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

function managedBlock(recordId, content) {
  return `<!-- project-design-keeper:managed record-id="${recordId}" content-hash="${sha256(content)}" -->${content}<!-- /project-design-keeper:managed -->`;
}

function derivedBlock(documentId, content) {
  return `<!-- project-design-keeper:derived document-id="${documentId}" content-hash="${sha256(content)}" -->${content}<!-- /project-design-keeper:derived -->`;
}

function renderCanonicalTemplate(templateName, template, replacements = {}) {
  let rendered = template.replaceAll("{{MODULE_SLUG}}", "example");
  for (const [name, value] of Object.entries(replacements)) rendered = rendered.replaceAll(`{{${name}}}`, value);
  rendered = rendered.replace(/\{\{[A-Z][A-Z0-9_]*\}\}/gu, "Installed smoke evidence-backed content.");
  let documentId;
  rendered = rendered.replace(/\{\{DERIVED_BLOCK:([A-Za-z0-9][A-Za-z0-9._:-]*) BEGIN\}\}\r?\n([\s\S]*?)\r?\n\{\{DERIVED_BLOCK:\1 END\}\}/gu,
    (_match, id, body) => {
      documentId = id;
      return derivedBlock(id, `${body}\n`);
    });
  rendered = rendered.replace(/\{\{MANAGED_BLOCK:([A-Za-z0-9][A-Za-z0-9._:-]*) BEGIN\}\}\r?\n([\s\S]*?)\r?\n\{\{MANAGED_BLOCK:\1 END\}\}/gu,
    (_match, id, body) => managedBlock(id, `${body}\n`));
  assert.ok(documentId && !/\{\{(?:DERIVED|MANAGED)_BLOCK:/u.test(rendered),
    `Installed template ${templateName} did not render as a canonical Schema 3 document`);
  return `${rendered.trim()}\n`;
}

async function captureEntryIdentity(label, path, kind) {
  const metadata = await lstat(path, { bigint: true });
  assert.ok(!metadata.isSymbolicLink(), `${label} must not be a reparse point or symbolic link`);
  assert.ok(kind === "directory" ? metadata.isDirectory() : metadata.isFile(), `${label} must be a ${kind}`);
  if (kind === "file") assert.equal(metadata.nlink, 1n, `${label} must be a single-link regular file`);
  return { label, path, kind, dev: metadata.dev, ino: metadata.ino };
}

async function assertEntryIdentity(expected, path = expected.path) {
  const current = await captureEntryIdentity(expected.label, path, expected.kind);
  assert.equal(current.dev, expected.dev, `${expected.label} device identity changed`);
  assert.equal(current.ino, expected.ino, `${expected.label} inode identity changed`);
}

async function assertDirectoryEntries(path, expected, label) {
  const directory = await opendir(path);
  const actual = [];
  try {
    for (let index = 0; index <= expected.length; index += 1) {
      const entry = await directory.read();
      if (!entry) break;
      actual.push(entry.name);
    }
  } finally {
    await directory.close();
  }
  actual.sort((left, right) => left.localeCompare(right, "en-US"));
  assert.deepEqual(actual, [...expected].sort((left, right) => left.localeCompare(right, "en-US")), label);
}

async function assertPathMissing(path, label) {
  await assert.rejects(lstat(path), (error) => {
    assert.equal(error?.code, "ENOENT", label);
    return true;
  });
}

async function waitForBounded(promise, timeoutMs, label) {
  let timer;
  try {
    await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = globalThis.setTimeout(() => reject(new Error(label)), timeoutMs);
      })
    ]);
  } finally {
    if (timer !== undefined) globalThis.clearTimeout(timer);
  }
}

async function invokeCleanupTestBarrier(environmentName, payload) {
  const barrierInput = process.env[environmentName];
  if (barrierInput === undefined) return;
  assert.equal(process.env.NODE_ENV, "test", `${environmentName} is restricted to NODE_ENV=test`);
  const testRootInput = process.env.KEEPER_INSTALLED_SMOKE_TEST_ROOT;
  assert.ok(testRootInput && isAbsolute(testRootInput), "Installed smoke test root must be absolute");
  assert.ok(isAbsolute(barrierInput), `${environmentName} must be absolute`);
  const systemTemporary = await realpath(tmpdir());
  const testRoot = await realpath(testRootInput);
  const barrierRoot = await realpath(barrierInput);
  assert.ok(samePath(dirname(testRoot), systemTemporary), "Installed smoke test root must be a direct child of system temp");
  assert.ok(samePath(dirname(barrierRoot), testRoot), `${environmentName} must be a direct child of the installed smoke test root`);
  const entered = join(barrierRoot, "entered");
  const release = join(barrierRoot, "release");
  await writeFile(entered, `${payload}\n`, { flag: "wx", mode: 0o600 });
  const expiresAt = Date.now() + 10_000;
  while (Date.now() < expiresAt) {
    try {
      const releaseIdentity = await captureEntryIdentity("Installed smoke test barrier release", release, "file");
      assert.equal(releaseIdentity.kind, "file");
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await delay(25);
  }
  throw new Error(`Timed out waiting for installed smoke test barrier release: ${release}`);
}

async function configuredTestCloseConfirmationDelay() {
  const raw = process.env.KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_DELAY_MS;
  if (raw === undefined) return 0;
  assert.equal(process.env.NODE_ENV, "test", "Close-confirm delay is restricted to NODE_ENV=test");
  const testRootInput = process.env.KEEPER_INSTALLED_SMOKE_TEST_ROOT;
  const controlInput = process.env.KEEPER_INSTALLED_SMOKE_TEST_CLOSE_CONFIRM_CONTROL;
  assert.ok(testRootInput && isAbsolute(testRootInput), "Installed smoke test root must be absolute");
  assert.ok(controlInput && isAbsolute(controlInput), "Close-confirm control path must be absolute");
  const systemTemporary = await realpath(tmpdir());
  const testRoot = await realpath(testRootInput);
  assert.ok(samePath(dirname(testRoot), systemTemporary), "Installed smoke test root must be a direct child of system temp");
  const control = resolve(controlInput);
  assert.ok(samePath(dirname(control), testRoot), "Close-confirm control must be a direct child of the test root");
  assert.match(raw, /^(?:0|[1-9][0-9]{0,4})$/u, "Close-confirm delay must be a bounded integer");
  const milliseconds = Number(raw);
  assert.ok(milliseconds <= 30_000, "Close-confirm delay exceeds the test-only bound");
  await writeFile(control, `delay=${milliseconds}\n`, { flag: "wx", mode: 0o600 });
  return milliseconds;
}

async function readBoundedFileEvidence(path, label, maximumBytes, budget) {
  const beforePath = await lstat(path, { bigint: true });
  assert.ok(!beforePath.isSymbolicLink(), `${label} must not be a reparse point or symbolic link`);
  assert.ok(beforePath.isFile(), `${label} must remain a regular file`);
  assert.equal(beforePath.nlink, 1n, `${label} must remain single-link`);
  assert.ok(beforePath.size >= 0n && beforePath.size <= BigInt(maximumBytes),
    `${label} size exceeds the per-file limit of ${maximumBytes} bytes`);
  budget?.consume(Number(beforePath.size));
  const handle = await open(path, "r");
  try {
    const before = await handle.stat({ bigint: true });
    assert.ok(before.isFile(), `${label} must remain a regular file`);
    assert.equal(before.nlink, 1n, `${label} must remain single-link`);
    assert.equal(before.dev, beforePath.dev, `${label} device identity changed before read`);
    assert.equal(before.ino, beforePath.ino, `${label} inode identity changed before read`);
    assert.equal(before.size, beforePath.size, `${label} size changed before read`);
    assert.equal(before.mtimeNs, beforePath.mtimeNs, `${label} modification time changed before read`);
    assert.equal(before.ctimeNs, beforePath.ctimeNs, `${label} change time changed before read`);
    const expectedSize = Number(before.size);
    const bytes = Buffer.alloc(expectedSize);
    let total = 0;
    while (total < expectedSize) {
      const read = await handle.read(bytes, total, bytes.length - total, total);
      if (read.bytesRead === 0) break;
      total += read.bytesRead;
    }
    assert.equal(total, expectedSize, `${label} changed size during its bounded cleanup read`);
    const overflow = Buffer.alloc(1);
    assert.equal((await handle.read(overflow, 0, 1, expectedSize)).bytesRead, 0,
      `${label} grew during its bounded read`);
    const after = await handle.stat({ bigint: true });
    assert.equal(after.dev, before.dev, `${label} device identity changed during read`);
    assert.equal(after.ino, before.ino, `${label} inode identity changed during read`);
    assert.equal(after.nlink, 1n, `${label} link count changed during read`);
    assert.equal(after.size, before.size, `${label} size changed during read`);
    assert.equal(after.mtimeNs, before.mtimeNs, `${label} modification time changed during read`);
    assert.equal(after.ctimeNs, before.ctimeNs, `${label} change time changed during read`);
    const afterPath = await lstat(path, { bigint: true });
    assert.ok(!afterPath.isSymbolicLink() && afterPath.isFile(), `${label} pathname kind changed after read`);
    assert.equal(afterPath.dev, beforePath.dev, `${label} pathname device identity changed after read`);
    assert.equal(afterPath.ino, beforePath.ino, `${label} pathname inode identity changed after read`);
    assert.equal(afterPath.nlink, 1n, `${label} pathname link count changed after read`);
    assert.equal(afterPath.size, beforePath.size, `${label} pathname size changed after read`);
    assert.equal(afterPath.mtimeNs, beforePath.mtimeNs, `${label} pathname modification time changed after read`);
    assert.equal(afterPath.ctimeNs, beforePath.ctimeNs, `${label} pathname change time changed after read`);
    return {
      dev: before.dev,
      ino: before.ino,
      size: expectedSize,
      digest: sha256(bytes),
      contents: bytes
    };
  } finally {
    await handle.close();
  }
}

async function readBoundedDirectoryNames(path, allowance, label) {
  const directory = await opendir(path);
  const names = [];
  try {
    for (let index = 0; index <= allowance; index += 1) {
      const entry = await directory.read();
      if (!entry) break;
      names.push(entry.name);
    }
  } finally {
    await directory.close();
  }
  assert.ok(names.length <= allowance, `${label} exceeds the bounded cleanup entry limit`);
  return names.sort((left, right) => left.localeCompare(right, "en-US"));
}

async function captureBoundedTree(root, label) {
  const rootIdentity = await captureEntryIdentity(label, root, "directory");
  const directories = [{ relativePath: "", ...rootIdentity }];
  const files = [];
  let entryCount = 0;
  let totalBytes = 0;
  const pending = [{ path: root, relativePath: "", depth: 0 }];
  while (pending.length > 0) {
    const current = pending.pop();
    assert.ok(current.depth <= CACHE_CLEANUP_MAX_DEPTH, `${label} exceeds the bounded cleanup depth limit`);
    const names = await readBoundedDirectoryNames(
      current.path,
      CACHE_CLEANUP_MAX_ENTRIES - entryCount,
      `${label} directory ${current.relativePath || "."}`
    );
    for (const name of names) {
      entryCount += 1;
      assert.ok(entryCount <= CACHE_CLEANUP_MAX_ENTRIES, `${label} exceeds the bounded cleanup entry limit`);
      const relativePath = current.relativePath ? `${current.relativePath}/${name}` : name;
      const path = join(current.path, name);
      const metadata = await lstat(path, { bigint: true });
      assert.ok(!metadata.isSymbolicLink(), `${label} contains a reparse point or symbolic link at ${relativePath}`);
      if (metadata.isDirectory()) {
        assert.ok(current.depth + 1 <= CACHE_CLEANUP_MAX_DEPTH, `${label} exceeds the bounded cleanup depth limit`);
        const identity = await captureEntryIdentity(`${label} directory ${relativePath}`, path, "directory");
        directories.push({ relativePath, ...identity });
        pending.push({ path, relativePath, depth: current.depth + 1 });
      } else {
        assert.ok(metadata.isFile(), `${label} contains a non-regular entry at ${relativePath}`);
        const remainingBytes = CACHE_CLEANUP_MAX_BYTES - totalBytes;
        assert.ok(remainingBytes >= 0, `${label} exceeds the bounded cleanup byte limit`);
        const evidence = await readBoundedFileEvidence(path, `${label} file ${relativePath}`, remainingBytes);
        totalBytes += evidence.size;
        assert.ok(totalBytes <= CACHE_CLEANUP_MAX_BYTES, `${label} exceeds the bounded cleanup byte limit`);
        files.push({
          relativePath,
          label: `${label} file ${relativePath}`,
          path,
          kind: "file",
          ...evidence
        });
      }
    }
  }
  directories.sort((left, right) => left.relativePath.localeCompare(right.relativePath, "en-US"));
  files.sort((left, right) => left.relativePath.localeCompare(right.relativePath, "en-US"));
  return { root, rootIdentity, directories, files, entryCount, totalBytes };
}

function treeEvidence(snapshot) {
  return {
    entryCount: snapshot.entryCount,
    totalBytes: snapshot.totalBytes,
    directories: snapshot.directories.map((entry) => ({
      relativePath: entry.relativePath,
      dev: entry.dev.toString(),
      ino: entry.ino.toString()
    })),
    files: snapshot.files.map((entry) => ({
      relativePath: entry.relativePath,
      dev: entry.dev.toString(),
      ino: entry.ino.toString(),
      size: entry.size,
      digest: entry.digest
    }))
  };
}

async function assertBoundedTreeMatches(snapshot, root, label) {
  const current = await captureBoundedTree(root, label);
  assert.deepEqual(treeEvidence(current), treeEvidence(snapshot), `${label} changed before cleanup`);
}

async function deleteCapturedTree(snapshot, root, label) {
  for (const file of snapshot.files) {
    const path = join(root, ...file.relativePath.split("/"));
    await assertEntryIdentity(file, path);
    const evidence = await readBoundedFileEvidence(path, file.label, file.size);
    assert.equal(evidence.size, file.size, `${file.label} size changed during cleanup`);
    assert.equal(evidence.digest, file.digest, `${file.label} contents changed during cleanup`);
    await unlink(path);
  }
  const directories = snapshot.directories
    .filter((entry) => entry.relativePath !== "")
    .sort((left, right) => right.relativePath.split("/").length - left.relativePath.split("/").length);
  for (const directory of directories) {
    const path = join(root, ...directory.relativePath.split("/"));
    await assertEntryIdentity(directory, path);
    await assertDirectoryEntries(path, [], `${directory.label} was not empty during cleanup`);
    await rmdir(path);
  }
  await assertEntryIdentity(snapshot.rootIdentity, root);
  await assertDirectoryEntries(root, [], `${label} root was not empty during cleanup`);
  await rmdir(root);
}

async function beginCanonicalFixture(installedRoot, smokeProjectRoot, installedFiles) {
  const smokeProjectIdentity = await captureEntryIdentity("Smoke project root", smokeProjectRoot, "directory");
  await assertDirectoryEntries(
    smokeProjectRoot,
    [],
    "Smoke project root must be an empty disposable directory; refusing to modify a nonempty project"
  );
  await assertEntryIdentity(smokeProjectIdentity);

  const fixtureName = `keeper-canonical-schema3-${randomUUID()}`;
  const fixtureRoot = join(smokeProjectRoot, fixtureName);
  await mkdir(fixtureRoot);
  const fixtureIdentity = await captureEntryIdentity("Canonical smoke fixture root", fixtureRoot, "directory");
  const state = {
    smokeProjectIdentity,
    fixtureName,
    fixtureRoot,
    fixtureIdentity,
    directories: [],
    files: []
  };
  await assertDirectoryEntries(smokeProjectRoot, [fixtureName], "Smoke project changed while the canonical fixture was created");
  await assertEntryIdentity(smokeProjectIdentity);

  const assetPrefix = "skills/distill-project-design/assets/knowledge-pack";
  const pack = readJson(installedFiles.get(`${assetPrefix}/manifest.json`), "Installed knowledge-pack manifest");
  delete pack.templateNotes;
  const sourceLine = "Installed smoke canonical evidence.";
  const sourceContent = `${sourceLine}\n`;
  pack.sourceRevision.files["README.md"] = sha256(sourceContent);
  for (const record of pack.records) {
    for (const evidence of record.evidence) {
      if (evidence.path === "README.md" && evidence.startLine === 1) evidence.excerptHash = sha256(sourceLine);
    }
  }
  const documentLinks = canonicalTemplates
    .map(([, path]) => `- [${path}](${path.replace("docs/project-design/", "")})`)
    .join("\n");
  const files = new Map([["README.md", sourceContent]]);
  for (const [templateName, path] of canonicalTemplates) {
    const templateBytes = installedFiles.get(`${assetPrefix}/${templateName}`);
    assert.ok(templateBytes, `Installed package inventory omitted ${templateName}`);
    const template = templateBytes.toString("utf8");
    files.set(path, renderCanonicalTemplate(
      templateName,
      template,
      templateName === "index.md.template" ? { DOCUMENT_LINKS: documentLinks } : {}
    ));
  }
  files.set("docs/project-design/manifest.json", `${JSON.stringify(pack, null, 2)}\n`);

  for (const relativePath of ["docs", "docs/project-design", "docs/project-design/modules"]) {
    const path = join(fixtureRoot, ...relativePath.split("/"));
    await mkdir(path);
    state.directories.push({ relativePath, ...(await captureEntryIdentity(`Canonical fixture directory ${relativePath}`, path, "directory")) });
  }
  for (const [relativePath, content] of [...files].sort(([left], [right]) => left.localeCompare(right, "en-US"))) {
    const path = join(fixtureRoot, ...relativePath.split("/"));
    const bytes = Buffer.from(content, "utf8");
    await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
    state.files.push({
      relativePath,
      digest: sha256(bytes),
      size: bytes.byteLength,
      ...(await captureEntryIdentity(`Canonical fixture file ${relativePath}`, path, "file"))
    });
  }
  return { state, pack };
}

async function assertExactFixtureEntries(state, root = state.fixtureRoot) {
  const expectedByDirectory = new Map([[".", []]]);
  for (const directory of state.directories) expectedByDirectory.set(directory.relativePath, []);
  for (const entry of [...state.directories, ...state.files]) {
    const parent = dirname(entry.relativePath).replaceAll("\\", "/");
    const expected = expectedByDirectory.get(parent);
    assert.ok(expected, `Canonical fixture manifest omitted parent directory ${parent}`);
    expected.push(entry.relativePath.split("/").at(-1));
  }
  for (const [relativeDirectory, expected] of expectedByDirectory) {
    const path = relativeDirectory === "." ? root : join(root, ...relativeDirectory.split("/"));
    await assertDirectoryEntries(path, expected, `Canonical fixture directory ${relativeDirectory} changed before cleanup`);
  }
}

async function verifyCanonicalFixtureAt(state, root) {
  await assertEntryIdentity(state.fixtureIdentity, root);
  await assertExactFixtureEntries(state, root);
  for (const file of state.files) {
    const path = join(root, ...file.relativePath.split("/"));
    await assertEntryIdentity(file, path);
    const evidence = await readBoundedFileEvidence(path, file.label, file.size);
    assert.equal(evidence.size, file.size, `${file.label} size changed before cleanup`);
    assert.equal(evidence.digest, file.digest, `${file.label} contents changed before cleanup`);
  }
  for (const directory of state.directories) {
    await assertEntryIdentity(directory, join(root, ...directory.relativePath.split("/")));
  }
}

async function deleteCanonicalFixtureAt(state, root) {
  for (const file of state.files) {
    const path = join(root, ...file.relativePath.split("/"));
    await assertEntryIdentity(file, path);
    const evidence = await readBoundedFileEvidence(path, file.label, file.size);
    assert.equal(evidence.digest, file.digest, `${file.label} changed during cleanup`);
    await unlink(path);
  }
  for (const directory of [...state.directories].reverse()) {
    const path = join(root, ...directory.relativePath.split("/"));
    await assertEntryIdentity(directory, path);
    await assertDirectoryEntries(path, [], `${directory.label} was not empty during cleanup`);
    await rmdir(path);
  }
  await assertEntryIdentity(state.fixtureIdentity, root);
  await assertDirectoryEntries(root, [], "Canonical fixture root was not empty during cleanup");
  await rmdir(root);
}

async function cleanupCanonicalFixture(state) {
  let quarantineContainer;
  let quarantinePayload;
  try {
    await assertEntryIdentity(state.smokeProjectIdentity);
    await assertEntryIdentity(state.fixtureIdentity);
    await assertDirectoryEntries(
      state.smokeProjectIdentity.path,
      [state.fixtureName],
      "Smoke project contents changed before canonical fixture cleanup"
    );
    await verifyCanonicalFixtureAt(state, state.fixtureRoot);

    quarantineContainer = await mkdtemp(join(
      state.smokeProjectIdentity.path,
      "keeper-installed-smoke-fixture-cleanup-"
    ));
    const quarantineIdentity = await captureEntryIdentity(
      "Canonical fixture cleanup quarantine",
      quarantineContainer,
      "directory"
    );
    const quarantineName = relative(state.smokeProjectIdentity.path, quarantineContainer);
    assert.ok(quarantineName && !quarantineName.includes(sep), "Canonical fixture quarantine must be a direct child");
    quarantinePayload = join(quarantineContainer, "payload");
    await assertEntryIdentity(state.smokeProjectIdentity);
    await assertDirectoryEntries(
      state.smokeProjectIdentity.path,
      [state.fixtureName, quarantineName],
      "Smoke project changed while the cleanup quarantine was created"
    );
    await verifyCanonicalFixtureAt(state, state.fixtureRoot);
    await invokeCleanupTestBarrier(
      "KEEPER_INSTALLED_SMOKE_TEST_FIXTURE_QUARANTINE_BARRIER",
      state.fixtureRoot
    );

    await rename(state.fixtureRoot, quarantinePayload);
    await assertEntryIdentity(quarantineIdentity);
    await assertEntryIdentity(state.fixtureIdentity, quarantinePayload);
    await assertPathMissing(state.fixtureRoot, "Original canonical fixture path was recreated after quarantine");
    await assertDirectoryEntries(quarantineContainer, ["payload"], "Canonical fixture cleanup quarantine changed");
    await assertDirectoryEntries(
      state.smokeProjectIdentity.path,
      [quarantineName],
      "Smoke project changed after canonical fixture quarantine"
    );
    await verifyCanonicalFixtureAt(state, quarantinePayload);
    await deleteCanonicalFixtureAt(state, quarantinePayload);
    await assertEntryIdentity(quarantineIdentity);
    await assertDirectoryEntries(quarantineContainer, [], "Canonical fixture cleanup quarantine was not empty");
    await rmdir(quarantineContainer);
    await assertEntryIdentity(state.smokeProjectIdentity);
    await assertDirectoryEntries(state.smokeProjectIdentity.path, [], "Smoke project was not empty after canonical fixture cleanup");
  } catch (error) {
    const evidence = [state.fixtureRoot, quarantineContainer, quarantinePayload].filter(Boolean).join(", ");
    throw new Error(
      `Canonical smoke fixture cleanup is ambiguous; preserving remaining evidence at ${evidence}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    );
  }
}

async function cleanupInstalledSmokeCache(state) {
  let quarantineContainer;
  let quarantinePayload;
  try {
    await assertEntryIdentity(state.parentIdentity);
    await assertEntryIdentity(state.rootIdentity);
    const snapshot = await captureBoundedTree(state.root, "Installed smoke cache");
    assert.equal(snapshot.rootIdentity.dev, state.rootIdentity.dev, "Installed smoke cache device identity changed");
    assert.equal(snapshot.rootIdentity.ino, state.rootIdentity.ino, "Installed smoke cache inode identity changed");

    quarantineContainer = await mkdtemp(join(state.parent, "keeper-installed-smoke-cache-cleanup-"));
    const quarantineIdentity = await captureEntryIdentity(
      "Installed smoke cache cleanup quarantine",
      quarantineContainer,
      "directory"
    );
    quarantinePayload = join(quarantineContainer, "payload");
    await assertEntryIdentity(state.parentIdentity);
    await assertEntryIdentity(state.rootIdentity);
    await assertBoundedTreeMatches(snapshot, state.root, "Installed smoke cache");
    await invokeCleanupTestBarrier(
      "KEEPER_INSTALLED_SMOKE_TEST_CACHE_QUARANTINE_BARRIER",
      state.root
    );

    await rename(state.root, quarantinePayload);
    await assertEntryIdentity(state.parentIdentity);
    await assertEntryIdentity(quarantineIdentity);
    await assertEntryIdentity(state.rootIdentity, quarantinePayload);
    await assertPathMissing(state.root, "Original installed smoke cache path was recreated after quarantine");
    await assertDirectoryEntries(quarantineContainer, ["payload"], "Installed smoke cache cleanup quarantine changed");
    await assertBoundedTreeMatches(snapshot, quarantinePayload, "Quarantined installed smoke cache");
    await deleteCapturedTree(snapshot, quarantinePayload, "Quarantined installed smoke cache");
    await assertEntryIdentity(quarantineIdentity);
    await assertDirectoryEntries(quarantineContainer, [], "Installed smoke cache cleanup quarantine was not empty");
    await rmdir(quarantineContainer);
    await assertEntryIdentity(state.parentIdentity);
    await assertPathMissing(state.root, "Installed smoke cache path was recreated during cleanup");
  } catch (error) {
    const evidence = [state.root, quarantineContainer, quarantinePayload].filter(Boolean).join(", ");
    throw new Error(
      `Installed smoke cache cleanup is ambiguous; preserving remaining evidence at ${evidence}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    );
  }
}

function samePath(left, right) {
  const normalize = (value) => process.platform === "win32"
    ? resolve(value).toLocaleLowerCase("en-US")
    : resolve(value);
  return normalize(left) === normalize(right);
}

function strictlyInside(parent, candidate) {
  const nested = relative(parent, candidate);
  return nested !== "" && nested !== ".." && !nested.startsWith(`..${sep}`) && !isAbsolute(nested);
}

async function validatedDirectory(label, input) {
  assert.equal(typeof input, "string", `${label} must be one of two absolute roots`);
  assert.ok(isAbsolute(input), `${label} must be an absolute root`);
  const lexical = resolve(input);
  const metadata = await lstat(lexical);
  assert.ok(!metadata.isSymbolicLink(), `${label} must not be a reparse point or symbolic link`);
  assert.ok(metadata.isDirectory(), `${label} must be a directory`);
  const canonical = await realpath(lexical);
  assert.ok(samePath(lexical, canonical), `${label} must not resolve through a reparse point or symbolic link`);
  return lexical;
}

function installedExpectedChildren() {
  const directories = new Set();
  for (const file of exactPackageFiles) {
    let directory = dirname(file).replaceAll("\\", "/");
    while (directory !== ".") {
      directories.add(directory);
      directory = dirname(directory).replaceAll("\\", "/");
    }
  }
  const expected = new Map([[".", new Map()]]);
  for (const directory of directories) expected.set(directory, new Map());
  for (const directory of directories) {
    const parent = dirname(directory).replaceAll("\\", "/");
    expected.get(parent).set(directory.split("/").at(-1), "directory");
  }
  for (const file of exactPackageFiles) {
    const parent = dirname(file).replaceAll("\\", "/");
    expected.get(parent).set(file.split("/").at(-1), "file");
  }
  return expected;
}

function installedPackageByteBudget() {
  let used = 0;
  return {
    consume(bytes) {
      assert.ok(Number.isSafeInteger(bytes) && bytes >= 0, "Installed package byte accounting must be non-negative");
      assert.ok(used + bytes <= PACKAGE_MAX_TOTAL_BYTES,
        `Installed package bytes exceed the aggregate limit of ${PACKAGE_MAX_TOTAL_BYTES}`);
      used += bytes;
    }
  };
}

async function exactInstalledFiles(root) {
  const expected = installedExpectedChildren();
  const budget = installedPackageByteBudget();
  const contents = new Map();
  for (const [relativeDirectory, expectedEntries] of expected) {
    const directory = relativeDirectory === "." ? root : join(root, ...relativeDirectory.split("/"));
    await assertDirectoryEntries(
      directory,
      [...expectedEntries.keys()],
      `Installed package directory ${relativeDirectory} does not match the exact allowlist`
    );
    for (const [name, kind] of expectedEntries) {
      const path = join(directory, name);
      const relativePath = relativeDirectory === "." ? name : `${relativeDirectory}/${name}`;
      const metadata = await lstat(path, { bigint: true });
      assert.ok(!metadata.isSymbolicLink(), `Installed root contains a reparse point or symbolic link: ${relativePath}`);
      assert.ok(kind === "directory" ? metadata.isDirectory() : metadata.isFile(),
        `Installed root entry has the wrong kind: ${relativePath}`);
      if (kind === "file") {
        const json = relativePath.toLowerCase().endsWith(".json");
        const evidence = await readBoundedFileEvidence(
          path,
          json ? `Installed package JSON file ${relativePath}` : `Installed package file ${relativePath}`,
          json ? PACKAGE_MAX_JSON_BYTES : PACKAGE_MAX_FILE_BYTES,
          budget
        );
        contents.set(relativePath, evidence.contents);
      }
    }
  }
  assert.equal(contents.size, exactPackageFiles.length, "Installed package file inventory is incomplete");
  return contents;
}

function readJson(contents, label) {
  assert.ok(Buffer.isBuffer(contents), `${label} is missing from the bounded installed package inventory`);
  return JSON.parse(contents.toString("utf8"));
}

async function validateInstalledIdentity(root) {
  const installedFiles = await exactInstalledFiles(root);
  const plugin = readJson(installedFiles.get(".codex-plugin/plugin.json"), "Installed plugin manifest");
  const pkg = readJson(installedFiles.get("package.json"), "Installed package manifest");
  const configuration = readJson(installedFiles.get(".mcp.json"), "Installed MCP manifest");
  assert.equal(plugin.name, "project-design-keeper", "Wrong installed package identity in plugin manifest");
  assert.equal(plugin.version, "1.0.2", "Wrong installed package identity in plugin manifest");
  assert.equal(plugin.skills, "./skills/", "Wrong installed package skill root");
  assert.equal(plugin.mcpServers, "./.mcp.json", "Wrong installed package MCP manifest");
  assert.equal(pkg.name, "project-design-keeper", "Wrong installed package identity in package manifest");
  assert.equal(pkg.version, "1.0.2", "Wrong installed package identity in package manifest");
  const parameters = configuration.mcpServers?.["project-design-keeper"];
  assert.deepEqual(parameters, { command: "node", args: ["dist/index.js"], cwd: "." }, "Wrong installed package MCP command");
  return { parameters, installedFiles };
}

function toolErrorText(result) {
  return JSON.stringify({ content: result.content, structuredContent: result.structuredContent });
}

function tamperCursorOffset(cursor) {
  const [body, signature, ...extra] = String(cursor).split(".");
  assert.ok(body && signature && extra.length === 0, "Scan cursor must be signed");
  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  assert.ok(Number.isSafeInteger(payload.offset), "Scan cursor must contain an integer offset");
  payload.offset += 1;
  return `${Buffer.from(JSON.stringify(payload), "utf8").toString("base64url")}.${signature}`;
}

if (process.argv.length !== 2 && process.argv.length !== 4) {
  throw new Error("Installed smoke requires exactly two absolute positional roots");
}
const fallback = process.argv.length === 2;
const installedInput = fallback ? process.env.KEEPER_INSTALLED_ROOT : process.argv[2];
const projectInput = fallback ? process.env.KEEPER_SMOKE_PROJECT : process.argv[3];
if (fallback) process.stderr.write("Compatibility fallback: KEEPER_INSTALLED_ROOT and KEEPER_SMOKE_PROJECT are deprecated; pass two absolute positional roots.\n");

const installedRoot = await validatedDirectory("Installed root", installedInput);
const projectRoot = await validatedDirectory("Smoke project root", projectInput);
assert.ok(!samePath(installedRoot, projectRoot), "Installed root and smoke project root must differ");
const installed = await validateInstalledIdentity(installedRoot);
const parameters = installed.parameters;
const closeConfirmationDelayMs = await configuredTestCloseConfirmationDelay();
const canonicalFixture = await beginCanonicalFixture(installedRoot, projectRoot, installed.installedFiles);
const canonicalRoot = canonicalFixture.state.fixtureRoot;

const cacheParent = await realpath(tmpdir());
const cacheParentIdentity = await captureEntryIdentity("Installed smoke cache parent", cacheParent, "directory");
const cacheRoot = await mkdtemp(join(cacheParent, "keeper-installed-smoke-cache-"));
assert.ok(strictlyInside(cacheParent, cacheRoot), "Installed smoke cache escaped the temporary parent");
const cacheRootIdentity = await captureEntryIdentity("Installed smoke cache root", cacheRoot, "directory");
await assertEntryIdentity(cacheParentIdentity);
const cacheState = {
  parent: cacheParent,
  parentIdentity: cacheParentIdentity,
  root: cacheRoot,
  rootIdentity: cacheRootIdentity
};
const childEnvironment = Object.fromEntries(Object.entries({ ...process.env, PLUGIN_DATA: cacheRoot })
  .filter((entry) => typeof entry[1] === "string"));
const transport = new StdioClientTransport({
  command: parameters.command,
  args: parameters.args,
  cwd: installedRoot,
  env: childEnvironment,
  stderr: "pipe"
});
const client = new Client({ name: "keeper-installed-smoke", version: "1.0.2" });
let operationError;
let stderr = "";
let stderrBytes = 0;
transport.stderr?.on("data", (chunk) => {
  const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  const remaining = Math.max(0, MCP_STDERR_MAX_BYTES - stderrBytes);
  if (remaining > 0) stderr += bytes.subarray(0, remaining).toString("utf8");
  stderrBytes += Math.min(bytes.length, remaining);
  if (bytes.length > remaining && operationError === undefined) {
    operationError = new Error(`Installed MCP stderr exceeded its bounded byte limit of ${MCP_STDERR_MAX_BYTES}`);
  }
});
let markTransportClosed;
const transportClosed = new Promise((resolveClosed) => {
  markTransportClosed = resolveClosed;
});
transport.onclose = () => {
  if (closeConfirmationDelayMs === 0) {
    markTransportClosed();
    return;
  }
  const delayedConfirmation = globalThis.setTimeout(markTransportClosed, closeConfirmationDelayMs);
  delayedConfirmation.unref?.();
};
const outputName = `installed-smoke-${randomUUID()}.md`;
const outputRelative = `.agents/skills/project-design-context/${outputName}`;
const outputPath = join(canonicalRoot, ...outputRelative.split("/"));
try {
  await assert.rejects(lstat(outputPath), { code: "ENOENT" });
  await client.connect(transport);
  const names = (await client.listTools()).tools.map((tool) => tool.name).sort();
  assert.deepEqual(names, exactTools, "Installed MCP tool catalog must contain the exact nine sorted tools");

  const validation = await client.callTool({
    name: "validate_pack",
    arguments: { root: canonicalRoot, pack: canonicalFixture.pack }
  });
  assert.notEqual(validation.isError, true, stderr || toolErrorText(validation));
  assert.equal(
    validation.structuredContent?.valid,
    true,
    `Installed canonical Schema 3 fixture must validate: ${toolErrorText(validation)}`
  );
  assert.deepEqual(validation.structuredContent?.errors, [], "Installed canonical Schema 3 fixture must have no validation errors");

  const scan = await client.callTool({
    name: "scan_scope",
    arguments: { root: canonicalRoot, path: "docs", view: "files", limit: 1 }
  });
  assert.notEqual(scan.isError, true, stderr || toolErrorText(scan));
  assert.ok(scan.structuredContent, "Installed scan must return structured content");
  const cursor = scan.structuredContent.page?.nextCursor;
  assert.equal(typeof cursor, "string", "Installed scan fixture must produce a signed cursor");
  const tampered = await client.callTool({
    name: "scan_scope",
    arguments: { root: canonicalRoot, path: "docs", view: "files", limit: 1, cursor: tamperCursorOffset(cursor) }
  });
  assert.equal(tampered.isError, true, "Installed MCP accepted a caller-modified signed cursor offset");
  assert.match(toolErrorText(tampered), /cursor.*tampered|tampered.*cursor/i);

  const preview = await client.callTool({
    name: "preview_update",
    arguments: {
      root: canonicalRoot,
      changes: [{
        path: outputRelative,
        managedBlock: {
          recordId: `installed-smoke.${randomUUID()}`,
          content: "# Installed smoke preview\n"
        }
      }]
    }
  });
  assert.notEqual(preview.isError, true, stderr || toolErrorText(preview));
  const changesetId = preview.structuredContent?.changesetId;
  assert.equal(typeof changesetId, "string", "Installed preview must return a changeset id");
  await assert.rejects(lstat(outputPath), { code: "ENOENT" });

  const apply = await client.callTool({
    name: "apply_update",
    arguments: { root: canonicalRoot, changesetId }
  });
  assert.equal(apply.isError, true, "Installed MCP allowed apply from a client without elicitation support");
  assert.match(toolErrorText(apply), /elicitation|approval/i);
  await assert.rejects(lstat(outputPath), { code: "ENOENT" });
} catch (error) {
  operationError ??= error;
}

let closeError;
try {
  const closingPid = transport.pid;
  await client.close();
  if (closingPid !== null) {
    await waitForBounded(
      transportClosed,
      MCP_CLOSE_CONFIRM_TIMEOUT_MS,
      `Installed MCP PID ${closingPid} was not confirmed closed within ${MCP_CLOSE_CONFIRM_TIMEOUT_MS}ms`
    );
  }
} catch (error) {
  closeError = new Error(
    `Installed MCP did not fully exit or confirm closed; preserving canonical fixture evidence at ${canonicalRoot} and cache evidence at ${cacheRoot}`,
    { cause: error }
  );
}

let fixtureCleanupError;
let cacheCleanupError;
if (!closeError) {
  try {
    await cleanupCanonicalFixture(canonicalFixture.state);
  } catch (error) {
    fixtureCleanupError = error;
  }
  try {
    await cleanupInstalledSmokeCache(cacheState);
  } catch (error) {
    cacheCleanupError = error;
  }
}

const failures = [operationError, closeError, fixtureCleanupError, cacheCleanupError].filter((error) => error !== undefined);
if (failures.length === 1) throw failures[0];
if (failures.length > 1) {
  throw new AggregateError(failures, "Installed smoke failed and cleanup did not complete unambiguously", { cause: failures[0] });
}

process.stdout.write("Canonical Schema 3 smoke fixture validated and removed after MCP exit\n");
process.stdout.write(`Installed smoke passed for ${installedRoot}\n`);
