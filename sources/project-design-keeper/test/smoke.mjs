import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);

const sourceRoot = process.cwd();
const temporaryRoot = await mkdtemp(join(tmpdir(), "project design keeper \u91cd\u5b9a\u4f4d-"));
const relocatedRoot = join(temporaryRoot, "\u63d2\u4ef6 root with spaces");
const projectRoot = join(temporaryRoot, "\u9879\u76ee fixture");
const cacheRoot = join(temporaryRoot, "plugin cache");

try {
  await mkdir(relocatedRoot, { recursive: true });
  const tracked = await execFile("git", [
    "-C", sourceRoot, "ls-files", "-z", "--", ".codex-plugin", ".mcp.json", "dist", "skills"
  ], { encoding: "buffer" });
  const payload = Buffer.from(tracked.stdout).toString("utf8").split("\0").filter(Boolean);
  assert.ok(payload.includes("dist/index.js"), "publishable bundle must be tracked by Git");
  for (const file of payload) {
    const destination = join(relocatedRoot, ...file.split("/"));
    await mkdir(dirname(destination), { recursive: true });
    await cp(join(sourceRoot, ...file.split("/")), destination);
  }
  await assert.rejects(readFile(join(relocatedRoot, "node_modules", "package.json"), "utf8"));

  await mkdir(projectRoot, { recursive: true });
  await writeFile(join(projectRoot, "evidence.txt"), "relocated keeper evidence\n", "utf8");

  const configuration = JSON.parse(await readFile(join(relocatedRoot, ".mcp.json"), "utf8"));
  const parameters = configuration.mcpServers["project-design-keeper"];
  assert.equal(parameters.cwd, ".");
  assert.equal(isAbsolute(parameters.args[0]), false);
  assert.equal(JSON.stringify(parameters).includes(sourceRoot), false);

  const transport = new StdioClientTransport({
    command: parameters.command,
    args: parameters.args,
    cwd: resolve(relocatedRoot, parameters.cwd),
    env: { PLUGIN_DATA: cacheRoot },
    stderr: "pipe"
  });
  const client = new Client({ name: "project-design-keeper-smoke", version: "0.1.0" });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  try {
    await client.connect(transport);
    const names = (await client.listTools()).tools.map((tool) => tool.name).sort();
    assert.deepEqual(names, [
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
    const scan = await client.callTool({ name: "scan_scope", arguments: { root: projectRoot } });
    assert.equal(scan.isError, undefined, stderr);
    assert.ok(scan.structuredContent);
    assert.deepEqual(scan.content[0].type, "text");
  } finally {
    await client.close();
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
