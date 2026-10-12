import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { createProjectDesignKeeper } from "../src/index.js";
import { createSettingsStore } from "../src/settings/store.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";

let directory: string;
beforeEach(async () => { directory = await mkdtemp(join(tmpdir(), "keeper-easy-service-")); });
afterEach(async () => { await rm(directory, { recursive: true, force: true }); });
const target = ".agents/skills/project-design-context/easy.md";
async function setup(easyMode: boolean) {
  const cacheDirectory = join(directory, "cache");
  const store = createSettingsStore({ cacheDirectory });
  await store.save({ easyMode, maxUpdateMiB: 8 }, (await store.read()).revision);
  // Scope is a sibling, never the cache itself.
  const { mkdir } = await import("node:fs/promises");
  const root = join(directory, "project"); await mkdir(root); await writeFile(join(root, "source.txt"), "source");
  return { root, store, cacheDirectory };
}
async function preview(api: ReturnType<typeof createProjectDesignKeeper>, root: string) {
  return api.previewUpdate({ root, changes: [{ path: target, managedBlock: { recordId: "easy", content: "Test content\n" } }] });
}
test("saved Easy policy survives a new service and skips the trusted human provider", async () => {
  const { root, cacheDirectory } = await setup(true);
  const provider = vi.fn(async () => ({ approved: false }));
  const first = createProjectDesignKeeper({ cacheDirectory, trustedApprovalProvider: provider });
  const staged = await preview(first, root);
  const restarted = createProjectDesignKeeper({ cacheDirectory, trustedApprovalProvider: provider });
  expect(await restarted.applyUpdate({ root, changesetId: staged.changesetId })).toMatchObject({ authorizationSource: "easy-policy" });
  expect(provider).not.toHaveBeenCalled();
  expect(await readFile(join(root, target), "utf8")).toContain("Test content");
});
test("a live service sees settings saves and rejects a preview made under the old revision", async () => {
  const { root, store, cacheDirectory } = await setup(false);
  const api = createProjectDesignKeeper({ cacheDirectory });
  const old = await preview(api, root);
  await store.save({ easyMode: true, maxUpdateMiB: 4 }, (await store.read()).revision);
  expect(await api.getSettings()).toMatchObject({ easyMode: true, maxUpdateMiB: 4 });
  await expect(api.applyUpdate({ root, changesetId: old.changesetId })).rejects.toThrow(/settings|policy|preview/i);
  const fresh = await preview(api, root);
  expect(await api.applyUpdate({ root, changesetId: fresh.changesetId })).toMatchObject({ authorizationSource: "easy-policy" });
});
test("a fresh bundled Node process reads the same durable settings outside its installation path", async () => {
  const { store, cacheDirectory } = await setup(true);
  const expected = await store.read();
  const bundle = join(directory, "relocated-install", "index.mjs");
  await build({ entryPoints: ["src/index.ts"], bundle: true, platform: "node", format: "esm", target: "node20", outfile: bundle, logLevel: "silent" });
  const script = `import {createProjectDesignKeeper} from ${JSON.stringify(pathToFileURL(bundle).href)}; console.log(JSON.stringify(await createProjectDesignKeeper({cacheDirectory:process.argv[1]}).getSettings()));`;
  const result = await promisify(execFile)(process.execPath, ["--input-type=module", "-e", script, cacheDirectory]);
  expect(JSON.parse(result.stdout)).toEqual(expected);
});
