import { lstat, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createSettingsStore } from "../src/settings/store.js";
import { openSettingsPanel, type SettingsPanel } from "../src/settings/panel.js";

const temporary: string[] = [];
const panels: SettingsPanel[] = [];
async function fixture() {
  const cacheDirectory = await mkdtemp(join(tmpdir(), "keeper-settings-"));
  temporary.push(cacheDirectory);
  return { cacheDirectory, store: createSettingsStore({ cacheDirectory }) };
}
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(panels.splice(0).map((panel) => panel.close()));
  await Promise.all(temporary.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("durable user settings", () => {
  it("leaves an existing empty cache untouched when reading defaults", async () => {
    const { store, cacheDirectory } = await fixture();
    expect(await store.read()).toEqual({ version: 1, revision: "default", easyMode: false, maxUpdateMiB: 8 });
    expect(await readdir(cacheDirectory)).toEqual([]);
  });
  it("does not create an absent cache directory when reading defaults", async () => {
    const { cacheDirectory } = await fixture();
    const absentCache = join(cacheDirectory, "not-created");
    const store = createSettingsStore({ cacheDirectory: absentCache });
    expect(await store.read()).toEqual({ version: 1, revision: "default", easyMode: false, maxUpdateMiB: 8 });
    await expect(lstat(absentCache)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readdir(cacheDirectory)).toEqual([]);
  });
  it("uses safe stable defaults and persists a new revision across store instances", async () => {
    const { store, cacheDirectory } = await fixture();
    const defaults = await store.read();
    expect(defaults).toEqual({ version: 1, revision: "default", easyMode: false, maxUpdateMiB: 8 });
    const saved = await store.save({ easyMode: true, maxUpdateMiB: 64 }, defaults.revision);
    expect(saved.revision).not.toBe(defaults.revision);
    expect(await createSettingsStore({ cacheDirectory }).read()).toEqual(saved);
    expect(JSON.parse(await readFile(join(cacheDirectory, "settings.json"), "utf8"))).toEqual(saved);
  });
  it.each([
    { easyMode: "true", maxUpdateMiB: 8 }, { easyMode: true, maxUpdateMiB: 0 },
    { easyMode: true, maxUpdateMiB: 65 }, { easyMode: true, maxUpdateMiB: 1.5 },
    { easyMode: true, maxUpdateMiB: "8" }, { easyMode: true, maxUpdateMiB: 8, unknown: true }
  ])("rejects invalid values without changing defaults: %j", async (values) => {
    const { store } = await fixture();
    await expect(store.save(values as never, "default")).rejects.toThrow();
    expect((await store.read()).easyMode).toBe(false);
  });
  it("fails closed on corrupt, unsupported, or oversized persisted settings", async () => {
    const { store, cacheDirectory } = await fixture();
    await store.read();
    for (const content of ["{", '{"version":2,"revision":"x","easyMode":true,"maxUpdateMiB":8}', " ".repeat(4097)]) {
      await writeFile(join(cacheDirectory, "settings.json"), content, { mode: 0o600 });
      await expect(store.read()).rejects.toThrow(/settings|Settings/);
    }
  });
  it("serializes competing stores and rejects stale revisions instead of losing a save", async () => {
    const { store, cacheDirectory } = await fixture();
    const second = createSettingsStore({ cacheDirectory });
    const results = await Promise.allSettled([
      store.save({ easyMode: true, maxUpdateMiB: 3 }, "default"),
      second.save({ easyMode: false, maxUpdateMiB: 16 }, "default")
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const winner = results.find((result) => result.status === "fulfilled")!;
    if (winner.status === "fulfilled") expect(await store.read()).toEqual(winner.value);
    await expect(store.save({ easyMode: false, maxUpdateMiB: 8 }, "default")).rejects.toThrow(/revision|修订/);
  });
});

describe("settings browser authority", () => {
  async function opened() {
    const { store } = await fixture();
    let browserUrl = "";
    const panel = await openSettingsPanel(store, { launch: async (url) => { browserUrl = url; } });
    panels.push(panel);
    const token = new URL(browserUrl).hash.slice(1);
    const headers = { origin: new URL(panel.url).origin, "content-type": "application/json", "x-keeper-settings-session": token };
    return { store, panel, browserUrl, token, headers };
  }
  it("returns a clickable tokenless link while handing capability only to the browser", async () => {
    const { panel, browserUrl, token } = await opened();
    expect(token.length).toBeGreaterThanOrEqual(43);
    expect(panel.url).not.toContain(token);
    expect(new URL(panel.url).hostname).toBe("127.0.0.1");
    const response = await fetch(panel.url);
    expect(response.status).toBe(200);
    expect(await response.text()).not.toContain(token);
    expect(browserUrl).toBe(`${panel.url}#${token}`);
  });
  it("denies missing tokens, foreign origins and host rebinding without writes", async () => {
    const { store, panel, headers } = await opened();
    const body = JSON.stringify({ expectedRevision: "default", values: { easyMode: true, maxUpdateMiB: 9 } });
    for (const invalid of [
      { ...headers, "x-keeper-settings-session": "" },
      { ...headers, origin: "https://evil.example" },
      { ...headers, "content-type": "text/plain" }
    ]) {
      expect((await fetch(`${panel.url}api/settings`, { method: "POST", headers: invalid, body })).status).toBeGreaterThanOrEqual(400);
    }
    const reboundStatus = await new Promise<number>((resolve, reject) => {
      const request = httpRequest(`${panel.url}api/settings`, { method: "POST", headers: { ...headers, host: "evil.example" } }, (response) => {
        response.resume();
        resolve(response.statusCode!);
      });
      request.on("error", reject);
      request.end(body);
    });
    expect(reboundStatus).toBe(403);
    expect((await store.read()).easyMode).toBe(false);
  });
  it("saves authorized JSON, exposes conflicts and bounds request bodies", async () => {
    const { store, panel, headers } = await opened();
    const body = JSON.stringify({ expectedRevision: "default", values: { easyMode: true, maxUpdateMiB: 6 } });
    expect((await fetch(`${panel.url}api/settings`, { method: "POST", headers, body })).status).toBe(200);
    expect((await store.read()).maxUpdateMiB).toBe(6);
    expect((await fetch(`${panel.url}api/settings`, { method: "POST", headers, body })).status).toBe(409);
    expect((await fetch(`${panel.url}api/settings`, { method: "POST", headers, body: " ".repeat(5000) })).status).toBe(413);
    expect((await fetch(`${panel.url}api/settings`, { method: "POST", headers, body: "{" })).status).toBe(400);
  });
  it("expires browser sessions before accepting settings changes", async () => {
    const { store, panel, headers } = await opened();
    const clock = vi.spyOn(Date, "now").mockReturnValue(Date.parse(panel.expiresAt) + 1);
    const response = await fetch(`${panel.url}api/settings`, {
      method: "POST", headers,
      body: JSON.stringify({ expectedRevision: "default", values: { easyMode: true, maxUpdateMiB: 9 } })
    });
    expect(response.status).toBe(410);
    clock.mockRestore();
    expect((await store.read()).easyMode).toBe(false);
  });
  it("never leaks private browser arguments when browser launching fails", async () => {
    const { store } = await fixture();
    await expect(openSettingsPanel(store, {
      launch: async (url) => { throw new Error(`Failed launch ${url}`); }
    })).rejects.toThrow(/^无法打开本机浏览器，请检查默认浏览器配置后重试。$/);
  });
});
