import { afterEach, expect, test, vi } from "vitest";
import { createProjectDesignKeeper } from "../src/index.js";
import { openSettingsPanel, type SettingsPanel } from "../src/settings/panel.js";

vi.mock("../src/settings/panel.js", () => ({ openSettingsPanel: vi.fn() }));
afterEach(() => vi.resetAllMocks());
function delayedPanel() {
  let complete!: (value: SettingsPanel) => void;
  const promise = new Promise<SettingsPanel>(resolve => { complete = resolve; });
  const panel = { url: "http://127.0.0.1:1/", expiresAt: new Date(Date.now() + 60_000).toISOString(), close: vi.fn(async () => {}) };
  return { promise, complete, panel };
}
test("concurrent requests reserve the four-panel limit before browser launch resolves", async () => {
  const delayed = delayedPanel();
  vi.mocked(openSettingsPanel).mockReturnValue(delayed.promise);
  const api = createProjectDesignKeeper();
  const requests = Array.from({ length: 4 }, () => api.openSettings());
  await expect(api.openSettings()).rejects.toThrow(/四个/);
  expect(openSettingsPanel).toHaveBeenCalledTimes(4);
  delayed.complete(delayed.panel);
  await Promise.all(requests);
  await api.closeSettings();
});
test("closing settings cancels a pending browser launch and closes its late server", async () => {
  const delayed = delayedPanel();
  vi.mocked(openSettingsPanel).mockReturnValue(delayed.promise);
  const api = createProjectDesignKeeper();
  const request = api.openSettings();
  await api.closeSettings();
  delayed.complete(delayed.panel);
  await expect(request).rejects.toThrow(/closed|关闭/i);
  expect(delayed.panel.close).toHaveBeenCalledOnce();
});
