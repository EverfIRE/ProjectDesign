import { execFile } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { promisify } from "node:util";
import { z } from "zod";
import { SettingsRevisionConflictError, type SettingsStore } from "./store.js";
import { settingsHtml } from "./ui.js";

export interface SettingsPanel { url: string; expiresAt: string; close(): Promise<void> }
export interface SettingsPanelOptions { launch?: (privateBrowserUrl: string) => Promise<void> }
const execute = promisify(execFile);
async function launchBrowser(url: string): Promise<void> {
  const options = { windowsHide: true, timeout: 15_000 };
  try {
    if (process.platform === "win32") await execute("rundll32.exe", ["url.dll,FileProtocolHandler", url], options);
    else if (process.platform === "darwin") await execute("open", [url], options);
    else await execute("xdg-open", [url], options);
  } catch {
    // Child-process errors can contain command arguments, including the capability.
    throw new Error("无法打开本机浏览器。请检查默认浏览器配置后重新打开 Keeper 设置。");
  }
}
const saveSchema = z.object({
  expectedRevision: z.string().min(1).max(128),
  values: z.object({ easyMode: z.boolean(), maxUpdateMiB: z.number().int().min(1).max(64) }).strict()
}).strict();
function json(response: ServerResponse, status: number, value: unknown) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(value));
}
async function body(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let count = 0;
  for await (const chunk of request) {
    count += chunk.length;
    if (count > 4096) throw Object.assign(new Error("请求过大。"), { status: 413 });
    chunks.push(Buffer.from(chunk));
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

/** The private URL is sent directly to the OS browser, never returned to an MCP caller. */
export async function openSettingsPanel(store: SettingsStore, options: SettingsPanelOptions = {}): Promise<SettingsPanel> {
  const secret = randomBytes(32).toString("base64url");
  const nonce = randomBytes(18).toString("base64url");
  const expires = Date.now() + 15 * 60_000;
  let origin = "";
  const server = createServer((request, response) => {
    response.setHeader("cache-control", "no-store");
    response.setHeader("referrer-policy", "no-referrer");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("x-frame-options", "DENY");
    response.setHeader("content-security-policy", `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`);
    void (async () => {
      if (Date.now() >= expires) return json(response, 410, { error: "设置页面已过期，请重新打开。" });
      if (request.headers.host !== new URL(origin).host || (request.headers.origin && request.headers.origin !== origin)) {
        return json(response, 403, { error: "拒绝非本机来源。" });
      }
      if (request.method === "GET" && request.url === "/") {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(settingsHtml(nonce));
        return;
      }
      if (request.url !== "/api/settings") return json(response, 404, { error: "页面不存在。" });
      if (request.method === "GET") return json(response, 200, await store.read());
      if (request.method !== "POST") return json(response, 405, { error: "不支持此操作。" });
      const token = request.headers["x-keeper-settings-session"];
      if (request.headers.origin !== origin || typeof token !== "string" || token.length !== secret.length || !timingSafeEqual(Buffer.from(token), Buffer.from(secret))) {
        return json(response, 403, { error: "设置会话无效，请重新打开设置。" });
      }
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers["content-type"] ?? "")) {
        return json(response, 415, { error: "必须使用 JSON。" });
      }
      const input = saveSchema.parse(await body(request));
      return json(response, 200, await store.save(input.values, input.expectedRevision));
    })().catch((error: unknown) => {
      if (response.destroyed) return;
      const status = error instanceof SettingsRevisionConflictError ? 409
        : (error as { status?: number }).status === 413 ? 413
        : error instanceof z.ZodError || error instanceof SyntaxError ? 400 : 500;
      json(response, status, { error: status === 409 ? (error as Error).message : status === 413 ? "请求过大。" : status === 400 ? "设置格式无效，请输入 1–64 的整数。" : "无法读取或保存设置，请检查本机设置文件后重试。" });
    });
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.maxHeadersCount = 32;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Unable to start settings panel");
  origin = `http://127.0.0.1:${address.port}`;
  server.unref();
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    clearTimeout(timer);
    await new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); });
  };
  const timer = setTimeout(() => { void close(); }, 15 * 60_000);
  timer.unref();
  const url = `${origin}/`;
  try { await (options.launch ?? launchBrowser)(`${url}#${secret}`); }
  catch { await close(); throw new Error("无法打开本机浏览器，请检查默认浏览器配置后重试。"); }
  return { url, expiresAt: new Date(expires).toISOString(), close };
}
