import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, test, vi } from "vitest";
import { createMcpServer, type McpKeeperService } from "../src/mcp.js";
import type { ApplyAuthorization, ChangesetApprovalBinding } from "../src/security/approval.js";

const policy = { revision: "settings-1", easyMode: true, maxUpdateMiB: 8 };
function service(easyMode = true) {
  const echo = vi.fn(async () => ({ ok: true }));
  const binding = {
    root: "C:/project", changesetId: "test", diffDigest: `sha256:${"a".repeat(64)}`,
    expiresAt: Date.now() + 60_000, paths: [], summary: { create: 0, update: 0, delete: 0 },
    archiveActions: { archivedRecordIds: [], tombstonedRecordIds: [] }, semanticDecisionIds: [],
    policy: { ...policy, easyMode }, authorizationSource: easyMode ? "easy-policy" : "human-form"
  } as ChangesetApprovalBinding;
  return {
    scanScope: echo, searchEvidence: echo, detectDrift: echo, queryContext: echo,
    queryHistory: echo, analyzeRedundancy: echo, validatePack: echo, previewUpdate: echo,
    inspectChangesetForApproval: vi.fn(async () => binding),
    issueApplyAuthorization: vi.fn(() => Object.freeze({}) as ApplyAuthorization),
    applyUpdate: vi.fn(async () => ({ applied: true })),
    getSettings: vi.fn(async () => ({ version: 1, ...policy, easyMode })),
    openSettings: vi.fn(async () => ({ url: "http://127.0.0.1:1234/", opened: true })),
    readPreview: vi.fn(async () => ({ diff: "完整差异", complete: true, nextCursor: null }))
  };
}
async function connected(svc: McpKeeperService, run: (client: Client) => Promise<void>) {
  const server = createMcpServer(svc);
  const client = new Client({ name: "easy-tests", version: "1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b); await client.connect(a);
  try { await run(client); } finally { await client.close(); await server.close(); }
}
describe("Easy MCP policy integration", () => {
  test("Easy uses an authenticated one-use authorization without form capability", async () => {
    const svc = service();
    await connected(svc, async client => {
      expect(await client.callTool({ name: "apply_update", arguments: { root: "C:/project", changesetId: "test" } }))
        .toMatchObject({ structuredContent: { applied: true } });
    });
    expect(svc.issueApplyAuthorization).toHaveBeenCalledOnce();
    expect(svc.applyUpdate).toHaveBeenCalledOnce();
  });
  test("normal mode still requires a confirmation-capable host", async () => {
    const svc = service(false);
    await connected(svc, async client => {
      expect(await client.callTool({ name: "apply_update", arguments: { root: "C:/project", changesetId: "test" } }))
        .toMatchObject({ isError: true, structuredContent: { error: expect.stringMatching(/elicitation/) } });
    });
    expect(svc.applyUpdate).not.toHaveBeenCalled();
  });
  test("settings are readable and clickable, with no model save tool", async () => {
    const svc = service();
    await connected(svc, async client => {
      const names = (await client.listTools()).tools.map(tool => tool.name);
      expect(names).toEqual(expect.arrayContaining(["get_settings", "open_settings", "read_preview"]));
      expect(names).not.toContain("save_settings");
      expect(await client.callTool({ name: "get_settings", arguments: {} })).toMatchObject({ structuredContent: { easyMode: true } });
      expect(await client.callTool({ name: "open_settings", arguments: {} })).toMatchObject({ structuredContent: { opened: true } });
      expect(await client.callTool({ name: "read_preview", arguments: { root: "C:/project", changesetId: "test" } }))
        .toMatchObject({ structuredContent: { diff: "完整差异", complete: true } });
    });
  });
  test("Easy accepts a 3 MiB file through the tool schema", async () => {
    const svc = service();
    await connected(svc, async client => {
      expect(await client.callTool({ name: "preview_update", arguments: {
        root: "C:/project", changes: [{ path: "docs/project-design/example.md", content: "x".repeat(3 * 1024 * 1024) }]
      } })).toMatchObject({ structuredContent: { ok: true } });
    });
    expect(svc.previewUpdate).toHaveBeenCalledOnce();
  });
  test("configured validation supports a candidate pack beyond the old 8 MiB wire cap", async () => {
    const svc = service();
    await connected(svc, async client => {
      expect(await client.callTool({ name: "validate_pack", arguments: {
        root: "C:/project", pack: { document: "x".repeat(9 * 1024 * 1024) }
      } })).toMatchObject({ structuredContent: { ok: true } });
    });
    expect(svc.validatePack).toHaveBeenCalledOnce();
  });
});
