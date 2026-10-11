import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createProjectDesignKeeper } from "../src/index.js";
import { createMcpServer, type McpKeeperService } from "../src/mcp.js";
import { keeperLimits } from "../src/security/limits.js";
import type { ApplyAuthorization, ChangesetApprovalBinding } from "../src/security/approval.js";
import { writeCanonicalPackFixture, writeV3PackFixture } from "./canonical-pack-fixture.js";
import { createProjectFixture, removeProjectFixture, type ProjectFixture } from "./fixtures.js";

const expectedTools = [
  "analyze_redundancy",
  "apply_update",
  "detect_drift",
  "preview_update",
  "query_context",
  "query_history",
  "scan_scope",
  "search_evidence",
  "validate_pack"
] as const;

let fixture: ProjectFixture | undefined;

beforeEach(async () => {
  fixture = await createProjectFixture();
});

afterEach(async () => {
  await removeProjectFixture(fixture);
  fixture = undefined;
});

function currentFixture(): ProjectFixture {
  if (!fixture) throw new Error("fixture was not created");
  return fixture;
}

async function connectedClient(form = false): Promise<{ client: Client; server: McpServer }> {
  const server = await createProjectDesignKeeper().createMcpServer();
  return connectServer(server, form);
}

async function connectServer(server: McpServer, form = false): Promise<{ client: Client; server: McpServer }> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client(
    { name: "project-design-keeper-mcp-test", version: "0.1.0" },
    form ? { capabilities: { elicitation: { form: {} } } } : undefined
  );
  if (form) {
    client.setRequestHandler(ElicitRequestSchema, async (request) => {
      const suffix = /final eight hexadecimal digest characters: ([a-f0-9]{8})\b/u.exec(String(request.params.message))?.[1];
      if (!suffix) throw new Error("approval digest suffix was not elicited");
      return { action: "accept", content: { decision: "approve", confirmation: suffix } };
    });
  }
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, server };
}

function stubService(overrides: Partial<McpKeeperService> = {}): McpKeeperService {
  const echo = async (input: Record<string, unknown>) => ({ received: input });
  const inspectChangesetForApproval = vi.fn(async (input: Record<string, unknown>): Promise<ChangesetApprovalBinding> => {
    const adapter = input.changeset as Record<string, unknown> | undefined;
    return {
      root: String(input.root),
      changesetId: String(input.changesetId ?? adapter?.changesetId),
      diffDigest: `sha256:${"a".repeat(64)}`,
      expiresAt: Date.now() + 60_000,
      paths: [],
      summary: { create: 0, update: 0, delete: 0 },
      archiveActions: { archivedRecordIds: [], tombstonedRecordIds: [] },
      semanticDecisionIds: []
    } as ChangesetApprovalBinding;
  });
  return {
    scanScope: vi.fn(echo),
    searchEvidence: vi.fn(echo),
    detectDrift: vi.fn(echo),
    queryContext: vi.fn(echo),
    queryHistory: vi.fn(echo),
    analyzeRedundancy: vi.fn(echo),
    previewUpdate: vi.fn(echo),
    inspectChangesetForApproval,
    issueApplyAuthorization: vi.fn(() => Object.freeze({}) as ApplyAuthorization),
    applyUpdate: vi.fn(echo),
    validatePack: vi.fn(echo),
    ...overrides
  };
}

async function withService(service: McpKeeperService, run: (client: Client) => Promise<void>, form = false): Promise<void> {
  const { client, server } = await connectServer(createMcpServer(service), form);
  try {
    await run(client);
  } finally {
    await client.close();
    await server.close();
  }
}

async function withClient(run: (client: Client) => Promise<void>, form = false): Promise<void> {
  const { client, server } = await connectedClient(form);
  try {
    await run(client);
  } finally {
    await client.close();
    await server.close();
  }
}

async function withIsolatedClient(run: (client: Client) => Promise<void>, form = false): Promise<void> {
  const cacheDirectory = await mkdtemp(join(tmpdir(), "project-design-mcp-isolated-"));
  const { client, server } = await connectServer(
    await createProjectDesignKeeper({ cacheDirectory }).createMcpServer(),
    form
  );
  try {
    await run(client);
  } finally {
    await client.close();
    await server.close();
    await rm(cacheDirectory, { recursive: true, force: true });
  }
}

function expectProtocolResult(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  expect(result).toMatchObject({
    content: [{ type: "text", text: expect.any(String) }],
    structuredContent: expect.any(Object)
  });
  expect(result.isError).not.toBe(true);
  const structured = result.structuredContent as Record<string, unknown>;
  const content = result.content as Array<{ type: string; text: string }>;
  expect(JSON.parse(content[0].text)).toEqual(structured);
  return structured;
}

describe("Project Design Keeper MCP protocol", () => {
  test("lists exactly nine tools with safe instructions and accurate annotations", async () => {
    await withClient(async (client) => {
      const listed = await client.listTools();
      expect(listed.tools.map((tool) => tool.name).sort()).toEqual(expectedTools);

      const instructions = client.getInstructions() ?? "";
      expect(instructions.slice(0, 512)).toMatch(
        /scan\/search.*preview.*show diff\/conflicts.*explicit user confirmation.*apply.*unexpired change-set/is
      );

      const byName = Object.fromEntries(listed.tools.map((tool) => [tool.name, tool]));
      for (const name of ["scan_scope", "search_evidence", "detect_drift", "query_context", "query_history", "analyze_redundancy", "validate_pack"]) {
        expect(byName[name].annotations).toMatchObject({
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false
        });
      }
      expect(byName.preview_update.annotations).toMatchObject({
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: false
      });
      expect(byName.apply_update.annotations).toMatchObject({
        readOnlyHint: false,
        destructiveHint: true,
        openWorldHint: false
      });
      expect(byName.apply_update.annotations).not.toHaveProperty("idempotentHint", true);
    });
  });

  test("publishes nonempty strict JSON schemas for every tool", async () => {
    await withClient(async (client) => {
      const listed = await client.listTools();
      const schemas = Object.fromEntries(listed.tools.map((tool) => [tool.name, tool.inputSchema]));
      expect(Object.keys(schemas).sort()).toEqual(expectedTools);

      const expectedProperties: Record<string, string[]> = {
        scan_scope: ["root", "path", "previousSnapshot", "view", "cursor", "limit"],
        search_evidence: ["root", "path", "query", "domain", "domains", "status", "statuses"],
        detect_drift: ["root", "path", "previousSnapshot", "sourceRevision", "pack", "requiredEvidence", "view", "cursor", "limit"],
        query_context: ["root", "path", "query", "paths", "module", "modules", "maxRecords", "maxEvidence"],
        query_history: ["root", "query", "recordIds", "paths", "modules", "includeTombstones", "cursor", "limit"],
        analyze_redundancy: ["root", "query", "paths", "modules"],
        preview_update: ["root", "path", "changes", "expectedContentHash", "pack", "analysisId", "redundancyDecisions"],
        apply_update: ["root", "changesetId", "changeset"],
        validate_pack: ["root", "pack"]
      };
      const expectedRequired: Record<string, string[]> = {
        scan_scope: [],
        search_evidence: ["query"],
        detect_drift: [],
        query_context: [],
        query_history: ["root"],
        analyze_redundancy: ["root"],
        preview_update: ["root", "changes"],
        apply_update: ["root"],
        validate_pack: ["root", "pack"]
      };

      for (const [name, propertyNames] of Object.entries(expectedProperties)) {
        const schema = schemas[name] as {
          properties?: Record<string, unknown>;
          required?: string[];
          additionalProperties?: boolean;
        };
        expect(Object.keys(schema.properties ?? {}).sort()).toEqual([...propertyNames].sort());
        expect([...(schema.required ?? [])].sort()).toEqual([...expectedRequired[name]].sort());
        expect(schema.additionalProperties).toBe(false);
        expect(JSON.stringify(schema)).not.toMatch(/"(?:approved|approval|confirmation|token|nonce|digest|diffDigest)"\s*:/iu);
      }
    });
  });

  test("rejects primitive snapshots, source revisions, and changesets at the schema boundary", async () => {
    const service = stubService();
    await withService(service, async (client) => {
      for (const request of [
        { name: "scan_scope", arguments: {} },
        { name: "scan_scope", arguments: { root: "C:/project", previousSnapshot: 42 } },
        { name: "scan_scope", arguments: { root: "C:/project", view: "everything" } },
        { name: "scan_scope", arguments: { root: "C:/project", limit: 1001 } },
        { name: "detect_drift", arguments: { root: "C:/project", sourceRevision: 42 } },
        { name: "apply_update", arguments: { root: "C:/project" } },
        { name: "apply_update", arguments: { root: "C:/project", changeset: { changesetId: 42 } } },
        { name: "apply_update", arguments: { root: "C:/project", changesetId: 42 } }
      ]) {
        await expect(client.callTool(request)).resolves.toMatchObject({ isError: true });
      }
    }, true);
    expect(service.scanScope).not.toHaveBeenCalled();
    expect(service.detectDrift).not.toHaveBeenCalled();
    expect(service.applyUpdate).not.toHaveBeenCalled();
  });

  test("preserves documented snapshot and source-revision extensions", async () => {
    const service = stubService();
    const fingerprint = `sha256:${"a".repeat(64)}`;
    const snapshot = { files: { "Source/file.cpp": fingerprint }, extension: { branch: "design" } };
    const revision = { files: { "Source/file.cpp": fingerprint }, kind: "git", extension: ["kept"] };
    const pack = { requiredEvidence: ["garden"], extension: { nested: true } };
    const changeset = { changesetId: "123e4567-e89b-12d3-a456-426614174000" };

    await withService(service, async (client) => {
      expectProtocolResult(await client.callTool({
        name: "scan_scope",
        arguments: { root: "C:/project", previousSnapshot: { "Source/file.cpp": fingerprint } }
      }));
      expectProtocolResult(await client.callTool({ name: "scan_scope", arguments: { root: "C:/project", previousSnapshot: snapshot } }));
      expectProtocolResult(await client.callTool({ name: "detect_drift", arguments: { root: "C:/project", sourceRevision: revision, pack } }));
      expectProtocolResult(await client.callTool({ name: "apply_update", arguments: { root: "C:/project", changeset } }));
    }, true);

    expect(service.scanScope).toHaveBeenNthCalledWith(1, { root: "C:/project", previousSnapshot: { "Source/file.cpp": fingerprint } });
    expect(service.scanScope).toHaveBeenNthCalledWith(2, { root: "C:/project", previousSnapshot: snapshot });
    expect(service.detectDrift).toHaveBeenCalledWith({ root: "C:/project", sourceRevision: revision, pack });
    expect(service.applyUpdate).toHaveBeenCalledWith(
      { root: "C:/project", changeset },
      expect.any(Object),
      expect.any(Object)
    );
    const issuedIdentity = vi.mocked(service.issueApplyAuthorization).mock.calls[0][1];
    const appliedIdentity = vi.mocked(service.applyUpdate).mock.calls[0][2];
    expect(issuedIdentity).toMatchObject({ requestId: expect.anything() });
    expect(appliedIdentity).toBe(issuedIdentity);
  });

  test("manually rejects a non-accept elicitation action with otherwise valid content", async () => {
    const service = stubService();
    const server = createMcpServer(service);
    vi.spyOn(server.server, "elicitInput").mockResolvedValue({
      action: "unexpected",
      content: { decision: "approve", confirmation: "aaaaaaaa" }
    } as never);
    const { client } = await connectServer(server, true);
    try {
      const result = await client.callTool({
        name: "apply_update",
        arguments: {
          root: "C:/project",
          changesetId: "123e4567-e89b-12d3-a456-426614174000"
        }
      });
      expect(result).toMatchObject({ isError: true });
      expect(service.applyUpdate).not.toHaveBeenCalled();
    } finally {
      await client.close();
      await server.close();
    }
  });

  test("summarizes archive actions and escapes approval-message format controls", async () => {
    const service = stubService({
      inspectChangesetForApproval: vi.fn(async () => ({
        root: "C:/project\u200b\u2028\u202e\u2060root",
        changesetId: "123e4567-e89b-12d3-a456-426614174000",
        diffDigest: `sha256:${"a".repeat(64)}`,
        expiresAt: Date.now() + 60_000,
        paths: ["docs/project-design/archive/\u2060\u202ereordered.jsonl"],
        summary: { create: 1, update: 0, delete: 0 },
        archiveActions: {
          archivedRecordIds: ["record.archived"],
          tombstonedRecordIds: ["record.tombstoned"]
        },
        semanticDecisionIds: []
      } as ChangesetApprovalBinding))
    });
    const server = createMcpServer(service);
    const elicitation = vi.spyOn(server.server, "elicitInput").mockResolvedValue({
      action: "accept",
      content: { decision: "approve", confirmation: "aaaaaaaa" }
    });
    const { client } = await connectServer(server, true);
    try {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: "C:/project", changesetId: "123e4567-e89b-12d3-a456-426614174000" }
      });
      expect(result.isError).not.toBe(true);
      const message = String(elicitation.mock.calls[0][0].message);
      expect(message).toContain("Records: 1 archive, 1 tombstone; semantic confirmations: 0");
      expect(message).not.toContain("record.archived");
      expect(message).not.toContain("record.tombstoned");
      expect(message).toContain("\\u200b");
      expect(message).toContain("\\u2028");
      expect(message).toContain("\\u202e");
      expect(message).toContain("\\u2060");
      expect(message).not.toMatch(/[\p{Cf}\p{Zl}\p{Zp}]/u);
    } finally {
      await client.close();
      await server.close();
    }
  });

  test("bounds approval display for long Unicode roots and large record lists without shortening the authorization", async () => {
    const binding: ChangesetApprovalBinding = {
      root: `C:/${"项目😀".repeat(1000)}/repository`,
      changesetId: "123e4567-e89b-12d3-a456-426614174000",
      diffDigest: `sha256:${"a".repeat(64)}`,
      expiresAt: Date.now() + 60_000,
      paths: Array.from({ length: 200 }, (_, index) => `docs/project-design/file-${index}.md`),
      summary: { create: 120, update: 60, delete: 20 },
      archiveActions: {
        archivedRecordIds: Array.from({ length: 500 }, (_, index) => `archived.${index}`),
        tombstonedRecordIds: Array.from({ length: 500 }, (_, index) => `tombstoned.${index}`)
      },
      semanticDecisionIds: Array.from({ length: 500 }, (_, index) => `confirmed.${index}`)
    };
    const service = stubService({ inspectChangesetForApproval: vi.fn(async () => binding) });
    const server = createMcpServer(service);
    const elicitation = vi.spyOn(server.server, "elicitInput").mockResolvedValue({
      action: "accept", content: { decision: "approve", confirmation: "aaaaaaaa" }
    });
    const { client } = await connectServer(server, true);
    try {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: "C:/project", changesetId: binding.changesetId }
      });
      expect(result.isError).not.toBe(true);
      const message = String(elicitation.mock.calls[0][0].message);
      expect(Buffer.byteLength(message, "utf8")).toBeLessThanOrEqual(1536);
      expect(message.split("\n").length).toBeLessThanOrEqual(8);
      expect(message).toContain("(shortened)");
      expect(message).toContain("Files: 120 create, 60 update, 20 delete");
      expect(message).toContain("Records: 500 archive, 500 tombstone; semantic confirmations: 500");
      expect(service.issueApplyAuthorization).toHaveBeenCalledWith(binding, expect.any(Object));
      expect(binding.paths).toHaveLength(200);
      expect(binding.archiveActions.archivedRecordIds).toHaveLength(500);
      expect(binding.semanticDecisionIds).toHaveLength(500);
    } finally {
      await client.close();
      await server.close();
    }
  });

  test("rejects undocumented changeset extensions at the schema boundary", async () => {
    const service = stubService();
    await withService(service, async (client) => {
      await expect(client.callTool({
        name: "apply_update",
        arguments: { root: "C:/project", changeset: { changesetId: "123e4567-e89b-12d3-a456-426614174000", extension: { nested: true } } }
      })).resolves.toMatchObject({ isError: true });
    });
    expect(service.applyUpdate).not.toHaveBeenCalled();
  });

  test("rejects oversized preview input without calling the service", async () => {
    const service = stubService();
    await withService(service, async (client) => {
      const result = await client.callTool({
        name: "preview_update",
        arguments: {
          root: "C:/project",
          changes: Array.from({ length: 201 }, (_, index) => ({
            path: `docs/project-design/${index}.md`,
            content: "x"
          }))
        }
      });
      expect(result).toMatchObject({ isError: true });
    });
    expect(service.previewUpdate).not.toHaveBeenCalled();
  });

  test.each([
    {
      name: "detect_drift pack documents",
      request: {
        name: "detect_drift",
        arguments: { root: "C:/project", pack: { documents: Array.from({ length: 257 }, () => ({})) } }
      },
      serviceMethod: "detectDrift" as const
    },
    {
      name: "preview_update pack records",
      request: {
        name: "preview_update",
        arguments: {
          root: "C:/project",
          changes: [{ path: ".agents/skills/project-design-context/bounded.md", content: "x" }],
          pack: { records: Array.from({ length: 10_001 }, () => ({})) }
        }
      },
      serviceMethod: "previewUpdate" as const
    },
    {
      name: "validate_pack record evidence",
      request: {
        name: "validate_pack",
        arguments: { root: "C:/project", pack: { records: [{ evidence: Array.from({ length: 129 }, () => "x") }] } }
      },
      serviceMethod: "validatePack" as const
    },
    {
      name: "validate_pack record impact",
      request: {
        name: "validate_pack",
        arguments: { root: "C:/project", pack: { records: [{ impact: Array.from({ length: 129 }, () => "x") }] } }
      },
      serviceMethod: "validatePack" as const
    }
  ])("rejects oversized $name before service work", async ({ request, serviceMethod }) => {
    const service = stubService();
    await withService(service, async (client) => {
      await expect(client.callTool(request)).resolves.toMatchObject({ isError: true });
    });
    expect(service[serviceMethod]).not.toHaveBeenCalled();
  });

  test("rejects schema-valid MCP arguments over 8 MiB without calling the service", async () => {
    const service = stubService();
    await withService(service, async (client) => {
      const result = await client.callTool({
        name: "validate_pack",
        arguments: {
          root: "C:/project",
          pack: { extension: "x".repeat(keeperLimits.mcpArgumentBytes) }
        }
      });
      expect(result).toMatchObject({
        isError: true,
        structuredContent: { error: expect.stringMatching(/MCP arguments.*8388608 bytes/i) }
      });
      expect(JSON.stringify(result)).not.toContain("C:/project");
      expect(Buffer.byteLength(JSON.stringify(result), "utf8")).toBeLessThanOrEqual(1024 * 1024);
    });
    expect(service.validatePack).not.toHaveBeenCalled();
  });

  test("accepts a query within the documented 32 KiB limit", async () => {
    const service = stubService();
    const query = "x".repeat(5 * 1024);
    await withService(service, async (client) => {
      expectProtocolResult(await client.callTool({
        name: "search_evidence",
        arguments: { root: "C:/project", query }
      }));
    });
    expect(service.searchEvidence).toHaveBeenCalledWith({ root: "C:/project", query });
  });

  test("redacts Windows, UNC, POSIX, cache, and output absolute paths from tool errors", async () => {
    const privatePaths = [
      "C:\\Users\\private-user\\keeper-cache\\changeset.json",
      "\\\\private-server\\keeper-share\\private-user\\changeset.json",
      "//private-server/keeper-share/private-user/changeset.json",
      "/home/private-user/.cache/project-design-keeper/changeset.json",
      "[C:\\Users\\private-user\\keeper cache\\changeset.json]",
      "<C:/Users/private-user/x>",
      "[//server/share/x]",
      "<\\\\server\\share\\x>",
      "[/home/private/x]",
      "</home/private/x>",
      "wrapper([<C:\\Users\\private-user\\nested path\\x>])",
      "wrapper{[</home/private/nested path/x>]} ",
      `${currentFixture().repository}\\.keeper-cache\\private.json`,
      currentFixture().repository.replaceAll("\\", "/") + "/docs/project-design/private.md"
    ];
    const service = stubService({
      scanScope: vi.fn(async (input) => {
        throw new Error(`Cannot inspect ${String(input.root)}`);
      })
    });

    await withService(service, async (client) => {
      for (const path of privatePaths) {
        const result = await client.callTool({ name: "scan_scope", arguments: { root: path } });
        expect(result).toMatchObject({ isError: true, structuredContent: { error: expect.stringContaining("Cannot inspect") } });
        const serialized = JSON.stringify(result);
        expect(serialized).not.toContain(path);
        expect(serialized).not.toContain("private-user");
        for (const sensitiveToken of ["keeper cache", "server/share", "server\\share", "home/private"]) {
          if (path.includes(sensitiveToken)) expect(serialized).not.toContain(sensitiveToken);
        }
        expect(serialized).toContain("<absolute-path>");
        expect((result.structuredContent as { error: string }).error).not.toContain("\n");
      }
    });

    const relativeService = stubService({
      scanScope: vi.fn(async () => {
        throw new Error("Target stale: docs/project-design/index.md");
      })
    });
    await withService(relativeService, async (client) => {
      const result = await client.callTool({ name: "scan_scope", arguments: { root: "C:/project" } });
      expect((result.structuredContent as { error: string }).error).toContain("docs/project-design/index.md");
    });
  });

  test("calls all nine tools through the SDK with content and structuredContent", async () => {
    const project = currentFixture();
    const legacyPack = await writeCanonicalPackFixture(project);
    await mkdir(join(project.repository, "docs", "project-design"), { recursive: true });
    await writeFile(join(project.repository, "docs", "project-design", "manifest.json"), `${JSON.stringify(legacyPack, null, 2)}\n`, "utf8");
    await withIsolatedClient(async (client) => {
      expectProtocolResult(await client.callTool({ name: "scan_scope", arguments: { root: project.repository } }));
      expectProtocolResult(await client.callTool({
        name: "search_evidence",
        arguments: { root: project.repository, query: "moon-garden", domains: ["gameplay"], statuses: ["observed"] }
      }));
      expectProtocolResult(await client.callTool({
        name: "detect_drift",
        arguments: {
          root: project.repository,
          pack: { requiredEvidence: ["moon-garden", "sun-garden"], nested: { preserved: true } }
        }
      }));
      const legacyContext = expectProtocolResult(await client.callTool({
        name: "query_context",
        arguments: { root: project.repository, query: "Base statement 1" }
      }));
      expect(legacyContext).toMatchObject({ records: [{ record: { id: "record.1" } }] });
      const legacyValidation = expectProtocolResult(await client.callTool({
        name: "validate_pack",
        arguments: { root: project.repository, pack: legacyPack }
      }));
      expect(legacyValidation).toMatchObject({ valid: true, errors: [] });

      const historyPack = await writeV3PackFixture(project);
      await writeFile(join(project.repository, "docs", "project-design", "manifest.json"), `${JSON.stringify(historyPack, null, 2)}\n`, "utf8");
      expectProtocolResult(await client.callTool({
        name: "query_history",
        arguments: { root: project.repository, query: "moon-garden", recordIds: ["record.1"], limit: 50 }
      }));
      expectProtocolResult(await client.callTool({
        name: "analyze_redundancy",
        arguments: { root: project.repository, query: "moon-garden", modules: ["garden"] }
      }));
      const preview = expectProtocolResult(await client.callTool({
        name: "preview_update",
        arguments: {
          root: project.repository,
          changes: [{
            path: ".agents/skills/project-design-context/mcp.md",
            managedBlock: { recordId: "mcp-record", content: "# MCP\n" }
          }]
        }
      }));
      expect(preview.changesetId).toEqual(expect.any(String));

      const applied = expectProtocolResult(await client.callTool({
        name: "apply_update",
        arguments: {
          root: project.repository,
          changeset: { changesetId: preview.changesetId }
        }
      }));
      expect(applied).toMatchObject({ applied: true, changesetId: preview.changesetId });
    }, true);
  });

  test("keeps the complete MCP envelope within one MiB without duplicating large structured results", async () => {
    const service = stubService({
      scanScope: vi.fn(async () => ({ payload: "x".repeat(700 * 1024) }))
    });
    await withService(service, async (client) => {
      const result = await client.callTool({ name: "scan_scope", arguments: { root: "C:/project" } });
      expect(result.isError).not.toBe(true);
      expect((result.structuredContent as { payload: string }).payload).toHaveLength(700 * 1024);
      expect(Buffer.byteLength(JSON.stringify(result), "utf8")).toBeLessThanOrEqual(1024 * 1024);
    });

    const oversized = stubService({
      scanScope: vi.fn(async () => ({ payload: "x".repeat(2 * 1024 * 1024) }))
    });
    await withService(oversized, async (client) => {
      const result = await client.callTool({ name: "scan_scope", arguments: { root: "C:/project" } });
      expect(result).toMatchObject({ isError: true, structuredContent: { error: expect.stringMatching(/one MiB|response budget/i) } });
      expect(Buffer.byteLength(JSON.stringify(result), "utf8")).toBeLessThanOrEqual(1024 * 1024);
    });
  });

  test("does not persist a real preview whose complete MCP-facing result exceeds one MiB", async () => {
    const cacheDirectory = await mkdtemp(join(tmpdir(), "project-design-mcp-result-budget-"));
    const server = await createProjectDesignKeeper({ cacheDirectory }).createMcpServer();
    const { client, server: connected } = await connectServer(server);
    try {
      const result = await client.callTool({
        name: "preview_update",
        arguments: {
          root: currentFixture().repository,
          changes: [{
            path: ".agents/skills/project-design-context/mcp-result-budget.md",
            managedBlock: { recordId: "mcp-result-budget", content: "z".repeat(600 * 1024) }
          }]
        }
      });

      expect(result).toMatchObject({
        isError: true,
        structuredContent: { error: expect.stringMatching(/one MiB|response budget/i) }
      });
      await expect(readdir(join(cacheDirectory, "changesets"))).resolves.toEqual([]);
    } finally {
      await client.close();
      await connected.close();
      await rm(cacheDirectory, { recursive: true, force: true });
    }
  });

  test("rejects malformed input at the MCP schema boundary", async () => {
    await withClient(async (client) => {
      const malformed = await client.callTool({
        name: "scan_scope",
        arguments: { root: 42, unexpected: true }
      });
      expect(malformed).toMatchObject({ isError: true, content: [{ type: "text", text: expect.stringMatching(/invalid|root/i) }] });

      const malformedChange = await client.callTool({
        name: "preview_update",
        arguments: { root: currentFixture().repository, changes: [{ path: 7, content: "bad" }] }
      });
      expect(malformedChange).toMatchObject({ isError: true });
    });
  });

  test("requires a candidate pack at the MCP boundary for project-design document changes", async () => {
    await withClient(async (client) => {
      const result = await client.callTool({
        name: "preview_update",
        arguments: {
          root: currentFixture().repository,
          changes: [{
            path: "docs/project-design/index.md",
            managedBlock: { recordId: "doc.index", content: "# Index\n" }
          }]
        }
      });
      expect(result).toMatchObject({ isError: true });
    });
  });

  test("executes query_context with root, query, paths, and modules", async () => {
    await withClient(async (client) => {
      const result = await client.callTool({
        name: "query_context",
        arguments: {
          root: currentFixture().repository,
          query: "moon-garden task",
          paths: ["docs/设计 evidence.txt"],
          modules: ["garden"]
        }
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({ context: expect.any(Array) });
    });
  });

  test("returns useful sanitized MCP tool errors without stack traces", async () => {
    await withClient(async (client) => {
      const result = await client.callTool({
        name: "scan_scope",
        arguments: { root: currentFixture().repository, path: "../outside.txt" }
      });
      expect(result).toMatchObject({
        isError: true,
        content: [{ type: "text", text: expect.stringMatching(/outside|scope|path|escape/i) }],
        structuredContent: { error: expect.any(String) }
      });
      const message = ((result.content as Array<{ type: string; text: string }>)[0]).text;
      expect(message).not.toMatch(/\n\s*at |[A-Za-z]:\\.*:\d+:\d+/u);
    });
  });

  test("importing the public entry does not auto-connect a stdio transport", async () => {
    const imported = await import("../src/index.js");
    expect(imported.projectDesignKeeper).toBeDefined();
    expect(process.stdin.listenerCount("data")).toBe(0);
  });
});
