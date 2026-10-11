import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { createHash, createHmac } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { createProjectDesignKeeper } from "../src/index.js";
import {
  createApplyApprovalAuthority,
  type ChangesetApprovalBinding
} from "../src/security/approval.js";
import { writeV3PackFixture } from "./canonical-pack-fixture.js";
import type { ServiceOptions } from "../src/types/schema.js";
import { createProjectFixture, removeProjectFixture, type ProjectFixture } from "./fixtures.js";

type ElicitationAction = "accept" | "decline" | "cancel";
type ElicitationReply = {
  action: ElicitationAction;
  content?: Record<string, string>;
};

let fixture: ProjectFixture | undefined;

beforeEach(async () => {
  fixture = await createProjectFixture();
});

afterEach(async () => {
  await removeProjectFixture(fixture);
  fixture = undefined;
});

function project(): ProjectFixture {
  if (!fixture) throw new Error("fixture was not created");
  return fixture;
}

function cacheDirectory(): string {
  return join(project().root, "approval-cache");
}

function targetFile(): string {
  return join(project().repository, ".agents", "skills", "project-design-context", "approval.md");
}

async function preview(api: ReturnType<typeof createProjectDesignKeeper>) {
  return api.previewUpdate({
    root: project().repository,
    changes: [{
      path: ".agents/skills/project-design-context/approval.md",
      managedBlock: {
        recordId: "approval.record",
        content: "# Host approval\n\nPRIVATE-FILE-BODY-MUST-NOT-BE-ELICITED\n"
      }
    }]
  });
}

async function connect(
  server: McpServer,
  options: {
    form?: boolean;
    onElicit?: (request: Parameters<Parameters<Client["setRequestHandler"]>[1]>[0]) => Promise<ElicitationReply>;
  } = {}
): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client(
    { name: "apply-approval-test", version: "1.0.0" },
    options.form ? { capabilities: { elicitation: { form: {} } } } : undefined
  );
  if (options.onElicit) {
    client.setRequestHandler(ElicitRequestSchema, async (request) => options.onElicit!(request));
  }
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
}

async function withApplyClient(
  api: ReturnType<typeof createProjectDesignKeeper>,
  options: Parameters<typeof connect>[1],
  run: (client: Client) => Promise<void>
): Promise<void> {
  const server = await api.createMcpServer() as McpServer;
  const client = await connect(server, options);
  try {
    await run(client);
  } finally {
    await client.close();
    await server.close();
  }
}

function suffixFrom(message: string): string {
  const suffix = /final eight hexadecimal digest characters: ([a-f0-9]{8})\b/u.exec(message)?.[1];
  if (!suffix) throw new Error("approval message did not contain an eight-character digest suffix");
  return suffix;
}

function canonicalJson(value: unknown): string {
  const normalize = (candidate: unknown): unknown => {
    if (Array.isArray(candidate)) return candidate.map(normalize);
    if (candidate && typeof candidate === "object") {
      return Object.fromEntries(Object.entries(candidate as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right, "en-US"))
        .map(([key, nested]) => [key, normalize(nested)]));
    }
    return candidate;
  };
  return JSON.stringify(normalize(value));
}

async function rewriteAuthenticatedChangeset(
  changesetId: string,
  mutate: (changeset: Record<string, unknown>) => void
): Promise<void> {
  const changesetPath = join(cacheDirectory(), "changesets", `${changesetId}.json`);
  const signaturePath = join(cacheDirectory(), "changesets", `${changesetId}.sig.json`);
  const keyPath = join(cacheDirectory(), "changeset-hmac.key");
  const changeset = JSON.parse(await readFile(changesetPath, "utf8")) as Record<string, unknown>;
  mutate(changeset);
  const key = await readFile(keyPath);
  const mac = createHmac("sha256", key).update(canonicalJson(changeset), "utf8").digest("hex");
  await writeFile(changesetPath, `${JSON.stringify(changeset, null, 2)}\n`, "utf8");
  await writeFile(signaturePath, `${JSON.stringify({
    version: 1,
    algorithm: "hmac-sha256",
    changesetId,
    mac
  }, null, 2)}\n`, "utf8");
}

function approvalBinding(overrides: Partial<ChangesetApprovalBinding> = {}): ChangesetApprovalBinding {
  return {
    root: "C:\\canonical-project",
    changesetId: "123e4567-e89b-12d3-a456-426614174000",
    diffDigest: `sha256:${"a".repeat(64)}`,
    expiresAt: 2_000_000,
    paths: ["docs/project-design/index.md"],
    summary: { create: 1, update: 0, delete: 0 },
    archiveActions: { archivedRecordIds: [], tombstonedRecordIds: [] },
    semanticDecisionIds: ["record.required"],
    ...overrides
  } as ChangesetApprovalBinding;
}

describe("host-mediated apply approval", () => {
  test("fails closed when the client lacks form elicitation", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);

    await withApplyClient(api, {}, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId: pending.changesetId }
      });
      expect(result).toMatchObject({ isError: true });
    });

    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(join(cacheDirectory(), "changesets", `${String(pending.changesetId)}.json`), "utf8"))
      .resolves.toContain(String(pending.changesetId));
    await expect(readFile(join(cacheDirectory(), "changesets", `${String(pending.changesetId)}.sig.json`), "utf8"))
      .resolves.toContain("hmac-sha256");
  });

  test("elicits an exact typed confirmation and applies once when accepted", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);
    const elicitations: Array<{ message: string; requestedSchema: unknown }> = [];

    await withApplyClient(api, {
      form: true,
      onElicit: async (request) => {
        const message = String(request.params.message);
        elicitations.push({ message, requestedSchema: request.params.requestedSchema });
        return {
          action: "accept",
          content: { decision: "approve", confirmation: suffixFrom(message) }
        };
      }
    }, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId: pending.changesetId }
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({ applied: true });
    });

    expect(elicitations).toHaveLength(1);
    expect(elicitations[0].message.length).toBeLessThan(16 * 1024);
    expect(elicitations[0].message).toContain("Files: 1 create, 0 update, 0 delete");
    expect(elicitations[0].message).toContain("preview_update");
    expect(elicitations[0].message).not.toContain("PRIVATE-FILE-BODY-MUST-NOT-BE-ELICITED");
    expect(elicitations[0].message).not.toContain(cacheDirectory());
    expect(JSON.stringify(elicitations[0].requestedSchema)).not.toContain("PRIVATE-FILE-BODY-MUST-NOT-BE-ELICITED");
    expect(JSON.stringify(elicitations[0].requestedSchema)).not.toContain(cacheDirectory());
    await expect(readFile(targetFile(), "utf8")).resolves.toContain("PRIVATE-FILE-BODY-MUST-NOT-BE-ELICITED");
  });

  test("keeps a 39-file approval compact with a labelled confirmation field and applies the full changeset", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const changes = Array.from({ length: 39 }, (_, index) => ({
      path: `.agents/skills/project-design-context/popup-${index}.md`,
      managedBlock: { recordId: `popup.record.${index}`, content: `# Popup regression ${index}\n` }
    }));
    const pending = await api.previewUpdate({ root: project().repository, changes });
    const binding = await api.inspectChangesetForApproval({
      root: project().repository, changesetId: pending.changesetId
    });
    const elicitations: Array<{ message: string; requestedSchema: unknown }> = [];

    await withApplyClient(api, {
      form: true,
      onElicit: async (request) => {
        const message = String(request.params.message);
        elicitations.push({ message, requestedSchema: request.params.requestedSchema });
        return { action: "accept", content: { decision: "approve", confirmation: suffixFrom(message) } };
      }
    }, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId: pending.changesetId }
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({ applied: true });
    });

    expect(elicitations).toHaveLength(1);
    const { message, requestedSchema } = elicitations[0];
    expect(Buffer.byteLength(message, "utf8")).toBeLessThanOrEqual(1536);
    expect(message.split("\n").length).toBeLessThanOrEqual(8);
    expect(suffixFrom(message.split("\n")[0])).toBe(binding.diffDigest.slice(-8));
    expect(message).toContain(binding.changesetId);
    expect(message).toContain(binding.diffDigest);
    expect(message).toContain("Files: 39 create, 0 update, 0 delete");
    expect(message).toContain("preview_update");
    expect(message).not.toContain(changes[0].path);
    expect(requestedSchema).toMatchObject({
      properties: {
        decision: { title: expect.any(String), description: expect.any(String), enum: ["approve"] },
        confirmation: {
          type: "string", title: expect.stringContaining(binding.diffDigest.slice(-8)),
          description: expect.any(String), minLength: 8, maxLength: 8
        }
      },
      required: ["decision", "confirmation"]
    });
    expect((requestedSchema as { properties: { confirmation: object } }).properties.confirmation)
      .not.toHaveProperty("default");
    expect(binding.paths).toHaveLength(39);
    for (const change of changes) {
      await expect(readFile(join(project().repository, change.path), "utf8"))
        .resolves.toContain(change.managedBlock.content);
    }
  });

  test.each(["decline", "cancel"] as const)("does not mutate when elicitation returns %s", async (action) => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);

    await withApplyClient(api, {
      form: true,
      onElicit: async () => ({ action })
    }, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId: pending.changesetId }
      });
      expect(result).toMatchObject({ isError: true });
    });

    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(join(cacheDirectory(), "changesets", `${String(pending.changesetId)}.json`), "utf8"))
      .resolves.toContain(String(pending.changesetId));
    await expect(readFile(join(cacheDirectory(), "changesets", `${String(pending.changesetId)}.sig.json`), "utf8"))
      .resolves.toContain("hmac-sha256");
  });

  test.each([
    ["malformed content", { decision: "approve" }],
    ["wrong digest suffix", { decision: "approve", confirmation: "00000000" }],
    ["wrong decision", { decision: "reject", confirmation: "00000000" }],
    ["an extra field", { decision: "approve", confirmation: "00000000", extra: "not-allowed" }]
  ] as const)("does not mutate after accepted elicitation with %s", async (_label, content) => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);

    await withApplyClient(api, {
      form: true,
      onElicit: async (request) => ({
        action: "accept",
        content: "confirmation" in content && content.confirmation === "00000000" && content.decision === "approve"
          ? content
          : content.decision === "reject"
            ? { ...content, confirmation: suffixFrom(String(request.params.message)) }
            : content
      })
    }, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId: pending.changesetId }
      });
      expect(result).toMatchObject({ isError: true });
    });

    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("does not mutate when an accepted elicitation omits content", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);

    await withApplyClient(api, {
      form: true,
      onElicit: async () => ({ action: "accept" })
    }, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId: pending.changesetId }
      });
      expect(result).toMatchObject({ isError: true });
    });

    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("re-authenticates the changeset after elicitation and rejects cache mutation", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);
    const changesetPath = join(cacheDirectory(), "changesets", `${String(pending.changesetId)}.json`);

    await withApplyClient(api, {
      form: true,
      onElicit: async (request) => {
        const cached = JSON.parse(await readFile(changesetPath, "utf8")) as {
          changes: Array<{ content?: string }>;
        };
        cached.changes[0].content = `${cached.changes[0].content ?? ""}\nTAMPERED-AFTER-INSPECTION\n`;
        await writeFile(changesetPath, `${JSON.stringify(cached, null, 2)}\n`, "utf8");
        const message = String(request.params.message);
        return {
          action: "accept",
          content: { decision: "approve", confirmation: suffixFrom(message) }
        };
      }
    }, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId: pending.changesetId }
      });
      expect(result).toMatchObject({ isError: true });
    });

    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("rejects an authenticated diff change between inspection and apply", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);
    const changesetId = String(pending.changesetId);

    await withApplyClient(api, {
      form: true,
      onElicit: async (request) => {
        await rewriteAuthenticatedChangeset(changesetId, (changeset) => {
          const changes = changeset.changes as Array<Record<string, unknown>>;
          changes[0].content = `${String(changes[0].content)}\nAUTHENTICATED-DIFF-CHANGE\n`;
          const semanticDecisionIds = changeset.semanticDecisionIds as string[];
          changeset.diffDigest = `sha256:${createHash("sha256")
            .update(canonicalJson({ changes, semanticDecisionIds }), "utf8")
            .digest("hex")}`;
        });
        const message = String(request.params.message);
        return {
          action: "accept",
          content: { decision: "approve", confirmation: suffixFrom(message) }
        };
      }
    }, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId }
      });
      expect(result).toMatchObject({ isError: true });
    });

    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("rejects an authenticated archive-action change between inspection and apply", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);
    const changesetId = String(pending.changesetId);

    await withApplyClient(api, {
      form: true,
      onElicit: async (request) => {
        await rewriteAuthenticatedChangeset(changesetId, (changeset) => {
          changeset.archiveActions = {
            archivedRecordIds: ["record.injected"],
            tombstonedRecordIds: []
          };
        });
        const message = String(request.params.message);
        return {
          action: "accept",
          content: { decision: "approve", confirmation: suffixFrom(message) }
        };
      }
    }, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId }
      });
      expect(result).toMatchObject({ isError: true });
    });

    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("rejects an accepted elicitation when the changeset expires before apply", async () => {
    let currentTime = 1_000_000;
    const api = createProjectDesignKeeper({
      cacheDirectory: cacheDirectory(),
      now: () => currentTime
    });
    const pending = await preview(api);

    await withApplyClient(api, {
      form: true,
      onElicit: async (request) => {
        currentTime += 30 * 60 * 1000;
        const message = String(request.params.message);
        return {
          action: "accept",
          content: { decision: "approve", confirmation: suffixFrom(message) }
        };
      }
    }, async (client) => {
      const result = await client.callTool({
        name: "apply_update",
        arguments: { root: project().repository, changesetId: pending.changesetId }
      });
      expect(result).toMatchObject({ isError: true });
    });

    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("direct embedded apply fails closed without an out-of-band trusted provider", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);

    await expect(api.applyUpdate({
      root: project().repository,
      changesetId: pending.changesetId
    })).rejects.toThrow(/trusted approval provider/i);
    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("does not enable direct apply when the caller mutates options after construction", async () => {
    const options: ServiceOptions = { cacheDirectory: cacheDirectory() };
    const api = createProjectDesignKeeper(options);
    const pending = await preview(api);
    options.trustedApprovalProvider = async () => ({ approved: true });

    await expect(api.applyUpdate({
      root: project().repository,
      changesetId: pending.changesetId
    })).rejects.toThrow(/trusted approval provider/i);
    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("direct embedded apply requires and invokes its trusted provider", async () => {
    const summaries: ChangesetApprovalBinding[] = [];
    const api = createProjectDesignKeeper({
      cacheDirectory: cacheDirectory(),
      trustedApprovalProvider: async (summary) => {
        summaries.push(summary);
        return { approved: true };
      }
    });
    const pending = await preview(api);

    await expect(api.applyUpdate({
      root: project().repository,
      changesetId: pending.changesetId
    })).resolves.toMatchObject({ applied: true });

    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toMatchObject({
      changesetId: pending.changesetId,
      paths: [".agents/skills/project-design-context/approval.md"],
      summary: { create: 1, update: 0, delete: 0 }
    });
    expect(summaries[0].diffDigest).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(JSON.stringify(summaries[0])).not.toContain("PRIVATE-FILE-BODY-MUST-NOT-BE-ELICITED");
  });

  test("direct embedded apply rejects a provider decline", async () => {
    const api = createProjectDesignKeeper({
      cacheDirectory: cacheDirectory(),
      trustedApprovalProvider: async () => ({ approved: false })
    });
    const pending = await preview(api);

    await expect(api.applyUpdate({
      root: project().repository,
      changesetId: pending.changesetId
    })).rejects.toThrow(/declined|approval/i);
    await expect(readFile(targetFile(), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("authenticated version-1 changesets are rejected as expired-format data", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);
    const changesetId = String(pending.changesetId);
    await rewriteAuthenticatedChangeset(changesetId, (changeset) => {
      changeset.version = 1;
      delete changeset.diffDigest;
      delete changeset.semanticDecisionIds;
    });

    await expect(api.inspectChangesetForApproval({
      root: project().repository,
      changesetId
    })).rejects.toThrow(/expired format|expired-format/i);
  });

  test("inspection returns only canonical summary fields and confirmed semantic IDs", async () => {
    const pack = await writeV3PackFixture(project()) as {
      records: Array<Record<string, unknown>>;
    } & Record<string, unknown>;
    const architecture = pack.records.find((record) => record.id === "record.architecture");
    if (!architecture) throw new Error("architecture fixture record is missing");
    architecture.strength = "required";
    architecture.approval = "confirmed";
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await api.previewUpdate({
      root: project().repository,
      pack,
      changes: [{
        path: "docs/project-design/manifest.json",
        content: `${JSON.stringify(pack, null, 2)}\n`
      }]
    });

    const summary = await api.inspectChangesetForApproval({
      root: project().repository,
      changesetId: pending.changesetId
    });

    expect(Object.keys(summary).sort()).toEqual([
      "archiveActions",
      "changesetId",
      "diffDigest",
      "expiresAt",
      "paths",
      "root",
      "semanticDecisionIds",
      "summary"
    ]);
    expect(summary).toMatchObject({
      changesetId: pending.changesetId,
      paths: ["docs/project-design/manifest.json"],
      summary: { create: 1, update: 0, delete: 0 },
      archiveActions: { archivedRecordIds: [], tombstonedRecordIds: [] },
      semanticDecisionIds: ["record.architecture"]
    });
    expect(JSON.stringify(summary)).not.toContain("The project has an atomic architecture record");
    await expect(readFile(join(project().repository, "docs/project-design/manifest.json"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  test("fails closed when the manifest baseline changes during preview", async () => {
    const initialPack = await writeV3PackFixture(project()) as {
      maintenanceRevision: number;
      records: Array<Record<string, unknown>>;
    } & Record<string, unknown>;
    const initialArchitecture = initialPack.records.find((record) => record.id === "record.architecture");
    if (!initialArchitecture) throw new Error("architecture fixture record is missing");
    initialArchitecture.strength = "required";
    initialArchitecture.approval = "confirmed";
    const manifestPath = join(project().repository, "docs/project-design/manifest.json");
    await writeFile(manifestPath, `${JSON.stringify(initialPack, null, 2)}\n`, "utf8");

    const exactBasePack = structuredClone(initialPack);
    const exactBaseArchitecture = exactBasePack.records.find((record) => record.id === "record.architecture")!;
    exactBaseArchitecture.strength = "informational";
    exactBaseArchitecture.approval = "not-required";
    const candidatePack = structuredClone(exactBasePack);
    candidatePack.maintenanceRevision += 1;
    const candidateArchitecture = candidatePack.records.find((record) => record.id === "record.architecture")!;
    candidateArchitecture.strength = "required";
    candidateArchitecture.approval = "confirmed";

    const api = createProjectDesignKeeper({
      cacheDirectory: cacheDirectory(),
      afterCurrentManifestRead: async () => {
        await writeFile(manifestPath, `${JSON.stringify(exactBasePack, null, 2)}\n`, "utf8");
      }
    } as ServiceOptions & { afterCurrentManifestRead(): Promise<void> });
    await expect(api.previewUpdate({
      root: project().repository,
      pack: candidatePack,
      changes: [{ path: "docs/project-design/manifest.json", content: `${JSON.stringify(candidatePack, null, 2)}\n` }]
    })).rejects.toThrow(/manifest.*changed.*preview|manifest.*stale/i);
  });

  test("does not validate an unchanged manifest target from a later live read", async () => {
    const currentPack = await writeV3PackFixture(project()) as {
      maintenanceRevision: number;
      records: Array<Record<string, unknown>>;
    } & Record<string, unknown>;
    const manifestPath = join(project().repository, "docs/project-design/manifest.json");
    const currentBytes = `${JSON.stringify(currentPack, null, 2)}\n`;
    await writeFile(manifestPath, currentBytes, "utf8");
    const transientPack = structuredClone(currentPack);
    transientPack.maintenanceRevision += 1;
    const architecture = transientPack.records.find((record) => record.id === "record.architecture")!;
    architecture.strength = "required";
    architecture.approval = "confirmed";
    const api = createProjectDesignKeeper({
      cacheDirectory: cacheDirectory(),
      afterManifestBaselineValidation: async () => {
        await writeFile(manifestPath, `${JSON.stringify(transientPack, null, 2)}\n`, "utf8");
      }
    });

    const result = await api.previewUpdate({
      root: project().repository,
      pack: transientPack,
      changes: [{
        path: ".agents/skills/project-design-context/no-manifest-overlay.md",
        managedBlock: { recordId: "no-manifest-overlay", content: "# Unrelated output\n" }
      }]
    });
    await writeFile(manifestPath, currentBytes, "utf8");

    expect(result).toMatchObject({
      applicable: false,
      conflicts: ["Candidate pack validation failed"],
      validation: { valid: false }
    });
  });

  test("rejects an authenticated approval summary over one MiB", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);
    const changesetId = String(pending.changesetId);
    await rewriteAuthenticatedChangeset(changesetId, (changeset) => {
      const semanticDecisionIds = [`record.${"a".repeat(1024 * 1024)}`];
      changeset.semanticDecisionIds = semanticDecisionIds;
      changeset.diffDigest = `sha256:${createHash("sha256")
        .update(canonicalJson({ changes: changeset.changes, semanticDecisionIds }), "utf8")
        .digest("hex")}`;
    });

    await expect(api.inspectChangesetForApproval({
      root: project().repository,
      changesetId
    })).rejects.toThrow(/approval summary.*1048576 bytes/i);
  });

  test("rejects authenticated archive action IDs that are not sorted and unique", async () => {
    const api = createProjectDesignKeeper({ cacheDirectory: cacheDirectory() });
    const pending = await preview(api);
    const changesetId = String(pending.changesetId);
    await rewriteAuthenticatedChangeset(changesetId, (changeset) => {
      changeset.archiveActions = {
        archivedRecordIds: ["record.z", "record.a", "record.a"],
        tombstonedRecordIds: []
      };
    });

    await expect(api.inspectChangesetForApproval({
      root: project().repository,
      changesetId
    })).rejects.toThrow(/archiveActions|sorted and unique|malformed/i);
  });
});

describe("one-call apply authorization", () => {
  test("is an unforgeable one-use object capability", () => {
    const authority = createApplyApprovalAuthority(() => 1_000_000);
    const binding = approvalBinding();
    const requestIdentity = { requestId: 7, sessionId: "session-a" };
    const token = authority.issue(binding, requestIdentity);

    expect(JSON.parse(JSON.stringify(token))).toEqual({});
    expect(() => authority.consume({} as typeof token, binding, requestIdentity)).toThrow(/authorization|capability/i);
    expect(() => authority.consume(token, binding, requestIdentity)).not.toThrow();
    expect(() => authority.consume(token, binding, requestIdentity)).toThrow(/consumed|authorization|capability/i);
  });

  test("binds exact summary fields and request identity and consumes on mismatch", () => {
    const authority = createApplyApprovalAuthority(() => 1_000_000);
    const binding = approvalBinding();
    const requestIdentity = { requestId: 7, sessionId: "session-a" };
    const token = authority.issue(binding, requestIdentity);

    expect(() => authority.consume(token, {
      ...binding,
      archiveActions: { archivedRecordIds: ["record.changed"], tombstonedRecordIds: [] }
    }, requestIdentity)).toThrow(/binding|authorization|capability/i);
    expect(() => authority.consume(token, binding, requestIdentity)).toThrow(/consumed|authorization|capability/i);

    const otherToken = authority.issue(binding, requestIdentity);
    expect(() => authority.consume(otherToken, binding, { requestId: 7, sessionId: "session-a" }))
      .toThrow(/request|identity|authorization|capability/i);
  });

  test("rejects a capability at its exact expiry", () => {
    let currentTime = 1_000_000;
    const authority = createApplyApprovalAuthority(() => currentTime);
    const binding = approvalBinding({ expiresAt: 1_000_100 });
    const requestIdentity = { requestId: 8 };
    const token = authority.issue(binding, requestIdentity);

    currentTime = binding.expiresAt;
    expect(() => authority.consume(token, binding, requestIdentity)).toThrow(/expired/i);
  });
});
