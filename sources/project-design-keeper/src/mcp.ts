import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { ApplyAuthorization, ChangesetApprovalBinding } from "./security/approval.js";
import {
  assertArrayWithin,
  assertSerializedWithin,
  assertStringWithin,
  assertToolResultBudget,
  keeperLimits,
  mcpToolResultBudgetBytes
} from "./security/limits.js";

export const serverInstructions = "Safe sequence: scan/search -> preview -> show diff/conflicts -> obtain explicit user confirmation -> apply the unexpired change-set. Never treat preview as approval. Use query_context to load only task-relevant design context, detect_drift before refreshes, and validate_pack before presenting completion.";

export interface McpKeeperService {
  scanScope(input: Record<string, unknown>): Promise<object>;
  searchEvidence(input: Record<string, unknown>): Promise<object>;
  detectDrift(input: Record<string, unknown>): Promise<object>;
  queryContext(input: Record<string, unknown>): Promise<object>;
  queryHistory(input: Record<string, unknown>): Promise<object>;
  analyzeRedundancy(input: Record<string, unknown>): Promise<object>;
  previewUpdate(input: Record<string, unknown>): Promise<object>;
  inspectChangesetForApproval(input: Record<string, unknown>): Promise<ChangesetApprovalBinding>;
  issueApplyAuthorization(binding: ChangesetApprovalBinding, requestIdentity: object): ApplyAuthorization;
  applyUpdate(input: Record<string, unknown>, authorization?: ApplyAuthorization, requestIdentity?: object): Promise<object>;
  validatePack(input: Record<string, unknown>): Promise<object>;
}

function boundedString(maxBytes: number, minimum = 0) {
  return z.string().min(minimum).max(maxBytes).superRefine((value, context) => {
    try {
      assertStringWithin("MCP string", value, maxBytes);
    } catch (error) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: error instanceof Error ? error.message : "MCP string exceeds its byte limit" });
    }
  });
}

const nonemptyString = boundedString(4 * 1024, 1);
const nonemptyQuery = boundedString(32 * 1024, 1);
const queryString = boundedString(32 * 1024);
const proposedFileContent = boundedString(keeperLimits.preview.maxFileBytes);
const fingerprint = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const fingerprintRecord = z.record(fingerprint);
const snapshotInput = z.union([
  fingerprintRecord,
  z.object({ files: fingerprintRecord }).passthrough()
]);
const sourceRevisionInput = z.object({ files: fingerprintRecord }).passthrough();
const changesetAdapterInput = z.object({ changesetId: nonemptyString }).strict();
const stringOrStrings = z.union([nonemptyString, z.array(nonemptyString).nonempty().max(1_000)]);
const scopeFields = {
  root: nonemptyString.optional(),
  path: nonemptyString.optional()
};
const pageLimit = z.number().int().min(1).max(1000);

function scoped<T extends z.ZodRawShape>(shape: T) {
  return z.object({ ...scopeFields, ...shape }).strict();
}

const scanInput = scoped({
  previousSnapshot: snapshotInput.optional(),
  view: z.enum(["summary", "files", "evidence"]).optional(),
  cursor: nonemptyString.optional(),
  limit: pageLimit.optional()
});
const searchInput = scoped({
  query: nonemptyQuery,
  domain: stringOrStrings.optional(),
  domains: stringOrStrings.optional(),
  status: stringOrStrings.optional(),
  statuses: stringOrStrings.optional()
});
const driftInput = scoped({
  previousSnapshot: snapshotInput.optional(),
  sourceRevision: sourceRevisionInput.optional(),
  pack: z.record(z.unknown()).optional(),
  requiredEvidence: z.array(nonemptyString).max(keeperLimits.pack.maxEvidencePerRecord).optional(),
  view: z.enum(["summary", "details"]).optional(),
  cursor: nonemptyString.optional(),
  limit: pageLimit.optional()
});
const contextInput = scoped({
  query: queryString.optional(),
  paths: z.array(nonemptyString).max(1_000).optional(),
  path: nonemptyString.optional(),
  module: stringOrStrings.optional(),
  modules: stringOrStrings.optional(),
  maxRecords: z.number().int().min(1).max(100).optional(),
  maxEvidence: z.number().int().min(1).max(500).optional()
});
const historyInput = z.object({
  root: nonemptyString,
  query: queryString.optional(),
  recordIds: z.array(nonemptyString).max(1_000).optional(),
  paths: z.array(nonemptyString).max(1_000).optional(),
  modules: z.array(nonemptyString).max(1_000).optional(),
  includeTombstones: z.boolean().optional(),
  cursor: nonemptyString.optional(),
  limit: z.number().int().min(1).max(500).optional()
}).strict();
const redundancyInput = z.object({
  root: nonemptyString,
  query: queryString.optional(),
  paths: z.array(nonemptyString).max(1_000).optional(),
  modules: z.array(nonemptyString).max(1_000).optional()
}).strict();
const validateInput = z.object({
  root: nonemptyString,
  pack: z.record(z.unknown())
}).strict();

const managedBlock = z.union([
  z.object({ recordId: nonemptyString, content: proposedFileContent }).strict(),
  z.object({ recordId: nonemptyString, delete: z.literal(true) }).strict()
]);
const expectedContentHash = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const requestedChange = z.union([
  z.object({
    path: nonemptyString,
    content: proposedFileContent,
    expectedContentHash: expectedContentHash.optional()
  }).strict(),
  z.object({
    path: nonemptyString,
    delete: z.literal(true),
    expectedContentHash: expectedContentHash.optional()
  }).strict(),
  z.object({
    path: nonemptyString,
    managedBlock,
    expectedContentHash: expectedContentHash.optional()
  }).strict()
]);
const previewInput = z.object({
  root: nonemptyString,
  path: nonemptyString.optional(),
  changes: z.array(requestedChange).nonempty().max(keeperLimits.preview.maxChanges),
  expectedContentHash: expectedContentHash.optional(),
  pack: z.record(z.unknown()).optional(),
  analysisId: nonemptyString.optional(),
  redundancyDecisions: z.array(z.object({
    candidateId: nonemptyString,
    decision: z.enum(["merge", "keep-separate", "defer"]),
    survivorId: nonemptyString.optional()
  }).strict()).nonempty().max(keeperLimits.redundancy.maxDecisions).optional()
}).strict();
const applyInput = z.object({
  root: nonemptyString,
  changesetId: nonemptyString.optional(),
  changeset: changesetAdapterInput.optional()
}).strict();

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: false
} as const;
const previewAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  openWorldHint: false
} as const;
const applyAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  openWorldHint: false
} as const;

function safeErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : "The keeper operation failed";
  const firstLine = raw.split(/\r?\n/u, 1)[0].trim();
  if (!firstLine) return "The keeper operation failed";
  const candidates = [
    /(?:^|[^A-Za-z0-9._/\\-])([A-Za-z]:[\\/])/u,
    /(?:^|[^A-Za-z0-9._/\\-])(\\\\[^\\/\s]+[\\/][^\\/\s]+)/u,
    /(?:^|[^A-Za-z0-9._/\\-])(\/\/[^/\s]+\/[^/\s]+)/u,
    /(?:^|[^A-Za-z0-9._/\\-])(\/(?!\/))/u
  ].map((pattern) => {
    const match = pattern.exec(firstLine);
    return match ? match.index + match[0].lastIndexOf(match[1]) : -1;
  }).filter((index) => index >= 0);
  if (candidates.length === 0) return firstLine;
  return `${firstLine.slice(0, Math.min(...candidates))}<absolute-path>`;
}

function requireScope(input: Record<string, unknown>): void {
  if (!input.root && !input.path) throw new Error("A repository root or path is required");
}

function scopedOperation(operation: (input: Record<string, unknown>) => Promise<object>) {
  return async (input: Record<string, unknown>): Promise<object> => {
    requireScope(input);
    return operation(input);
  };
}

function requireApplyChangeset(input: Record<string, unknown>): void {
  const adapter = input.changeset as Record<string, unknown> | undefined;
  if (!input.changesetId && !adapter?.changesetId) throw new Error("A changeset id is required");
}

function previewOperation(operation: (input: Record<string, unknown>) => Promise<object>) {
  return async (input: Record<string, unknown>): Promise<object> => {
    const changes = input.changes as Array<Record<string, unknown>>;
    const totalBytes = changes.reduce((total, change) => {
      if (typeof change.content === "string") return total + Buffer.byteLength(change.content, "utf8");
      const managedBlock = change.managedBlock as Record<string, unknown> | undefined;
      return total + (typeof managedBlock?.content === "string" ? Buffer.byteLength(managedBlock.content, "utf8") : 0);
    }, 0);
    if (totalBytes > keeperLimits.preview.maxAggregateBytes) {
      throw new Error(`Proposed file content exceeds the aggregate limit of ${keeperLimits.preview.maxAggregateBytes} bytes`);
    }
    return operation(input);
  };
}

function assertOptionalPackArrayWithin(label: string, value: unknown, maxItems: number): void {
  if (Array.isArray(value)) assertArrayWithin(label, value, maxItems);
}

function assertPackWithin(value: unknown): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) return;
  const pack = value as Record<string, unknown>;
  assertOptionalPackArrayWithin("Pack documents", pack.documents, keeperLimits.pack.maxDocuments);
  assertOptionalPackArrayWithin("Pack records", pack.records, keeperLimits.pack.maxRecords);
  if (!Array.isArray(pack.records)) return;
  for (const record of pack.records) {
    if (!record || typeof record !== "object" || Array.isArray(record)) continue;
    const typedRecord = record as Record<string, unknown>;
    assertOptionalPackArrayWithin("Pack record evidence", typedRecord.evidence, keeperLimits.pack.maxEvidencePerRecord);
    assertOptionalPackArrayWithin("Pack record impact", typedRecord.impact, keeperLimits.pack.maxImpactPerRecord);
  }
}

function packOperation(operation: (input: Record<string, unknown>) => Promise<object>) {
  return async (input: Record<string, unknown>): Promise<object> => {
    if (input.pack !== undefined) assertPackWithin(input.pack);
    return operation(input);
  };
}

function toolResult(value: Record<string, unknown>) {
  assertToolResultBudget(value);
  const hardLimit = mcpToolResultBudgetBytes;
  const fullText = JSON.stringify(value, null, 2);
  const duplicated = {
    content: [{ type: "text" as const, text: fullText }],
    structuredContent: value
  };
  if (Buffer.byteLength(JSON.stringify(duplicated), "utf8") <= hardLimit - 1024) return duplicated;
  return {
    content: [{ type: "text" as const, text: "Structured result returned without text duplication to preserve the one MiB response budget." }],
    structuredContent: value
  };
}

function toolError(error: unknown) {
  const message = safeErrorMessage(error);
  const value = { error: message };
  return {
    ...toolResult(value),
    isError: true
  };
}

function registerTool(
  server: McpServer,
  name: string,
  description: string,
  inputSchema: z.ZodTypeAny,
  annotations: typeof readOnlyAnnotations | typeof previewAnnotations | typeof applyAnnotations,
  operation: (input: Record<string, unknown>) => Promise<object>
): void {
  server.registerTool(name, { description, inputSchema, annotations }, async (input) => {
    try {
      assertSerializedWithin("MCP arguments", input, 8 * 1024 * 1024);
      return toolResult(await operation(input as Record<string, unknown>) as Record<string, unknown>);
    } catch (error) {
      return toolError(error);
    }
  });
}

function approvalMessage(binding: ChangesetApprovalBinding): string {
  const escapeFormatControls = (value: string): string => value.replace(
    /[\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}]/gu,
    (character) => `\\u${character.codePointAt(0)!.toString(16).padStart(4, "0")}`
  );
  const summaryJson = escapeFormatControls(JSON.stringify({
    root: binding.root,
    changesetId: binding.changesetId,
    diffDigest: binding.diffDigest,
    expiresAt: new Date(binding.expiresAt).toISOString(),
    summary: binding.summary,
    paths: binding.paths,
    archiveActions: binding.archiveActions,
    semanticDecisionIds: binding.semanticDecisionIds
  }, null, 2));
  const message = [
    "Approve this authenticated Project Design Keeper changeset?",
    summaryJson,
    `Select approve and type the final eight hexadecimal digest characters: ${binding.diffDigest.slice(-8)}`
  ].join("\n");
  assertStringWithin("Approval summary", message, 1024 * 1024);
  return message;
}

function approvalRequestIdentity(extra: {
  requestId: string | number;
  sessionId?: string;
  authInfo?: { clientId?: string };
}): object {
  return Object.freeze({
    requestId: extra.requestId,
    ...(extra.sessionId !== undefined ? { sessionId: extra.sessionId } : {}),
    ...(extra.authInfo?.clientId !== undefined ? { clientId: extra.authInfo.clientId } : {})
  });
}

function validateElicitationApproval(
  result: { action: string; content?: Record<string, unknown> },
  expectedSuffix: string
): void {
  if (result.action === "decline") throw new Error("Apply approval was declined");
  if (result.action === "cancel") throw new Error("Apply approval was cancelled");
  if (result.action !== "accept") throw new Error("Apply approval action is malformed");
  if (!result.content || Array.isArray(result.content)) throw new Error("Apply approval response content is malformed");
  const keys = Object.keys(result.content).sort();
  if (keys.length !== 2 || keys[0] !== "confirmation" || keys[1] !== "decision") {
    throw new Error("Apply approval response content is malformed");
  }
  if (result.content.decision !== "approve") throw new Error("Apply approval decision is malformed");
  if (typeof result.content.confirmation !== "string" ||
      !/^[a-f0-9]{8}$/u.test(result.content.confirmation) ||
      result.content.confirmation !== expectedSuffix) {
    throw new Error("Apply approval digest confirmation does not match");
  }
}

function registerApplyTool(server: McpServer, service: McpKeeperService): void {
  server.registerTool("apply_update", {
    description: "Apply one explicitly confirmed, unexpired change-set with optimistic concurrency and recovery snapshots.",
    inputSchema: applyInput,
    annotations: applyAnnotations
  }, async (input, extra) => {
    try {
      assertSerializedWithin("MCP arguments", input, 8 * 1024 * 1024);
      const applyInputValue = input as Record<string, unknown>;
      requireApplyChangeset(applyInputValue);
      if (server.server.getClientCapabilities()?.elicitation?.form === undefined) {
        throw new Error("The connected client must support form elicitation for apply approval");
      }
      const binding = await service.inspectChangesetForApproval(applyInputValue);
      const requestIdentity = approvalRequestIdentity(extra);
      const message = approvalMessage(binding);
      const result = await server.server.elicitInput({
        mode: "form",
        message,
        requestedSchema: {
          type: "object",
          properties: {
            decision: { type: "string", enum: ["approve"] },
            confirmation: { type: "string", minLength: 8, maxLength: 8 }
          },
          required: ["decision", "confirmation"]
        }
      }, {
        signal: extra.signal,
        relatedRequestId: extra.requestId,
        timeout: 60_000
      });
      extra.signal.throwIfAborted();
      validateElicitationApproval(result, binding.diffDigest.slice(-8));
      const authorization = service.issueApplyAuthorization(binding, requestIdentity);
      return toolResult(await service.applyUpdate(
        applyInputValue,
        authorization,
        requestIdentity
      ) as Record<string, unknown>);
    } catch (error) {
      return toolError(error);
    }
  });
}

export function createMcpServer(service: McpKeeperService): McpServer {
  const server = new McpServer(
    { name: "project-design-keeper", version: "1.0.2" },
    { instructions: serverInstructions }
  );

  registerTool(server, "scan_scope", "Scan a repository scope and return a bounded summary or cursor-paged files/evidence for an immutable snapshot.", scanInput, readOnlyAnnotations, scopedOperation(service.scanScope));
  registerTool(server, "search_evidence", "Search repository evidence by query and optional design classifications.", searchInput, readOnlyAnnotations, scopedOperation(service.searchEvidence));
  registerTool(server, "detect_drift", "Compare current source evidence with a prior snapshot or design pack.", driftInput, readOnlyAnnotations, packOperation(scopedOperation(service.detectDrift)));
  registerTool(server, "query_context", "Return the smallest relevant design context for a task, path, or module.", contextInput, readOnlyAnnotations, scopedOperation(service.queryContext));
  registerTool(server, "query_history", "Query stale, terminal, archived, and optionally tombstoned project-design knowledge.", historyInput, readOnlyAnnotations, service.queryHistory);
  registerTool(server, "analyze_redundancy", "Find deterministic semantic-redundancy candidates for explicit Agent and user decisions.", redundancyInput, readOnlyAnnotations, service.analyzeRedundancy);
  registerTool(server, "preview_update", "Validate a proposed managed update, store an expiring change-set in keeper cache, and return its diff and conflicts without changing the project.", previewInput, previewAnnotations, previewOperation(packOperation(service.previewUpdate)));
  registerApplyTool(server, service);
  registerTool(server, "validate_pack", "Validate a project-design knowledge pack, links, records, evidence, and ownership metadata.", validateInput, readOnlyAnnotations, packOperation(service.validatePack));
  return server;
}

export async function connectStdioServer(service: McpKeeperService): Promise<McpServer> {
  const server = createMcpServer(service);
  await server.connect(new StdioServerTransport());
  return server;
}
