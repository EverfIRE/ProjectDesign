import {
  createScopeService,
  detectDrift,
  queryContext,
  resolveScope,
  scanScope,
  searchEvidence,
  snapshot
} from "./scope/index.js";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { connectStdioServer, createMcpServer } from "./mcp.js";
import { createTransactionService, resolveCacheDirectory } from "./transactions.js";
import { validatePack, type ServiceOptions } from "./types/schema.js";
import { queryHistory } from "./knowledge/history.js";
import { analyzeRedundancy } from "./knowledge/redundancy.js";
import { createApplyApprovalAuthority } from "./security/approval.js";
import { createSettingsStore } from "./settings/store.js";
import { openSettingsPanel, type SettingsPanel } from "./settings/panel.js";
import { freezeRuntimePolicy } from "./settings/policy.js";

export function createProjectDesignKeeper(options: ServiceOptions = {}) {
  const trustedApprovalProvider = options.trustedApprovalProvider;
  const settings = createSettingsStore(options);
  const authority = createApplyApprovalAuthority(options.now ?? Date.now);
  const operationOptions = async () => ({ ...options, runtimePolicy: freezeRuntimePolicy(await settings.read()) });
  const transactionSnapshot = async () => createTransactionService(await operationOptions(), authority);
  const transactions = {
    previewUpdate: async (input: Record<string, unknown>) => (await transactionSnapshot()).previewUpdate(input),
    inspectChangesetForApproval: async (input: Record<string, unknown>) => (await transactionSnapshot()).inspectChangesetForApproval(input),
    issueApplyAuthorization: authority.issue,
    applyUpdate: async (input: Record<string, unknown>, authorization?: Parameters<ReturnType<typeof createTransactionService>["applyUpdate"]>[1], identity?: object) =>
      (await transactionSnapshot()).applyUpdate(input, authorization, identity),
    readPreview: async (input: Record<string, unknown>) => (await transactionSnapshot()).readPreview(input)
  };
  const panels = new Set<SettingsPanel>();
  let openingPanels = 0;
  let settingsGeneration = 0;
  const openSettings = async () => {
    const generation = settingsGeneration;
    for (const panel of panels) {
      if (Date.parse(panel.expiresAt) <= Date.now()) { await panel.close(); panels.delete(panel); }
    }
    if (panels.size + openingPanels >= 4) throw new Error("最多同时打开四个设置面板；请等待已有会话过期后重试。");
    openingPanels += 1;
    try {
      const panel = await openSettingsPanel(settings);
      if (generation !== settingsGeneration) {
        await panel.close();
        throw new Error("设置会话已关闭，请重新打开。");
      }
      panels.add(panel);
      return { url: panel.url, expiresAt: panel.expiresAt, opened: true,
        message: "Keeper 设置已在本地浏览器打开。保存后下一次操作生效。设置作用于本机当前用户的 Keeper 安装。" };
    } finally { openingPanels -= 1; }
  };
  const closeSettings = async () => {
    settingsGeneration += 1;
    const closing = [...panels];
    panels.clear();
    await Promise.all(closing.map(panel => panel.close()));
  };
  const scope = createScopeService(options);
  const validatePackWithOptions = async (input: Record<string, unknown>) => validatePack(input, {
    limits: options.limits,
    io: options.validationIo,
    runtimePolicy: (await operationOptions()).runtimePolicy
  });
  const mcpService = {
    ...scope,
    queryHistory: (input: Record<string, unknown>) => queryHistory(input, options),
    analyzeRedundancy: (input: Record<string, unknown>) => analyzeRedundancy(input, options),
    validatePack: validatePackWithOptions,
    getSettings: settings.read,
    openSettings,
    closeSettings,
    ...transactions
  };
  const applyUpdate = async (input: Record<string, unknown>) => {
    const binding = await transactions.inspectChangesetForApproval(input);
    if (!binding.policy?.easyMode) {
      if (!trustedApprovalProvider) throw new Error("Direct apply requires a trusted approval provider");
      const decision = await trustedApprovalProvider(binding);
      if (decision?.approved !== true) throw new Error("Trusted approval provider declined the apply request");
    }
    const requestIdentity = Object.freeze({ directApply: true });
    const authorization = transactions.issueApplyAuthorization(binding, requestIdentity);
    return transactions.applyUpdate(input, authorization, requestIdentity);
  };
  return {
    ...scope,
    queryHistory: mcpService.queryHistory,
    analyzeRedundancy: mcpService.analyzeRedundancy,
    validatePack: validatePackWithOptions,
    previewUpdate: transactions.previewUpdate,
    inspectChangesetForApproval: transactions.inspectChangesetForApproval,
    applyUpdate,
    getSettings: settings.read,
    openSettings,
    closeSettings,
    readPreview: transactions.readPreview,
    createMcpServer: async () => createMcpServer(mcpService),
    connectStdioServer: async () => connectStdioServer(mcpService)
  };
}

export {
  analyzeRedundancy,
  detectDrift,
  queryContext,
  queryHistory,
  resolveCacheDirectory,
  resolveScope,
  scanScope,
  searchEvidence,
  snapshot,
  validatePack
};

export type { CandidateModule, ResolvedScope, ScanResult, ScopeInput, ServiceOptions } from "./types/schema.js";

export const projectDesignKeeper = createProjectDesignKeeper();

export function isDirectExecution(metaUrl: string, argv: string[] = process.argv): boolean {
  if (!argv[1]) return false;
  return metaUrl === pathToFileURL(resolve(argv[1])).href;
}

if (isDirectExecution(import.meta.url)) {
  void projectDesignKeeper.connectStdioServer().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "Failed to start Project Design Keeper MCP server";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
