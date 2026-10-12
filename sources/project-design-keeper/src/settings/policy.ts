export interface RuntimePolicy {
  readonly revision: string;
  readonly easyMode: boolean;
  readonly maxUpdateMiB: number;
}

export const defaultRuntimePolicy: RuntimePolicy = Object.freeze({ revision: "defaults-v1", easyMode: false, maxUpdateMiB: 8 });
export const maximumUpdateBytes = 64 * 1024 * 1024;
/** Old managed files remain readable after the user reduces the write budget. */
export const managedReadLimits = Object.freeze({ maxFileBytes: maximumUpdateBytes, maxAggregateBytes: 256 * 1024 * 1024 });

export function freezeRuntimePolicy(value: RuntimePolicy = defaultRuntimePolicy): RuntimePolicy {
  if (!value || typeof value.revision !== "string" || value.revision.length === 0 || value.revision.length > 128 ||
      typeof value.easyMode !== "boolean" || !Number.isInteger(value.maxUpdateMiB) || value.maxUpdateMiB < 1 || value.maxUpdateMiB > 64) {
    throw new Error("Invalid trusted runtime settings policy");
  }
  return Object.freeze({ revision: value.revision, easyMode: value.easyMode, maxUpdateMiB: value.maxUpdateMiB });
}

export function sameRuntimePolicy(left: RuntimePolicy, right: RuntimePolicy): boolean {
  return left.revision === right.revision && left.easyMode === right.easyMode && left.maxUpdateMiB === right.maxUpdateMiB;
}
