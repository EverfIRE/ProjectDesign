import type { RuntimePolicy } from "../settings/policy.js";

export interface ChangesetApprovalBinding {
  policy?: RuntimePolicy;
  authorizationSource?: "easy-policy" | "human-form";
  root: string;
  changesetId: string;
  diffDigest: `sha256:${string}`;
  expiresAt: number;
  paths: string[];
  summary: {
    create: number;
    update: number;
    delete: number;
  };
  archiveActions: {
    archivedRecordIds: string[];
    tombstonedRecordIds: string[];
  };
  semanticDecisionIds: string[];
}

declare const applyAuthorizationBrand: unique symbol;

export type ApplyAuthorization = object & {
  readonly [applyAuthorizationBrand]: true;
};

export interface ApplyApprovalAuthority {
  issue(binding: ChangesetApprovalBinding, requestIdentity: object): ApplyAuthorization;
  consume(
    authorization: ApplyAuthorization,
    expectedBinding: ChangesetApprovalBinding,
    requestIdentity: object
  ): void;
}

interface AuthorizationRecord {
  binding: ChangesetApprovalBinding;
  requestIdentity: object;
  consumed: boolean;
}

function snapshotBinding(binding: ChangesetApprovalBinding): ChangesetApprovalBinding {
  return {
    ...(binding.policy ? { policy: { ...binding.policy } } : {}),
    ...(binding.authorizationSource ? { authorizationSource: binding.authorizationSource } : {}),
    root: binding.root,
    changesetId: binding.changesetId,
    diffDigest: binding.diffDigest,
    expiresAt: binding.expiresAt,
    paths: [...binding.paths],
    summary: { ...binding.summary },
    archiveActions: {
      archivedRecordIds: [...binding.archiveActions.archivedRecordIds],
      tombstonedRecordIds: [...binding.archiveActions.tombstonedRecordIds]
    },
    semanticDecisionIds: [...binding.semanticDecisionIds]
  };
}

function equalStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function equalBindings(left: ChangesetApprovalBinding, right: ChangesetApprovalBinding): boolean {
  return left.policy?.revision === right.policy?.revision &&
    left.policy?.easyMode === right.policy?.easyMode &&
    left.policy?.maxUpdateMiB === right.policy?.maxUpdateMiB &&
    left.authorizationSource === right.authorizationSource &&
    left.root === right.root &&
    left.changesetId === right.changesetId &&
    left.diffDigest === right.diffDigest &&
    left.expiresAt === right.expiresAt &&
    equalStrings(left.paths, right.paths) &&
    left.summary.create === right.summary.create &&
    left.summary.update === right.summary.update &&
    left.summary.delete === right.summary.delete &&
    equalStrings(left.archiveActions.archivedRecordIds, right.archiveActions.archivedRecordIds) &&
    equalStrings(left.archiveActions.tombstonedRecordIds, right.archiveActions.tombstonedRecordIds) &&
    equalStrings(left.semanticDecisionIds, right.semanticDecisionIds);
}

export function createApplyApprovalAuthority(now: () => number): ApplyApprovalAuthority {
  const records = new WeakMap<object, AuthorizationRecord>();

  return {
    issue(binding, requestIdentity) {
      if (now() >= binding.expiresAt) throw new Error("Apply authorization cannot be issued for an expired changeset");
      const authorization = Object.freeze(Object.create(null)) as ApplyAuthorization;
      records.set(authorization, {
        binding: snapshotBinding(binding),
        requestIdentity,
        consumed: false
      });
      return authorization;
    },

    consume(authorization, expectedBinding, requestIdentity) {
      const record = records.get(authorization);
      if (!record) throw new Error("Apply authorization capability is invalid");
      if (record.consumed) throw new Error("Apply authorization capability was already consumed");
      record.consumed = true;
      if (now() >= record.binding.expiresAt) throw new Error("Apply authorization capability has expired");
      if (record.requestIdentity !== requestIdentity) throw new Error("Apply authorization request identity does not match");
      if (!equalBindings(record.binding, expectedBinding)) throw new Error("Apply authorization binding does not match the authenticated changeset");
    }
  };
}
