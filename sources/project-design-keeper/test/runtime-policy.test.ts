import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, expect, test } from "vitest";
import { createTransactionService } from "../src/transactions.js";
import { createApplyApprovalAuthority } from "../src/security/approval.js";
import { createProjectFixture, removeProjectFixture } from "./fixtures.js";
import { writeCanonicalPackFixture } from "./canonical-pack-fixture.js";
import { createChangesetStore, persistedDiffDigest } from "../src/changesets/store.js";
import { validatePack } from "../src/types/schema.js";

const MiB = 1024 * 1024;
let root: string;
let cacheDirectory: string;
const path = ".agents/skills/project-design-context/large.md";
const hash = (text: string) => `sha256:${createHash("sha256").update(text).digest("hex")}`;
const block = (body: string, id = "large") => `<!-- project-design-keeper:managed record-id="${id}" content-hash="${hash(body)}" -->${body}<!-- /project-design-keeper:managed -->`;
function sized(bytes: number) { const overhead = Buffer.byteLength(block("")); return block("中".repeat(Math.floor((bytes - overhead) / 3)) + "x".repeat((bytes - overhead) % 3)); }
const policy = (easyMode = true, maxUpdateMiB = 8, revision = "test-revision") => ({ easyMode, maxUpdateMiB, revision });
function service(runtimePolicy = policy()) { return createTransactionService({ cacheDirectory, runtimePolicy }); }
async function apply(api: ReturnType<typeof service>, changesetId: unknown) {
  const request = { root, changesetId };
  const binding = await api.inspectChangesetForApproval(request);
  const identity = {};
  return api.applyUpdate(request, api.issueApplyAuthorization(binding, identity), identity);
}
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), "keeper-policy-project-")); cacheDirectory = await mkdtemp(join(tmpdir(), "keeper-policy-cache-")); await writeFile(join(root, "source.txt"), "source"); });
afterEach(async () => { await rm(root, { recursive: true, force: true }); await rm(cacheDirectory, { recursive: true, force: true }); });

test("Easy persists, pages, reloads and applies a greater-than-two-MiB UTF-8 file", async () => {
  const content = sized(3 * MiB);
  const preview = await service().previewUpdate({ root, changes: [{ path, content }] });
  expect(preview.applicable).toBe(true);
  expect(preview.policy).toEqual(policy());
  expect(preview.complete).toBe(false);
  const restarted = service();
  let cursor: unknown;
  let full = "";
  do {
    const page = await restarted.readPreview({ root, changesetId: preview.changesetId, ...(cursor ? { cursor } : {}) });
    expect(Buffer.byteLength(JSON.stringify(page))).toBeLessThan(MiB);
    expect(page.diff).not.toContain("�");
    full += page.diff;
    cursor = page.nextCursor;
  } while (cursor);
  expect(full).toContain(content);
  const result = await apply(restarted, preview.changesetId);
  expect(result.authorizationSource).toBe("easy-policy");
  expect(await readFile(join(root, path), "utf8")).toBe(content);
  const snapshotsDirectory = join(cacheDirectory, "snapshots", createHash("sha256").update(root).digest("hex"));
  const [snapshotName] = await readdir(snapshotsDirectory);
  expect(JSON.parse(await readFile(join(snapshotsDirectory, snapshotName!), "utf8")).authorization).toEqual({
    source: "easy-policy", policy: policy(), diffDigest: preview.diffDigest
  });
}, 120000);

test("normal mode enforces two MiB even with a larger aggregate setting", async () => {
  await expect(service(policy(false)).previewUpdate({ root, changes: [{ path, content: sized(2 * MiB + 1) }] })).rejects.toThrow(/file.*limit/i);
});

test("aggregate counts exact final UTF-8 bytes without JSON overhead and rejects one extra byte", async () => {
  const api = service(policy(true, 1));
  expect((await api.previewUpdate({ root, changes: [{ path, content: sized(MiB) }] })).applicable).toBe(true);
  await expect(api.previewUpdate({ root, changes: [{ path, content: sized(MiB + 1) }] })).rejects.toThrow(/aggregate.*limit/i);
  await expect(api.previewUpdate({ root, changes: [{ path, content: sized(MiB / 2) }, { path: path.replace("large", "second"), content: sized(MiB / 2 + 1) }] })).rejects.toThrow(/aggregate.*limit/i);
});

test("managed-block aggregate includes surrounding content and counts each merged file once", async () => {
  await mkdir(dirname(join(root, path)), { recursive: true });
  await writeFile(join(root, path), block("a", "a") + block("b", "b"));
  const api = service(policy(true, 1));
  const halfBody = "x".repeat((MiB - Buffer.byteLength(block("", "a")) - Buffer.byteLength(block("", "b"))) / 2);
  const changes = [{ path, managedBlock: { recordId: "a", content: halfBody } }, { path, managedBlock: { recordId: "b", content: halfBody } }];
  expect((await api.previewUpdate({ root, changes })).applicable).toBe(true);
  changes[1].managedBlock.content += "x";
  await expect(api.previewUpdate({ root, changes })).rejects.toThrow(/aggregate.*limit/i);
});

test("normal mode can shrink and delete old Easy files above its write budget", async () => {
  await mkdir(dirname(join(root, path)), { recursive: true });
  await writeFile(join(root, path), sized(3 * MiB));
  const api = service(policy(false, 1));
  const shrink = await api.previewUpdate({ root, changes: [{ path, managedBlock: { recordId: "large", content: "small" } }] });
  await apply(api, shrink.changesetId);
  expect(await readFile(join(root, path), "utf8")).toBe(block("small"));
  await writeFile(join(root, path), sized(3 * MiB));
  const deletion = await api.previewUpdate({ root, changes: [{ path, delete: true }] });
  await apply(api, deletion.changesetId);
  await expect(readFile(join(root, path))).rejects.toThrow(/ENOENT/);
}, 120000);

test("changed settings invalidate approval, paging and outstanding capabilities before writes", async () => {
  const authority = createApplyApprovalAuthority(Date.now);
  const api = createTransactionService({ cacheDirectory, runtimePolicy: policy() }, authority);
  const preview = await api.previewUpdate({ root, changes: [{ path, content: block("small") }] });
  const request = { root, changesetId: preview.changesetId };
  const binding = await api.inspectChangesetForApproval(request);
  const identity = {};
  const authorization = api.issueApplyAuthorization(binding, identity);
  const revised = createTransactionService({ cacheDirectory, runtimePolicy: policy(false, 8, "changed") }, authority);
  await expect(revised.inspectChangesetForApproval(request)).rejects.toThrow(/settings.*changed|revision/i);
  await expect(revised.readPreview(request)).rejects.toThrow(/settings.*changed|revision/i);
  await expect(revised.applyUpdate(request, authorization, identity)).rejects.toThrow(/settings.*changed|revision/i);
  await expect(readFile(join(root, path))).rejects.toThrow(/ENOENT/);
});

test("full diff and policy are authenticated cache contents", async () => {
  const api = service();
  const preview = await api.previewUpdate({ root, changes: [{ path, content: block("small") }] });
  const cachedPath = join(cacheDirectory, "changesets", `${preview.changesetId}.json`);
  const original = await readFile(cachedPath, "utf8");
  const changed = JSON.parse(original);
  changed.diff += "tampered";
  await writeFile(cachedPath, JSON.stringify(changed));
  await expect(api.readPreview({ root, changesetId: preview.changesetId })).rejects.toThrow(/authentic|signature/i);
  changed.diff = JSON.parse(original).diff;
  changed.policy.easyMode = false;
  await writeFile(cachedPath, JSON.stringify(changed));
  await expect(api.inspectChangesetForApproval({ root, changesetId: preview.changesetId })).rejects.toThrow(/authentic|signature/i);
});

test("candidate validation and apply accept a nine-MiB merged managed document without widening source reads", async () => {
  const fixture = await createProjectFixture();
  try {
    const pack = await writeCanonicalPackFixture(fixture);
    const api = service(policy(true, 16));
    const managedPath = "docs/project-design/intent.md";
    const body = "x".repeat(9 * MiB);
    const preview = await api.previewUpdate({ root: fixture.repository, pack, changes: [
      { path: managedPath, managedBlock: { recordId: "record.2", content: body } },
      { path: "docs/project-design/manifest.json", content: JSON.stringify(pack) }
    ] });
    expect(preview.validation).toMatchObject({ valid: true });
    expect(preview.applicable).toBe(true);
    const request = { root: fixture.repository, changesetId: preview.changesetId };
    const binding = await api.inspectChangesetForApproval(request);
    const identity = {};
    expect(await api.applyUpdate(request, api.issueApplyAuthorization(binding, identity), identity)).toMatchObject({ applied: true });
    expect(await readFile(join(fixture.repository, managedPath), "utf8")).toContain(body);
  } finally { await removeProjectFixture(fixture); }
}, 120000);

test("legacy authenticated previews require regeneration and remain garbage collectable", async () => {
  const api = service();
  const preview = await api.previewUpdate({ root, changes: [{ path, content: block("small") }] });
  const cache = createChangesetStore({ cacheDirectory, runtimePolicy: policy() });
  const loaded = await cache.loadAuthenticated(root, String(preview.changesetId));
  await cache.consumePair(loaded);
  const legacy = { ...loaded.changeset, version: 2 as const };
  delete legacy.policy;
  delete legacy.diff;
  legacy.diffDigest = persistedDiffDigest(legacy.changes, legacy.semanticDecisionIds);
  await cache.publishPair(await cache.preparePublication(legacy));
  await expect(api.inspectChangesetForApproval({ root, changesetId: preview.changesetId })).rejects.toThrow(/legacy.*regenerate/i);
  const expired = createChangesetStore({ cacheDirectory, runtimePolicy: policy(), now: () => legacy.expiresAt + 1 });
  await expired.collectGarbage(root);
  await expect(readFile(join(cacheDirectory, "changesets", `${preview.changesetId}.json`))).rejects.toThrow(/ENOENT/);
});

test("stores heavily escaped large text compactly and applies its exact bytes", async () => {
  const content = block("\u0001".repeat(3 * MiB));
  const api = service();
  const preview = await api.previewUpdate({ root, changes: [{ path, content }] });
  const bytes = await readFile(join(cacheDirectory, "changesets", `${preview.changesetId}.json`));
  expect(bytes.length).toBeLessThan(MiB);
  const restarted = service();
  await apply(restarted, preview.changesetId);
  expect(await readFile(join(root, path), "utf8")).toBe(content);
}, 120000);

test("the configured sixty-four-MiB upper boundary survives cache reload and actual apply", async () => {
  const content = sized(64 * MiB);
  const api = service(policy(true, 64));
  const preview = await api.previewUpdate({ root, changes: [{ path, content }] });
  expect(preview.applicable).toBe(true);
  const restarted = service(policy(true, 64));
  await apply(restarted, preview.changesetId);
  const written = await readFile(join(root, path), "utf8");
  expect(Buffer.byteLength(written)).toBe(64 * MiB);
  expect(hash(written)).toBe(hash(content));
}, 120000);

test("validates a sixty-three-MiB managed Unicode document with the trusted policy", async () => {
  const fixture = await createProjectFixture();
  try {
    const pack = await writeCanonicalPackFixture(fixture);
    await writeFile(join(fixture.repository, "docs/project-design/intent.md"), block("中".repeat(21 * MiB), "record.2"));
    expect(await validatePack({ root: fixture.repository, pack }, { runtimePolicy: policy(true, 64) })).toMatchObject({ valid: true });
  } finally { await removeProjectFixture(fixture); }
}, 120000);

test("a recovery snapshot for four large deletions remains readable by the next small apply", async () => {
  const paths = Array.from({ length: 4 }, (_, index) => `.agents/skills/project-design-context/old-${index}.md`);
  await mkdir(dirname(join(root, paths[0]!)), { recursive: true });
  const content = sized(56 * MiB);
  for (const oldPath of paths) await writeFile(join(root, oldPath), content, "utf8");
  const api = service(policy(false, 1));
  const deletion = await api.previewUpdate({ root, changes: paths.map((oldPath) => ({ path: oldPath, delete: true })) });
  expect(deletion.applicable).toBe(true);
  expect(await apply(api, deletion.changesetId)).toMatchObject({ applied: true });
  const small = await api.previewUpdate({ root, changes: [{ path, content: block("after large recovery") }] });
  expect(await apply(api, small.changesetId)).toMatchObject({ applied: true });
  expect(await readFile(join(root, path), "utf8")).toBe(block("after large recovery"));
}, 180000);
