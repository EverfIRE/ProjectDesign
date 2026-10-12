import { createHash } from "node:crypto";
import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "vitest";
import { createTransactionService } from "../src/transactions.js";
import { createProjectFixture, removeProjectFixture } from "./fixtures.js";
import { writeV3PackFixture } from "./canonical-pack-fixture.js";

const hash = (value: string) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
const block = (id: string, body: string) => `<!-- project-design-keeper:managed record-id="${id}" content-hash="${hash(body)}" -->${body}<!-- /project-design-keeper:managed -->`;

test("Easy applies forty outputs with ninety-nine records and 1002 source fingerprints", async () => {
  const fixture = await createProjectFixture();
  try {
    const pack = await writeV3PackFixture(fixture) as Record<string, any>;
    await mkdir(join(fixture.repository, "inputs"));
    for (let index = 0; index < 1001; index += 1) {
      const path = `inputs/source-${index}.txt`;
      const contents = `source ${index}\n`;
      await writeFile(join(fixture.repository, path), contents);
      pack.sourceRevision.files[path] = hash(contents);
    }
    const changes: Array<{ path: string; content: string }> = [];
    for (const document of pack.documents) {
      changes.push({ path: document.path, content: await readFile(join(fixture.repository, document.path), "utf8") });
      await unlink(join(fixture.repository, document.path));
    }
    for (let index = 0; index < 29; index += 1) {
      const document = { id: `module.${index}`, path: `docs/project-design/modules/module-${index}.md` };
      pack.documents.push(document);
      const title = `# Module ${index}\n`;
      let content = `<!-- project-design-keeper:derived document-id="${document.id}" content-hash="${hash(title)}" -->${title}<!-- /project-design-keeper:derived -->`;
      for (let recordIndex = index; recordIndex < 91; recordIndex += 29) {
        const id = `module.record.${recordIndex}`;
        pack.records.push({ ...pack.records[0], id, kind: "module", ownerDocument: document.id,
          statement: `Module contract ${recordIndex}`, scope: `module-${index}` });
        content += block(id, `Module ${recordIndex}\n`);
      }
      changes.push({ path: document.path, content });
    }
    changes.push({ path: "docs/project-design/manifest.json", content: JSON.stringify(pack) });
    expect(changes).toHaveLength(40);
    expect(pack.records).toHaveLength(99);
    expect(Object.keys(pack.sourceRevision.files)).toHaveLength(1002);
    const api = createTransactionService({ cacheDirectory: join(fixture.root, "apply-cache"),
      runtimePolicy: { revision: "test-easy", easyMode: true, maxUpdateMiB: 64 } });
    const preview = await api.previewUpdate({ root: fixture.repository, pack, changes });
    expect(preview, JSON.stringify(preview.validation)).toMatchObject({ applicable: true, conflicts: [] });
    const request = { root: fixture.repository, changesetId: preview.changesetId };
    const binding = await api.inspectChangesetForApproval(request);
    const identity = {};
    await expect(api.applyUpdate(request, api.issueApplyAuthorization(binding, identity), identity)).resolves.toMatchObject({ applied: true });
    for (const change of changes) expect(await readFile(join(fixture.repository, change.path), "utf8")).toBe(change.content);
  } finally { await removeProjectFixture(fixture); }
}, 300000);
