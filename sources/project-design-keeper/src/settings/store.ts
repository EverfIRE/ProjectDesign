import { randomUUID } from "node:crypto";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import {
  assertSecureOwnerFileMetadata, captureSecurePathIdentity, prepareSecureCache, resolveCacheDirectory,
  validateCacheFile, validateSecurePathIdentity, type SecureCacheLayout
} from "../security/cache.js";
import { withProcessLease } from "../security/process-lock.js";
import type { ServiceOptions } from "../types/schema.js";

const valuesSchema = z.object({ easyMode: z.boolean(), maxUpdateMiB: z.number().int().min(1).max(64) }).strict();
const settingsSchema = valuesSchema.extend({ version: z.literal(1), revision: z.string().min(1).max(128) }).strict();
export type KeeperSettings = z.infer<typeof settingsSchema>;
export type KeeperSettingsValues = z.infer<typeof valuesSchema>;
export interface SettingsStore {
  read(): Promise<KeeperSettings>;
  save(values: KeeperSettingsValues, expectedRevision: string): Promise<KeeperSettings>;
}
export class SettingsRevisionConflictError extends Error {
  constructor() { super("Settings revision conflict: 设置已在其他面板更改，请刷新后重试。"); }
}
const defaults: Readonly<KeeperSettings> = Object.freeze({ version: 1, revision: "default", easyMode: false, maxUpdateMiB: 8 });

async function readSettings(layout: SecureCacheLayout): Promise<KeeperSettings> {
  const path = join(layout.root, "settings.json");
  await validateCacheFile(layout, path, true);
  let handle;
  try { handle = await open(path, "r"); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { ...defaults };
    throw error;
  }
  try {
    const identity = await captureSecurePathIdentity(layout, path, "file");
    const metadata = await handle.stat({ bigint: true });
    assertSecureOwnerFileMetadata(metadata, path, 1n);
    if (metadata.dev !== identity.dev || metadata.ino !== identity.ino) throw new Error("Settings file identity changed");
    if (metadata.size > 4096n) throw new Error("Settings file exceeds the 4096-byte limit");
    const bytes = Buffer.alloc(4097);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead > 4096) throw new Error("Settings file exceeds the 4096-byte limit");
    await validateSecurePathIdentity(layout, identity);
    return settingsSchema.parse(JSON.parse(bytes.subarray(0, bytesRead).toString("utf8")));
  } catch (error) {
    throw new Error("Invalid Keeper settings; repair the settings file before continuing", { cause: error });
  } finally { await handle.close(); }
}

export function createSettingsStore(options: Pick<ServiceOptions, "cacheDirectory" | "environment" | "homeDirectory"> = {}): SettingsStore {
  async function locked<T>(operation: (layout: SecureCacheLayout, assertOwned: () => Promise<void>) => Promise<T>) {
    const layout = await prepareSecureCache(options);
    return withProcessLease({ layout, projectRoot: layout.root, now: Date.now },
      (lease) => operation(layout, () => lease.assertOwned()));
  }
  return {
    async read() {
      const root = resolveCacheDirectory(options, options.environment ?? process.env, options.homeDirectory ?? homedir());
      try {
        // A missing setting is a complete default snapshot. Do not initialize the
        // cache or a lease before unrelated operations have validated their input.
        // A concurrent save may linearize after this observation; revision binding
        // still prevents applying a preview under a different saved policy.
        await lstat(join(root, "settings.json"));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return { ...defaults };
        throw error;
      }
      // lstat above reads no contents. Existing settings still require the full
      // secure directory/file validation and lock, including symlink rejection.
      return locked((layout) => readSettings(layout));
    },
    async save(values, expectedRevision) {
      const valid = valuesSchema.parse(values);
      if (typeof expectedRevision !== "string" || !expectedRevision || expectedRevision.length > 128) throw new Error("Invalid settings revision");
      return locked(async (layout, assertOwned) => {
        const current = await readSettings(layout);
        if (current.revision !== expectedRevision) throw new SettingsRevisionConflictError();
        const next: KeeperSettings = { version: 1, revision: randomUUID(), ...valid };
        const target = join(layout.root, "settings.json");
        const temporary = join(layout.root, `.settings-${randomUUID()}.tmp`);
        const parent = await captureSecurePathIdentity(layout, layout.root, "directory");
        const handle = await open(temporary, "wx", 0o600);
        const created = await handle.stat({ bigint: true });
        let published = false;
        try {
          await handle.writeFile(`${JSON.stringify(next)}\n`, "utf8");
          await handle.sync();
          await handle.close();
          const temporaryIdentity = await captureSecurePathIdentity(layout, temporary, "file");
          if (temporaryIdentity.dev !== created.dev || temporaryIdentity.ino !== created.ino) throw new Error("Settings temporary file identity changed");
          await validateCacheFile(layout, temporary, false);
          await validateSecurePathIdentity(layout, parent);
          await validateCacheFile(layout, target, true);
          await assertOwned();
          await validateSecurePathIdentity(layout, temporaryIdentity);
          await rename(temporary, target);
          published = true;
          await validateSecurePathIdentity(layout, { ...temporaryIdentity, path: target });
          // Flush the replacement file. POSIX also requires flushing its directory;
          // Windows does not expose directory fsync through Node's ordinary handles.
          const finalHandle = await open(target, "r+");
          try {
            const finalMetadata = await finalHandle.stat({ bigint: true });
            if (finalMetadata.dev !== created.dev || finalMetadata.ino !== created.ino) throw new Error("Settings replacement identity changed");
            assertSecureOwnerFileMetadata(finalMetadata, target, 1n);
            await finalHandle.sync();
          } finally { await finalHandle.close(); }
          if (process.platform !== "win32") {
            const directory = await open(layout.root, "r");
            try { await directory.sync(); } finally { await directory.close(); }
          }
          return next;
        } finally {
          await handle.close().catch(() => undefined);
          if (!published) {
            try {
              const remaining = await captureSecurePathIdentity(layout, temporary, "file");
              if (remaining.dev !== created.dev || remaining.ino !== created.ino) throw new Error("Settings temporary cleanup identity changed");
              await validateSecurePathIdentity(layout, remaining);
              await unlink(temporary);
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
            }
          }
        }
      });
    }
  };
}
