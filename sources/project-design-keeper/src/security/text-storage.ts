import { gzipSync, gunzipSync } from "node:zlib";
import { TextDecoder } from "node:util";

const marker = "$keeperCompressedText";
const escaped = "$keeperLiteralObject";
const threshold = 32 * 1024;
export const textStorageLimits = Object.freeze({ maxStringBytes: 384 * 1024 * 1024, maxExpandedBytes: 1024 * 1024 * 1024, maxNodes: 2_000_000, maxDepth: 64 });

/** Preserve small legacy JSON verbatim; large strings use an explicit reversible wire envelope. */
export function encodeStoredText(value: unknown): unknown {
  let compressed = false;
  let nodes = 0;
  let expanded = 0;
  const visit = (item: unknown, depth: number): unknown => {
    if (++nodes > textStorageLimits.maxNodes || depth > textStorageLimits.maxDepth) throw new Error("Stored text structure exceeds its bounded budget");
    if (typeof item === "string") {
      const bytes = Buffer.byteLength(item, "utf8");
      expanded += bytes;
      if (bytes > textStorageLimits.maxStringBytes || expanded > textStorageLimits.maxExpandedBytes) throw new Error("Stored text exceeds its expanded byte budget");
      if (bytes <= threshold) return item;
      compressed = true;
      return { [marker]: { bytes, data: gzipSync(Buffer.from(item, "utf8")).toString("base64") } };
    }
    if (Array.isArray(item)) return item.map((child) => visit(child, depth + 1));
    if (item && typeof item === "object") {
      const entries = Object.entries(item).map(([key, child]) => [key, visit(child, depth + 1)]);
      if (Object.hasOwn(item, marker) || Object.hasOwn(item, escaped)) return { [escaped]: entries };
      return Object.fromEntries(entries);
    }
    return item;
  };
  const payload = visit(value, 0);
  return compressed ? { textStorage: "keeper-text-v1", payload } : value;
}

/** Only call after authenticating a changeset's wire bytes. Recovery data is revalidated afterwards. */
export function decodeStoredText(value: unknown, consumeExpandedBytes?: (bytes: number) => void): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value) || !Object.hasOwn(value, "textStorage")) return value;
  const envelope = value as Record<string, unknown>;
  if (envelope.textStorage !== "keeper-text-v1" || Object.keys(envelope).length !== 2 || !Object.hasOwn(envelope, "payload")) throw new Error("Stored text envelope is invalid");
  let expanded = 0;
  let nodes = 0;
  const charge = (bytes: number) => {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > textStorageLimits.maxStringBytes || expanded + bytes > textStorageLimits.maxExpandedBytes) throw new Error("Stored text exceeds its expanded byte budget");
    consumeExpandedBytes?.(bytes);
    expanded += bytes;
  };
  const visit = (item: unknown, depth: number): unknown => {
    if (++nodes > textStorageLimits.maxNodes || depth > textStorageLimits.maxDepth) throw new Error("Stored text structure exceeds its bounded budget");
    if (typeof item === "string") { charge(Buffer.byteLength(item, "utf8")); return item; }
    if (Array.isArray(item)) return item.map((child) => visit(child, depth + 1));
    if (item && typeof item === "object") {
      const object = item as Record<string, unknown>;
      if (Object.hasOwn(object, marker)) {
        const encoded = object[marker] as Record<string, unknown>;
        if (Object.keys(object).length !== 1 || !encoded || typeof encoded !== "object" || Array.isArray(encoded) ||
            Object.keys(encoded).length !== 2 || typeof encoded.bytes !== "number" || typeof encoded.data !== "string") throw new Error("Compressed stored text is malformed");
        charge(encoded.bytes);
        const compressed = Buffer.from(encoded.data, "base64");
        if (compressed.toString("base64") !== encoded.data) throw new Error("Compressed stored text encoding is invalid");
        const output = gunzipSync(compressed, { maxOutputLength: Math.max(1, encoded.bytes) });
        if (output.length !== encoded.bytes) throw new Error("Compressed stored text length does not match its binding");
        return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(output);
      }
      if (Object.hasOwn(object, escaped)) {
        const entries = object[escaped];
        if (Object.keys(object).length !== 1 || !Array.isArray(entries) || entries.some((entry) => !Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string")) throw new Error("Escaped stored object is malformed");
        return Object.fromEntries(entries.map(([key, child]) => [key, visit(child, depth + 1)]));
      }
      return Object.fromEntries(Object.entries(object).map(([key, child]) => [key, visit(child, depth + 1)]));
    }
    return item;
  };
  return visit(envelope.payload, 0);
}

/** Stream canonical JSON without allocating a potentially enormous escaped aggregate string. */
export function* canonicalJsonChunks(value: unknown): Generator<string> {
  if (typeof value === "string") {
    yield '"';
    for (let start = 0; start < value.length;) {
      let end = Math.min(value.length, start + 64 * 1024);
      if (end < value.length && value.charCodeAt(end - 1) >= 0xd800 && value.charCodeAt(end - 1) <= 0xdbff) end -= 1;
      yield JSON.stringify(value.slice(start, end)).slice(1, -1);
      start = end;
    }
    yield '"';
  } else if (Array.isArray(value)) {
    yield "[";
    for (const [index, child] of value.entries()) { if (index) yield ","; yield* canonicalJsonChunks(child === undefined ? null : child); }
    yield "]";
  } else if (value && typeof value === "object") {
    yield "{";
    // Preserve JSON's integer-key ordering after the same lexical normalization as legacy writers.
    const normalized = Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b, "en-US")));
    let index = 0;
    for (const [key, child] of Object.entries(normalized)) {
      if (child === undefined) continue;
      if (index++) yield ",";
      yield* canonicalJsonChunks(key);
      yield ":";
      yield* canonicalJsonChunks(child);
    }
    yield "}";
  } else {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("Value cannot be serialized as canonical JSON");
    yield encoded;
  }
}
